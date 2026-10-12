"""Оркестратор сканирования (ТЗ §4.1 «Архитектура», §5 «Скорость/Логирование»).

run_scan(site) = crawl → asset-check → analysis (чекеры блоков 3.1–3.6) →
индекс соответствия → сохранение в БД (история для отслеживания динамики).
"""
from __future__ import annotations

import logging
import time as _time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from .checklists import RULES_BY_ID, CRITICAL, MAJOR, MINOR, ALL_BLOCKS
from .crawler import Crawler, render_screenshot
from .models import ScanResult, Violation, Store, compute_compliance_index, now_iso
from .checkers import CHECKERS
from .checkers.common import ScanContext

log = logging.getLogger("scanner.engine")


class _ProgressFilter(logging.Filter):
    """Пропускает только записи с атрибутом ``scan_event`` (события прогресса),
    чтобы не тащить в лог скана служебные сообщения других модулей."""

    def filter(self, record: logging.LogRecord) -> bool:
        return hasattr(record, "scan_event")


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


ICON_INFO = "ℹ"
ICON_PASS = "✓"
ICON_WARN = "⚠"
ICON_FAIL = "✗"


def make_progress_handler(job_key: str) -> logging.FileHandler:
    """FileHandler с фильтром scan_event — пишет ход скана в data/logs/<job>.log.

    Формат строки (ТЗ §4.2 «отчёт в реальном времени»):
    [HH:MM:SS] <иконка> <сообщение>
    """
    log_dir = Path(__file__).resolve().parent.parent / "data" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_dir / f"{job_key}.log", encoding="utf-8")
    fh.addFilter(_ProgressFilter())
    fh.setFormatter(logging.Formatter("[%(ts)s] %(icon)s %(message)s"))
    return fh


def run_scan(site: str, *, store: Store | None = None, max_pages: int = 1000,
             deadline_min: float = 15.0, screenshots: bool = False,
             out_dir: str | Path | None = None,
             progress_log: logging.Handler | None = None) -> ScanResult:
    """Полное сканирование сайта; результат сохраняется в БД (если store задан).

    progress_log — необязательный обработчик событий прогресса (см.
    make_progress_handler): на него дублируются ключевые шаги обхода и вердикты
    правил, что позволяет UI показывать живой лог сканирования.
    """
    started = now_iso()
    t0 = _time.monotonic()

    handlers: list[logging.Handler] = []
    if progress_log is not None:
        progress_log.setLevel(logging.INFO)
        for name in ("scanner.crawler", "scanner.engine"):
            lg = logging.getLogger(name)
            lg.addHandler(progress_log)
            handlers.append((lg, progress_log))

    def emit(icon: str, message: str, ts: float | None = None):
        """Логирует событие прогресса (с атрибутами для форматтера handler'а)."""
        extra = {"scan_event": True, "icon": icon,
                 "ts": _fmt_ts(_time.time() if ts is None else ts)}
        log.info(message, extra=extra)

    # фиксируем лимиты старта — попадут в живой лог и в заметки результата (ТЗ §3.1)
    max_pages = max(1, int(max_pages))
    deadline_min = max(0.1, float(deadline_min))

    emit(ICON_INFO, f"Начало сканирования {site}")
    emit(ICON_INFO, f"Лимиты: максимум {max_pages} стр., таймаут {deadline_min:.0f} мин")
    emit(ICON_INFO, "Обход главной страницы...")

    crawler = Crawler(site, max_pages=max_pages, deadline_sec=deadline_min * 60,
                      on_event=lambda ev: emit(ev.get("icon", ICON_INFO),
                                               ev.get("message", ""),
                                               ev.get("ts")))
    try:
        stats = crawler.run()
    except Exception:
        emit(ICON_FAIL, f"Сканирование прервано ошибкой: {site}")
        raise
    log.info("Обход завершён: %d страниц за %.1f c", stats.fetched, stats.duration)

    # собираем все ссылки на файлы/внешние ИС и проверяем их HEAD-запросами
    from .checkers.common import link_text_map
    ctx_rules = {r["id"]: r["enabled"] for r in (store.get_rules() if store else [])} \
        if store else {}
    ctx = ScanContext(root=crawler.root, pages=crawler.pages, assets=crawler.assets,
                      rules_enabled=ctx_rules or {rid: True for rid in RULES_BY_ID})
    all_links = set(link_text_map(ctx).keys())
    doc_like = {u for u in all_links
                if Path(__import__("urllib.parse", fromlist=["urlparse"]).urlparse(u).path).suffix.lower()
                in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip"} or
                not _same_host(u, crawler.root)}
    emit(ICON_INFO, f"Проверка ссылок на документы и внешние ИС ({len(doc_like)} шт.)...")
    crawler.check_assets(doc_like)
    ctx.assets = crawler.assets

    # ---- анализ контента: чекеры блоков 3.1–3.6 (ТЗ §3) ----
    violations: list[Violation] = []
    checker_errors: list[str] = []
    emit(ICON_INFO, "Анализ контента по чек-листу нормативных требований...")
    for checker in CHECKERS:
        try:
            found = checker(ctx)
        except Exception as e:                     # чекер не должен ронять скан
            log.exception("Чекер %s завершился с ошибкой", checker.__name__)
            checker_errors.append(f"{checker.__name__}: {e}")
            continue
        violations.extend(found)
        by_block: dict[str, int] = {}
        for v in found:
            by_block[v.block] = by_block.get(v.block, 0) + 1
        if not by_block:
            emit(ICON_PASS, f"{checker.__name__}: замечаний нет")
        for b in sorted(by_block):
            n = by_block[b]
            emit(ICON_WARN if n else ICON_PASS,
                 f"Блок «{b}»: нарушений — {n}")

    notes = [f"Отсканировано страниц: {stats.fetched}"]
    if stats.truncated:
        notes.append(f"Сканирование прервано по лимиту ({max_pages} стр. / {deadline_min} мин).")
    if stats.blocked_events:
        notes.append("Страницы с признаками CAPTCHA/WAF: " + ", ".join(stats.blocked_events[:5]))
    if stats.errors:
        notes.append(f"Не удалось загрузить страниц/файлов: {stats.errors}.")
    if checker_errors:
        notes.append("Ошибки чекеров: " + "; ".join(checker_errors))

    # правила, по которым нет нарушений → passed
    violated_ids = {v.rule_id for v in violations}
    passed = [rid for rid in RULES_BY_ID if rid not in violated_ids and ctx.enabled(rid)]

    res = ScanResult(site=site, started_at=started, finished_at=now_iso(),
                     pages_scanned=stats.fetched, violations=violations,
                     passed_rules=passed, duration_sec=round(_time.monotonic() - t0, 1),
                     notes=notes)
    rules_for_index = store.get_rules() if store else [r.to_dict() for r in RULES_BY_ID.values()]
    res.compliance_index = compute_compliance_index(rules_for_index, violations)
    emit(ICON_PASS, f"Сканирование завершено. Индекс соответствия: {res.compliance_index:.1f}%")

    # скриншоты критичных нарушений (опционально, требует Selenium — ТЗ §4.2)
    if screenshots and out_dir:
        shot_dir = Path(out_dir)
        done = 0
        for v in violations:
            if v.severity == CRITICAL and v.page_url and done < 10:
                p = shot_dir / f"scan_v{done}_{v.rule_id}.png"
                if render_screenshot(v.page_url, str(p)):
                    v.screenshot = str(p)
                    done += 1

    if store is not None:
        sid = store.save_scan(res)
        res.notes.append(f"Сканирование сохранено, id={sid}")
    return res


def _same_host(url: str, root: str) -> bool:
    from urllib.parse import urlparse
    return urlparse(url).netloc.lower() == urlparse(root).netloc.lower()


_SEVERITY_ICON = {CRITICAL: ICON_FAIL, MAJOR: ICON_WARN, MINOR: "ℹ"}


def format_console_report(res: ScanResult) -> str:
    """Текстовый отчёт сканирования в формате ТЗ §«Пример полного отчёта»:

        ИНДЕКС СООТВЕТСТВИЯ: 72.1%
        БЛОК 1: ... (выполнено/всего)
          [✓]/[✗] по каждому правилу блока + краткое описание нарушения
    """
    sep = "=" * 43
    lines = [sep, "ОТЧЁТ О СКАНИРОВАНИИ",
             f"Сайт: {res.site}",
             f"Дата: {res.started_at} — {res.finished_at}"
             f" ({res.pages_scanned} стр., {res.duration_sec:.0f} c)",
             sep, ""]
    tl = {"green": "🟢 высокое", "yellow": "🟡 частичное", "red": "🔴 низкое"}[traffic_light(res.compliance_index)]
    lines.append(f"ИНДЕКС СООТВЕТСТВИЯ: {res.compliance_index:.1f}%  ({tl})")
    lines.append("")

    total_checked = len(res.passed_rules) + len({v.rule_id for v in res.violations})
    crit = sum(1 for v in res.violations if v.severity == CRITICAL)
    for i, block in enumerate(ALL_BLOCKS, 1):
        rule_ids = [rid for rid, r in RULES_BY_ID.items() if r["block"] == block]
        vs = [v for v in res.violations if v.block == block]
        bad_ids = {v.rule_id for v in vs}
        ok_n = sum(1 for rid in rule_ids if rid not in bad_ids)
        mark = "✓" if not vs else ("⚠" if all(v.severity != CRITICAL for v in vs) else "✗")
        lines.append(f"БЛОК {i}: {block.split(' ', 1)[1]} ({ok_n}/{len(rule_ids)}) {mark}")
        for v in sorted(vs, key=lambda x: (x.severity != CRITICAL, x.rule_id)):
            icon = _SEVERITY_ICON.get(v.severity, "ℹ")
            law = f" ({v.law})" if v.law else ""
            first_line = (v.message or v.title).splitlines()[0]
            lines.append(f"  [{icon}] {v.title}: {first_line}{law}")
        for rid in rule_ids:
            if rid not in bad_ids:
                lines.append(f"  [{ICON_PASS}] {RULES_BY_ID[rid]['title']}")
        lines.append("")

    lines += [sep,
              f"ВСЕГО ПРАВИЛ ПРОВЕРЕНО: {total_checked}, НАРУШЕНИЙ: {len(res.violations)}",
              f"КРИТИЧНЫХ: {crit} (требуют немедленного исправления)" if crit
              else "КРИТИЧНЫХ: 0",
              sep]
    return "\n".join(lines)


def traffic_light(index: float) -> str:
    """Светофорная индикация (ТЗ §4.2): ≥80 % зелёный, 50–79 жёлтый, <50 красный."""
    if index >= 80:
        return "green"
    if index >= 50:
        return "yellow"
    return "red"
