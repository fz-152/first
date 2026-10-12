"""Оркестратор сканирования (ТЗ §4.1 «Архитектура», §5 «Скорость/Логирование»).

run_scan(site) = crawl → asset-check → analysis (чекеры блоков 3.1–3.6) →
индекс соответствия → сохранение в БД (история для отслеживания динамики).
"""
from __future__ import annotations

import logging
from pathlib import Path

from .checklists import RULES_BY_ID, CRITICAL, MAJOR, MINOR, ALL_BLOCKS
from .crawler import Crawler, render_screenshot
from .models import ScanResult, Violation, Store, compute_compliance_index, now_iso
from .checkers import CHECKERS
from .checkers.common import ScanContext

log = logging.getLogger("scanner.engine")


def run_scan(site: str, *, store: Store | None = None, max_pages: int = 1000,
             deadline_min: float = 15.0, screenshots: bool = False,
             out_dir: str | Path | None = None) -> ScanResult:
    """Полное сканирование сайта; результат сохраняется в БД (если store задан)."""
    started = now_iso()
    t0 = __import__("time").monotonic()
    crawler = Crawler(site, max_pages=max_pages, deadline_sec=deadline_min * 60)
    stats = crawler.run()
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
    crawler.check_assets(doc_like)
    ctx.assets = crawler.assets

    violations: list[Violation] = []
    for checker in CHECKERS:
        try:
            violations.extend(checker(ctx))
        except Exception as e:                     # чекер не должен ронять скан
            log.exception("Чекер %s завершился с ошибкой", checker.__name__)
            ctx_note = f"Ошибка чекера {checker.__name__}: {e}"
    notes = [f"Отсканировано страниц: {stats.fetched}"]
    if stats.truncated:
        notes.append(f"Сканирование прервано по лимиту ({max_pages} стр. / {deadline_min} мин).")
    if stats.blocked_events:
        notes.append("Страницы с признаками CAPTCHA/WAF: " + ", ".join(stats.blocked_events[:5]))
    if stats.errors:
        notes.append(f"Не удалось загрузить страниц/файлов: {stats.errors}.")

    # правила, по которым нет нарушений → passed
    violated_ids = {v.rule_id for v in violations}
    passed = [rid for rid in RULES_BY_ID if rid not in violated_ids and ctx.enabled(rid)]

    res = ScanResult(site=site, started_at=started, finished_at=now_iso(),
                     pages_scanned=stats.fetched, violations=violations,
                     passed_rules=passed, duration_sec=round(__import__("time").monotonic() - t0, 1),
                     notes=notes)
    rules_for_index = store.get_rules() if store else [r.to_dict() for r in RULES_BY_ID.values()]
    res.compliance_index = compute_compliance_index(rules_for_index, violations)

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


def traffic_light(index: float) -> str:
    """Светофорная индикация (ТЗ §4.2): ≥80 % зелёный, 50–79 жёлтый, <50 красный."""
    if index >= 80:
        return "green"
    if index >= 50:
        return "yellow"
    return "red"
