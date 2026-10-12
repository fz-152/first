"""Личный кабинет сканера: дашборд, детализация, карточки нарушений,
тикеты, экспорт PDF/Excel, администрирование чек-листов (ТЗ §4.2).

Запуск:  python -m app.app  (http://127.0.0.1:8050)
"""
from __future__ import annotations

import json
import ipaddress
import logging
import queue
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, abort, send_file, jsonify, Response)

from scanner.engine import (run_scan, traffic_light, make_progress_handler,
                            _ProgressFilter)
from scanner.models import Store, DB_PATH
from scanner.checklists import ALL_BLOCKS, RULES_BY_ID, CRITICAL, MAJOR, MINOR
from scanner import reports as report_mod
from .auth import login_required, role_required, current_user, init_default_users, ROLE_LABELS

BASE_DIR = Path(__file__).resolve().parent.parent
EXPORT_DIR = BASE_DIR / "data" / "exports"

app = Flask(__name__)
# Флаг для интеграционных тестов/локальной разработки: разрешает запуск сканов
# по localhost-адресам (в production-режиме start_scan их отклоняет).
app.config["ALLOW_TEST_SCANS"] = False
app.secret_key = (BASE_DIR / "data" / "secret_key").read_bytes() if (BASE_DIR / "data" / "secret_key").exists() \
    else None
if app.secret_key is None:
    import secrets
    (BASE_DIR / "data").mkdir(exist_ok=True)
    app.secret_key = secrets.token_hex(32)
    (BASE_DIR / "data" / "secret_key").write_text(app.secret_key)

store = Store(DB_PATH)
DEFAULT_PW = init_default_users(store)

# реестр запущенных сканирований (память процесса)
JOBS: dict[str, dict] = {}

# время хранения завершённых задач в JOBS (НФТ: очистка от «мусора» памяти)
JOB_RETENTION_SEC = 86400  # 24 часа

# --------------------------------------------------------------- SSE-лог сканера
# Потокобезопасное хранилище очередей сообщений: job_id -> queue.Queue.
# Ограниченная очередь (maxsize) не даёт памяти расти при долгих сканах:
# если ни один клиент не подключён, старые сообщения вытесняются новыми.
SCAN_LOGS: dict[str, queue.Queue] = {}
SCAN_LOGS_LOCK = threading.Lock()
SCAN_LOG_MAXSIZE = 500          # размер очереди на задачу
SCAN_LOG_GC_SEC = 15 * 60       # TTL: принудительно чистить незакрытые очереди через 15 мин


class _QueueLogHandler(logging.Handler):
    """Мост engine.emit → SSE: каждое событие прогресса сканера (scan_event)
    превращается в сообщение типа info/pass/warning/error.

    ВАЖНО: не наследует фильтр _ProgressFilter от logging.Filter — у того метод
    называется ``filter()``, а Handler вызывает ``filter()`` как предикат, что
    приводит к бесконечной рекурсии и молчаливой потере всех событий. Здесь
    проверка атрибута scan_event выполняется напрямую.
    """
    _ICON_TYPES = {"ℹ": "info", "✓": "pass", "⚠": "warning", "✗": "error"}

    def __init__(self, job_id: str):
        super().__init__()
        self.job_id = job_id

    def handle(self, record: logging.LogRecord):
        if not hasattr(record, "scan_event"):   # только события прогресса скана
            return
        self.emit(record)

    def emit(self, record: logging.LogRecord):
        try:
            icon = getattr(record, "icon", "ℹ")
            etype = self._ICON_TYPES.get(icon, "info")
            _push_event(self.job_id, etype, message=record.getMessage(), icon=icon)
        except Exception:
            self.handleError(record)   # UI-лог не должен ронять сканирование


def cleanup_scan_logs():
    """GC для SCAN_LOGS/SCAN_HISTORY: удаляет «осиротевшие» очереди — задача
    завершена, но терминатор не был прочитан клиентом (клиент отключился /
    не подключался), либо истёк TTL. Вызывается из потоков-раздатчиков SSE,
    по finish-сигналу и при AJAX-опросе /api/jobs.

    Буфер истории (SCAN_HISTORY) чистится одновременно с очередью, чтобы
    словарь не рос бесконечно (ТЗ §4 «Очистка памяти»)."""
    now = time.time()
    with SCAN_LOGS_LOCK:
        stale = []
        for jid in list(SCAN_LOGS):
            job = JOBS.get(jid)
            status = (job or {}).get("status")
            started_at = (job or {}).get("started_at", 0)
            finished_at = (job or {}).get("finished_at", 0)
            done = status in ("completed", "failed")
            # очередь-терминатор отправлена, но 5 минут никто не читал → GC
            orphaned = done and finished_at and now - finished_at > 5 * 60
            # страховка от «вечных» очередей задач, удалённых из JOBS, или зависших
            ttl_expired = (not started_at) or (now - started_at > SCAN_LOG_GC_SEC * 4)
            if orphaned or (job is None and ttl_expired) or (done and ttl_expired):
                stale.append(jid)
        for jid in stale:
            SCAN_LOGS.pop(jid, None)
            SCAN_HISTORY.pop(jid, None)
    return stale


def cleanup_old_jobs():
    """Удаляет из JOBS завершённые/упавшие задачи старше JOB_RETENTION_SEC."""
    current_time = time.time()
    keys_to_delete = []

    for key, job in list(JOBS.items()):
        if job.get("status") in ("completed", "failed"):
            finished_at = job.get("finished_at", 0)
            if current_time - finished_at > JOB_RETENTION_SEC:
                keys_to_delete.append(key)

    for key in keys_to_delete:
        del JOBS[key]
    return keys_to_delete


def _active_jobs() -> dict:
    """Только активые задачи (pending/running), без тестовых адресов — для дашборда."""
    return {k: v for k, v in JOBS.items()
            if v.get("status") in ("pending", "running")
            and not is_test_site(v.get("site", ""))}


# ----------------------------------------------------- фильтр тестовых адресов
_LOCAL_HOST_PREFIXES = ("http://127.0.0.1", "https://127.0.0.1",
                        "http://localhost", "https://localhost",
                        "http://0.0.0.0", "https://0.0.0.0",
                        "http://[::1]", "https://[::1]")


def is_test_site(url: str) -> bool:
    """True, если URL указывает на локальный/тестовый стенд.

    Скрывает из UI артефакты разработки: localhost/127.0.0.1/0.0.0.0
    и адреса из приватных диапазонов RFC1918 (10.x, 192.168.x, 172.16-31.x).
    """
    u = (url or "").lower().strip()
    if any(u.startswith(p) for p in _LOCAL_HOST_PREFIXES):
        return True
    try:
        host = urlsplit(u if "//" in u else "//" + u).hostname or ""
    except ValueError:
        return False
    # localhost может встретиться и без схемы / с портом (host:port уже разобран)
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_link_local or ip.is_private


def _completed_jobs_sorted() -> list:
    """Завершённые задачи (completed/failed), без тестовых адресов, новые сверху."""
    completed = [(k, v) for k, v in JOBS.items()
                 if v.get("status") in ("completed", "failed")
                 and not is_test_site(v.get("site", ""))]
    return sorted(completed, key=lambda item: item[1].get("finished_at", 0),
                  reverse=True)


@app.context_processor
def inject():
    return {"current_user": current_user, "ROLE_LABELS": ROLE_LABELS,
            "traffic_light": traffic_light}


# ------------------------------------------------------------------ вход
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = store.check_user(request.form.get("login", ""), request.form.get("password", ""))
        if u:
            session["user"] = u
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Неверный логин или пароль", "error")
    return render_template("login.html", default_pw=DEFAULT_PW)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------ дашборд
@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    # очистка старых завершённых задач при каждом открытии дашборда
    cleanup_old_jobs()

    scans = store.list_scans()
    sites = {}
    for s in scans:
        # артефакты разработки (localhost/127.x/приватные сети) не показываем
        if is_test_site(s["site"]):
            continue
        sites.setdefault(s["site"], []).append(s)
    history = {site: list(reversed(h[:12])) for site, h in sites.items()}

    # на дашборде — только активные задачи (pending/running);
    # завершённые ушли на страницу /history
    active_jobs = _active_jobs()
    return render_template("dashboard.html", sites=history, jobs=active_jobs)


# ------------------------------------------------------------------ история сканирований (JOBS)
@app.route("/history")
@login_required
def history():
    """Страница завершённых задач текущего процесса (после очистки — пустая).

    Полная постоянная история сканирований хранится в БД и доступна
    на дашборде и по ссылкам /scan/<id>.
    """
    cleanup_old_jobs()
    sorted_jobs = _completed_jobs_sorted()
    return render_template("history.html", jobs=sorted_jobs)


@app.route("/history/clear", methods=["POST"])
@role_required("admin")
def history_clear():
    """Полная ручная очистка реестра JOBS от завершённых задач (админ)."""
    removed = [k for k, v in JOBS.items()
               if v.get("status") in ("completed", "failed")]
    for k in removed:
        del JOBS[k]
    flash(f"Удалено завершённых задач из памяти: {len(removed)}", "ok")
    return redirect(url_for("history"))


@app.route("/admin/clear-test-data", methods=["POST"])
@role_required("admin")
def clear_test_data():
    """Вариант В: удаляет из хранилища и памяти все сканирования тестовых
    адресов (localhost/127.x/0.0.0.0/приватные сети). Только админ."""
    db_ids = [s["id"] for s in store.list_scans() if is_test_site(s["site"])]
    deleted_db = store.delete_scans(db_ids)
    mem_keys = [k for k, v in JOBS.items() if is_test_site(v.get("site", ""))]
    for k in mem_keys:
        del JOBS[k]
        SCAN_LOGS.pop(k, None)
        SCAN_HISTORY.pop(k, None)
    flash(f"Тестовые данные удалены: сканов из БД — {deleted_db}, "
          f"задач из памяти — {len(mem_keys)}.", "ok")
    return redirect(request.referrer or url_for("dashboard"))


# ------------------------------------------------------------------ запуск скана
@app.route("/scan", methods=["POST"])
@role_required("admin", "auditor")
def start_scan():
    site = request.form.get("site", "").strip()
    if not site.startswith(("http://", "https://")):
        site = "https://" + site
    # валидация: тестовые/локальные адреса не должны попадать в хранилище (ТЗ, чек-лист п.4)
    if is_test_site(site) and not app.config.get("ALLOW_TEST_SCANS"):
        flash("Сканирование локальных/тестовых адресов (localhost, 127.x.x.x, "
              "приватные сети) запрещено в production-режиме.", "error")
        return redirect(url_for("dashboard"))
    job_id = uuid.uuid4().hex[:8]
    try:
        max_pages = int(request.form.get("max_pages", 1000))
    except (TypeError, ValueError):
        max_pages = 1000
    JOBS[job_id] = {"site": site, "status": "running", "result": None,
                    "started_at": time.time(),
                    "started_dt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "finished_at": 0, "finished_dt": "",
                    "scan_id": None, "index": None}

    def worker():
        # мост событий прогресса сканера (engine.emit) в SSE-очередь задачи
        _get_queue(job_id)   # создаём очередь сразу, до появления первых событий
        qh = _QueueLogHandler(job_id)
        _push_event(job_id, "info", message=f"Сканирование запущено: {site}", icon="ℹ")
        try:
            res = run_scan(site, store=store, max_pages=max_pages, progress_log=qh)
            JOBS[job_id].update(status="completed",
                                result=res.notes[-1] if res.notes else "ok",
                                scan_id=_last_scan_id(site), index=res.compliance_index)
            # финальное событие с индексом соответствия
            _push_event(job_id, "done",
                        message=f"Сканирование завершено. Индекс соответствия: "
                                f"{res.compliance_index:.1f}%",
                        icon="✓", index=res.compliance_index,
                        pages=res.pages_scanned, violations=len(res.violations),
                        scan_id=JOBS[job_id]["scan_id"])
        except Exception as e:
            JOBS[job_id].update(status="failed", result=str(e))
            _push_event(job_id, "error",
                        message=f"Сканирование завершилось ошибкой: {e}", icon="✗")
        finally:
            # фиксируем время окончания и сразу чистим «старьё» (ТЗ §5 логирование/память)
            JOBS[job_id]["finished_at"] = time.time()
            JOBS[job_id]["finished_dt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            qh.close()
            # терминатор ОБЯЗАТЕЛЬНО (успех или ошибка): стрим отдаст event: end
            # и завершится; очередь до читателя удалит GC cleanup_scan_logs().
            # put с таймаутом — если очередь полна и не читается клиентом,
            # worker не должен зависать навсегда (антидедлок).
            term_q = _get_queue(job_id)
            try:
                term_q.put(None, timeout=30)
            except queue.Full:
                with SCAN_LOGS_LOCK:      # никто не читал — удаляем сразу сами
                    SCAN_LOGS.pop(job_id, None)
                    SCAN_HISTORY.pop(job_id, None)
            cleanup_old_jobs()

    threading.Thread(target=worker, daemon=True).start()
    return redirect(url_for("dashboard"))


def _last_scan_id(site: str) -> int | None:
    rows = [s for s in store.list_scans(site)]
    return rows[0]["id"] if rows else None


# --------------------------------------------------------------- SSE-стрим логов
# Буфер всех сообщений задачи (для догоняющей подписки после reconnect/F5):
# job_id -> список сериализованных сообщений (кроме терминатора). Ограничен
# SCAN_LOG_MAXSIZE записей, живёт до GC (cleanup_scan_logs) — см. ТЗ §4.
SCAN_HISTORY: dict[str, list] = {}


def _get_queue(job_id: str) -> queue.Queue:
    """Возвращает (создавая при необходимости) очередь логов задачи."""
    with SCAN_LOGS_LOCK:
        q = SCAN_LOGS.get(job_id)
        if q is None:
            q = SCAN_LOGS[job_id] = queue.Queue(maxsize=SCAN_LOG_MAXSIZE)
        return q


def _push_event(job_id: str, etype: str, **data):
    """Кладёт типизированное сообщение {"type": ..., "ts": ..., "data": {...}}
    в очередь live-доставки И в буфер истории задачи.

    Буфер истории нужен для критерия «логи подхватываются автоматически»:
    клиент, подключившийся к стриму позже начала скана (F5, обрыв связи),
    получает уже накопленные сообщения до перехода к live-режиму.

    Никогда не блокирует worker: если очередь полна, выбрасываем самое старое
    сообщение и повторяем попытку (сканирование важнее полного лога).
    """
    msg = json.dumps({"type": etype, "ts": datetime.now().strftime("%H:%M:%S"),
                      "data": data}, ensure_ascii=False)
    q = _get_queue(job_id)
    with SCAN_LOGS_LOCK:
        hist = SCAN_HISTORY.setdefault(job_id, [])
        hist.append(msg)
        if len(hist) > SCAN_LOG_MAXSIZE * 2:
            del hist[:len(hist) - SCAN_LOG_MAXSIZE]
    while True:
        try:
            q.put_nowait(msg)
            return
        except queue.Full:
            try:
                q.get_nowait()
            except queue.Empty:
                pass


@app.route("/api/scan/<job_id>/stream")
@login_required
def scan_stream(job_id):
    """Live-трансляция хода сканирования (Server-Sent Events).

    text/event-stream; при простое — служебный heartbeat (`: ping`, разрывающий
    таймауты обратных прокси, напр. Nginx) ИЛИ event `keepalive` (полезная
    нагрузка, сбрасывающая client-side watchdog на случай молчаливой потери
    данных через буферизирующий прокси); по терминатору None — финальное
    событие `end` и корректное завершение генератора.

    Поддержка reconnect: новые клиенты сначала получают буфер уже накопленных
    сообщений (history), затем переходят в live-режим без дублей.
    """
    if job_id not in JOBS:
        abort(404)
    q = _get_queue(job_id)

    def gen():
        yield "retry: 3000\n\n"           # автопереподключение клиента через 3 c
        # --- догоняющая подписка: отдаём накопленный буфер истории ---
        with SCAN_LOGS_LOCK:
            backlog = list(SCAN_HISTORY.get(job_id, []))
        for msg in backlog:
            yield f"data: {msg}\n\n"
        # буфер отправлен — live-режим начинается с чистого листа:
        # всё, что worker успел положить в очередь за время отправки backlog,
        # будет отдано ниже; дубли из backlog вычищаем сравнением.
        sent = set(backlog)
        finished = False
        idle_pings = 0
        while True:
            try:
                msg = q.get(timeout=15)   # ждём не дольше таймаута типичного прокси
            except queue.Empty:
                idle_pings += 1
                if idle_pings >= 2:
                    # полезная нагрузка: гарантирует активность потока даже
                    # если прокси съедает SSE-комментарии
                    yield 'event: keepalive\ndata: {"type": "keepalive"}\n\n'
                    idle_pings = 0
                else:
                    yield ": ping\n\n"    # служебный комментарий SSE
                continue
            if msg is None:               # сигнал завершения от worker'а
                status = (JOBS.get(job_id) or {}).get("status", "completed")
                yield ('data: ' + json.dumps({"type": "finished", "ts":
                        datetime.now().strftime("%H:%M:%S"),
                        "data": {"status": status}}, ensure_ascii=False) + "\n\n")
                yield 'event: end\ndata: {"type": "end"}\n\n'
                finished = True
                break
            if msg in sent:               # уже отдали из backlog — не дублируем
                continue
            sent.add(msg)                 # защита от дублей при reconnect'е
            yield f"data: {msg}\n\n"
        # поток дочитан до конца — очередь больше не нужна (антиутечка памяти);
        # буфер истории оставляем до GC, чтобы reconnect-клиент мог догнать лог
        with SCAN_LOGS_LOCK:
            SCAN_LOGS.pop(job_id, None)
        if finished:
            cleanup_scan_logs()

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",   # Nginx: не буферизовать ответ
                             "Connection": "keep-alive"})


@app.route("/api/scan/<job_id>/logs")
@login_required
def api_scan_logs(job_id):
    """Все накопленные логи задачи (snapshot) — резервный канал на случай,
    если EventSource не может восстановить соединение со стримом."""
    with SCAN_LOGS_LOCK:
        raw = list(SCAN_HISTORY.get(job_id, []))
    logs = [json.loads(m) for m in raw]
    job = JOBS.get(job_id) or {}
    return jsonify({"job_id": job_id, "status": job.get("status"),
                    "logs": logs})


@app.route("/api/jobs")
@login_required
def api_jobs():
    """Статусы АКТИВНЫХ задач — для AJAX-опроса на дашборде без перезагрузки."""
    cleanup_old_jobs()
    cleanup_scan_logs()   # GC «осиротевших» SSE-очередей (клиент не дочитал)
    return jsonify(_active_jobs())


# ------------------------------------------------------------------ история/детализация
@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    scan = store.get_scan(scan_id)
    if not scan:
        abort(404)
    viols = store.get_violations(scan_id)
    grouped: dict[str, list] = {}
    for v in viols:
        grouped.setdefault(v["block"], []).append(v)
    open_cnt = sum(1 for v in viols if v["status"] == "open")
    resolved_cnt = sum(1 for v in viols if v["status"] == "resolved")
    return render_template("scan_detail.html", scan=scan, grouped=grouped,
                           blocks=ALL_BLOCKS, open_cnt=open_cnt, resolved_cnt=resolved_cnt,
                           light=traffic_light(scan["compliance_index"]))


@app.route("/violation/<int:vid>")
@login_required
def violation_card(vid):
    row = store._con.execute("SELECT * FROM violations WHERE id=?", (vid,)).fetchone()
    if not row:
        abort(404)
    d = dict(row)
    d["details"] = json.loads(d["details"] or "[]")
    rule = RULES_BY_ID.get(d["rule_id"])
    return render_template("violation_card.html", v=d, rule=rule)


# ------------------------------------------------------------------ тикет-система
@app.route("/ticket/<int:vid>", methods=["POST"])
@role_required("admin", "auditor")
def update_ticket(vid):
    store.update_ticket(
        vid,
        status=request.form.get("status") or None,
        assignee=request.form.get("assignee") or None,
        due_date=request.form.get("due_date") or None,
        comment=request.form.get("comment") or None)
    flash("Тикет обновлён", "ok")
    return redirect(url_for("violation_card", vid=vid))


# ------------------------------------------------------------------ экспорт
@app.route("/export/<int:scan_id>/<fmt>")
@login_required
def export(scan_id, fmt):
    scan = store.get_scan(scan_id)
    if not scan or fmt not in ("pdf", "xlsx"):
        abort(404)
    viols = [v for v in store.get_violations(scan_id)]
    from scanner.models import Violation
    vs = []
    for v in viols:
        vs.append(Violation(rule_id=v["rule_id"], block=v["block"], law=v["law"],
                            severity=v["severity"], title=v["title"], message=v["message"],
                            page_url=v["page_url"], details=v["details"],
                            screenshot=v["screenshot"]))
    passed = json.loads((scan.get("result_json") or "{}")).get("passed", [])
    res_obj = type("R", (), {})()
    from scanner.models import ScanResult
    sr = ScanResult(site=scan["site"], started_at=scan["started_at"], finished_at=scan["finished_at"],
                    pages_scanned=scan["pages_scanned"], violations=vs, passed_rules=passed,
                    compliance_index=scan["compliance_index"], duration_sec=scan["duration_sec"],
                    notes=json.loads(scan["notes"] or "[]"))
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    name = f"report_scan{scan_id}"
    if fmt == "pdf":
        p = report_mod.export_pdf(sr, EXPORT_DIR / (name + ".pdf"))
    else:
        p = report_mod.export_excel(sr, EXPORT_DIR / (name + ".xlsx"))
    return send_file(p, as_attachment=True, download_name=p.name)


# ------------------------------------------------------------------ админ: чек-листы
@app.route("/admin/rules")
@role_required("admin")
def admin_rules():
    rules = store.get_rules()
    by_block: dict[str, list] = {}
    for r in rules:
        by_block.setdefault(r["block"], []).append(r)
    return render_template("admin_rules.html", by_block=by_block)


@app.route("/admin/rules/<rule_id>", methods=["POST"])
@role_required("admin")
def admin_rule_update(rule_id):
    if rule_id not in RULES_BY_ID:
        abort(404)
    enabled = request.form.get("enabled") == "on"
    sev = request.form.get("severity") or None
    law = request.form.get("law") or None
    store.update_rule(rule_id, enabled=enabled, severity=sev, law=law)
    flash(f"Правило {rule_id} обновлено", "ok")
    return redirect(url_for("admin_rules"))


@app.route("/admin/users", methods=["GET", "POST"])
@role_required("admin")
def admin_users():
    if request.method == "POST":
        login_ = request.form.get("login", "").strip()
        pw = request.form.get("password", "")
        role = request.form.get("role", "user")
        if login_ and pw and role in ROLE_LABELS:
            store.add_user(login_, pw, role)
            flash(f"Пользователь {login_} сохранён (роль: {ROLE_LABELS[role]})", "ok")
        else:
            flash("Заполните логин, пароль и корректную роль", "error")
    return render_template("admin_users.html", users=store.list_users())


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403,
                           desc="Доступ запрещён. Ваша роль не позволяет выполнить это действие."), 403


@app.errorhandler(404)
def nf(e):
    return render_template("error.html", code=404, desc="Страница не найдена"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050, debug=False)
