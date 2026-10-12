"""Личный кабинет сканера: дашборд, детализация, карточки нарушений,
тикеты, экспорт PDF/Excel, администрирование чек-листов (ТЗ §4.2).

Запуск:  python -m app.app  (http://127.0.0.1:8050)
"""
from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path

from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, abort, send_file, jsonify)

from scanner.engine import run_scan, traffic_light
from scanner.models import Store, DB_PATH
from scanner.checklists import ALL_BLOCKS, RULES_BY_ID, CRITICAL, MAJOR, MINOR
from scanner import reports as report_mod
from .auth import login_required, role_required, current_user, init_default_users, ROLE_LABELS

BASE_DIR = Path(__file__).resolve().parent.parent
EXPORT_DIR = BASE_DIR / "data" / "exports"

app = Flask(__name__)
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
@login_required
def dashboard():
    scans = store.list_scans()
    sites = {}
    for s in scans:
        sites.setdefault(s["site"], []).append(s)
    history = {site: list(reversed(h[:12])) for site, h in sites.items()}
    return render_template("dashboard.html", sites=history, jobs=JOBS)


# ------------------------------------------------------------------ запуск скана
@app.route("/scan", methods=["POST"])
@role_required("admin", "auditor")
def start_scan():
    site = request.form.get("site", "").strip()
    if not site.startswith(("http://", "https://")):
        site = "https://" + site
    job_id = uuid.uuid4().hex[:8]
    JOBS[job_id] = {"site": site, "status": "running", "result": None}

    def worker():
        try:
            res = run_scan(site, store=store, max_pages=int(request.form.get("max_pages", 1000)))
            JOBS[job_id].update(status="done", result=res.notes[-1] if res.notes else "ok",
                                scan_id=_last_scan_id(site), index=res.compliance_index)
        except Exception as e:
            JOBS[job_id].update(status="error", result=str(e))

    threading.Thread(target=worker, daemon=True).start()
    return redirect(url_for("dashboard"))


def _last_scan_id(site: str) -> int | None:
    rows = [s for s in store.list_scans(site) ]
    return rows[0]["id"] if rows else None


@app.route("/api/jobs")
@login_required
def api_jobs():
    return jsonify(JOBS)


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
