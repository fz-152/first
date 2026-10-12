"""Доменные модели и SQLite-хранилище (ТЗ §5 «Логирование», §4.2 «Тикет-система»)."""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .checklists import RULES, SEVERITY_WEIGHTS, CRITICAL, MAJOR, MINOR

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scanner.db"

STATUS_OPEN     = "open"
STATUS_IN_PROGRESS = "in_progress"
STATUS_RESOLVED = "resolved"
STATUS_IGNORED  = "ignored"   # ложное срабатывание (калибровка, ТЗ §6 этап 5)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------- доменные модели
@dataclass
class Page:
    """Собранная crawlers страница."""
    url: str
    status: int = 0
    content_type: str = ""
    html: str = ""
    headers: dict = field(default_factory=dict)
    depth: int = 0
    title: str = ""
    lang: str = ""
    last_modified: str = ""      # из HTTP-заголовков
    fetch_seconds: float = 0.0

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or self.html.strip().startswith(("<", "<!"))

    @property
    def path(self) -> str:
        return urlparse(self.url).path.lower()


@dataclass
class Violation:
    """Карточка нарушения (ТЗ §4.2)."""
    rule_id: str
    block: str
    law: str
    severity: str
    title: str
    message: str
    page_url: str = ""
    details: list = field(default_factory=list)   # [(фрагмент, комментарий), ...]
    screenshot: str = ""                          # путь к PNG (если доступен рендеринг)

    def fingerprint(self) -> str:
        return f"{self.rule_id}|{self.page_url}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["details"] = [list(x) if isinstance(x, tuple) else x for x in self.details]
        return d


@dataclass
class ScanResult:
    site: str
    started_at: str
    finished_at: str
    pages_scanned: int
    violations: list = field(default_factory=list)
    passed_rules: list = field(default_factory=list)
    compliance_index: float = 0.0
    duration_sec: float = 0.0
    notes: list = field(default_factory=list)     # предупреждения движка (WAF/CAPTCHA и т.п.)


# --------------------------------------------------------------- утилиты URL
def normalize_url(base: str, url: str) -> str | None:
    """Приведение URL к каноничному виду для краулера; None — не HTML-страница/вне сайта."""
    if not url or url.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
        return None
    absu = urljoin(base, url)
    p = urlparse(absu)
    if p.scheme not in ("http", "https"):
        return None
    ext = Path(p.path).suffix.lower().lstrip(".")
    skip_ext = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "mp3", "mp4",
                "avi", "mov", "wmv", "flv", "woff", "woff2", "ttf", "eot", "otf"}
    if ext in skip_ext:
        return None
    frag = p.fragment
    clean = p._replace(fragment="", query="").geturl()
    if clean.endswith("/") and len(urlparse(clean).path) > 1:
        clean = clean.rstrip("/")
    return clean if not frag else None


def same_site(url: str, root: str) -> bool:
    a, b = urlparse(url).netloc.lower(), urlparse(root).netloc.lower()
    return a == b or a.startswith("www.") and a[4:] == b or b.startswith("www.") and b[4:] == a


# --------------------------------------------------------------- хранилище
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  pages_scanned INTEGER, duration_sec REAL,
  compliance_index REAL, red_count INTEGER, yellow_count INTEGER, green_count INTEGER,
  notes TEXT, result_json TEXT
);
CREATE TABLE IF NOT EXISTS violations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  fp TEXT, rule_id TEXT, block TEXT, law TEXT, severity TEXT,
  title TEXT, message TEXT, page_url TEXT, details TEXT, screenshot TEXT,
  status TEXT DEFAULT 'open',
  assignee TEXT DEFAULT '', due_date TEXT DEFAULT '', comment TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_v_scan ON violations(scan_id);
CREATE INDEX IF NOT EXISTS idx_v_fp   ON violations(fp);
CREATE TABLE IF NOT EXISTS rules_override(
  rule_id TEXT PRIMARY KEY, enabled INTEGER, severity TEXT, law TEXT, params TEXT
);
CREATE TABLE IF NOT EXISTS users(
  login TEXT PRIMARY KEY, password_hash TEXT, role TEXT CHECK(role IN ('admin','auditor','user'))
);
"""


class Store:
    def __init__(self, path: str | Path = DB_PATH):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(self.path, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._con.executescript(SCHEMA)
        self._con.commit()

    # ---- правила (чек-листы, редактируемые в админ-панели) ----
    def get_rules(self) -> list[dict]:
        ov = {r["rule_id"]: r for r in self._con.execute("SELECT * FROM rules_override")}
        out = []
        for rule in RULES:
            d = rule.to_dict()
            o = ov.get(d["id"])
            if o:
                if o["enabled"] is not None:
                    d["enabled"] = bool(o["enabled"])
                if o["severity"]:
                    d["severity"] = o["severity"]
                if o["law"]:
                    d["law"] = o["law"]
                if o["params"]:
                    d["params"].update(json.loads(o["params"]))
            out.append(d)
        return out

    def update_rule(self, rule_id: str, *, enabled: bool | None = None,
                    severity: str | None = None, law: str | None = None,
                    params: dict | None = None) -> None:
        cur = self._con.execute("SELECT * FROM rules_override WHERE rule_id=?", (rule_id,))
        row = cur.fetchone()
        e = int(enabled) if enabled is not None else (row["enabled"] if row else 1)
        s = severity or (row["severity"] if row else "")
        l = law or (row["law"] if row else "")
        p = json.dumps(params or (json.loads(row["params"]) if row and row["params"] else {}))
        self._con.execute(
            "INSERT INTO rules_override(rule_id,enabled,severity,law,params) VALUES(?,?,?,?,?) "
            "ON CONFLICT(rule_id) DO UPDATE SET enabled=?,severity=?,law=?,params=?",
            (rule_id, e, s, l, p, e, s, l, p))
        self._con.commit()

    # ---- сканирования ----
    def save_scan(self, res: ScanResult) -> int:
        counts = _traffic_counts(res.violations)
        cur = self._con.execute(
            "INSERT INTO scans(site,started_at,finished_at,pages_scanned,duration_sec,"
            "compliance_index,red_count,yellow_count,green_count,notes,result_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (res.site, res.started_at, res.finished_at, res.pages_scanned, res.duration_sec,
             res.compliance_index, counts["red"], counts["yellow"], counts["green"],
             json.dumps(res.notes, ensure_ascii=False), json.dumps({"passed": res.passed_rules}, ensure_ascii=False)))
        sid = cur.lastrowid
        for v in res.violations:
            d = v.to_dict()
            self._con.execute(
                "INSERT INTO violations(scan_id,fp,rule_id,block,law,severity,title,message,"
                "page_url,details,screenshot,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, v.fingerprint(), v.rule_id, v.block, v.law, v.severity, v.title,
                 v.message, v.page_url, json.dumps(d["details"], ensure_ascii=False),
                 v.screenshot, STATUS_OPEN))
        self._con.commit()
        return sid

    def list_scans(self, site: str | None = None) -> list[dict]:
        q = "SELECT * FROM scans"
        args: tuple = ()
        if site:
            q += " WHERE site=?"
            args = (site,)
        q += " ORDER BY id DESC"
        return [dict(r) for r in self._con.execute(q, args)]

    def delete_scans(self, ids: list[int]) -> int:
        """Удаляет сканирования (и связанные нарушения каскадом). Возвращает число."""
        if not ids:
            return 0
        marks = ",".join("?" * len(ids))
        n = self._con.execute(
            f"DELETE FROM violations WHERE scan_id IN ({marks})", ids).rowcount
        self._con.execute(f"DELETE FROM scans WHERE id IN ({marks})", ids)
        self._con.commit()
        return len(ids)

    def get_scan(self, scan_id: int) -> dict | None:
        r = self._con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(r) if r else None

    def get_violations(self, scan_id: int) -> list[dict]:
        rows = self._con.execute(
            "SELECT * FROM violations WHERE scan_id=? ORDER BY CASE severity "
            "WHEN 'critical' THEN 0 WHEN 'major' THEN 1 ELSE 2 END, rule_id", (scan_id,))
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d["details"] or "[]")
            out.append(d)
        return out

    # ---- тикет-система (ТЗ §4.2) ----
    def update_ticket(self, violation_id: int, *, status: str | None = None,
                      assignee: str | None = None, due_date: str | None = None,
                      comment: str | None = None) -> None:
        fields, args = [], []
        for col, val in (("status", status), ("assignee", assignee),
                         ("due_date", due_date), ("comment", comment)):
            if val is not None:
                fields.append(f"{col}=?")
                args.append(val)
        if fields:
            args.append(violation_id)
            self._con.execute(f"UPDATE violations SET {','.join(fields)} WHERE id=?", args)
            self._con.commit()

    # ---- пользователи / разграничение прав (ТЗ §5) ----
    def add_user(self, login: str, password: str, role: str) -> None:
        import hashlib
        h = hashlib.sha256(password.encode()).hexdigest()
        self._con.execute(
            "INSERT INTO users(login,password_hash,role) VALUES(?,?,?) "
            "ON CONFLICT(login) DO UPDATE SET password_hash=?,role=?", (login, h, role, h, role))
        self._con.commit()

    def check_user(self, login: str, password: str) -> dict | None:
        import hashlib
        r = self._con.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
        if r and r["password_hash"] == hashlib.sha256(password.encode()).hexdigest():
            return {"login": r["login"], "role": r["role"]}
        return None

    def list_users(self) -> list[dict]:
        return [dict(r) for r in self._con.execute("SELECT login,role FROM users")]


def _traffic_counts(violations: list[Violation]) -> dict:
    red = sum(1 for v in violations if v.severity == CRITICAL)
    yellow = sum(1 for v in violations if v.severity == MAJOR)
    minor = sum(1 for v in violations if v.severity == MINOR)
    return {"red": red, "yellow": yellow, "minor": minor, "green": 0}


def compute_compliance_index(rules: list[dict], violations: list[Violation],
                             passed_weight: float = 1.0) -> float:
    """Индекс соответствия, % (ТЗ §4.2 «Дашборд»).

    Для каждого включённого правила — взвешенный вклад (по severity).
    Нарушение критичного правила обнуляет его вклад полностью,
    major — оставляет 30 %, minor — 70 %.
    """
    sev_w = SEVERITY_WEIGHTS
    total = got = 0.0
    violated = {}
    for v in violations:
        cur = violated.get(v.rule_id, 3)
        violated[v.rule_id] = min(cur, {CRITICAL: 0, MAJOR: 1, MINOR: 2}[v.severity])
    for r in rules:
        if not r.get("enabled", True):
            continue
        w = sev_w[r["severity"]]
        total += w
        worst = violated.get(r["id"])
        if worst is None:
            got += w
        elif worst == 1:
            got += w * 0.3
        elif worst == 2:
            got += w * 0.7
    return round(100.0 * got / total, 1) if total else 0.0


DATE_RE = re.compile(r"\b(0?[1-9]|[12]\d|3[01])[./](0?[1-9]|1[0-2])[./](20\d{2})\b|"
                     r"\b(20\d{2})[-.](0?[1-9]|1[0-2])[-.](0?[1-9]|[12]\d|3[01])\b")


def extract_dates(text: str) -> list[datetime]:
    """Извлечение дат дд.мм.гггг / гггг-мм-дд из текста страницы."""
    found = []
    for m in DATE_RE.finditer(text or ""):
        g = m.groups()
        try:
            if g[2]:
                found.append(datetime(int(g[3]), int(g[2]), int(g[0][:2].rstrip('./') or g[0])))
            else:
                found.append(datetime(int(g[4]), int(g[5]), int(g[6])))
        except ValueError:
            try:
                if g[2]:
                    dd = int(re.sub(r"[./]", "", g[0]))
                    found.append(datetime(int(g[3]), int(g[2]), dd))
            except Exception:
                continue
    return found
