"""Разграничение прав доступа: Администратор / Аудитор / Пользователь (ТЗ §5)."""
from __future__ import annotations

import secrets
from functools import wraps

from flask import abort, session, redirect, request, url_for, flash

from scanner.models import Store


ROLE_ADMIN = "admin"      # чек-листы, пользователи, запуск сканирований
ROLE_AUDITOR = "auditor"  # сканирования, тикеты, отчёты
ROLE_USER = "user"        # просмотр дашборда и отчётов

ROLE_LABELS = {ROLE_ADMIN: "Администратор", ROLE_AUDITOR: "Аудитор", ROLE_USER: "Пользователь"}


def current_user() -> dict | None:
    u = session.get("user")
    return u if isinstance(u, dict) else None


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user():
            # request.endpoint надёжно даёт имя текущего маршрута,
            # request.view_args — актуальные параметры из URL (f.defaults их мог пропустить)
            return redirect(url_for("login",
                                    next=url_for(request.endpoint, **request.view_args)))
        return f(*a, **kw)
    return wrapper


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                return redirect(url_for("login"))
            if roles and u["role"] not in roles:
                abort(403, description="Недостаточно прав: требуется роль "
                        + "/".join(ROLE_LABELS.get(r, r) for r in roles))
            return f(*a, **kw)
        return wrapper
    return deco


def init_default_users(store: Store) -> None:
    """Служебные учётки при первом запуске (пароли — сменить в продакшене!)."""
    if store.list_users():
        return
    default_pw = secrets.token_hex(6)
    store.add_user("admin", default_pw, ROLE_ADMIN)
    store.add_user("auditor", "auditor123", ROLE_AUDITOR)
    store.add_user("user", "user123", ROLE_USER)
    return default_pw
