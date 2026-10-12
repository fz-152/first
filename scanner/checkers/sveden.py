"""Блок 3.1 — «Сведения об образовательной организации» (ТЗ §3.1).

Проверяются: наличие специального раздела, все обязательные подпункты
(Приказ № 1493 п. 8), форматы документов, их актуальность, битые ссылки,
обязательные документы (устав/лицензия/аккредитация).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..checklists import (MANDATORY_SUBSECTIONS, REQUIRED_DOCS, IMAGE_EXTS,
                          MACHINEREADABLE_EXTS, DOC_STALE_DAYS)
from ..analysis import norm, page_text, soup_of
from ..models import extract_dates
from .common import ScanContext, make_violation, link_text_map, find_section_by_title

SVEDEN_KW = ["сведения об образовательной организации", "сведения об оу", "od2021", "ob-organizatsii"]


def check_sveden(ctx: ScanContext) -> list:
    v = []
    links = link_text_map(ctx)
    main = ctx.main_page()

    # ---------- SV-01: наличие раздела ----------
    sveden_page, sveden_url = None, ""
    for url in links:
        low = url.lower()
        if any(k in low for k in ("sveden", "obrazovaniya/sveden", "сведений")) or \
           ("сведения" in low and "организаци" in low):
            sveden_url, sveden_page = url, ctx.pages.get(url)
            break
    if not sveden_page:
        sveden_page, sveden_url = find_section_by_title(links, SVEDEN_KW, ctx)
    # ссылка на раздел должна быть с главной
    linked_from_main = False
    if main and sveden_url:
        soup = BeautifulSoup(main.html, "lxml")
        for a in soup.find_all("a", href=True):
            if urljoin(main.url, a["href"]).split("#")[0].rstrip("/") == sveden_url.rstrip("/"):
                linked_from_main = True
    if ctx.enabled("SV-01") and (not sveden_page or not linked_from_main):
        msg = ("Раздел «Сведения об образовательной организации» не найден"
               if not sveden_page else
               f"Раздел найден ({sveden_url}), но ссылка на него отсутствует на главной странице")
        v.append(make_violation("SV-01", msg, main.url if main else "",
                                [(sveden_url, "найденный URL раздела")] if sveden_url else []))

    # ---------- SV-02-*: обязательные подразделы ----------
    sub_pages = {}
    if sveden_page:
        soup = BeautifulSoup(sveden_page.html, "lxml")
        for a in soup.find_all("a", href=True):
            absu = urljoin(sveden_page.url, a["href"])
            pr = urlparse(absu)
            key = pr._replace(fragment="", query="").geturl().rstrip("/")
            sub_pages.setdefault(key, []).append(norm(a.get_text(" ")))
        # и сами подстраницы, собранные краулером (могут быть глубже)
        for u, p in ctx.pages.items():
            if u.rstrip("/").startswith(sveden_url.rstrip("/")) and u != sveden_url:
                sub_pages.setdefault(u.rstrip("/"), []).append(norm(p.title))

    found_subs: dict[str, str] = {}
    for s in MANDATORY_SUBSECTIONS:
        rid = f"SV-02-{s['key']}"
        if not ctx.enabled(rid):
            continue
        hit_url = ""
        syn = [norm(x) for x in s["synonyms"]]
        for url, texts in sub_pages.items():
            blob = " ".join(texts) + " " + url.lower()
            if any(t in blob for t in syn):
                hit_url = url
                break
        if hit_url:
            found_subs[s["key"]] = hit_url
        elif s["required"]:
            v.append(make_violation(
                rid,
                f"В разделе «Сведения об образовательной организации» не найден обязательный "
                f"подраздел «{s['title']}».",
                sveden_page.url if sveden_page else (main.url if main else "")))

    # ---------- документы раздела: формат / актуальность ----------
    docs_urls: set[str] = set()
    doc_refs: list[tuple[str, str, str]] = []   # (abs_url, текст ссылки, страница-источник)
    scan_scope = ([sveden_page] + [ctx.pages[u] for u in found_subs.values() if u in ctx.pages]
                  if sveden_page else [])
    for p in scan_scope:
        if not p.is_html:
            continue
        soup = BeautifulSoup(p.html, "lxml")
        for a in soup.find_all("a", href=True):
            absu = urljoin(p.url, a["href"])
            ext = Path(urlparse(absu).path).suffix.lower().lstrip(".")
            if ext:
                docs_urls.add(absu)
                doc_refs.append((absu, norm(a.get_text(" ")), p.url))

    # SV-03: машиночитаемость
    if ctx.enabled("SV-03"):
        img_docs = [(u, t, src) for u, t, src in doc_refs
                    if Path(urlparse(u).path).suffix.lower().lstrip(".") in IMAGE_EXTS
                    and any(k in (t + u.lower()) for k in
                            ("устав", "лиценз", "аккредитац", "документ", "образец", "заявлен"))]
        if img_docs:
            v.append(make_violation(
                "SV-03",
                f"{len(img_docs)} документ(ов) размещены в виде изображений (JPG/PNG) вместо "
                f"машиночитаемых форматов PDF/DOCX/XLS.",
                img_docs[0][2],
                [(u, f"текст ссылки: «{t}»") for u, t, _ in img_docs[:10]]))

    # SV-04: актуальность (по дате Last-Modified файла или датам в тексте страницы-источника)
    if ctx.enabled("SV-04") and doc_refs:
        stale = []
        now = datetime.now(timezone.utc)
        for u, t, src in doc_refs:
            ext = Path(urlparse(u).path).suffix.lower().lstrip(".")
            if ext not in MACHINEREADABLE_EXTS:
                continue
            age_days = None
            status, ctype = ctx.assets.get(u, (None, ""))
            # дата из HTTP-заголовка сервера
            lm = _asset_lastmod(ctx, u)
            if lm:
                try:
                    dt = datetime.strptime(lm, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
                    age_days = (now - dt).days
                except ValueError:
                    pass
            if age_days is None:
                # даты в тексте ссылки/окружении: «от 12.05.2019»
                m = re.search(r"(0?[1-9]|[12]\d|3[01])[./](0?[1-9]|1[0-2])[./](20\d{2})", t)
                if m:
                    try:
                        dt = datetime(int(m.group(3)), int(m.group(2)), int(m.group(1)))
                        age_days = (now - dt.replace(tzinfo=timezone.utc)).days
                    except ValueError:
                        pass
            if age_days is None:
                # крайний случай — последние изменения самой страницы
                sp = ctx.pages.get(src)
                if sp:
                    ds = extract_dates(page_text(sp))
                    if ds:
                        age_days = (now - ds[-1].replace(tzinfo=timezone.utc)).days
            limit = DOC_STALE_DAYS["default"]
            if age_days is not None and age_days > limit:
                stale.append((u, f"возраст ~{age_days} дн. (лимит {limit})"))
        if stale:
            v.append(make_violation(
                "SV-04",
                f"{len(stale)} документ(ов) требуют обновления — размещены давно "
                f"(старше {DOC_STALE_DAYS['default']} дней).",
                stale[0][0], stale[:10]))

    # SV-05: работоспособность ссылок на документы/внешние ИС
    if ctx.enabled("SV-05"):
        broken = []
        for u in docs_urls | {x for x in links if not _is_internal(x, ctx.root)}:
            st, _ct = ctx.assets.get(u, (None, ""))
            if st is not None and (st == 0 or st >= 400):
                broken.append((u, f"HTTP {st}" if st else "не отвечает"))
        if broken:
            v.append(make_violation(
                "SV-05",
                f"Обнаружено {len(broken)} неработающих ссылок (документы, учредитель, библиотечные ИС).",
                ctx.root, broken[:20]))

    # SV-06: устав / лицензия / аккредитация
    if ctx.enabled("SV-06"):
        missing = []
        blob_all = " ".join(t for _, t, _ in doc_refs)
        if sveden_page:
            blob_all += " " + " ".join(norm(x) for lst in sub_pages.values() for x in lst)
        docs_page_blob = ""
        for url, texts in sub_pages.items():
            if "документ" in " ".join(texts) or "document" in url.lower():
                docs_page_blob += " ".join(texts) + " "
        for d in REQUIRED_DOCS:
            if not d["critical"]:
                continue
            syn = [norm(x) for x in d["synonyms"]]
            if not any(s in (blob_all + docs_page_blob) for s in syn):
                missing.append(d["title"])
        if missing and sveden_page is not None:
            v.append(make_violation(
                "SV-06",
                "В подразделе «Документы» не обнаружены обязательные документы: "
                + ", ".join(missing) + ".",
                sveden_page.url, [(m, "не найдено ссылок/упоминаний") for m in missing]))
    return v


def _is_internal(url: str, root: str) -> bool:
    return urlparse(url).netloc.lower() == urlparse(root).netloc.lower()


def _asset_lastmod(ctx: ScanContext, url: str) -> str:
    """Last-Modified документа, если он уже был скачан/проверен."""
    st_ctype = ctx.assets.get(url)
    if isinstance(st_ctype, tuple) and len(st_ctype) == 3:
        return st_ctype[2]
    return ""
