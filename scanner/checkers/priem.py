"""Блок 3.5 — «Приемная кампания и Комитет по образованию СПб» (ТЗ §3.5)."""
from __future__ import annotations

import re
from datetime import datetime

from ..analysis import page_text, soup_of, has_any
from .common import ScanContext, make_violation, link_text_map, find_section_by_title

PRIEM_KW = ["абитуриенту", "абитуриент", "приемная комиссия", "приёмная комиссия",
            "postuplenie", "abiturient", "priem", "поступающим"]
REGAMENT_KW = ["регламент", "пошаговая инструкция", "как поступить", "порядок подачи",
               "госуслуг", "зачислен"]
KCP_KW = ["контрольные цифры", "кцп", "проходн", "баллы", "бюджетн мест"]
KPO_HOSTS = ("kokl.spb.ru", "edu.gov.spb.ru", "komobraz", "kpo.gov.spb.ru")


def check_priem(ctx: ScanContext) -> list:
    v = []
    pages = ctx.html_pages()
    if not pages:
        return v
    main = ctx.main_page() or pages[0]
    links = link_text_map(ctx)

    # ---------- PK-01: раздел «Абитуриенту» ----------
    priem_page, priem_url = find_section_by_title(links, PRIEM_KW, ctx)
    if not priem_page:
        for u, p in ctx.pages.items():
            if any(k in u.lower() for k in ("abitur", "priem", "postup")):
                priem_url, priem_page = u, p
                break
    if ctx.enabled("PK-01"):
        linked_from_main = False
        if priem_url and main:
            soup = soup_of(main.html)
            for a in soup.find_all("a", href=True):
                if priem_url.rstrip("/").endswith(a["href"].split("#")[0].rstrip("/")) or \
                   any(k in a.get_text(" ").lower().replace("ё", "е") for k in ("абитуриент", "приемная", "приёмная", "поступающим")):
                    linked_from_main = True
        if not priem_page or not linked_from_main:
            msg = ("Выделенный раздел «Абитуриенту» / «Приемная комиссия» не найден."
                   if not priem_page else
                   f"Раздел найден ({priem_url}), но отсутствует явная ссылка с главной страницы.")
            v.append(make_violation("PK-01", msg, main.url))

    scope_pages = [priem_page] if priem_page else []
    if priem_page:
        for u, p in ctx.pages.items():
            if u.rstrip("/").startswith(priem_url.rstrip("/")) and p is not priem_page:
                scope_pages.append(p)

    # ---------- PK-02: регламенты/инструкции зачисления ----------
    if ctx.enabled("PK-02"):
        blob = " ".join(page_text(p) for p in scope_pages)
        if not has_any(blob, REGAMENT_KW):
            v.append(make_violation(
                "PK-02",
                "В разделе приёмной кампании не обнаружены административные регламенты / "
                "пошаговые инструкции по зачислению (предоставлению госуслуги).",
                priem_page.url if priem_page else main.url))

    # ---------- PK-03: КЦП и проходные баллы ----------
    if ctx.enabled("PK-03"):
        tables_ok = False
        this_year = datetime.now().year
        for p in scope_pages + ([main] if not scope_pages else []):
            soup = soup_of(p.html)
            for table in soup.find_all("table"):
                txt = table.get_text(" ")
                if has_any(txt, ["контрольн", "кцп", "бюджет"]):
                    years = re.findall(r"20\d{2}", txt)
                    recent = [int(y) for y in years if int(y) >= this_year - 1]
                    if recent:
                        tables_ok = True
            if has_any(page_text(p), KCP_KW) and str(this_year) in p.html:
                tables_ok = True
        if not tables_ok:
            v.append(make_violation(
                "PK-03",
                f"Контрольные цифры приёма (КЦП)/проходные баллы не найдены или не содержат "
                f"данных за актуальный {this_year} год.",
                priem_page.url if priem_page else main.url))

    # ---------- PK-04: ссылки на Комитет по образованию СПб ----------
    if ctx.enabled("PK-04"):
        found_kpo = any(any(h in u.lower() for h in KPO_HOSTS) for u in links)
        if not found_kpo:
            blob = " ".join(page_text(p) for p in pages[:30])
            found_kpo = has_any(blob, ["комитет по образованию"])
        if not found_kpo:
            v.append(make_violation(
                "PK-04",
                "Отсутствуют ссылки на официальные ресурсы/распоряжения Комитета по "
                "образованию Санкт-Петербурга.",
                main.url))
    return v
