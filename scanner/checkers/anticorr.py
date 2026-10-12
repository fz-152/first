"""Блок 3.6 — «Антикоррупция и прочее» (ТЗ §3.6; ФЗ-273, 5307-I, 63-ФЗ, 149-ФЗ)."""
from __future__ import annotations

import re

from ..analysis import page_text, has_any, soup_of
from .common import ScanContext, make_violation, link_text_map, find_section_by_title

CORR_KW = ["противодействие коррупции", "антикоррупцион", "anticorruption", "korruptsiya",
           "недопущение коррупции"]
EP_KW = ("заявлен", "подача документов", "личный кабинет", "электронн{0,20}подан")
EP_HINT_KW = ["электронн{0,30}подпис", "укэп", "усиливающ{0,20}квалифицирован",
              "удостоверяющ{0,20}центр", "гостех", "точка"]


def check_anticorr(ctx: ScanContext) -> list:
    v = []
    pages = ctx.html_pages()
    if not pages:
        return v
    main = ctx.main_page() or pages[0]
    links = link_text_map(ctx)

    # ---------- AK-01: раздел «Противодействие коррупции» ----------
    corr_page, corr_url = find_section_by_title(links, CORR_KW, ctx)
    if not corr_page:
        for u, p in ctx.pages.items():
            if any(k in u.lower() for k in ("korrupts", "anticorruption", "protivodeystvie-korru")):
                corr_url, corr_page = u, p
                break
    if ctx.enabled("AK-01") and not corr_page:
        blob_all = " ".join(page_text(p) for p in pages[:40])
        if not has_any(blob_all, CORR_KW):
            v.append(make_violation(
                "AK-01",
                "Раздел/страница «Противодействие коррупции» не обнаружены.",
                main.url))

    # ---------- AK-02: телефоны доверия / форма сообщений ----------
    if ctx.enabled("AK-02") and corr_page:
        txt = page_text(corr_page) + corr_page.html
        has_phone = bool(re.search(r"(телефон\W{0,15}(доверия|горячей линии)|"
                                   r"\b8[- ]?800[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}|495\d{6,}|(?:\+7|8)[ -]?\(?\d{3}\)?[ -]\d{3}[ -]\d{2})",
                                   txt, re.I))
        has_form = bool(re.search(r"<form", corr_page.html, re.I))
        if not (has_phone and has_form):
            v.append(make_violation(
                "AK-02",
                "На странице противодействия коррупции отсутствуют "
                + ("телефоны доверия/горячей линии " if not has_phone else "")
                + ("и форма для сообщений о фактах коррупции." if not has_form else
                   "(нет формы для сообщений)." if not has_form else "")))

    # ---------- AK-03: lang="ru" ----------
    if ctx.enabled("AK-03"):
        html_pages = [p for p in pages if p.is_html]
        ru = sum(1 for p in html_pages
                 if re.match(r"^\s*<html[^>]+lang=[\"'](ru)", p.html, re.I | re.S)
                 or (p.lang or "").lower().startswith("ru"))
        if html_pages:
            share = ru / len(html_pages)
            if share < 0.9:
                bad_urls = [(p.url, f"lang='{p.lang or 'не задан'}'")
                            for p in html_pages
                            if not (p.lang or "").lower().startswith("ru")][:15]
                v.append(make_violation(
                    "AK-03",
                    f"Только {share:.0%} страниц имеют lang=\"ru\" (требуется ≥ 90 %, "
                    f"Закон РФ № 5307-I ст. 5).",
                    main.url, bad_urls))

    # ---------- AK-04: электронная подпись ----------
    if ctx.enabled("AK-04"):
        services = [p for p in pages
                    if re.search(r"(подать заявление|запись на обучение|прием заявлений|"
                                 r"личный кабинет|e-dosug|gosuslugi)", p.html, re.I)]
        if services:
            blob = " ".join(p.html for p in services) + " ".join(u for u in links)
            ep_found = bool(re.search(r"(электронн\w*\s+(усиленн\w*\s+)?квалифицированн\w*\s+"
                                      r"подпис|укэп|удостоверяющ\w+\s+центр)", blob, re.I))
            if not ep_found:
                v.append(make_violation(
                    "AK-04",
                    f"Обнаружено {len(services)} страниц сервисов подачи заявлений, но нет "
                    f"информации об использовании УКЭП и ссылках на удостоверяющие центры "
                    f"(63-ФЗ ст. 16).",
                    services[0].url, [(p.url, "сервис подачи заявлений") for p in services[:5]]))

    # ---------- AK-05: контакты ----------
    if ctx.enabled("AK-05"):
        blob = " ".join(page_text(p) for p in [main] + pages[:15])
        addr = bool(re.search(r"(адрес\W{0,20}(Санкт-Петербург|spb)|г\.?\s*санкт-петербург|"
                              r"ул\.|пр\.|проспект|наб\.|шоссе)", blob, re.I))
        phone = bool(re.search(r"(?:\+7|8)[\s(]?[\d]{3}[\s)]?[\d\- ]{6,}", blob))
        email = bool(re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", blob))
        miss = [n for n, ok in (("адрес", addr), ("телефон", phone), ("e-mail", email)) if not ok]
        if miss:
            v.append(make_violation(
                "AK-05",
                "На сайте (главная/контакты) не обнаружены: " + ", ".join(miss) + ".",
                main.url, [(m, "отсутствует") for m in miss]))
    return v
