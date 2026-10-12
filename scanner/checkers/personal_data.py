"""Блок 3.3 — «Персональные данные» (ТЗ §3.3; 152-ФЗ)."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from ..analysis import analyze_forms, page_text, COOKIE_RE, soup_of
from .common import ScanContext, make_violation, link_text_map, find_section_by_title

POLICY_KW = ["политика в отношении обработки персональных данных",
             "политика обработки персональных", "politika", "personal-data", "privacy"]
AGREEMENT_KW = ["пользовательское соглашение", "соглашение об использовании",
                "user-agreement", "pravila-sayta", "правила использования сайта"]


def check_personal_data(ctx: ScanContext) -> list:
    v = []
    pages = ctx.html_pages()
    if not pages:
        return v
    main = ctx.main_page() or pages[0]
    links = link_text_map(ctx)

    # ---------- PD-01: политика обработки ПДн ----------
    policy_page, policy_url = find_section_by_title(links, POLICY_KW, ctx)
    if not policy_page:
        # вариант: PDF-файл политики, ссылка из подвала
        for url in links:
            if re.search(r"(politika|privacy)", url, re.I):
                policy_url, policy_page = url, ctx.pages.get(url)
                break
    if ctx.enabled("PD-01") and not policy_page and not policy_url:
        v.append(make_violation(
            "PD-01",
            "Не найдена страница «Политика в отношении обработки персональных данных».",
            main.url))

    # ---------- PD-02: пользовательское соглашение ----------
    agr_page, agr_url = find_section_by_title(links, AGREEMENT_KW, ctx)
    if ctx.enabled("PD-02") and not agr_page and not agr_url:
        v.append(make_violation(
            "PD-02",
            "Не найдено пользовательское соглашение / правила использования сайта.",
            main.url))

    # ---------- PD-03: чекбоксы согласия в формах ----------
    if ctx.enabled("PD-03"):
        bad_forms = []
        for p in pages:
            for f in analyze_forms(p):
                if not f["has_consent"]:
                    bad_forms.append((f["action"],
                                      f"форма на {p.url} собирает ПДн без чекбокса согласия"))
                elif not f["consent_has_link"] and policy_url:
                    # согласие есть, но нет ссылки на политику — minor-уточнение в деталях
                    bad_forms.append((f["action"],
                                      f"форма на {p.url}: согласие есть, но отсутствует "
                                      f"гиперссылка на политику обработки ПДн"))
        if bad_forms:
            uniq = list({(a, m): (a, m) for a, m in bad_forms}.values())
            v.append(make_violation(
                "PD-03",
                f"{len(uniq)} форм(ы) сбора персональных данных не соответствуют "
                f"требованиям ст. 9 152-ФЗ (отсутствует оформленное согласие).",
                main.url, uniq[:15]))

    # ---------- PD-04: cookie-баннер ----------
    if ctx.enabled("PD-04"):
        found = False
        for p in [main] + pages[:10]:
            html = p.html or ""
            if re.search(r"(cookie[-_ ]?(banner|notice|alert|popup|consent)|"
                         r"использ\w+\s+(файлы\s+)?cookie|куки[- ]?файл|мы используем файлы)",
                         html, re.I):
                found = True
                break
        if not found:
            v.append(make_violation(
                "PD-04",
                "Не обнаружено уведомление (баннер) об использовании cookie-файлов.",
                main.url))
    return v
