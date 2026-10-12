"""Блок 3.2 — «Доступность для ОВЗ» (ТЗ §3.2; 419-ФЗ, ГОСТ Р 52872-2019)."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..analysis import (has_version_for_blind, find_low_contrast, font_sizing_issue,
                        KEYBOARD_TRAPS_RE, TABINDEX_POS_RE, SKIP_LINK_RE, soup_of)
from .common import ScanContext, make_violation


def check_ovz(ctx: ScanContext) -> list:
    v = []
    pages = ctx.html_pages()
    if not pages:
        return v
    main = ctx.main_page() or pages[0]

    # ---------- OZ-01: версия для слабовидящих ----------
    if ctx.enabled("OZ-01"):
        if not has_version_for_blind(pages):
            v.append(make_violation(
                "OZ-01",
                "Не обнаружена кнопка/ссылка переключения версии сайта для слабовидящих.",
                main.url))

    # ---------- OZ-02: alt-теги ----------
    if ctx.enabled("OZ-02"):
        missing = []
        total = 0
        for p in pages[:60]:                     # ограничиваем глубину выборки
            soup = soup_of(p.html)
            for img in soup.find_all("img"):
                role = (img.get("role") or "").lower()
                if role == "presentation" or img.get("alt") is not None and img.get("alt").strip():
                    continue
                if role == "presentation":
                    continue
                total += 1
                src = urljoin(p.url, img.get("src", ""))
                missing.append((src, f"страница {p.url}"))
        if missing:
            ratio = len(missing) / max(total + len(missing), 1)
            sev = None
            v.append(make_violation(
                "OZ-02",
                f"{len(missing)} информативных изображений без атрибута alt.",
                missing[0][1].split(" ", 1)[1], missing[:15]))

    # ---------- OZ-03: контрастность ----------
    if ctx.enabled("OZ-03"):
        issues = find_low_contrast(pages, min_ratio=float(ctx.param("OZ-03", "min_ratio", 4.5)))
        if issues:
            v.append(make_violation(
                "OZ-03",
                f"Обнаружено {len(issues)} CSS-правил с контрастностью текста ниже 4.5:1 "
                f"(требование WCAG AA / ГОСТ Р 52872-2019).",
                main.url,
                [(i["selector"], f"цвет {i['fg']} на фоне {i['bg']}, контраст {i['ratio']}:1")
                 for i in issues[:10]]))

    # ---------- OZ-04: клавиатурная навигация ----------
    if ctx.enabled("OZ-04"):
        problems = []
        skip_found = False
        for p in pages[:40]:
            html = p.html
            if SKIP_LINK_RE.search(html):
                skip_found = True
            m = TABINDEX_POS_RE.findall(html)
            if m:
                problems.append((p.url, f"положительные tabindex={m[:5]} нарушают естественный порядок обхода"))
            if KEYBOARD_TRAPS_RE.search(html):
                problems.append((p.url, "перехват клавиатуры (preventDefault в onkeydown) — возможная ловушка фокуса"))
        if not skip_found and len(pages) > 1:
            problems.append((main.url, "нет skip-ссылки «Перейти к содержанию» для обхода меню с Tab"))
        real = [x for x in problems if "tabindex" in x[1] or "preventDefault" in x[1] or "skip" in x[1]]
        if real:
            v.append(make_violation("OZ-04",
                                    "Проблемы клавиатурной навигации: " + "; ".join(r[1] for r in real[:3]),
                                    real[0][0], real[:10]))

    # ---------- OZ-05: мультимедиа ----------
    if ctx.enabled("OZ-05"):
        bad = []
        for p in pages:
            soup = soup_of(p.html)
            for mm in soup.find_all(["video", "audio"]):
                tracks = [t for t in mm.find_all("track")
                          if (t.get("kind", "").lower() in ("captions", "subtitles", "descriptions"))]
                text_near = bool(re.search(r"(субтитр|расшифровк|текстовая версия)", p.html, re.I))
                if not tracks and not text_near:
                    src = urljoin(p.url, mm.get("src", "") or
                                  (mm.find("source").get("src", "") if mm.find("source") else ""))
                    bad.append((src or p.url, f"на странице {p.url} нет субтитров/расшифровки"))
        if bad:
            v.append(make_violation("OZ-05",
                                    f"{len(bad)} аудио-/видеоматериалов без субтитров или текстовой расшифровки.",
                                    bad[0][1].split("на странице ")[-1].strip(), bad[:10]))

    # ---------- OZ-06: масштабирование текста ----------
    if ctx.enabled("OZ-06"):
        if font_sizing_issue(pages) is True:
            v.append(make_violation(
                "OZ-06",
                "Все размеры шрифтов заданы только в px — увеличение масштаба может привести "
                "к потере вёрстки; рекомендуется em/rem/%.",
                main.url))
    return v
