"""Общие утилиты анализа контента (HTML/CSS/цвета) для модулей-чекеров."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup


def soup_of(html: str) -> BeautifulSoup:
    return BeautifulSoup(html or "", "lxml")


def norm(text: str) -> str:
    """Нормализация текста для поиска по чек-листу: регистр, ё→е, схлопывание пробелов."""
    t = (text or "").lower().replace("ё", "е")
    return re.sub(r"\s+", " ", t).strip()


def page_text(page) -> str:
    s = soup_of(page.html)
    for tag in s(["script", "style", "noscript"]):
        tag.decompose()
    return norm(s.get_text(" "))


def has_any(text: str, keywords: list[str]) -> bool:
    t = text if text == norm(text) else norm(text)
    return any(norm(k) in t for k in keywords if k)


# ------------------------------------------------------------------ цвета/контраст
NAMED_COLORS = {
    "black": "#000000", "white": "#ffffff", "red": "#ff0000", "green": "#008000",
    "blue": "#0000ff", "yellow": "#ffff00", "gray": "#808080", "grey": "#808080",
    "silver": "#c0c0c0", "maroon": "#800000", "navy": "#000080", "teal": "#008080",
    "orange": "#ffa500", "purple": "#800080", "lime": "#00ff00", "aqua": "#00ffff",
    "fuchsia": "#ff00ff", "olive": "#808000",
}


def parse_color(value: str) -> tuple[int, int, int] | None:
    v = (value or "").strip().lower()
    if not v:
        return None
    if v in NAMED_COLORS:
        v = NAMED_COLORS[v]
    m = re.fullmatch(r"#([0-9a-f]{3}|[0-9a-f]{6})", v)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    m = re.match(r"rgba?\((\d+)[,\s]+(\d+)[,\s]+(\d+)", v)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


def luminance(rgb: tuple[int, int, int]) -> float:
    def ch(c: float) -> float:
        c /= 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = map(ch, rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg: tuple, bg: tuple) -> float:
    l1, l2 = sorted((luminance(fg), luminance(bg)), reverse=True)
    return (l1 + 0.05) / (l2 + 0.05)


CSS_RULE_RE = re.compile(r"([^{}]+)\{([^}]*)\}")


def collect_css_rules(pages) -> list[tuple[str, dict]]:
    """[(селектор, {color:…, background(-color):…, font-size:…}), …] из inline <style>."""
    rules: list[tuple[str, dict]] = []
    for p in pages:
        s = soup_of(p.html)
        for st in s.find_all("style"):
            css = st.get_text()
            css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
            for sel, body in CSS_RULE_RE.findall(css):
                decls = {}
                for d in body.split(";"):
                    if ":" in d:
                        k, _, v = d.partition(":")
                        decls[k.strip().lower()] = v.strip().lower()
                sel_n = norm(sel)
                if sel_n:
                    rules.append((sel_n, decls))
    return rules


BODY_SELECTORS = ("body", "html", "html body")


def find_low_contrast(pages, min_ratio: float = 4.5) -> list[dict]:
    """Эвристическая проверка контрастности по CSS-правилам (ТЗ §3.2).

    Сравниваются только явные пары color/background в правилах, относящихся
    к тексту (body/.content/#content и т.п.), чтобы снизить ложные срабатывания.
    """
    issues = []
    rules = collect_css_rules(pages)
    # карта «фон от родителя» — сначала глобальные фоны body/html
    global_bg = None
    for sel, d in rules:
        if sel in BODY_SELECTORS and ("background" in d or "background-color" in d):
            global_bg = parse_color(d.get("background-color") or d.get("background", "").split()[0])
    for sel, d in rules:
        fg = parse_color(d.get("color", ""))
        if not fg:
            continue
        bg_decl = d.get("background-color") or (d.get("background", "").split()[0] if d.get("background") else "")
        bg = parse_color(bg_decl) if bg_decl else global_bg
        if not bg:
            continue
        ratio = contrast_ratio(fg, bg)
        if ratio < min_ratio:
            issues.append({"selector": sel, "fg": d.get("color"), "bg": bg_decl or "(унаследованный)",
                           "ratio": round(ratio, 2)})
    # дедупликация по селектору
    uniq, seen = [], set()
    for i in issues:
        if i["selector"] not in seen:
            seen.add(i["selector"])
            uniq.append(i)
    return uniq


FONT_PX_RE = re.compile(r"font-size\s*:\s*\d+px", re.I)
FONT_EM_RE = re.compile(r"font-size\s*:\s*[\d.]+\s*(em|rem|%)", re.I)


def font_sizing_issue(pages) -> bool | None:
    """True — все размеры шрифта заданы только в px; False — есть em/rem/%; None — нет данных."""
    px = em = 0
    for p in pages:
        for st in soup_of(p.html).find_all("style"):
            css = st.get_text()
            px += len(FONT_PX_RE.findall(css))
            em += len(FONT_EM_RE.findall(css))
    if px == 0 and em == 0:
        return None
    return px > 0 and em == 0


# ------------------------------------------------------------------ формы
PD_FIELD_RE = re.compile(r"(имя|фамилия|отчество|фио|e-?mail|почт|тел|phone|name|документ|паспорт|дата рождения)", re.I)
CONSENT_RE = re.compile(r"(согласие|соглашаюсь|обработк.{0,30}персональн|персональн.{0,30}данных|пдн)", re.I)


def analyze_forms(page) -> list[dict]:
    """Возвращает [{action, collects_pd, has_consent, consent_has_link}, ...] по формам страницы."""
    s = soup_of(page.html)
    out = []
    for form in s.find_all("form"):
        fields_txt = " ".join(
            (inp.get("name", "") + " " + (inp.get("placeholder", "") or ""))
            for inp in form.find_all(["input", "textarea", "select"])
            if inp.get("type") not in ("hidden", "submit", "button")
        )
        labels = " ".join(l.get_text(" ") for l in form.find_all("label"))
        collects = bool(PD_FIELD_RE.search(fields_txt + " " + labels))
        if not collects:
            continue
        inputs_html = str(form)
        has_checkbox = bool(re.search(r"type=[\"']checkbox[\"']", inputs_html, re.I))
        consent_in_label = bool(CONSENT_RE.search(labels))
        link_to_policy = bool(re.search(r"(politika|personal|152|consent|pdn|privacy)",
                                        " ".join(a.get("href", "") for a in form.find_all("a")), re.I))
        out.append({
            "action": urljoin(page.url, form.get("action", "")),
            "collects_pd": True,
            "has_consent": (has_checkbox and (consent_in_label or link_to_policy)) or consent_in_label,
            "consent_has_link": link_to_policy,
        })
    return out


COOKIE_RE = re.compile(r"(cookie|куки|кук-?файл|файл\W?cookie)", re.I)
VSION_RE = re.compile(r"(версия.{0,25}(слабовид|для слабовидящих)|visually[- ]?impaired|"
                      r"version[-_/]?slabov|ver[-_]?vision|glaznik|strong[- ]?version)", re.I)


def has_version_for_blind(site_pages) -> bool:
    for p in site_pages:
        s = soup_of(p.html)
        for a in s.find_all(["a", "button"]):
            if VSION_RE.search(a.get_text(" ")) or VSION_RE.search(a.get("href", "")) \
               or VSION_RE.search(a.get("class", "") or "") or VSION_RE.search(a.get("id", "") or ""):
                return True
        if VSION_RE.search(p.html[:60000]):
            return True
    return False


KEYBOARD_TRAPS_RE = re.compile(r"on(?:keydown|keypress)[^=]*=[^>]*preventDefault", re.I)
TABINDEX_POS_RE = re.compile(r'tabindex=["\']([1-9]\d*)["\']')
SKIP_LINK_RE = re.compile(r'(skip[- _]?(to[- _])?content|перейти к содержанию|к основному содержимому)', re.I)
