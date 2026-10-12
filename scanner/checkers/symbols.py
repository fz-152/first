"""Блок 3.4 — «Государственная символика» (ТЗ §3.4; ФКЗ № 2-ФКЗ, Закон СПб № 165-23).

Проверяются: наличие гербов РФ/СПб на главной и в подвале, отсутствие искажений
пропорций (растяжения), опциональная сверка хэш-сумм с эталонным реестром.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..analysis import soup_of
from .common import ScanContext, make_violation

RF_KW = ("gerb", "герб", "emblem", "coat-of-arms", "coat_of_arms", "gerb_rf", "rf_state")
SPB_KW = ("spb", "petrograd", "питер", "санкт-петербург", "sanct", "peterburg", "165")

# Эталонный реестр хэш-сумм (SHA-256) — пополняется администратором (ТЗ §2).
REFERENCE_HASHES: dict[str, str] = {}


def _img_meta(img, base_url: str) -> dict | None:
    src = img.get("src") or ""
    if not src:
        return None
    attrs = {k.lower(): v for k, v in img.attrs.items()}
    w_css = h_css = None
    style = (attrs.get("style") or "").lower()
    m = re.search(r"width\s*:\s*(\d+)", style)
    if m:
        w_css = int(m.group(1))
    m = re.search(r"height\s*:\s*(\d+)", style)
    if m:
        h_css = int(m.group(1))
    return {
        "url": urljoin(base_url, src),
        "alt": (attrs.get("alt") or "").lower(),
        "title": (attrs.get("title") or "").lower(),
        "cls": " ".join(attrs.get("class", []) if isinstance(attrs.get("class"), list)
                        else [attrs.get("class", "")]).lower(),
        "w_native": _to_int(attrs.get("width")),
        "h_native": _to_int(attrs.get("height")),
        "w_css": w_css,
        "h_css": h_css,
        "tag": img,
    }


def _to_int(v):
    try:
        return int(str(v).strip().rstrip("px"))
    except (ValueError, TypeError):
        return None


def _looks_like_crest(meta: dict, keywords: tuple[str, ...]) -> bool:
    blob = " ".join([meta["url"], meta["alt"], meta["title"], meta["cls"]]).lower()
    return any(k in blob for k in keywords)


def check_symbols(ctx: ScanContext) -> list:
    v = []
    main = ctx.main_page()
    if not main:
        return v
    soup = soup_of(main.html)
    footer = soup.find("footer") or soup.find(class_=re.compile("foot", re.I)) \
        or soup.find(id=re.compile("foot", re.I))
    scope = [main] + [ctx.pages[u] for u in list(ctx.pages)[:5] if ctx.pages[u] is not main][:4]

    rf_imgs, spb_imgs = [], []
    for p in scope:
        s = soup_of(p.html)
        imgs = [_img_meta(i, p.url) for i in s.find_all("img")]
        imgs = [m for m in imgs if m]
        for m in imgs:
            if _looks_like_crest(m, RF_KW):
                rf_imgs.append((p, m))
            elif _looks_like_crest(m, SPB_KW) and "gerb" in m["url"].lower() + m["alt"]:
                spb_imgs.append((p, m))

    # ---------- GS-01: Герб РФ ----------
    if ctx.enabled("GS-01"):
        on_main_or_footer = any(p is main or (footer and footer.find("img", src=m["url"].split("/")[-1]))
                                for p, m in rf_imgs)
        if not rf_imgs or not on_main_or_footer:
            v.append(make_violation(
                "GS-01",
                "Изображение Государственного герба Российской Федерации не обнаружено "
                "на главной странице / в шапке или подвале сайта.",
                main.url, [(m["url"], "найден, но вне главной/подвала") for _p, m in rf_imgs[:5]]))

    # ---------- GS-02: Герб СПб ----------
    if ctx.enabled("GS-02"):
        if not spb_imgs:
            v.append(make_violation(
                "GS-02",
                "Изображение герба Санкт-Петербурга не обнаружено (рекомендуется для "
                "организаций, подведомственных Комитету по образованию СПб).",
                main.url))

    # ---------- GS-03: пропорции (без растяжения) ----------
    if ctx.enabled("GS-03"):
        distorted = []
        for p, m in rf_imgs + spb_imgs:
            wn, hn = m["w_native"], m["h_native"]
            wc, hc = m["w_css"], m["h_css"]
            if wn and hn and wc and hc:
                native_ratio = wn / hn
                css_ratio = wc / hc
                dev = abs(css_ratio - native_ratio) / native_ratio
                if dev > 0.10:
                    distorted.append((m["url"],
                                      f"нативные {wn}×{hn}, отображается {wc}×{hc}, "
                                      f"искажение {dev:.0%}"))
        if distorted:
            v.append(make_violation(
                "GS-03",
                "Изображение герба отображается с нарушением пропорций (растянуто/сплющено).",
                main.url, distorted[:5]))

    # ---------- GS-04: сверка с эталоном (hash) ----------
    if ctx.enabled("GS-04") and REFERENCE_HASHES:
        mismatches = []
        for p, m in rf_imgs:
            content = _fetch_bytes(ctx, m["url"])
            if content is None:
                continue
            h = hashlib.sha256(content).hexdigest()
            ref = REFERENCE_HASHES.get(Path(urlparse(m["url"]).path).name.lower())
            if ref and h != ref:
                mismatches.append((m["url"], f"SHA-256 {h[:16]}… ≠ эталон {ref[:16]}…"))
        if mismatches:
            v.append(make_violation(
                "GS-04",
                "Хэш-суммы изображений гербов не совпадают с эталонными образцами.",
                main.url, mismatches[:5]))
    return v


def _fetch_bytes(ctx: ScanContext, url: str) -> bytes | None:
    """Байты файла: из кэша краулера либо HEAD/GET-запросом."""
    cached = getattr(ctx, "asset_bytes", {})
    if url in cached:
        return cached[url]
    try:
        import requests
        r = requests.get(url, timeout=8)
        if r.ok:
            return r.content
    except Exception:
        pass
    return None
