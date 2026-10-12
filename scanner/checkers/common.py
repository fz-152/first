"""Общая инфраструктура чекеров."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from pathlib import Path

from ..checklists import RULES_BY_ID, BLOCK_SVEDEN, CRITICAL, MAJOR, MINOR
from ..models import Page, Violation


@dataclass
class ScanContext:
    root: str
    pages: dict                       # url -> Page
    assets: dict = field(default_factory=dict)   # url -> (status, content-type)
    rules_enabled: dict = field(default_factory=dict)  # rule_id -> bool/params

    def html_pages(self) -> list[Page]:
        return [p for p in self.pages.values() if p.is_html and p.status == 200]

    def main_page(self) -> Page | None:
        for u, p in self.pages.items():
            if urlparse(u).path in ("", "/"):
                return p
        return next(iter(self.pages.values()), None)

    def enabled(self, rule_id: str) -> bool:
        return self.rules_enabled.get(rule_id, True)

    def param(self, rule_id: str, name: str, default=None):
        from ..checklists import RULES_BY_ID
        r = RULES_BY_ID.get(rule_id)
        return (r.params.get(name, default) if r else default)


def make_violation(rule_id: str, message: str, page_url: str = "",
                   details: list | None = None, severity_override: str | None = None) -> Violation:
    rule = RULES_BY_ID[rule_id]
    return Violation(
        rule_id=rule.id, block=rule.block, law=rule.law,
        severity=severity_override or rule.severity, title=rule.title,
        message=message, page_url=page_url, details=details or [])


def link_text_map(ctx: ScanContext) -> dict[str, list[tuple[Page, str]]]:
    """url -> [(страница-источник, текст ссылки)] для всех <a> на сайте."""
    from bs4 import BeautifulSoup
    out: dict[str, list] = {}
    for p in ctx.html_pages():
        soup = BeautifulSoup(p.html, "lxml")
        for a in soup.find_all("a", href=True):
            absu = urljoin(p.url, a["href"])
            # канонизация без fragment
            pr = urlparse(absu)
            absu = pr._replace(fragment="").geturl()
            out.setdefault(absu, []).append((p, a.get_text(" ", strip=True), a["href"]))
    return out


def find_section_by_title(links: dict, keywords: list[str], ctx: ScanContext,
                          within_paths: list[str] | None = None) -> tuple[Page | None, str]:
    """Ищет страницу раздела по ключевым словам в тексте ссылок/заголовках/URL.

    Возвращает (Page или None, URL).
    """
    kw = [k.lower() for k in keywords]
    best_url, best_score = None, 0
    for url, refs in links.items():
        low = url.lower()
        score = 0
        for _, text, _href in refs:
            t = text.lower().replace("ё", "е")
            for k in kw:
                kk = k.replace("ё", "е")
                if kk in t:
                    score = max(score, 3)
        if any(k in low for k in kw):
            score = max(score, 2)
        # заголовок самой страницы
        page = ctx.pages.get(url)
        if page:
            head = (page.title or "").lower().replace("ё", "е")
            if any(k.replace("ё", "е") in head for k in kw):
                score = max(score, 3)
        if within_paths and not any(w in low for w in within_paths):
            continue
        if score > best_score:
            best_score, best_url = score, url
    if best_score >= 2:
        return ctx.pages.get(best_url), best_url
    return None, best_url or ""
