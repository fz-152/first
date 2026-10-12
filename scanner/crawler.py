"""Движок обхода сайта (ТЗ §4.1 «Crawler», §5 «Скорость/Обход защит»).

Особенности:
  * Sitemap-first: сначала robots.txt и sitemap.xml, затем BFS по ссылкам;
  * учёт директивы Crawl-delay из robots.txt + троттлинг запросов (anti-ban);
  * реалистичный User-Agent, обработка 403/429 (WAF/частота) — повтор с паузой,
    детект типовых CAPTCHA-страниц (flood-protection) без агрессии;
  * ограничение числа страниц (по умолчанию 1000) и таймаут сканирования;
  * HEAD-проверка внешних документов (PDF/DOCX) на битые ссылки;
  * опциональный JS-рендеринг через Selenium (если установлен драйвер).
"""
from __future__ import annotations

import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

from .models import Page, normalize_url, same_site

log = logging.getLogger("scanner.crawler")

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 EduComplianceBot/1.0")

CAPTCHA_HINTS = ("captcha", "подтвердите, что вы не робот", "are you a robot",
                 "flood-control", "access denied", "unusual traffic", "cf-browser-verification",
                 "just a moment", "enable javascript and cookies")


@dataclass
class CrawlStats:
    fetched: int = 0
    errors: int = 0
    skipped_robots: int = 0
    blocked_events: list = field(default_factory=list)   # URL, где сработал WAF/CAPTCHA
    duration: float = 0.0
    truncated: bool = False


class Crawler:
    def __init__(self, root_url: str, *, max_pages: int = 1000, max_depth: int = 6,
                 timeout: int = 12, delay: float | None = None, user_agent: str = DEFAULT_UA,
                 respect_robots: bool = True, deadline_sec: float = 15 * 60):
        self.root = root_url if urlparse(root_url).path not in ("", "/") else root_url.rstrip("/") + "/"
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.delay = delay                    # None → из robots.txt / 0.35 c
        self.respect_robots = respect_robots
        self.deadline = deadline_sec
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru,en;q=0.8",
        })
        self.stats = CrawlStats()
        self._rp: RobotFileParser | None = None
        self.pages: dict[str, Page] = {}      # url -> Page
        self.assets: dict[str, tuple[int, str]] = {}   # url документа -> (status, content-type)
        self.sitemaps: list[str] = []

    # ---------------------------------------------------------------- robots
    def _load_robots(self) -> None:
        url = urljoin(f"{urlparse(self.root).scheme}://{urlparse(self.root).netloc}/", "robots.txt")
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200 and "\x00" not in r.text[:200]:
                rp = RobotFileParser()
                rp.parse(r.text.splitlines())
                self._rp = rp
                for line in r.text.splitlines():
                    low = line.lower().strip()
                    if low.startswith("crawl-delay:"):
                        try:
                            cd = float(line.split(":", 1)[1].strip())
                            if self.delay is None or cd > self.delay:
                                self.delay = min(cd, 2.0)
                        except ValueError:
                            pass
                    elif low.startswith("sitemap:"):
                        self.sitemaps.append(line.split(":", 1)[1].strip())
        except requests.RequestException:
            log.info("robots.txt недоступен — работаем без него")

    def allowed(self, url: str) -> bool:
        if not self.respect_robots or self._rp is None:
            return True
        return self._rp.can_fetch("*", url)

    # ---------------------------------------------------------------- fetch
    def _fetch(self, url: str, method: str = "GET") -> requests.Response | None:
        base_wait = self.delay if self.delay is not None else 0.35
        for attempt in range(3):
            try:
                t0 = time.monotonic()
                r = self.session.request(method, url, timeout=self.timeout, allow_redirects=True)
                time.sleep(base_wait)   # троттлинг anti-ban
                if r.status_code in (403, 429, 503):
                    wait = base_wait * (2 ** attempt) * 3
                    log.warning("HTTP %s на %s — пауза %.1f c (WAF/частота)", r.status_code, url, wait)
                    time.sleep(wait)
                    continue
                return r
            except requests.RequestException as e:
                log.debug("Ошибка запроса %s: %s", url, e)
                time.sleep(base_wait)
        return None

    @staticmethod
    def _looks_like_captcha(text: str) -> bool:
        low = text.lower()[:4000]
        return any(h in low for h in CAPTCHA_HINTS)

    # ---------------------------------------------------------------- crawl
    def run(self) -> CrawlStats:
        start = time.monotonic()
        self._load_robots()
        queue: deque[tuple[str, int]] = deque()

        # 1) seed из sitemap.xml (полное покрытие быстрее BFS)
        base_org = f"{urlparse(self.root).scheme}://{urlparse(self.root).netloc}"
        sm_urls = [urljoin(base_org + "/", s) if s.startswith("/") else s
                   for s in (self.sitemaps or [base_org + "/sitemap.xml"])]
        for sm in sm_urls[:3]:
            for u in self._parse_sitemap(sm):
                queue.append((u, 1))
        # 2) seed — корень сайта
        queue.appendleft((self.root, 0))

        seen: set[str] = {normalize_url(self.root, self.root) or self.root.rstrip("/")}
        while queue:
            if self.stats.fetched >= self.max_pages:
                self.stats.truncated = True
                break
            if time.monotonic() - start > self.deadline:
                log.warning("Достигнут лимит времени сканирования (%.0f мин)", self.deadline / 60)
                self.stats.truncated = True
                break
            url, depth = queue.popleft()
            if depth > self.max_depth or not self.allowed(url):
                self.stats.skipped_robots += 1
                continue
            page = self._crawl_page(url, depth)
            if page is None:
                continue
            self.pages[url] = page
            self.stats.fetched += 1
            if depth < self.max_depth:
                for href in extract_links(page.html, url):
                    n = normalize_url(url, href)
                    if n and same_site(n, self.root) and n not in seen:
                        seen.add(n)
                        queue.append((n, depth + 1))
        self.stats.duration = time.monotonic() - start
        return self.stats

    def _crawl_page(self, url: str, depth: int) -> Page | None:
        r = self._fetch(url)
        if r is None:
            self.stats.errors += 1
            return None
        ctype = r.headers.get("Content-Type", "")
        page = Page(url=url, status=r.status_code, content_type=ctype, depth=depth,
                    headers=dict(r.headers), last_modified=r.headers.get("Last-Modified", ""))
        if "html" not in ctype and not r.text.lstrip().startswith("<"):
            self.assets[url] = (r.status_code, ctype)
            return None
        page.html = r.text
        if self._looks_like_captcha(r.text):
            self.stats.blocked_events.append(url)
        soup = BeautifulSoup(r.text, "lxml")
        title = soup.title.get_text(strip=True) if soup.title else ""
        page.title = title
        html_tag = soup.find("html")
        page.lang = (html_tag.get("lang", "") if html_tag else "")
        return page

    def _parse_sitemap(self, url: str) -> list[str]:
        r = self._fetch(url)
        out: list[str] = []
        if r is None or r.status_code != 200:
            return out
        text = r.text
        if "<sitemapindex" in text:
            for loc in re.findall(r"<loc>(.*?)</loc>", text)[:5]:
                out.extend(self._parse_sitemap(loc.strip()))
        elif "<urlset" in text or "<url>" in text:
            for loc in re.findall(r"<loc>(.*?)</loc>", text):
                n = normalize_url(url, loc.strip())
                if n and same_site(n, self.root):
                    out.append(n)
        return out[: self.max_pages]

    # --------------------------------------------------- проверка документов
    def check_assets(self, urls: set[str]) -> dict[str, tuple[int, str]]:
        """HEAD-проверка ссылок на документы/внешние системы (ТЗ §3.1 «Ссылки»)."""
        for u in list(urls)[:200]:
            if u in self.assets:
                continue
            r = self._fetch(u, method="HEAD")
            if r is None:
                self.assets[u] = (0, "")
            else:
                if r.status_code in (405, 501):     # HEAD не поддерживается → GET
                    g = self._fetch(u, method="GET")
                    self.assets[u] = (g.status_code, g.headers.get("Content-Type", "")) if g else (0, "")
                else:
                    self.assets[u] = (r.status_code, r.headers.get("Content-Type", ""))
        return self.assets


def extract_links(html: str, base: str) -> list[str]:
    soup = BeautifulSoup(html, "lxml")
    links = []
    for a in soup.find_all("a", href=True):
        links.append(a["href"])
    # ссылки, «зашитые» в onclick/js (типовые для самописных сайтов колледжей)
    for m in re.finditer(r"""(?:window\.location|location\.href)\s*=\s*['"]([^'"]+)['"]""", html):
        links.append(m.group(1))
    return links


def document_links(html: str, base: str) -> list[tuple[str, str]]:
    """Все ссылки на файлы-документы: [(abs_url, текст ссылки), ...]."""
    soup = BeautifulSoup(html, "lxml")
    out = []
    for a in soup.find_all("a", href=True):
        ext = Path(urlparse(urljoin(base, a["href"])).path).suffix.lower().lstrip(".")
        if ext in {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "rtf",
                   "jpg", "jpeg", "png", "gif", "zip", "rar"}:
            out.append((urljoin(base, a["href"]), a.get_text(" ", strip=True)))
    return out


def render_screenshot(url: str, out_path: str, width: int = 1280) -> bool:
    """Скриншот страницы через Selenium (ТЗ §4.2 «скриншот проблемной зоны»).

    Возвращает False, если Selenium/драйвер недоступны — сканер деградирует
    мягко (скриншот просто не прикладывается).
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        return False
    try:
        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument(f"--window-size={width},900")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--no-sandbox")
        driver = webdriver.Chrome(options=opts)
        try:
            driver.set_page_load_timeout(25)
            driver.get(url)
            Path(out_path).parent.mkdir(parents=True, exist_ok=True)
            driver.save_screenshot(out_path)
        finally:
            driver.quit()
        return True
    except Exception as e:      # нет драйвера/браузера в окружении
        log.info("Скриншот недоступен (%s): %s", url, e)
        return False
