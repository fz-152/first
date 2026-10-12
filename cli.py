#!/usr/bin/env python3
"""CLI-запуск сканера без веб-интерфейса.

Примеры:
  python cli.py https://college.example.ru --report pdf,xlsx
  python cli.py http://127.0.0.1:8000 --max-pages 500 --out data/exports
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner.engine import run_scan, traffic_light          # noqa: E402
from scanner.models import Store                            # noqa: E402
from scanner.checklists import CRITICAL, MAJOR, MINOR       # noqa: E402
from scanner import reports                                 # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Сканер соответствия сайта колледжа нормам РФ/СПб")
    ap.add_argument("site", help="URL сайта, напр. https://spbstai.edu.ru")
    ap.add_argument("--max-pages", type=int, default=1000)
    ap.add_argument("--deadline-min", type=float, default=15.0)
    ap.add_argument("--report", default="", help="pdf,xlsx — экспорт отчётов")
    ap.add_argument("--out", default="data/exports", help="каталог для отчётов")
    ap.add_argument("--screenshots", action="store_true",
                    help="скриншоты критичных нарушений (нужен Selenium+Chrome)")
    ap.add_argument("--no-db", action="store_true", help="не сохранять в БД истории")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")

    store = None if args.no_db else Store()
    res = run_scan(args.site, store=store, max_pages=args.max_pages,
                   deadline_min=args.deadline_min, screenshots=args.screenshots,
                   out_dir=args.out)

    light = traffic_light(res.compliance_index)
    print("\n" + "=" * 72)
    print(f"Сайт: {res.site}")
    print(f"Страниц просканировано: {res.pages_scanned}  (время {res.duration_sec} c)")
    print(f"ИНДЕКС СООТВЕТСТВИЯ: {res.compliance_index}%  [{light.upper()}]")
    counts = {CRITICAL: 0, MAJOR: 0, MINOR: 0}
    for v in res.violations:
        counts[v.severity] += 1
    print(f"Нарушений: критических {counts[CRITICAL]}, существенных {counts[MAJOR]}, "
          f"незначительных {counts[MINOR]}; пройдено проверок: {len(res.passed_rules)}")
    print("-" * 72)
    for vd in sorted(res.violations, key=lambda x: (x.block, x.rule_id)):
        mark = {"critical": "🔴", "major": "🟡", "minor": "🟢"}[vd.severity]
        print(f"{mark} [{vd.rule_id}] {vd.title}\n     {vd.message}\n     Основание: {vd.law}"
              + (f"\n     Страница: {vd.page_url}" if vd.page_url else ""))
    for n in res.notes:
        print("•", n)

    fmts = [f.strip().lower() for f in args.report.split(",") if f.strip()]
    out = Path(args.out)
    for f in fmts:
        if f == "pdf":
            p = reports.export_pdf(res, out / f"report_{Path(res.site.replace('https://','').replace('http://','')).stem}.pdf")
            print("Отчёт PDF:", p)
        elif f in ("xlsx", "xls", "excel"):
            p = reports.export_excel(res, out / f"report_{Path(res.site.replace('https://','').replace('http://','')).stem}.xlsx")
            print("Отчёт Excel:", p)
    return 1 if counts[CRITICAL] else 0


if __name__ == "__main__":
    raise SystemExit(main())
