"""Модули анализа контента по нормативным блокам (ТЗ §3, §6 этап 3).

Каждый чекер — функция check_<block>(ctx) -> list[Violation], где ctx — ScanContext
со всеми собранными страницами. Чекеры регистрируются в CHECKERS.
"""
from .sveden import check_sveden
from .ovz import check_ovz
from .personal_data import check_personal_data
from .symbols import check_symbols
from .priem import check_priem
from .anticorr import check_anticorr

CHECKERS = [check_sveden, check_ovz, check_personal_data, check_symbols,
            check_priem, check_anticorr]
