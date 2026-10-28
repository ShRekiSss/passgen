#!/usr/bin/env python3
"""
passgen — учебный проект: генератор паролей и анализатор их надёжности.

 Два режима работы:
    generate  — создать один или несколько стойких паролей
    check     — оценить надёжность существующего пароля

 Используются только модули стандартной библиотеки.
 Для генерации берём `secrets` (криптостойкий ГПСЧ), а НЕ `random`:
 `random` не подходит для секретов — его выход предсказуем.
"""

import argparse
import math
import string
import sys
from secrets import choice

# ---------------------------------------------------------------------------
# Словари
# ---------------------------------------------------------------------------

AMBIGUOUS = set("Il1O0o")  # символы, которые легко перепутать «на глаз»

# Небольшой встроенный список для проверки passphrase-режима.
# В настоящем проекте стоит взять EFF-словарь: https://www.eff.org/dice/wordlists
WORDLIST = [
    "apple", "anchor", "bishop", "brave", "cipher", "cobalt", "dawn", "delta",
    "ember", "falcon", "forge", "glide", "harbor", "ivory", "jade", "kernel",
    "lantern", "lumen", "maple", "meteor", "nimbus", "onyx", "orbit", "pixel",
    "quartz", "quiet", "raven", "ripple", "saffron", "shadow", "signal",
    "summit", "tundra", "umpire", "vector", "willow", "xenon", "yonder",
    "zephyr", "bamboo", "cedar", "dolphin", "echo", "fjord", "granite",
    "horizon", "indigo", "jasmine", "koala", "lotus", "mango",
]

# Самые популярные пароли (фрагмент). Полный список: https://haveibeenpwned.com
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "qwerty", "abc123",
    "111111", "123123", "admin", "letmein", "iloveyou", "monkey", "dragon",
    "passw0rd", "qwerty123", "1q2w3e4r", "admin123", "root", "toor", "test",
    "welcome", "password1", "p@ssword", "sunshine", "princess", "football",
}


# ---------------------------------------------------------------------------
# Генерация
# ---------------------------------------------------------------------------

def generate_password(
    length: int = 16,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    no_ambiguous: bool = False,
) -> str:
    """Собрать пароль из выбранных классов символов.

    Важно: гарантируем хотя бы по одному символу из КАЖДОГО выбранного
    класса, иначе длина!=гарантия разнообразия, и пароль мог бы получиться
    только из букв.
    """
    if length < 4:
        raise ValueError("Длина пароля должна быть не меньше 4")

    pools = [string.ascii_lowercase]
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.<>?/~")

    if no_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

    # По одному символу из каждого пула — гарантия покрытия классов.
    chars = [choice(pool) for pool in pools]
    # Остальные позиции — из объединённого пула.
    all_chars = "".join(pools)
    chars += [choice(all_chars) for _ in range(length - len(chars))]

    # Перемешивание Фишера–Йетса с `secrets.choice` — криптостойкая версия
    # (в отличие от random.shuffle, который предсказуем).
    for i in range(len(chars) - 1, 0, -1):
        j = choice(range(i + 1))
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def generate_passphrase(words: int = 4, separator: str = "-") -> str:
    """Парольная фраза из случайных слов — легко запомнить, трудно подобрать."""
    if not 3 <= words <= 12:
        raise ValueError("Количество слов: от 3 до 12")
    return separator.join(choice(WORDLIST) for _ in range(words)) + choice(string.digits)


# ---------------------------------------------------------------------------
# Анализ надёжности
# ---------------------------------------------------------------------------

def charset_size(password: str) -> int:
    """Размер алфавита, из которого собран пароль (для оценки энтропии)."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 33  # примерный размер пула спецсимволов
    return size


def find_flaws(password: str) -> list[str]:
    """Эвристики слабых мест: повторы, последовательности, словарные пароли."""
    flaws = []
    lower = password.lower()

    if lower in COMMON_PASSWORDS:
        flaws.append("популярный пароль из списков утечек")
    if len(password) < 8:
        flaws.append("слишком короткий (меньше 8 символов)")
    if len(set(password)) <= 3:
        flaws.append("мало уникальных символов")
    for seq in ("0123456789", "abcdefghijklmnopqrstuvwxyz"):
        for i in range(len(seq) - 3):
            window = seq[i:i + 4]
            if window in lower or window[::-1] in lower:
                flaws.append(f"последовательность «{window}»")
                break
        else:
            continue
        break
    for triple in (password[i:i + 3] for i in range(len(password) - 2)):
        if len(set(triple)) == 1:
            flaws.append("три одинаковых символа подряд")
            break
    if password.isdigit():
        flaws.append("только цифры")
    return flaws


def analyse(password: str) -> dict:
    """Вернуть энтропию (в битах) и вердикт. См. estimate брутфорса ниже."""
    alphabet = charset_size(password)
    if alphabet == 0:
        raise ValueError("Пустой пароль")
    # Брутфорс в среднем вскрывает на половине пространства ключей,
    # поэтому берём log2 от полного размера пространства.
    bits = math.log2(alphabet ** len(password))
    # Эвристики резко снижают реальную стойкость — штрафуем, если что-то нашлось.
    flaws = find_flaws(password)
    if flaws:
        bits = min(bits, len(password) * 1.5)

    if bits < 28:
        verdict, color = "крайне слабый", "31"
    elif bits < 36:
        verdict, color = "слабый", "33"
    elif bits < 60:
        verdict, color = "средний", "36"
    elif bits < 100:
        verdict, color = "хороший", "32"
    else:
        verdict, color = "отличный", "32"
    return {"bits": bits, "verdict": verdict, "color": color, "flaws": flaws}


def crack_time(bits: float) -> str:
    """Грубая оценка времени подбора: 10 млрд попыток/сек (совр. GPU-ферма)."""
    # Брутфорс вскрытия — полный перебор, в среднем угадывание
    # происходит на половине пространства ключей.
    seconds = 2 ** (bits - 1) / 10_000_000_000
    if seconds < 60:
        return f"{seconds:.1f} сек"
    if seconds < 3600:
        return f"{seconds / 60:.1f} мин"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} ч"
    if seconds < 365 * 86400:
        return f"{seconds / 86400:.1f} дн"
    years = seconds / (365 * 86400)
    if years > 1e9:
        return f"{years:.1e} лет"
    return f"{years:,.0f} лет"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def colorize(text: str, code: int, enabled: bool = True) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled and sys.stdout.isatty() else text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="passgen",
        description="Генератор надёжных паролей и анализатор их стойкости.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", aliases=["gen"], help="сгенерировать пароль")
    g.add_argument("-l", "--length", type=int, default=16, help="длина (по умолчанию 16)")
    g.add_argument("-n", "--count", type=int, default=1, help="сколько штук")
    g.add_argument("--no-upper", action="store_true", help="без заглавных букв")
    g.add_argument("--no-digits", action="store_true", help="без цифр")
    g.add_argument("--no-symbols", action="store_true", help="без спецсимволов")
    g.add_argument("--no-ambiguous", action="store_true", help="исключить Il1O0o")
    g.add_argument("--phrase", action="store_true", help="парольная фраза из слов")
    g.add_argument("-w", "--words", type=int, default=4, help="слов в фразе (3–12)")
    g.add_argument("-s", "--separator", default="-", help="разделитель слов во фразе")

    c = sub.add_parser("check", help="оценить надёжность пароля")
    c.add_argument("password", nargs="?", help="пароль (лучше передать через stdin)")

    args = parser.parse_args(argv)

    if args.command in ("generate", "gen"):
        try:
            if args.phrase:
                for _ in range(args.count):
                    print(generate_passphrase(args.words, args.separator))
            else:
                for _ in range(args.count):
                    pw = generate_password(
                        length=args.length,
                        upper=not args.no_upper,
                        digits=not args.no_digits,
                        symbols=not args.no_symbols,
                        no_ambiguous=args.no_ambiguous,
                    )
                    info = analyse(pw)
                    print(f"{pw}   ({colorize(info['verdict'], info['color'])}, "
                          f"{info['bits']:.0f} бит)")
        except ValueError as exc:
            parser.error(str(exc))
        return 0

    # Режим check: без аргумента читаем пароль со stdin (безопаснее истории shell)
    password = args.password or sys.stdin.readline().rstrip("\n")
    if not password:
        print("Пустой пароль", file=sys.stderr)
        return 1
    try:
        info = analyse(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Длина:            {len(password)}")
    print(f"Алфавит:          {charset_size(password)} символов")
    print(f"Энтропия:         {info['bits']:.1f} бит")
    print(f"Подбор (~):       {crack_time(info['bits'])}")
    verdict = colorize(info["verdict"], info["color"])
    print(f"Вердикт:          {verdict}")
    for flaw in info["flaws"]:
        print(f"  ⚠ {colorize(flaw, 33)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
