"""Streaming feature helpers (entropy, n-grams, periodicity) from metadata only."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence

_ALNUM = re.compile(r"[^a-z0-9]")


def shannon_entropy(values: Sequence[str | int | float]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    n = len(values)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    return shannon_entropy(list(s.lower()))


def char_ngrams(s: str, n: int = 3) -> list[str]:
    s = _ALNUM.sub("", s.lower())
    if len(s) < n:
        return [s] if s else []
    return [s[i : i + n] for i in range(len(s) - n + 1)]


def ngram_rarity(s: str, n: int = 3) -> float:
    """Higher means more unusual character transitions (DGA-like)."""
    grams = char_ngrams(s, n)
    if not grams:
        return 0.0
    vowelish = set("aeiou")
    rare = 0
    for g in grams:
        vowels = sum(1 for ch in g if ch in vowelish)
        if vowels == 0 or (len(g) >= 3 and vowels == len(g)):
            rare += 1
    return rare / len(grams)


def coefficient_of_variation(xs: Sequence[float]) -> float:
    if len(xs) < 2:
        return 0.0
    mean = sum(xs) / len(xs)
    if mean == 0:
        return 0.0
    var = sum((x - mean) ** 2 for x in xs) / (len(xs) - 1)
    return math.sqrt(var) / abs(mean)


def periodicity_score(iats: Sequence[float], bins: int = 20) -> float:
    """Score in [0, 1]: 1 means tightly clustered inter-arrival times (beacon)."""
    if len(iats) < 3:
        return 0.0
    cv = coefficient_of_variation(iats)
    # Low CV => regular; map with a smooth curve.
    return 1.0 / (1.0 + cv * 4.0)


def numeric_ratio(s: str) -> float:
    if not s:
        return 0.0
    digits = sum(ch.isdigit() for ch in s)
    return digits / len(s)


def label_entropy(labels: Sequence[str]) -> float:
    return shannon_entropy(list(labels))
