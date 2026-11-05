"""Alert rule validation shared by create and patch."""

from __future__ import annotations

import math

KINDS = ("kev_added", "cvss_min", "epss_min", "keyword")
KEYWORD_MAX = 100


class RuleInvalid(ValueError):
    """Generic rule validation failure (message never echoes input)."""


def _has_control(s: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7F or 0x80 <= ord(c) <= 0x9F for c in s)


def validate_rule(
    kind: str, threshold: float | None, keyword: str | None
) -> tuple[float | None, str | None]:
    """Return normalized (threshold, keyword) or raise RuleInvalid."""
    if threshold is not None and not math.isfinite(threshold):
        raise RuleInvalid("invalid threshold")
    if kind == "kev_added":
        if threshold is not None or keyword is not None:
            raise RuleInvalid("kev_added takes no threshold or keyword")
        return None, None
    if kind in ("cvss_min", "epss_min"):
        hi = 10.0 if kind == "cvss_min" else 1.0
        if threshold is None or not 0.0 <= threshold <= hi or keyword is not None:
            raise RuleInvalid("invalid threshold")
        return float(threshold), None
    if kind == "keyword":
        if threshold is not None or keyword is None:
            raise RuleInvalid("invalid keyword rule")
        kw = keyword.strip()
        if not 1 <= len(kw) <= KEYWORD_MAX or _has_control(kw):
            raise RuleInvalid("invalid keyword")
        return None, kw
    raise RuleInvalid("invalid kind")
