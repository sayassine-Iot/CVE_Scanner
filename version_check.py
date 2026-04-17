"""
version_check.py
~~~~~~~~~~~~~~~~
Robust version-range vulnerability checker for CVE / product databases.

Handles every version format found in practice:

  Format                 Example(s)
  ─────────────────────  ─────────────────────────────────────────────
  Semantic / PEP 440     1.2.3, 1.0a1, 2.0.post1, 0.5.0b3.dev97
  Pre/post suffixes      4.1.3c, 5.0_fix-01, 3.5.1_sp2, 2.1_stable
  Trailing-letter patch  8.2.1d, 4.26.4m, 12.1a
  Cisco IOS (DB-escaped) 12.0\\(1\\)w, 11.1\\(15\\)ca, 4.1\\(3e\\)
  Date-based             2026-03-17T21:25:16Z, 2026.03.17, 2026-01-19
  Drupal module          8.x-1.17, 7.x-1.35  →  8.1.17
  Huawei / vendor        v200r003sph011, v200r001c00
  sr-prefixed            sr10.2, sr10.3
  v-prefixed             v4.0, v6r2013xe
  Plain integers         9, 300, 2000
  True wildcards         1.x, 4.7.x, 8.x, all_versions

Operators supported
───────────────────
  start_op : '=', '>=', '>', ''   (empty = no lower bound)
  end_op   :      '<=', '<', ''   (empty = no upper bound)
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from packaging import version as _pkg
from packaging.version import InvalidVersion


# ─────────────────────────────────────────────────────────────────────────────
# Suffix rank tables
# ─────────────────────────────────────────────────────────────────────────────
#   Negative rank  → pre-release  (sorts BELOW the base version)
#   Zero           → neutral / release modifier
#   Positive rank  → post-release (sorts ABOVE  the base version)

_PRE_RANK: dict[str, int] = {
    "dev":     -40,
    "alpha":   -30, "a":   -30,
    "beta":    -20, "b":   -20,
    "rc":      -10, "cr":  -10, "preview": -10, "pre": -10, "ea": -10,
}
_POST_RANK: dict[str, int] = {
    "post":    10, "patch": 10, "p":   10, "sp":  10, "sph": 10,
    "fix":      5, "mu":     5, "iop":  5, "ipr":  5,
    "stable":   0, "current": 0, "t":   0, "es":   0,
}


# ─────────────────────────────────────────────────────────────────────────────
# Pre-processing  — normalise raw strings before comparison
# ─────────────────────────────────────────────────────────────────────────────

def _preprocess(raw: str) -> str:
    """
    Normalise a raw version string to a canonical dot-separated form.

    Transformations (applied in order):
      1. Unescape  \\(  \\)  \\+  (produced by some DB exporters)
      2. Strip leading non-numeric prefixes followed by a digit:
           v, V, sr, SR, cs, CS, r, R
           e.g. sr10.3 → 10.3,  v4.0 → 4.0,  r32_p4 → 32_p4
      3. Cisco IOS parenthesised segments:
           12.0\\(1\\)w → 12.0.1.w   (after step 1 unescaping)
      4. Drupal module style with specific minor version:
           8.x-1.17 → 8.1.17,  7.x-1.35 → 7.1.35
      5. ISO-8601 datetime:
           2026-03-17T21:25:16Z → 2026.03.17
      6. Collapse consecutive dots introduced by earlier steps
    """
    v = raw.strip()

    # 1. Unescape backslash sequences
    v = v.replace("\\(", "(").replace("\\)", ")").replace("\\+", "+")

    # 2. Strip leading non-numeric prefixes (only when directly before a digit)
    v = re.sub(r"^(?:v|sr|cs|r)(?=\d)", "", v, flags=re.IGNORECASE)

    # 3. Cisco IOS: 12.0(1)w  →  12.0.1.w
    v = re.sub(r"\((\w+)\)", r".\1.", v)

    # 4. Drupal: 8.x-1.17 → 8.1.17   (only when followed by a concrete minor)
    v = re.sub(r"^(\d+)\.x-", r"\1.", v)

    # 5. ISO-8601 datetime → YYYY.MM.DD
    v = re.sub(
        r"^(\d{4})-(\d{2})-(\d{2})[tT].*$",
        lambda m: f"{m.group(1)}.{m.group(2)}.{m.group(3)}",
        v,
    )

    # 6. Collapse multiple consecutive dots; strip leading/trailing dots
    v = re.sub(r"[.]{2,}", ".", v).strip(".")
    return v


# ─────────────────────────────────────────────────────────────────────────────
# Flexible tuple-based comparator  (fallback for non-PEP-440 strings)
# ─────────────────────────────────────────────────────────────────────────────

def _suffix_rank(suf: str) -> int:
    """Return the sort weight for an alphanumeric suffix token."""
    rank = _PRE_RANK.get(suf, _POST_RANK.get(suf))
    if rank is not None:
        return rank
    # Match on the leading alpha portion:  "b3" → "b",  "rc2" → "rc"
    m = re.match(r"^([a-z]+)", suf)
    if m:
        return _PRE_RANK.get(m.group(1), _POST_RANK.get(m.group(1), 0))
    return 0


def _to_tuple(preprocessed: str) -> tuple:
    """
    Convert a preprocessed version string to a sortable tuple of 3-tuples
    (numeric_part: int, rank: int, text_part: str).

    Rules
    -----
    • Pure numeric token  "3"      → (3,  0,  "")
    • Digit + alpha       "3c"     → (3, -30, "c")   ← pre-release (c ≈ alpha)
    • Digit + alpha       "3sp2"   → (3, +10, "sp2")  ← post-release
    • Alpha + digit/rest  "b2"     → (0, -20, "b2")   ← beta
    • Alpha + digit/rest  "dev97"  → (0, -40, "dev97") ← dev
    • Pure alpha          "stable" → (0,   0, "stable")
    """
    tokens = re.split(r"[.\-_]", preprocessed)
    result: list[tuple] = []

    for tok in tokens:
        if not tok:
            continue

        # Pure integer
        if tok.isdigit():
            result.append((int(tok), 0, ""))
            continue

        # digit + trailing alpha:  "3c", "0b2", "1rc"
        m = re.fullmatch(r"(\d+)([A-Za-z]\w*)", tok)
        if m:
            num, suf = int(m.group(1)), m.group(2).lower()
            result.append((num, _suffix_rank(suf), suf))
            continue

        # leading alpha + rest:  "b2", "rc1", "dev97", "sp3"
        m = re.fullmatch(r"([A-Za-z]+)(.*)", tok)
        if m:
            pref, rest = m.group(1).lower(), m.group(2)
            result.append((0, _suffix_rank(pref), pref + rest))
            continue

        # Anything else (should be rare)
        result.append((0, 0, tok.lower()))

    return tuple(result) if result else ((0, 0, ""),)


# ─────────────────────────────────────────────────────────────────────────────
# Core comparison  — always returns an int (-1, 0, +1)
# ─────────────────────────────────────────────────────────────────────────────

def _compare(a_raw: str, b_raw: str) -> int:
    """
    Compare two raw version strings; return -1, 0, or +1.

    Strategy
    --------
    1. Preprocess both strings (strip prefixes, normalise separators, …).
    2. Try strict PEP 440 comparison via *packaging.version.Version*.
       This correctly handles all standard semver + pre/dev/post releases.
    3. If either string fails PEP 440 (e.g. Cisco, Drupal, vendor-specific),
       fall back to the flexible *_to_tuple* comparator for **both** strings,
       ensuring consistent single-type comparison throughout.
    """
    a_p, b_p = _preprocess(a_raw), _preprocess(b_raw)
    try:
        a_v, b_v = _pkg.Version(a_p), _pkg.Version(b_p)
        return 0 if a_v == b_v else (-1 if a_v < b_v else 1)
    except InvalidVersion:
        pass
    a_t, b_t = _to_tuple(a_p), _to_tuple(b_p)
    return 0 if a_t == b_t else (-1 if a_t < b_t else 1)


# ─────────────────────────────────────────────────────────────────────────────
# Wildcard / sentinel helpers
# ─────────────────────────────────────────────────────────────────────────────

_SENTINEL_ALL: frozenset[str] = frozenset({"all_versions"})


def _is_empty(v: Optional[str]) -> bool:
    """True for None, '', or '-' — i.e. an absent / missing version field."""
    return not v or v.strip() in ("", "-")


def _is_sentinel_all(v: str) -> bool:
    """True for the 'all_versions' sentinel (every version is affected)."""
    return v.strip().lower() in _SENTINEL_ALL


def _is_wildcard(v: str) -> bool:
    """
    True for 'all_versions', '8.x', '4.7.x', etc.

    Note: Drupal-style '8.x-1.17' is NOT a wildcard — it is a concrete
    version that _preprocess() will convert to '8.1.17'.
    """
    if _is_sentinel_all(v):
        return True
    # Must end with a bare '.x' (or be just 'x'), after stripping whitespace
    return bool(re.match(r"^(?:[\d.]+\.)?x$", v.strip(), re.IGNORECASE))


def _wildcard_prefix(v: str) -> Optional[Tuple[int, ...]]:
    """
    Return the leading numeric prefix for a wildcard version.

    '1.x'   → (1,)
    '2.0.x' → (2, 0)
    'x'     → ()           — matches any version
    Returns None for unrecognised patterns.
    """
    s = v.strip()
    if re.fullmatch(r"x", s, re.IGNORECASE):
        return ()  # bare 'x' = any version
    m = re.match(r"^([\d.]+)\.x$", s, re.IGNORECASE)
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split(".") if p.isdigit())


def _matches_wildcard_prefix(installed_raw: str, prefix: Tuple[int, ...]) -> bool:
    """
    True if the leading numeric components of *installed_raw* exactly equal *prefix*.

    Examples
    --------
    installed='1.2.3', prefix=(1,)    → True   (any 1.y.z)
    installed='1.2.3', prefix=(1, 2)  → True   (any 1.2.z)
    installed='2.0.0', prefix=(1,)    → False
    installed='8.5',   prefix=()      → True    (bare 'x' matches everything)
    """
    if not prefix:          # bare wildcard — matches every version
        return True
    parts = re.split(r"[.\-_]", _preprocess(installed_raw))
    nums: list[int] = []
    for p in parts:
        if p.isdigit():
            nums.append(int(p))
        else:
            break           # stop at first non-numeric component
    return len(nums) >= len(prefix) and tuple(nums[: len(prefix)]) == prefix


# ─────────────────────────────────────────────────────────────────────────────
# Public parse helper  (kept for backward-compatibility)
# ─────────────────────────────────────────────────────────────────────────────

def parse(raw: Optional[str]) -> Optional[str]:
    """
    Return the stripped version string, or None if the value is absent.

    In the original code this returned a packaging.version object.
    The new architecture delegates all comparisons to _compare(), so
    this function now simply validates presence and strips whitespace.
    It is kept so existing call-sites using  `if parse(v):`  still work.
    """
    return None if _is_empty(raw) else raw.strip()  # type: ignore[union-attr]


# ─────────────────────────────────────────────────────────────────────────────
# Main vulnerability check
# ─────────────────────────────────────────────────────────────────────────────

def check_vulnerable(
    installed_v: str,
    start_v: str,
    start_op: str,
    end_v: str,
    end_op: str,
) -> bool:
    """
    Return True if *installed_v* falls within the vulnerable range
    defined by  [start_op  start_v,  end_op  end_v].

    Parameters
    ----------
    installed_v : str
        The installed software version to test.
    start_v : str
        Lower bound version.  Use '' or '-' for no lower bound.
    start_op : str
        Operator for the lower bound: '=', '>=', '>', or ''.
    end_v : str
        Upper bound version.  Use '' or '-' for no upper bound.
    end_op : str
        Operator for the upper bound: '<=', '<', or ''.

    Special version values
    ----------------------
    'all_versions'    Sentinel — every installed version is affected.
    '1.x', '4.7.x'   Wildcard — matches any version with that numeric prefix.
    '-' / '' / None   Absent bound — no constraint in that direction.

    Logic overview
    --------------
    1. If start_op == '=':  exact / wildcard match shortcut.
    2. Check end (upper) bound: installed must be ≤ or < end.
    3. Check start (lower) bound: installed must be ≥ or > start.
    4. If all applicable checks pass → vulnerable.
    """

    # Guard: cannot check an absent installed version
    if _is_empty(installed_v):
        return False

    # ── 1. Exact-match shortcut  (start_op == '=') ───────────────────────
    if start_op == "=" and not _is_empty(start_v):
        s = start_v.strip()
        if _is_sentinel_all(s):
            return True                          # every version is affected
        if _is_wildcard(s):
            pfx = _wildcard_prefix(s)
            if pfx is None:
                return True                      # unrecognised wildcard → conservative
            return _matches_wildcard_prefix(installed_v, pfx)
        # True exact comparison
        return _compare(installed_v, s) == 0

    # ── 2. End (upper) bound ─────────────────────────────────────────────
    if not _is_empty(end_v):
        e = end_v.strip()
        if not _is_wildcard(e):                  # wildcard end = no upper limit
            cmp = _compare(installed_v, e)
            if end_op == "<=" and cmp > 0:       # installed > end  → safe
                return False
            if end_op == "<"  and cmp >= 0:      # installed >= end → safe
                return False
            # Unknown / unparseable end: skip bound (conservative)

    # ── 3. Start (lower) bound ────────────────────────────────────────────
    if not _is_empty(start_v):
        s = start_v.strip()
        if _is_wildcard(s):
            pfx = _wildcard_prefix(s)
            if pfx is not None and not _matches_wildcard_prefix(installed_v, pfx):
                return False
        else:
            cmp = _compare(installed_v, s)
            if start_op == ">=" and cmp < 0:     # installed < start → safe
                return False
            if start_op == ">"  and cmp <= 0:    # installed ≤ start → safe
                return False
            if start_op == "="  and cmp != 0:    # (guard; already handled above)
                return False

    return True


# ─────────────────────────────────────────────────────────────────────────────
# Improved DB file generation
# ─────────────────────────────────────────────────────────────────────────────

def write_versions_file(cursor, path: str = "versions.txt") -> None:
    """
    Generate versions.txt from the PRODUCTS table.

    Each line: 'VERSION_END | VERSION_START'
    NULL / None / '-' DB values are written as an empty string so that
    _is_empty() correctly treats them as absent (no bound).
    Handles both NULL and string 'None' values from cursors.
    """
    cursor.execute("SELECT DISTINCT VERSION_END, VERSION_START FROM PRODUCTS")
    rows = cursor.fetchall()

    def _clean(v) -> str:
        if v is None:
            return ""
        s = str(v).strip()
        return "" if s in ("-", "None") else s

    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(
            f"{_clean(end)} | {_clean(start)}\n"
            for end, start in rows
        )


# ─────────────────────────────────────────────────────────────────────────────
# Self-tests
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    def _test(label, result, expected):
        status = "✓" if result == expected else "✗ FAIL"
        print(f"  {status}  {label}")
        if result != expected:
            print(f"       got {result!r}, expected {expected!r}")

    print("=== Preprocessing ===")
    cases = [
        ("sr10.3",                  "10.3"),
        ("v4.0",                    "4.0"),
        (r"12.0\(1\)w",             "12.0.1.w"),
        (r"11.1\(15\)ca",           "11.1.15.ca"),
        ("8.x-1.17",                "8.1.17"),
        ("7.x-1.35",                "7.1.35"),
        ("2026-03-17t21-25-16z",    "2026.03.17"),
        ("2026-01-19",              "2026-01-19"),   # date without time → kept
        ("2.0.",                    "2.0"),           # trailing dot stripped
        ("v200r003sph011",          "200r003sph011"),
    ]
    for raw, expected in cases:
        _test(f"_preprocess({raw!r})", _preprocess(raw), expected)

    print("\n=== Ordering (_compare) ===")
    order_cases = [
        # (a, b, expected_sign)   sign: -1 = a<b, 0 = equal, 1 = a>b
        ("1.0",       "1.1",        -1),
        ("1.0a",      "1.0",        -1),   # alpha < release
        ("1.0b2",     "1.0rc1",     -1),   # beta < rc
        ("1.0rc1",    "1.0",        -1),   # rc < release
        ("1.0",       "1.0.post1",  -1),   # release < post
        ("1.0_sp1",   "1.0",         1),   # sp1 > release
        ("1.0_fix01", "1.0",         1),   # fix > release (post)
        ("0.5.0b3.dev97", "0.5.0b3", -1), # dev < beta
        ("2.0",       "2.0",         0),
        ("10",        "9",           1),   # numeric (not lexicographic)
        ("9.17",      "9.5",         1),   # numeric comparison of components
        ("sr10.3",    "sr10.2",      1),   # sr prefix stripped
        ("8.x-1.17",  "8.x-1.16",   1),   # Drupal normalised
        (r"12.0\(2\)xf", r"12.0\(1\)w", 1),  # Cisco
        ("2026.03.17", "2025.12.01", 1),   # date-based
    ]
    for a, b, expected in order_cases:
        got = _compare(a, b)
        _test(f"_compare({a!r}, {b!r})", got, expected)

    print("\n=== check_vulnerable ===")
    vuln_cases = [
        # description, (installed, start_v, start_op, end_v, end_op), expected
        ("exact =",              ("1.2.3", "1.2.3",  "=",  "",      ""),    True),
        ("exact = miss",         ("1.2.4", "1.2.3",  "=",  "",      ""),    False),
        ("range >= <=",          ("1.5",   "1.0",    ">=", "2.0",   "<="),  True),
        ("range >= <= (low)",    ("0.9",   "1.0",    ">=", "2.0",   "<="),  False),
        ("range >= <= (high)",   ("2.1",   "1.0",    ">=", "2.0",   "<="),  False),
        ("range > <",            ("1.5",   "1.0",    ">",  "2.0",   "<"),   True),
        ("range > < (equal lo)", ("1.0",   "1.0",    ">",  "2.0",   "<"),   False),
        ("only end <=",          ("3.0",   "",       "",   "4.0",   "<="),  True),
        ("only end <= (above)",  ("5.0",   "",       "",   "4.0",   "<="),  False),
        ("only start >=",        ("5.0",   "4.0",    ">=", "",      ""),    True),
        ("only start >= (below)",("3.0",   "4.0",    ">=", "",      ""),    False),
        ("wildcard 1.x",         ("1.3.5", "1.x",   "=",  "",      ""),    True),
        ("wildcard 1.x miss",    ("2.0.0", "1.x",   "=",  "",      ""),    False),
        ("wildcard 4.7.x",       ("4.7.2", "4.7.x", "=",  "",      ""),    True),
        ("all_versions",         ("99.0",  "all_versions","=","",   ""),    True),
        ("no bounds",            ("1.0",   "",       "",   "",      ""),    True),
        ("empty installed",      ("",      "1.0",    ">=", "2.0",   "<="),  False),
        ("Cisco range",          (r"12.0\(1\)xc", r"12.0\(1\)w", ">=", r"12.0\(2\)xg", "<="), True),
        ("Drupal range",         ("8.x-1.17", "8.x-1.0", ">=", "8.x-1.20", "<="), True),
    ]
    for desc, args, expected in vuln_cases:
        got = check_vulnerable(*args)
        _test(desc, got, expected)
        _test(desc, got, expected)