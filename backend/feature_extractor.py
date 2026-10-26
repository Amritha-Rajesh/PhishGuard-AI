"""
feature_extractor.py - the ONE place where a URL becomes model input.

Both train.py (training) and predictor.py (live prediction) import from here,
so the features and their order are identical in training and inference.

The extractor only looks at the URL *string*. It never opens the URL, never
resolves DNS, never follows redirects and never downloads anything.

Scope of this version: HOSTNAME ONLY. The scheme (http/https), a leading
"www.", the port, the path, the query string and the fragment are ignored.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

import pandas as pd

MAX_URL_LENGTH = 2048

# Words that phishing hostnames often contain (own hand-written list, not learned from the dataset).
SUSPICIOUS_KEYWORDS = (
    "login", "signin", "secure", "verify", "account", "update", "bank",
    "paypal", "support", "confirm", "wallet", "password", "billing", "service",
)

# Second-level labels used under country codes (co.uk, com.au, ac.in ...).
# Only used to build a rough "registered domain" key for the grouped train/test split.
SECOND_LEVEL_LABELS = frozenset(
    {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "lg", "ind", "mil", "gob", "nom"}
)

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_EXPLICIT_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_UNSUPPORTED_SCHEME_RE = re.compile(
    r"^(javascript|data|mailto|file|ftp|tel|vbscript|about|blob):", re.IGNORECASE
)
_CONSONANT_RUN_RE = re.compile(r"[b-df-hj-np-tv-z]+")
_DIGIT_RUN_RE = re.compile(r"\d+")

# ---------------------------------------------------------------- feature list
NUMERIC_COLUMNS = [
    "host_length", "num_dots", "num_hyphens", "num_digits", "digit_ratio",
    "num_labels", "longest_label_len", "avg_label_len", "first_label_len",
    "entropy", "is_ip", "tld_length", "has_punycode", "vowel_ratio",
    "max_consonant_run", "max_digit_run", "num_suspicious_keywords",
]
CATEGORICAL_COLUMNS = ["tld"]
FEATURE_COLUMNS = NUMERIC_COLUMNS + CATEGORICAL_COLUMNS  # exact input order of the model

FEATURE_DESCRIPTIONS = {
    "host_length": "Number of characters in the normalized hostname",
    "num_dots": "Number of dots in the hostname",
    "num_hyphens": "Number of hyphens in the hostname",
    "num_digits": "Number of digits in the hostname",
    "digit_ratio": "Digits divided by hostname length",
    "num_labels": "Number of dot-separated parts (labels) in the hostname",
    "longest_label_len": "Length of the longest label",
    "avg_label_len": "Average label length",
    "first_label_len": "Length of the left-most label",
    "entropy": "Shannon entropy of the hostname characters (higher = more random-looking)",
    "is_ip": "1 if the host is an IP address, else 0",
    "tld_length": "Length of the top-level domain (the last label)",
    "has_punycode": "1 if any label starts with 'xn--' (internationalised domain), else 0",
    "vowel_ratio": "Vowels divided by letters in the hostname",
    "max_consonant_run": "Longest run of consecutive consonants",
    "max_digit_run": "Longest run of consecutive digits",
    "num_suspicious_keywords": "How many words from a fixed keyword list (login, secure, verify ...) appear in the hostname",
    "tld": "Top-level domain as a category (rare TLDs are grouped together by the encoder)",
}


class InvalidURLError(ValueError):
    """Raised with a user-friendly message when the input cannot be analysed."""


@dataclass(frozen=True)
class ParsedURL:
    host: str                 # normalized hostname (lowercase, no www., no port)
    scheme: str | None        # "http" / "https" / None if the user typed none
    is_ip: bool
    www_removed: bool
    has_path_or_query: bool   # True if a path, query or fragment was ignored


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def tld_of(host: str) -> str:
    return "(ip)" if _is_ip(host) else host.rsplit(".", 1)[-1]


def parse_url(raw) -> ParsedURL:
    """Validate and normalize a user-supplied URL. Raises InvalidURLError."""
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be text.")
    s = raw.strip()
    if not s:
        raise InvalidURLError("Please enter a URL.")
    if len(s) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if re.search(r"[\s\x00-\x1f\x7f]", s):
        raise InvalidURLError("URL must not contain spaces or control characters.")

    explicit = bool(_EXPLICIT_SCHEME_RE.match(s))
    if explicit:
        candidate = s
    elif _UNSUPPORTED_SCHEME_RE.match(s):
        raise InvalidURLError("Only http and https URLs are supported.")
    else:
        candidate = "http://" + s.lstrip("/")  # allow "example.com/login"

    try:
        parts = urlsplit(candidate)
        host = parts.hostname
    except ValueError:
        raise InvalidURLError("This does not look like a valid URL.") from None

    if parts.scheme.lower() not in ("http", "https"):
        raise InvalidURLError("Only http and https URLs are supported.")
    scheme = parts.scheme.lower() if explicit else None
    if not host:
        raise InvalidURLError("The URL has no hostname (example: https://example.com).")

    host = host.lower().rstrip(".")
    if not host:
        raise InvalidURLError("The URL has no hostname (example: https://example.com).")

    ip = _is_ip(host)
    www_removed = False
    if not ip:
        if not host.isascii():
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                raise InvalidURLError("The hostname contains invalid international characters.") from None
        if host.startswith("www.") and host.count(".") >= 2:
            host = host[4:]
            www_removed = True
        if len(host) > 253:
            raise InvalidURLError("The hostname is too long.")
        labels = host.split(".")
        if len(labels) < 2:
            raise InvalidURLError("The hostname must contain a dot, for example example.com.")
        if not all(_LABEL_RE.match(lbl) for lbl in labels):
            raise InvalidURLError("The hostname contains invalid characters.")
        tld = labels[-1]
        if len(tld) < 2 or tld.isdigit():
            raise InvalidURLError("The top-level domain looks invalid.")

    has_extra = parts.path not in ("", "/") or bool(parts.query) or bool(parts.fragment)
    return ParsedURL(host=host, scheme=scheme, is_ip=ip, www_removed=www_removed, has_path_or_query=has_extra)


def host_from_url(raw) -> str:
    """Convenience used by training: normalized hostname or InvalidURLError."""
    return parse_url(raw).host


def registered_domain_key(host: str) -> str:
    """Rough 'site' key (example.com, shop.co.uk) used ONLY to group related hosts in the split."""
    if _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL_LABELS and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def extract_features(host: str) -> dict:
    """Features of one normalized hostname. Keys follow FEATURE_COLUMNS."""
    ip = _is_ip(host)
    labels = host.split(".") if not ip else [host]
    letters = [c for c in host if c.isalpha()]
    n = len(host)
    digits = sum(c.isdigit() for c in host)
    tld = tld_of(host)
    lowered = host.lower()
    return {
        "host_length": n,
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "num_digits": digits,
        "digit_ratio": digits / n if n else 0.0,
        "num_labels": len(labels),
        "longest_label_len": max(len(x) for x in labels),
        "avg_label_len": sum(len(x) for x in labels) / len(labels),
        "first_label_len": len(labels[0]),
        "entropy": _entropy(host),
        "is_ip": int(ip),
        "tld_length": 0 if ip else len(tld),
        "has_punycode": int(any(x.startswith("xn--") for x in labels)),
        "vowel_ratio": (sum(c in "aeiou" for c in letters) / len(letters)) if letters else 0.0,
        "max_consonant_run": max((len(m) for m in _CONSONANT_RUN_RE.findall(lowered)), default=0),
        "max_digit_run": max((len(m) for m in _DIGIT_RUN_RE.findall(lowered)), default=0),
        "num_suspicious_keywords": sum(k in lowered for k in SUSPICIOUS_KEYWORDS),
        "tld": tld,
    }


def features_frame(hosts) -> pd.DataFrame:
    """DataFrame with exactly FEATURE_COLUMNS, in order - the model's input."""
    rows = [extract_features(h) for h in hosts]
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    df[NUMERIC_COLUMNS] = df[NUMERIC_COLUMNS].astype(float)
    return df
