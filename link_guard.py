#!/usr/bin/env python3
"""link_guard.py: Offline URL/domain phishing risk heuristic scorer.

Examples:
  python link_guard.py "https://secure-paypal.com/login"
  python link_guard.py "google.com" --explain
  python link_guard.py "http://185.12.34.56/verify" --json
  python link_guard.py "xn--pple-43d.com/account/update?token=abcd" --explain
  python link_guard.py "paypal-security-check.top/login?next=wallet" --quiet
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import ParseResult, urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "update",
    "security",
    "account",
    "bank",
    "payment",
    "invoice",
    "wallet",
    "password",
    "confirm",
    "free",
    "bonus",
    "gift",
    "win",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "country",
    "stream",
    "gq",
    "tk",
    "cf",
    "ga",
    "ml",
    "pw",
    "work",
}

BRAND_TOKENS = {
    "paypal",
    "google",
    "apple",
    "microsoft",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "bank",
    "chase",
    "wellsfargo",
    "coinbase",
    "binance",
}

WEIGHTS = {
    "host_ip": 35,
    "http": 12,
    "many_subdomains": 10,
    "long_host": 8,
    "suspicious_keywords": 12,
    "userinfo_at": 35,
    "many_hyphens": 8,
    "punycode": 12,
    "non_ascii_host": 15,
    "suspicious_tld": 10,
    "long_query": 8,
    "brand_extra": 14,
}


@dataclass
class Trigger:
    """A single heuristic trigger result."""

    rule: str
    points: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        """Return trigger as JSON-serializable dict."""
        return {"rule": self.rule, "points": self.points, "reason": self.reason}


def normalize_input(raw: str) -> ParseResult:
    """Parse an input URL/domain, defaulting to https scheme when missing."""
    value = raw.strip()
    if not value:
        raise ValueError("Input URL/domain cannot be empty.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = f"https://{value}"

    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError("Could not parse a host from input.")

    return parsed


def host_is_ip(host: str) -> bool:
    """Return True when host is an IP address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def label_from_score(score: int) -> str:
    """Map numeric score to LOW/MEDIUM/HIGH labels."""
    if score >= 67:
        return "HIGH"
    if score >= 34:
        return "MEDIUM"
    return "LOW"


def analyze(parsed: ParseResult) -> dict[str, Any]:
    """Analyze a parsed URL and return risk details."""
    host = (parsed.hostname or "").strip(".").lower()
    if not host:
        raise ValueError("Host is empty after parsing.")

    normalized_url = parsed.geturl()
    triggers: list[Trigger] = []

    def add(rule: str, reason: str) -> None:
        triggers.append(Trigger(rule=rule, points=WEIGHTS[rule], reason=reason))

    if host_is_ip(host):
        add("host_ip", "Host is a raw IP address, common in phishing infrastructure.")

    if parsed.scheme.lower() == "http":
        add("http", "URL uses HTTP instead of HTTPS.")

    labels = host.split(".")
    if len(labels) >= 5:
        add("many_subdomains", f"Host has many subdomains ({len(labels) - 2}).")

    if len(host) >= 30:
        add("long_host", f"Host is unusually long ({len(host)} characters).")

    combined_text = f"{host} {parsed.path} {parsed.query}".lower()
    hit_keywords = sorted(k for k in SUSPICIOUS_KEYWORDS if k in combined_text)
    if hit_keywords:
        add(
            "suspicious_keywords",
            "Contains suspicious terms: " + ", ".join(hit_keywords[:6]),
        )

    if parsed.username is not None or "@" in parsed.netloc:
        add("userinfo_at", "URL contains '@' userinfo pattern that can hide true destination.")

    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        add("many_hyphens", f"Host contains many hyphens ({hyphen_count}).")

    if any(label.startswith("xn--") for label in labels):
        add("punycode", "Host uses punycode (xn--) which can mask lookalike domains.")

    if any(ord(ch) > 127 for ch in host):
        add("non_ascii_host", "Host contains non-ASCII characters (possible confusable scripts).")

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", f"TLD '.{tld}' appears on a commonly abused list.")

    if len(parsed.query) >= 80:
        add("long_query", f"Query string is very long ({len(parsed.query)} chars).")

    registrable_part = labels[-2] if len(labels) >= 2 else labels[0]
    split_tokens = [t for t in re.split(r"[^a-z0-9]+", registrable_part) if t]
    brands_present = [b for b in BRAND_TOKENS if b in split_tokens]
    extra_tokens = [t for t in split_tokens if t not in BRAND_TOKENS]
    if brands_present and extra_tokens:
        add(
            "brand_extra",
            "Host combines brand-like token(s) with extra words: "
            + ", ".join(sorted(brands_present)[:3]),
        )

    score = min(100, sum(t.points for t in triggers))
    label = label_from_score(score)

    return {
        "normalized_url": normalized_url,
        "host": host,
        "score": score,
        "label": label,
        "triggers": [t.as_dict() for t in triggers],
    }


def build_explanation(result: dict[str, Any]) -> str:
    """Create plain-language explanation text from analysis result."""
    triggers = result["triggers"]
    if not triggers:
        return "This link did not trigger any high-risk heuristics in the offline checks."

    top = sorted(triggers, key=lambda t: t["points"], reverse=True)[:3]
    reasons = "; ".join(t["reason"] for t in top)
    return (
        f"This link is rated {result['label']} risk (score {result['score']}/100) because {reasons}. "
        "Heuristic checks are not proof of malicious intent, but caution is advised."
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line flags."""
    parser = argparse.ArgumentParser(description="Offline phishing/scam URL heuristic analyzer")
    parser.add_argument("url_or_domain", help="URL or domain to analyze")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output JSON only")
    parser.add_argument("--explain", action="store_true", help="Include plain-language explanation")
    parser.add_argument("--quiet", action="store_true", help="Hide trigger list in text output")
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""
    args = parse_args()
    parsed = normalize_input(args.url_or_domain)
    result = analyze(parsed)

    if args.explain:
        result["explanation"] = build_explanation(result)

    if args.as_json:
        print(json.dumps(result, ensure_ascii=False))
        return

    print(f"Normalized URL: {result['normalized_url']}")
    print(f"Host: {result['host']}")
    print(f"Risk: {result['score']}/100 ({result['label']})")

    if not args.quiet:
        print("Triggers:")
        if result["triggers"]:
            for trig in result["triggers"]:
                print(f"- [+{trig['points']}] {trig['reason']}")
        else:
            print("- None")

    if args.explain:
        print("Explanation:")
        print(result["explanation"])


if __name__ == "__main__":
    main()