"""
Web Security Header Audit Tool

A defensive security utility that evaluates HTTP response headers
against a small set of recommended web security controls.

This tool analyzes supplied header data. It does not exploit,
attack, or perform unauthorized scanning against websites.

Author: Ian Kipkorir
Project: web-security-header-audit
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List


SECURITY_HEADERS = {
    "content-security-policy": {
        "severity": "High",
        "description": (
            "Helps control which resources a browser is allowed to load "
            "and can reduce certain classes of injection attacks."
        ),
    },
    "strict-transport-security": {
        "severity": "High",
        "description": (
            "Instructs browsers to use HTTPS for future connections "
            "to the site."
        ),
    },
    "x-content-type-options": {
        "severity": "Medium",
        "description": (
            "Helps prevent browsers from MIME-sniffing responses "
            "away from the declared content type."
        ),
    },
    "x-frame-options": {
        "severity": "Medium",
        "description": (
            "Controls whether the page may be embedded in a frame "
            "and can help reduce clickjacking risk."
        ),
    },
    "referrer-policy": {
        "severity": "Low",
        "description": (
            "Controls how much referrer information is sent "
            "with outgoing requests."
        ),
    },
    "permissions-policy": {
        "severity": "Low",
        "description": (
            "Controls access to selected browser capabilities "
            "and features."
        ),
    },
}


class SecurityAuditError(ValueError):
    """Raised when security audit input is invalid."""


def normalize_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    """
    Normalize HTTP header names and values.

    Header names are converted to lowercase so that comparisons
    are case-insensitive.
    """

    if not isinstance(headers, dict):
        raise SecurityAuditError("Headers must be provided as a dictionary.")

    normalized = {}

    for name, value in headers.items():
        if not isinstance(name, str):
            raise SecurityAuditError("Header names must be strings.")

        if not isinstance(value, str):
            raise SecurityAuditError(
                f"Header value for '{name}' must be a string."
            )

        normalized[name.strip().lower()] = value.strip()

    return normalized


def audit_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Audit supplied HTTP headers against the project's security criteria.
    """

    normalized = normalize_headers(headers)

    findings: List[Dict[str, str]] = []

    present = 0
    total = len(SECURITY_HEADERS)

    for header_name, metadata in SECURITY_HEADERS.items():
        if header_name in normalized and normalized[header_name]:
            present += 1

            findings.append(
                {
                    "header": header_name,
                    "status": "Present",
                    "severity": metadata["severity"],
                    "description": metadata["description"],
                    "recommendation": "Review the value and keep it appropriately configured.",
                }
            )
        else:
            findings.append(
                {
                    "header": header_name,
                    "status": "Missing",
                    "severity": metadata["severity"],
                    "description": metadata["description"],
                    "recommendation": (
                        f"Consider adding {header_name} with a policy "
                        "appropriate for the application."
                    ),
                }
            )

    score = round((present / total) * 100, 2)

    if score >= 90:
        rating = "Strong"
    elif score >= 75:
        rating = "Good"
    elif score >= 50:
        rating = "Needs Improvement"
    else:
        rating = "Weak"

    return {
        "score": score,
        "rating": rating,
        "headers_checked": total,
        "headers_present": present,
        "findings": findings,
    }


def format_report(result: Dict[str, Any]) -> str:
    """Create a readable security audit report."""

    lines = [
        "Web Security Header Audit",
        "=" * 60,
        f"Security header score: {result['score']:.2f}/100",
        f"Overall rating: {result['rating']}",
        f"Headers present: {result['headers_present']}/{result['headers_checked']}",
        "",
        "Findings:",
        "-" * 60,
    ]

    for finding in result["findings"]:
        lines.extend(
            [
                f"Header: {finding['header']}",
                f"Status: {finding['status']}",
                f"Severity: {finding['severity']}",
                f"Description: {finding['description']}",
                f"Recommendation: {finding['recommendation']}",
                "",
            ]
        )

    return "\n".join(lines)


def load_input(file_path: str) -> Dict[str, Any]:
    """Load a JSON security-header dataset."""

    path = Path(file_path)

    if not path.exists():
        raise SecurityAuditError(f"Input file not found: {file_path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise SecurityAuditError(
            f"Invalid JSON input: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise SecurityAuditError(
            "Input JSON must contain an object of HTTP headers."
        )

    return data


def main() -> int:
    """Run the command-line security audit."""

    if len(sys.argv) != 2:
        print(
            "Usage: python src/header_auditor.py "
            "examples/sample_headers.json"
        )
        return 1

    try:
        headers = load_input(sys.argv[1])
        result = audit_headers(headers)
        print(format_report(result))
        return 0

    except SecurityAuditError as exc:
        print(f"Security audit error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
