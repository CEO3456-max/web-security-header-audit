import unittest

from src.header_auditor import (
    SecurityAuditError,
    audit_headers,
    calculate_score,
    normalize_headers,
)


class TestHeaderAuditor(unittest.TestCase):

    def test_normalize_headers(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
        }

        result = normalize_headers(headers)

        self.assertIn("content-security-policy", result)
        self.assertIn("x-frame-options", result)

    def test_all_headers_present(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }

        result = audit_headers(headers)

        self.assertEqual(result["score"], 100.0)
        self.assertEqual(result["rating"], "Strong")
        self.assertEqual(result["headers_present"], 6)

    def test_missing_header_is_detected(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }

        result = audit_headers(headers)

        self.assertEqual(result["score"], 83.33)
        self.assertEqual(result["headers_present"], 5)

        missing = [
            finding
            for finding in result["findings"]
            if finding["status"] == "Missing"
        ]

        self.assertEqual(len(missing), 1)
        self.assertEqual(
            missing[0]["header"],
            "permissions-policy",
        )

    def test_empty_header_value_is_missing(self):
        headers = {
            "Content-Security-Policy": "",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }

        result = audit_headers(headers)

        self.assertEqual(result["headers_present"], 5)
        self.assertEqual(result["score"], 83.33)

    def test_invalid_header_name(self):
        headers = {
            123: "invalid"
        }

        with self.assertRaises(SecurityAuditError):
            normalize_headers(headers)

    def test_invalid_header_value(self):
        headers = {
            "Content-Security-Policy": 123
        }

        with self.assertRaises(SecurityAuditError):
            normalize_headers(headers)

    def test_calculate_score(self):
        scores = {
            "content-security-policy": 5,
            "strict-transport-security": 5,
            "x-content-type-options": 5,
            "x-frame-options": 5,
            "referrer-policy": 5,
            "permissions-policy": 5,
        }

        self.assertEqual(calculate_score(scores), 100.0)


if __name__ == "__main__":
    unittest.main()
