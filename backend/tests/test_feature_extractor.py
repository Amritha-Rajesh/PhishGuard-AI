import math
import unittest

from feature_extractor import (FEATURE_COLUMNS, NUMERIC_COLUMNS, InvalidURLError, extract_features,
                               features_frame, parse_url, registered_domain_key)


class ParseUrlTests(unittest.TestCase):
    def test_normalization(self):
        cases = {
            "https://www.Example.COM/Path?q=1#frag": "example.com",
            "http://example.com:8080/x": "example.com",
            "example.com/login": "example.com",
            "  https://sub.example.co.uk.  ": "sub.example.co.uk",
            "https://user:pw@evil.example.net/": "evil.example.net",
            "https://bücher.de": "xn--bcher-kva.de",
            "http://192.168.1.5/a": "192.168.1.5",
        }
        for raw, host in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(parse_url(raw).host, host)

    def test_flags(self):
        p = parse_url("https://www.example.com/a?b=1")
        self.assertTrue(p.www_removed and p.has_path_or_query)
        self.assertEqual(p.scheme, "https")
        q = parse_url("example.com")
        self.assertIsNone(q.scheme)
        self.assertFalse(q.has_path_or_query)

    def test_invalid_inputs(self):
        bad = ["", "   ", None, 123, "example", "http://", "javascript:alert(1)", "ftp://example.com",
               "http://exa mple.com", "http://-bad-.com", "http://a..b.com", "http://example.123",
               "http://" + "a" * 70 + ".com", "x" * 2100, "http://[::1", "mailto:a@b.com", "http://exa\tmple.com"]
        for raw in bad:
            with self.subTest(raw=str(raw)[:30]):
                with self.assertRaises(InvalidURLError):
                    parse_url(raw)

    def test_error_messages_are_helpful(self):
        with self.assertRaisesRegex(InvalidURLError, "enter a URL"):
            parse_url("")
        with self.assertRaisesRegex(InvalidURLError, "http and https"):
            parse_url("javascript:alert(1)")

    def test_never_touches_network(self):
        import socket
        orig = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used"))
        try:
            parse_url("https://www.example.com/x")
            extract_features("example.com")
        finally:
            socket.socket = orig


class FeatureTests(unittest.TestCase):
    def test_hand_computed_values(self):
        f = extract_features("paypal-login.verify-account.xyz")
        self.assertEqual(f["host_length"], 31)
        self.assertEqual(f["num_dots"], 2)
        self.assertEqual(f["num_hyphens"], 2)
        self.assertEqual(f["num_digits"], 0)
        self.assertEqual(f["num_labels"], 3)
        self.assertEqual(f["longest_label_len"], 14)
        self.assertEqual(f["first_label_len"], 12)
        self.assertEqual(f["tld"], "xyz")
        self.assertEqual(f["tld_length"], 3)
        self.assertEqual(f["num_suspicious_keywords"], 4)  # paypal, login, verify, account
        self.assertEqual(f["is_ip"], 0)

    def test_entropy(self):
        self.assertAlmostEqual(extract_features("aa.bb")["entropy"], -(2 * 0.4 * math.log2(0.4) + 0.2 * math.log2(0.2)), places=6)

    def test_ip_and_punycode(self):
        ip = extract_features("192.168.1.5")
        self.assertEqual((ip["is_ip"], ip["tld"], ip["num_digits"], ip["max_digit_run"]), (1, "(ip)", 8, 3))
        self.assertEqual(extract_features("xn--bcher-kva.de")["has_punycode"], 1)

    def test_frame_columns_and_order(self):
        df = features_frame(["example.com", "a-b.c1.org"])
        self.assertEqual(list(df.columns), FEATURE_COLUMNS)
        self.assertEqual(len(df), 2)
        self.assertTrue(all(str(df[c].dtype) == "float64" for c in NUMERIC_COLUMNS))
        self.assertFalse(df.isna().any().any())

    def test_deterministic(self):
        self.assertEqual(extract_features("shop.example.co.uk"), extract_features("shop.example.co.uk"))

    def test_registered_domain_key(self):
        self.assertEqual(registered_domain_key("a.b.example.com"), "example.com")
        self.assertEqual(registered_domain_key("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(registered_domain_key("10.0.0.1"), "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
