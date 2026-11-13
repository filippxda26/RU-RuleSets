"""Offline safety tests for SUIP GeoIP refresh."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import update_geoip as u

class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ru.json"
        self.path.write_text(json.dumps({
            "version": 1, "rules": [{"ip_cidr": ["8.8.8.0/24", "2001:4860::/32"]}]
        }), encoding="utf-8")

    def test_convert_ipv4_and_ipv6_ranges(self):
        data = "8.8.8.0-8.8.8.127\n8.8.8.128-8.8.8.255\n2001:4860::-2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\n"
        with patch.object(u, "MIN_SOURCE_LINES", 3), patch.dict(u.MIN_NETWORKS, {4: 1, 6: 1}):
            parsed = u.parse_ranges(data)
        self.assertEqual([str(x) for x in parsed[4]], ["8.8.8.0/24"])
        self.assertEqual([str(x) for x in parsed[6]], ["2001:4860::/32"])

    def test_invalid_download_rejected(self):
        with self.assertRaises(ValueError):
            u.parse_ranges("<html>error</html>")
        with patch.object(u, "MIN_SOURCE_LINES", 1):
            with self.assertRaisesRegex(ValueError, "Bad SUIP line"):
                u.parse_ranges("8.8.8.8-2001:4860::")

    def test_excessive_deletion_keeps_file_unchanged(self):
        original = self.path.read_text()
        data = "1.1.1.0-1.1.1.255\n2606:4700::-2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\n"
        with patch.object(u, "MIN_SOURCE_LINES", 2), patch.dict(u.MIN_NETWORKS, {4: 1, 6: 1}):
            with self.assertRaisesRegex(ValueError, "excessive IPv4 deletion"):
                u.refresh(self.path, data)
        self.assertEqual(self.path.read_text(), original)

    def test_dry_run_keeps_file(self):
        original = self.path.read_text()
        data = "8.8.8.0-8.8.9.255\n2001:4860::-2001:4861:ffff:ffff:ffff:ffff:ffff:ffff\n"
        with patch.object(u, "MIN_SOURCE_LINES", 2), patch.dict(u.MIN_NETWORKS, {4: 1, 6: 1}):
            self.assertTrue(u.refresh(self.path, data, dry_run=True))
        self.assertEqual(self.path.read_text(), original)

    def test_retention_for_split_prefix(self):
        import ipaddress
        old = [ipaddress.ip_network("8.8.8.0/24")]
        new = [ipaddress.ip_network("8.8.8.0/25"), ipaddress.ip_network("8.8.8.128/25")]
        self.assertEqual(u.covered_addresses(old, new), (256, 256))

if __name__ == "__main__":
    unittest.main()
