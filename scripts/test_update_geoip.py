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

    def test_only_requested_cidr_is_kept_from_old_supernet(self):
        import ipaddress
        broad = ipaddress.ip_network("85.172.0.0/14")
        narrow = ipaddress.ip_network("85.175.96.0/22")
        result = u.apply_pinned_ipv4([broad, ipaddress.ip_network("8.8.8.0/24")])
        self.assertIn(narrow, result)
        self.assertNotIn(broad, result)
        self.assertIn(ipaddress.ip_network("8.8.8.0/24"), result)
        self.assertFalse(any(
            net.overlaps(broad) and net != narrow for net in result
        ))

    def test_refresh_replaces_old_supernet(self):
        self.path.write_text(json.dumps({
            "version": 1, "rules": [{"ip_cidr": ["85.172.0.0/14", "8.8.8.0/24", "2001:4860::/32"]}]
        }), encoding="utf-8")
        data = "85.172.0.0-85.175.255.255\n8.8.8.0-8.8.8.255\n2001:4860::-2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\n"
        with patch.object(u, "MIN_SOURCE_LINES", 3), patch.dict(u.MIN_NETWORKS, {4: 1, 6: 1}), patch.object(u, "MIN_RETAINED", 0.0):
            self.assertTrue(u.refresh(self.path, data))
        saved = json.loads(self.path.read_text(encoding="utf-8"))["rules"][0]["ip_cidr"]
        self.assertIn("85.175.96.0/22", saved)
        self.assertNotIn("85.175.0.0/14", saved)
        self.assertNotIn("85.172.0.0/14", saved)

    def test_retention_for_split_prefix(self):
        import ipaddress
        old = [ipaddress.ip_network("8.8.8.0/24")]
        new = [ipaddress.ip_network("8.8.8.0/25"), ipaddress.ip_network("8.8.8.128/25")]
        self.assertEqual(u.covered_addresses(old, new), (256, 256))


    def test_foreign_exclusions_remove_full_and_partial_subnets(self):
        import ipaddress
        net = ipaddress.ip_network
        networks = {
            4: [net("8.8.8.0/23"), net("9.9.9.0/24")],
            6: [net("2001:4860::/32")],
        }
        exclusions = {
            4: [net("8.8.8.0/25"), net("9.9.9.0/24")],
            6: [net("2001:4860::/33")],
        }
        filtered = u.apply_foreign_exclusions(networks, exclusions)
        self.assertEqual([str(n) for n in filtered[4]],
                         ["8.8.8.128/25", "8.8.9.0/24"])
        self.assertEqual([str(n) for n in filtered[6]],
                         ["2001:4860:8000::/33"])

    def test_foreign_exclusions_survive_suip_refresh(self):
        exclusions_file = Path(self.tmp.name) / "foreign.txt"
        exclusions_file.write_text("# Confirmed foreign network\n8.8.8.0/25\n", encoding="utf-8")
        data = "8.8.8.0-8.8.9.255\n2001:4860::-2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\n"
        with patch.object(u, "MIN_SOURCE_LINES", 2), patch.dict(u.MIN_NETWORKS, {4: 1, 6: 1}), patch.object(u, "MIN_RETAINED", 0.0):
            self.assertTrue(u.refresh(self.path, data, exclusions_file=exclusions_file))
        saved = json.loads(self.path.read_text())["rules"][0]["ip_cidr"]
        self.assertNotIn("8.8.8.0/23", saved)
        self.assertIn("8.8.8.128/25", saved)
        self.assertIn("8.8.9.0/24", saved)

    def test_missing_foreign_exclusions_aborts_refresh(self):
        missing = Path(self.tmp.name) / "does-not-exist.txt"
        data = "8.8.8.0-8.8.8.255\n2001:4860::-2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\n"
        before = self.path.read_text()
        with patch.object(u, "MIN_SOURCE_LINES", 2), patch.dict(u.MIN_NETWORKS, {4: 1, 6: 1}):
            with self.assertRaises(FileNotFoundError):
                u.refresh(self.path, data, exclusions_file=missing)
        self.assertEqual(self.path.read_text(), before)

if __name__ == "__main__":
    unittest.main()
