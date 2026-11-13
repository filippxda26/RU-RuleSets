import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import audit_ownership as audit


class OwnershipAuditTests(unittest.TestCase):
    def test_rdap_requires_holder_organization_and_country(self):
        base = {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["org", {}, "text", "Foreign Registrar"], ["adr", {}, "text", ["", "", "", "", "", "", "US"]]]]}]}
        self.assertEqual(audit.classify_rdap(base, "test")["status"], "unverified")
        base["entities"][0]["roles"] = ["registrant"]
        self.assertEqual(audit.classify_rdap(base, "test")["status"], "foreign")
        base["entities"][0]["vcardArray"][1][1][3][-1] = "RU"
        self.assertEqual(audit.classify_rdap(base, "test")["status"], "russian")

    def test_no_country_does_not_mean_russian(self):
        data = {"country": "RU", "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["org", {}, "text", "Some company"]]]}]}
        self.assertEqual(audit.classify_rdap(data, "test")["status"], "unverified")

    def test_keep_whole_zones_and_do_not_mutate_active_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "geosite").mkdir()
            (root / "geoip").mkdir()
            domain_data = audit.rules({"domain": ["service.example.com"], "domain_suffix": [".ru", ".su", ".xn--p1ai", "foreign.example.com", "unknown.example.com"]})
            ip_data = audit.rules({"ip_cidr": ["1.2.3.0/24", "2001:db8::/32"]})
            audit.write(root / "geosite/ru.json", domain_data)
            audit.write(root / "geoip/ru.json", ip_data)
            audit.write(root / "audit/cache.json", {"domain_suffix:foreign.example.com": {"status": "foreign", "organization": "Example", "country": "US", "source": "registry"}, "ip:1.2.3.0/24": {"status": "foreign", "organization": "Example", "country": "US", "source": "registry"}})
            with patch.object(audit, "query_network") as query:
                audit.run(root, 0, 0, 0, offline=True)
                query.assert_not_called()
            self.assertEqual(audit.load(root / "geosite/ru.json"), domain_data)
            self.assertEqual(audit.load(root / "geoip/ru.json"), ip_data)
            foreign = audit.load(root / "audit/foreign-domains.json")["rules"][0]
            unknown = audit.load(root / "audit/unverified-domains.json")["rules"][0]
            self.assertEqual(foreign["domain_suffix"], ["foreign.example.com"])
            self.assertNotIn(".ru", unknown["domain_suffix"])
            self.assertNotIn(".su", unknown["domain_suffix"])
            self.assertNotIn(".xn--p1ai", unknown["domain_suffix"])
            self.assertIn("unknown.example.com", unknown["domain_suffix"])
            self.assertEqual(audit.load(root / "audit/foreign-ip.json")["rules"][0]["ip_cidr"], ["1.2.3.0/24"])


    def test_whois_blank_org_does_not_consume_next_field(self):
        empty = "domain: example.ru\norg:\ntaxpayer-id: 12345\nregistrar: TEST\n"
        with patch.object(audit, "query_whois", return_value=empty):
            result = audit.query_domain("sub.example.ru", {})
        self.assertEqual(result["status"], "unverified")
        self.assertNotIn("organization", result)

        filled = "domain: example.ru\norg: LLC Example\ntaxpayer-id: 12345\n"
        with patch.object(audit, "query_whois", return_value=filled):
            result = audit.query_domain("sub.example.ru", {})
        self.assertEqual(result["organization"], "LLC Example")
        self.assertEqual(result["status"], "unverified")

    def test_http_400_on_subdomain_tries_parent(self):
        from urllib.error import HTTPError
        with patch.object(audit, "fetch_json", side_effect=[
            HTTPError("https://rdap.example/domain/sub.example.com", 400, "invalid", None, None),
            {"entities": []}
        ]) as request:
            result = audit.query_domain("sub.example.com", {"com": "https://rdap.example"})
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["queried"], "example.com")
        self.assertEqual(result["status"], "unverified")

if __name__ == "__main__":
    unittest.main()
