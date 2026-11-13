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
            audit.write(root / "audit/cache.json", {"domain_suffix:foreign.example.com": {"status": "foreign", "organization": "Example", "country": "US", "source": "registry", "audit_version": audit.AUDIT_SCHEMA_VERSION}, "ip:1.2.3.0/24": {"status": "foreign", "organization": "Example", "country": "US", "source": "registry", "audit_version": audit.AUDIT_SCHEMA_VERSION}})
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

    def test_http_400_on_public_suffix_tries_registered_domain(self):
        from urllib.error import HTTPError
        with patch.object(audit, "fetch_json", side_effect=[
            HTTPError("https://rdap.example/domain/co.uk", 400, "invalid", None, None),
            {"entities": []}
        ]) as request:
            result = audit.query_domain("sub.example.co.uk", {"uk": "https://rdap.example"})
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["queried"], "example.co.uk")
        self.assertEqual(result["status"], "unverified")


    def test_rdap_ripe_organisation_fn_handle(self):
        org = {"roles": ["registrant"], "handle": "ORG-SOME1-RIPE", "vcardArray": ["vcard", [
            ["fn", {}, "text", "Actual Network Ltd"],
            ["adr", {"cc": "GB"}, "text", ["", "", "", "London", "", "", ""]]
        ]]}
        self.assertEqual(audit.classify_rdap({"entities": [org]}, "mock")["status"], "foreign")
        org["vcardArray"][1][1][1] = {}
        result = audit.classify_rdap({"entities": [org]}, "mock")
        self.assertEqual(result["status"], "unverified")
        self.assertEqual(result["organization"], "Actual Network Ltd")

    def test_network_geolocation_is_not_holder_country(self):
        item = {"startAddress": "198.51.100.0", "endAddress": "198.51.100.255", "country": "RU", "name": "SAMPLE", "entities": []}
        with patch.object(audit, "fetch_json", return_value=item):
            value = audit.query_network("198.51.100.0/24")
        self.assertEqual(value["status"], "unverified")
        self.assertEqual(value["network_country_hint"], "RU")

    def test_network_partial_registration_cannot_classify_entire_cidr(self):
        entity = {"roles": ["registrant"], "vcardArray": ["vcard", [
            ["org", {}, "text", "Example Ltd"],
            ["adr", {"cc": "GB"}, "text", ["", "", "", "", "", "", "GB"]]
        ]]}
        item = {"startAddress": "198.51.100.0", "endAddress": "198.51.100.127", "entities": [entity]}
        with patch.object(audit, "fetch_json", return_value=item):
            value = audit.query_network("198.51.100.0/24")
        self.assertEqual(value["status"], "unverified")
        self.assertEqual(value["organization"], "Example Ltd")
        self.assertIn("entire CIDR", value["reason"])

    def test_whois_ignores_registrar_organization_after_domain_record(self):
        raw = ("domain: EXAMPLE.RU\r\norg: \r\nregistrar: SOME-RU\r\nsource: TCI\r\n\r\n"
               "nic-hdl: SOME-RU\r\norg: Registrar Company\r\nsource: TCI\r\n")
        with patch.object(audit, "query_whois", return_value=raw) as call:
            result = audit.query_domain("deep.sub.example.ru", {})
        self.assertEqual(result["status"], "unverified")
        self.assertNotIn("organization", result)
        self.assertEqual(result["queried"], "example.ru")
        call.assert_called_once_with("example.ru")

    def test_whois_memo_prevents_duplicate_queries(self):
        raw = "domain: EXAMPLE.RU\norg: Ltd Example\nsource: TCI\n"
        with patch.object(audit, "query_whois", return_value=raw) as call:
            memo = {}
            first = audit.query_domain("one.example.ru", {}, memo)
            second = audit.query_domain("two.example.ru", {}, memo)
        call.assert_called_once_with("example.ru")
        self.assertEqual(first["organization"], second["organization"])

    def test_invalid_manual_evidence_cannot_override(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit.write(root / "geosite/ru.json", audit.rules({"domain": [], "domain_suffix": [".ru", "sample.example"]}))
            audit.write(root / "geoip/ru.json", audit.rules({"ip_cidr": []}))
            audit.write(root / "audit/manual-evidence.json", {"domain_suffix:sample.example": {
                "status": "russian", "organization": "Sample foreign LLC", "country": "US", "source": "https://example.org/filing"
            }})
            audit.run(root, 0, 0, 0, offline=True)
            result = audit.load(root / "audit/unverified-domains.json")
            self.assertEqual(result["rules"][0]["domain_suffix"], ["sample.example"])

    def test_old_cache_is_not_trusted_for_classification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit.write(root / "geosite/ru.json", audit.rules({"domain": [], "domain_suffix": [".ru", "sample.example"]}))
            audit.write(root / "geoip/ru.json", audit.rules({"ip_cidr": []}))
            audit.write(root / "audit/cache.json", {"domain_suffix:sample.example": {
                "status": "foreign", "organization": "Unknown", "country": "US", "source": "legacy cache"
            }})
            audit.run(root, 0, 0, 0, offline=True)
            result = audit.load(root / "audit/foreign-domains.json")
            self.assertEqual(result["rules"][0]["domain_suffix"], [])

if __name__ == "__main__":
    unittest.main()
