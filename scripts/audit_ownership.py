#!/usr/bin/env python3
"""Incrementally audit rule ownership using registry data; never mutate active rules."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ZONE_EXCEPTIONS = {"ru", "su", "xn--p1ai", ".ru", ".su", ".xn--p1ai"}
WHOIS_TLDS = {"ru", "su", "xn--p1ai"}
RU_COUNTRIES = {"RU", "RUSSIAN FEDERATION", "RUSSIA"}
USER_AGENT = "RU-RuleSets ownership-audit/1.1 (registry verification)"
AUDIT_SCHEMA_VERSION = 4


def load(path, default=None):
    if not path.exists():
        return {} if default is None else default
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def fetch_json(url):
    request = Request(url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT})
    with urlopen(request, timeout=15) as response:
        return json.load(response)


def rdap_dns_services():
    data = fetch_json("https://data.iana.org/rdap/dns.json")
    services = {}
    for zones, urls in data.get("services", []):
        if urls:
            for zone in zones:
                services[zone.lower()] = urls[0]
    return services


def entity_owner(data):
    """Read only registrant/holder entities, never registrar or network geography.

    A RIPE ORGANISATION can have an ORG-* handle and a jCard "fn" instead
    of "org". A countryless name is useful evidence but cannot establish
    whether an entity belongs to a Russian or foreign jurisdiction.
    """
    fallback = None
    for entity in data.get("entities", []):
        if not isinstance(entity, dict) or not {"registrant", "holder"}.intersection(entity.get("roles", [])):
            continue
        card = entity.get("vcardArray")
        props = card[1] if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list) else []
        org = fn = country = None
        for item in props:
            if not isinstance(item, list) or len(item) < 4:
                continue
            key, params, _, value = item[:4]
            if key == "org" and isinstance(value, str):
                org = value.strip()
            elif key == "fn" and isinstance(value, str):
                fn = value.strip()
            elif key == "adr":
                if isinstance(params, dict) and params.get("cc"):
                    country = str(params["cc"]).strip().upper()
                elif isinstance(value, list) and value and value[-1]:
                    country = str(value[-1]).strip().upper()
        if not org and str(entity.get("handle", "")).upper().startswith("ORG-"):
            org = fn
        if not org:
            continue
        if country in RU_COUNTRIES or (country and re.fullmatch(r"[A-Z]{2}", country) and country not in {"ZZ", "EU", "UN", "AP"}):
            return org, country
        fallback = (org, None)
    return fallback or (None, None)


def classify_rdap(data, source):
    owner, country = entity_owner(data)
    status = "russian" if country in RU_COUNTRIES else "foreign" if country else "unverified"
    return {"status": status, "organization": owner, "country": country, "source": source}



def query_whois(domain):
    """The authoritative .RU/.SU/.РФ WHOIS; collect organizations only."""
    with socket.create_connection(("whois.tcinet.ru", 43), timeout=10) as connection:
        connection.settimeout(10)
        connection.sendall((domain + "\r\n").encode("ascii"))
        data = bytearray()
        while len(data) < 65536:
            block = connection.recv(4096)
            if not block:
                break
            data.extend(block)
    return data.decode("utf-8", "replace")


def query_domain(name, services, memo=None):
    ascii_name = name.strip(".").encode("idna").decode("ascii").lower()
    pieces = ascii_name.split(".")
    if len(pieces) < 2:
        return {"status": "unverified", "source": "TLD (preserved)"}
    tld = pieces[-1]
    memo = {} if memo is None else memo
    # Prefer shorter registered parents to avoid querying every subdomain.
    # Multi-level public suffixes will return 404 and we continue with more labels.
    for size in range(2, len(pieces) + 1):
        candidate = ".".join(pieces[-size:])
        if candidate in memo:
            cached = memo[candidate]
            if cached is None:
                continue
            return dict(cached)
        if tld in WHOIS_TLDS:
            try:
                raw = query_whois(candidate)
            except (OSError, UnicodeError) as exc:
                result = {"status": "unverified", "source": "whois.tcinet.ru", "error": str(exc)[:160]}
                memo[candidate] = result
                return result
            # WHOIS can contain a separate organisation belonging to the REGISTRAR.
            # Only fields in the domain object (before the first 'source:') count.
            first = re.split(r"(?im)^source:[ \t]*TCI[ \t]*\r?$", raw, maxsplit=1)[0]
            match_domain = re.search(r"(?im)^domain:[ \t]*(\S+)[ \t]*\r?$", first)
            if not match_domain or match_domain[1].lower().rstrip(".") != candidate:
                memo[candidate] = None
                continue
            match_org = re.search(r"(?im)^org:[ \t]*(.*?)\r?$", first)
            result = {"status": "unverified", "source": "whois.tcinet.ru", "queried": candidate}
            if match_org and match_org[1].strip():
                result["organization"] = match_org[1].strip()
            memo[candidate] = result
            return dict(result)
        base = services.get(tld)
        if not base:
            return {"status": "unverified", "source": "IANA: no RDAP endpoint", "queried": candidate}
        url = base.rstrip("/") + "/domain/" + quote(candidate, safe="")
        try:
            data = fetch_json(url)
        except HTTPError as exc:
            if exc.code in (400, 404):
                memo[candidate] = None
                continue
            result = {"status": "unverified", "source": url, "error": "HTTP " + str(exc.code)}
            memo[candidate] = result
            return dict(result)
        except (OSError, ValueError, URLError) as exc:
            result = {"status": "unverified", "source": url, "error": str(exc)[:160]}
            memo[candidate] = result
            return dict(result)
        result = classify_rdap(data, url)
        result["queried"] = candidate
        memo[candidate] = result
        return dict(result)
    return {"status": "unverified", "source": "no domain registration found"}


def ripe_organisation(handle, memo=None):
    """Get the explicit country of a RIPE resource-holder ORGANISATION object.

    A network's country, routing ASN and administrative contacts are not legal
    owner evidence. RIPE NCC itself is the registry, not the downstream holder.
    """
    handle = str(handle).upper()
    if not re.fullmatch(r"ORG-[A-Z0-9-]+-RIPE", handle) or handle == "ORG-NCC1-RIPE":
        return None
    memo = {} if memo is None else memo
    if handle in memo:
        return memo[handle]
    url = "https://rest.db.ripe.net/ripe/organisation/" + quote(handle, safe="") + ".json"
    memo[handle] = None
    try:
        payload = fetch_json(url)
    except (OSError, ValueError, URLError, HTTPError):
        return None
    objects = payload.get("objects", {}).get("object", [])
    if not isinstance(objects, list):
        return None
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "organisation":
            continue
        attrs = obj.get("attributes", {}).get("attribute", [])
        if not isinstance(attrs, list):
            continue
        fields = {str(a.get("name", "")).lower(): a.get("value") for a in attrs if isinstance(a, dict)}
        if str(fields.get("organisation", "")).upper() != handle:
            continue
        if str(fields.get("org-type", "")).upper() == "RIR":
            return None
        country = str(fields.get("country") or "").strip().upper()
        name = str(fields.get("org-name") or "").strip()
        if not name or not country:
            return None
        if country not in RU_COUNTRIES and (
            not re.fullmatch(r"[A-Z]{2}", country) or country in {"ZZ", "EU", "UN", "AP"}
        ):
            return None
        result = {"organization": name, "country": country, "owner_source": url}
        memo[handle] = result
        return result
    return None


def query_network(cidr, org_memo=None):
    # RIPE redirects to the authoritative RIR for resources outside RIPE.
    url = "https://rdap.db.ripe.net/ip/" + quote(cidr, safe="/:")
    try:
        data = fetch_json(url)
        result = classify_rdap(data, url)
        # Country of the IP network is not the registered organisation country.
        if data.get("country"):
            result["network_country_hint"] = data["country"]
        if data.get("name"):
            result["network_name_hint"] = data["name"]
        start, end = data.get("startAddress"), data.get("endAddress")
        if start and end:
            requested = ipaddress.ip_network(cidr)
            first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
            if first.version != requested.version or not (first <= requested.network_address and last >= requested.broadcast_address):
                result["status"] = "unverified"
                result["reason"] = "RDAP registration does not cover entire CIDR"
        else:
            result["status"] = "unverified"
            result["reason"] = "RDAP registration range missing"
        # Only enrich a full-range registration with an explicit organisation
        # reference. Don't infer ownership from network name or country.
        if result["status"] == "unverified" and "reason" not in result:
            for entity in data.get("entities", []):
                if not isinstance(entity, dict):
                    continue
                if not {"registrant", "holder"}.intersection(entity.get("roles", [])):
                    continue
                evidence = ripe_organisation(entity.get("handle"), org_memo)
                if evidence:
                    result.update(evidence)
                    result["status"] = "russian" if evidence["country"] in RU_COUNTRIES else "foreign"
                    break
    except (OSError, ValueError, URLError) as exc:
        result = {"status": "unverified", "source": url, "error": str(exc)[:160]}
    return result



def rules(items):
    return {"version": 1, "rules": [items]}


def run(root, max_domains, max_ips, delay, offline=False):
    root = Path(root)
    geosite = load(root / "geosite/ru.json")["rules"][0]
    networks = load(root / "geoip/ru.json")["rules"][0]["ip_cidr"]
    domains = [(kind, domain) for kind in ("domain", "domain_suffix") for domain in geosite.get(kind, [])]
    audited = [item for item in domains if item[1].lower() not in ZONE_EXCEPTIONS]
    cache_path = root / "audit/cache.json"
    cache = load(cache_path)
    manual = load(root / "audit/manual-evidence.json")
    now = int(time.time())

    def status_for(key):
        proof = manual.get(key)
        if isinstance(proof, dict):
            country = str(proof.get("country", "")).strip().upper()
            expected = "russian" if country in RU_COUNTRIES else "foreign" if re.fullmatch(r"[A-Z]{2}", country) and country not in {"ZZ", "EU", "UN", "AP"} else None
            if (expected and proof.get("status") == expected and
                    isinstance(proof.get("organization"), str) and proof["organization"].strip() and
                    isinstance(proof.get("source"), str) and proof["source"].startswith("https://")):
                return expected
        entry = cache.get(key, {})
        if entry.get("audit_version") == AUDIT_SCHEMA_VERSION:
            return entry.get("status", "unverified")
        return "unverified"

    services = {}
    if not offline and max_domains > 0:
        try:
            services = rdap_dns_services()
        except (OSError, ValueError, URLError) as exc:
            print(f"IANA bootstrap unavailable: {exc}; .ru/.su/.рф WHOIS remains enabled")

    def needs_check(key):
        entry = cache.get(key)
        return (not entry or bool(entry.get("error")) or
                entry.get("audit_version") != AUDIT_SCHEMA_VERSION or
                now - entry.get("checked_at", 0) > 45 * 86400)
    count_domain = count_ip = 0
    org_memo = {}
    domain_memo = {}
    for kind, domain in audited:
        key = kind + ":" + domain
        if not offline and count_domain < max_domains and needs_check(key):
            cache[key] = query_domain(domain, services, domain_memo)
            cache[key]["checked_at"] = now
            cache[key]["audit_version"] = AUDIT_SCHEMA_VERSION
            count_domain += 1
            if delay:
                time.sleep(delay)
    for cidr in networks:
        key = "ip:" + cidr
        if not offline and count_ip < max_ips and needs_check(key):
            cache[key] = query_network(cidr, org_memo)
            cache[key]["checked_at"] = now
            cache[key]["audit_version"] = AUDIT_SCHEMA_VERSION
            count_ip += 1
            if delay:
                time.sleep(delay)
    domain_foreign = {"domain": [], "domain_suffix": []}
    domain_unknown = {"domain": [], "domain_suffix": []}
    for kind, domain in audited:
        state = status_for(kind + ":" + domain)
        if state == "foreign":
            domain_foreign[kind].append(domain)
        elif state != "russian":
            domain_unknown[kind].append(domain)
    ip_foreign, ip_unknown = [], []
    for cidr in networks:
        state = status_for("ip:" + cidr)
        if state == "foreign":
            ip_foreign.append(cidr)
        elif state != "russian":
            ip_unknown.append(cidr)
    audit = root / "audit"
    write(cache_path, cache)
    write(audit / "foreign-domains.json", rules(domain_foreign))
    write(audit / "unverified-domains.json", rules(domain_unknown))
    write(audit / "foreign-ip.json", rules({"ip_cidr": ip_foreign}))
    write(audit / "unverified-ip.json", rules({"ip_cidr": ip_unknown}))
    checked_domains = sum(1 for kind, domain in audited if kind + ":" + domain in cache or kind + ":" + domain in manual)
    checked_ips = sum(1 for cidr in networks if "ip:" + cidr in cache or "ip:" + cidr in manual)
    russian_domains = sum(1 for kind, domain in audited if status_for(kind + ":" + domain) == "russian")
    russian_ips = sum(1 for cidr in networks if status_for("ip:" + cidr) == "russian")
    print(f"Registry checks this run: domains={count_domain}, CIDRs={count_ip}")
    print(f"Cached or documented: domains={checked_domains}/{len(audited)}, CIDRs={checked_ips}/{len(networks)}")
    print(f"Ownership statuses: Russian domains={russian_domains}, foreign domains={sum(map(len,domain_foreign.values()))}; Russian CIDRs={russian_ips}, foreign CIDRs={len(ip_foreign)}")
    print(f"Unverified (including not yet checked): domains={sum(map(len,domain_unknown.values()))}, CIDRs={len(ip_unknown)}. Active rules unchanged.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--max-domains", type=int, default=50)
    parser.add_argument("--max-ips", type=int, default=200)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--offline", action="store_true")
    options = parser.parse_args()
    if options.max_domains < 0 or options.max_ips < 0 or options.delay < 0:
        parser.error("limits and delay must be non-negative")
    run(options.root, options.max_domains, options.max_ips, options.delay, options.offline)


if __name__ == "__main__":
    main()
