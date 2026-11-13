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
USER_AGENT = "RU-RuleSets ownership-audit/1.0 (registry verification)"


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
    """A registrar, abuse contact, network's geography are never proof of owner."""
    for entity in data.get("entities", []):
        if not {"registrant", "holder"}.intersection(entity.get("roles", [])):
            continue
        vcard = entity.get("vcardArray", [None, []])
        properties = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        organization = None
        country = None
        for item in properties:
            if not isinstance(item, list) or len(item) < 4:
                continue
            if item[0] == "org" and isinstance(item[3], str):
                organization = item[3].strip()
            if item[0] == "adr":
                value = item[3]
                if isinstance(value, list) and value:
                    country = str(value[-1]).strip().upper()
                if isinstance(item[1], dict) and item[1].get("cc"):
                    country = str(item[1]["cc"]).strip().upper()
        if organization and country and (country in RU_COUNTRIES or (re.fullmatch(r"[A-Z]{2}", country) and country not in {"ZZ", "EU", "UN", "AP"})):
            return organization, country
    return None, None


def classify_rdap(data, source):
    owner, country = entity_owner(data)
    state = "unverified"
    if owner and country:
        state = "russian" if country in RU_COUNTRIES else "foreign"
    return {"status": state, "organization": owner, "country": country, "source": source}


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


def query_domain(name, services):
    ascii_name = name.strip(".").encode("idna").decode("ascii").lower()
    pieces = ascii_name.split(".")
    tld = pieces[-1]
    if len(pieces) < 2:
        return {"status": "unverified", "source": "TLD (preserved)"}
    # RDAP/WHOIS do not usually resolve subdomains. Walk toward their registered parent.
    for size in range(len(pieces), 1, -1):
        candidate = ".".join(pieces[-size:])
        if tld in WHOIS_TLDS:
            try:
                raw = query_whois(candidate)
            except (OSError, UnicodeError) as exc:
                return {"status": "unverified", "source": "whois.tcinet.ru", "error": str(exc)[:160]}
            match = re.search(r"^org:[ \t]*(\S[^\n]*)$", raw, re.M | re.I)
            if match:
                # WHOIS provides an organisation but not its legal country.
                return {"status": "unverified", "organization": match[1].strip(), "source": "whois.tcinet.ru", "queried": candidate}
            if re.search(r"^(person|registrar):", raw, re.M | re.I):
                return {"status": "unverified", "source": "whois.tcinet.ru", "queried": candidate}
            continue
        base = services.get(tld)
        if not base:
            return {"status": "unverified", "source": "IANA: no RDAP endpoint", "queried": candidate}
        url = base.rstrip("/") + "/domain/" + quote(candidate, safe="")
        try:
            data = fetch_json(url)
        except HTTPError as exc:
            if exc.code in (400, 404):
                continue
            return {"status": "unverified", "source": url, "error": "HTTP " + str(exc.code)}
        except (OSError, ValueError, URLError) as exc:
            return {"status": "unverified", "source": url, "error": str(exc)[:160]}
        result = classify_rdap(data, url)
        result["queried"] = candidate
        return result
    return {"status": "unverified", "source": "no domain registration found"}


def query_network(cidr):
    # RIPE's RDAP service redirects non-RIPE resources to the authoritative RIR.
    url = "https://rdap.db.ripe.net/ip/" + quote(cidr, safe="/:")
    try:
        data = fetch_json(url)
        result = classify_rdap(data, url)
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
        if isinstance(proof, dict) and proof.get("status") in {"foreign", "russian"} and proof.get("organization") and proof.get("country") and str(proof.get("source", "")).startswith("https://"):
            return proof["status"]
        return cache.get(key, {}).get("status", "unverified")

    services = {}
    if not offline and max_domains > 0:
        try:
            services = rdap_dns_services()
        except (OSError, ValueError, URLError) as exc:
            print(f"IANA bootstrap unavailable: {exc}")
            max_domains = 0

    def needs_check(key):
        entry = cache.get(key)
        if not entry:
            return True
        # A prior parser mistakenly swallowed the next line after an empty "org:".
        if entry.get("source") == "whois.tcinet.ru" and entry.get("organization") == "taxpayer-id:":
            return True
        return now - entry.get("checked_at", 0) > 45 * 86400

    count_domain = count_ip = 0
    for kind, domain in audited:
        key = kind + ":" + domain
        if not offline and count_domain < max_domains and needs_check(key):
            cache[key] = query_domain(domain, services)
            cache[key]["checked_at"] = now
            count_domain += 1
            if delay:
                time.sleep(delay)
    for cidr in networks:
        key = "ip:" + cidr
        if not offline and count_ip < max_ips and needs_check(key):
            cache[key] = query_network(cidr)
            cache[key]["checked_at"] = now
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
