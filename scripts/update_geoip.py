#!/usr/bin/env python3
"""Refresh Russian GeoIP geolocation networks using SUIP (not a proof of ownership)."""
from __future__ import annotations
import argparse
import ipaddress
import json
import sys
import time
import urllib.request
from pathlib import Path

SOURCE_URL = "https://suip.biz/?act=all-country-ip&all-download=&country=RU"
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024
MIN_SOURCE_LINES = 10000
MIN_NETWORKS = {4: 2000, 6: 2000}
MIN_RETAINED = 0.80
# Use only the requested /22 inside the previously pinned /14.
PINNED_CIDR = "85.175.96.0/22"
PINNED_NETWORK = ipaddress.ip_network(PINNED_CIDR)
EXCLUDED_SUPERNET = ipaddress.ip_network("85.175.0.0/14", strict=False)
FOREIGN_EXCLUSIONS_PATH = Path("geoip/foreign-company-exclusions.txt")

def download():
    req = urllib.request.Request(
        SOURCE_URL, headers={"User-Agent": "RU-RuleSets/1.0 (GitHub Actions updater)"}
    )
    error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                if resp.status != 200:
                    raise ValueError(f"HTTP {resp.status}")
                data = resp.read(MAX_DOWNLOAD_BYTES + 1)
                if len(data) > MAX_DOWNLOAD_BYTES:
                    raise ValueError("Download larger than 8 MiB")
                return data.decode("utf-8-sig")
        except (OSError, ValueError, UnicodeError) as exc:
            error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed downloading SUIP: {error}")

def parse_ranges(text):
    lines = [s.strip() for s in text.splitlines() if s.strip()]
    if len(lines) < MIN_SOURCE_LINES:
        raise ValueError(f"Suspected incomplete SUIP data: {len(lines)} lines")
    result = {4: [], 6: []}
    for number, line in enumerate(lines, 1):
        try:
            if "-" in line:
                start, end = map(lambda s: ipaddress.ip_address(s.strip()), line.split("-", 1))
                if start.version != end.version or start > end:
                    raise ValueError("invalid order or mixed versions")
                networks = ipaddress.summarize_address_range(start, end)
            else:
                networks = [ipaddress.ip_network(line, strict=True)]
            for network in networks:
                if network.is_global:
                    result[network.version].append(network)
        except ValueError as exc:
            raise ValueError(f"Bad SUIP line {number}: {line!r}: {exc}") from exc
    for version in (4, 6):
        result[version] = list(ipaddress.collapse_addresses(result[version]))
        if len(result[version]) < MIN_NETWORKS[version]:
            raise ValueError(f"Suspected incomplete IPv{version} data: {len(result[version])} CIDRs")
    return result

def apply_pinned_ipv4(networks):
    """Replace the broad 85.172.0.0/14 coverage with only 85.175.96.0/22."""
    kept = []
    for network in networks:
        if not network.overlaps(EXCLUDED_SUPERNET):
            kept.append(network)
        elif EXCLUDED_SUPERNET.subnet_of(network) and network != EXCLUDED_SUPERNET:
            kept.extend(network.address_exclude(EXCLUDED_SUPERNET))
    return list(ipaddress.collapse_addresses([*kept, PINNED_NETWORK]))



def load_foreign_exclusions(path):
    """Read permanent foreign registrant exclusions, failing closed if missing."""
    exclusions = {4: [], 6: []}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            network = ipaddress.ip_network(line, strict=True)
        except ValueError as exc:
            raise ValueError(f"Bad foreign exclusion on line {number}: {line!r}") from exc
        if not network.is_global:
            raise ValueError(f"Foreign exclusion is not global: {line}")
        exclusions[network.version].append(network)
    return {version: list(ipaddress.collapse_addresses(exclusions[version])) for version in (4, 6)}


def apply_foreign_exclusions(networks, exclusions):
    """Subtract excluded networks, even when SUIP returns a broader subnet."""
    cleaned = {4: [], 6: []}
    for version in (4, 6):
        for network in networks[version]:
            parts = [network]
            for excluded in exclusions[version]:
                remaining = []
                for part in parts:
                    if not part.overlaps(excluded):
                        remaining.append(part)
                    elif part.subnet_of(excluded):
                        continue
                    else:
                        remaining.extend(part.address_exclude(excluded))
                parts = remaining
                if not parts:
                    break
            cleaned[version].extend(parts)
        cleaned[version] = list(ipaddress.collapse_addresses(cleaned[version]))
    return cleaned


def current_ranges(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or len(data.get("rules", [])) != 1:
        raise ValueError("Unexpected sing-box JSON")
    groups = {4: [], 6: []}
    for value in data["rules"][0]["ip_cidr"]:
        net = ipaddress.ip_network(value, strict=True)
        groups[net.version].append(net)
    return {v: list(ipaddress.collapse_addresses(groups[v])) for v in (4, 6)}

def covered_addresses(before, after):
    old = [(int(n.network_address), int(n.broadcast_address)) for n in before]
    new = [(int(n.network_address), int(n.broadcast_address)) for n in after]
    total = sum(b - a + 1 for a, b in old)
    retained = 0
    i = j = 0
    while i < len(old) and j < len(new):
        a, b = old[i]
        c, d = new[j]
        retained += max(0, min(b, d) - max(a, c) + 1)
        if b < d:
            i += 1
        else:
            j += 1
    return retained, total

def refresh(path, source, dry_run=False, exclusions_file=FOREIGN_EXCLUSIONS_PATH):
    old, new = current_ranges(path), parse_ranges(source)
    new[4] = apply_pinned_ipv4(new[4])
    new = apply_foreign_exclusions(new, load_foreign_exclusions(exclusions_file))
    for version in (4, 6):
        kept, total = covered_addresses(old[version], new[version])
        ratio = kept / total if total else 0
        print(f"IPv{version}: old={len(old[version])}; new={len(new[version])}; retained={ratio:.2%}")
        if ratio < MIN_RETAINED:
            raise ValueError(f"Refusing excessive IPv{version} deletion ({ratio:.1%} retained)")
    cidrs = [str(n) for v in (4, 6) for n in new[v]]
    content = json.dumps({"version": 1, "rules": [{"ip_cidr": cidrs}]}, separators=(",", ":"))
    if path.read_text(encoding="utf-8") == content:
        print("GeoIP unchanged")
        return False
    if dry_run:
        print(f"Would update {path} with {len(cidrs)} CIDRs")
    else:
        path.write_text(content, encoding="utf-8")
        print(f"Updated {path} with {len(cidrs)} CIDRs")
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, default=Path("geoip/ru.json"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--foreign-exclusions", type=Path, default=FOREIGN_EXCLUSIONS_PATH)
    args = parser.parse_args()
    try:
        refresh(args.file, download(), dry_run=args.dry_run, exclusions_file=args.foreign_exclusions)
        return 0
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(f"SUIP refresh aborted: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
