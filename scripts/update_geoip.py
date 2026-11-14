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
PINNED_RU_IPV4 = ipaddress.ip_network("85.175.96.0/22")

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

def preserve_pinned_ipv4(networks):
    """Preserve the exact user-requested /22 even inside a SUIP supernet."""
    merged = list(ipaddress.collapse_addresses([*networks, PINNED_RU_IPV4]))
    result = []
    for network in merged:
        if PINNED_RU_IPV4.subnet_of(network) and network != PINNED_RU_IPV4:
            result.extend(network.address_exclude(PINNED_RU_IPV4))
        else:
            result.append(network)
    result.append(PINNED_RU_IPV4)
    return sorted(result, key=lambda network: (int(network.network_address), network.prefixlen))


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

def refresh(path, source, dry_run=False):
    old, new = current_ranges(path), parse_ranges(source)
    new[4] = preserve_pinned_ipv4(new[4])
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
    args = parser.parse_args()
    try:
        refresh(args.file, download(), dry_run=args.dry_run)
        return 0
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(f"SUIP refresh aborted: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
