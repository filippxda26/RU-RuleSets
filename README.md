# RU-RuleSets

GeoIP and GeoSite rule sets for sing-box.

## Automatically refresh RU GeoIP

The existing build workflow imports the Russian IPv4 and IPv6 address ranges
from https://suip.biz/?act=all-country-ip&country=RU&all on Mondays at
03:37 UTC. It can also be started manually via Actions > Build RU sing-box
rule sets > Run workflow.

The updater downloads SUIP's full plain-text range list, converts it to CIDR,
merges overlapping networks and updates geoip/ru.json. IPs newly classified
as Russian by SUIP are added; IPs missing from its latest database are removed.
Then geoip/ru.srs and geosite/ru.srs are rebuilt and changes are committed.

If the download fails, contains invalid data or lacks either IP version, the
update stops. To prevent mass accidental deletion, at least 80% of the prior
IPv4 AND IPv6 address space must remain covered. Run
python3 scripts/update_geoip.py --dry-run to preview changes.

Note: SUIP is a geographic IP database, NOT proof of legal ownership by a
Russian organization. The GeoSite list is unchanged by this automation.
