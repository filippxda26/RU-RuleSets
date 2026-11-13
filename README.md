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

## Проверка принадлежности доменов и IP-адресов

Скрипт `scripts/audit_ownership.py` постепенно проверяет владельцев доменных
имён через RDAP (список серверов IANA) и WHOIS для .ru, .рф, .su,
а держателей IP-диапазонов — через RDAP RIPE NCC и перенаправления к
авторитетным региональным реестрам.

**Зоны `.ru`, `.рф` (в JSON: `.xn--p1ai`) и `.su` сохраняются целиком.**
Аудит не изменяет `geoip/ru.json`, `geosite/ru.json` и скомпилированные
`.srs`-файлы. Подтверждённые иностранные и не подтверждённые реестром записи
выводятся раздельно для проверки перед возможным изменением основных правил:

- `audit/foreign-domains.json`, `audit/foreign-ip.json` — записи с признаками иностранного держателя;
- `audit/unverified-domains.json`, `audit/unverified-ip.json` — неизвестные или ещё не проверенные;
- `audit/cache.json` — дата, организация, страна и URL реестрового ответа;
- `audit/manual-evidence.json` — проверенные вручную сведения из корпоративных источников.

Данные реестров не всегда показывают конечного собственника организации. Страна
IP-геолокации, страна `inetnum`, регистратор домена и владелец автономной системы
не являются доказательством юридической принадлежности. При отсутствии ясных
сведений сохраняется статус `unverified`, а не делается предположение.

Запуск (по умолчанию не более 50 доменов и 200 CIDR за один проход;
результаты кешируются на 45 дней):

```bash
python3 scripts/audit_ownership.py
python3 scripts/audit_ownership.py --offline   # только обновить отчёты по кешу
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

Для подтверждения по корпоративным данным можно заполнить
`audit/manual-evidence.json`, например:

```json
{
  "domain_suffix:example.com": {
    "status": "foreign",
    "organization": "Example Corporation",
    "country": "US",
    "source": "https://example.com/company"
  }
}
```

Здесь `example.com` — только образец формата, не результат проверки.
Поддерживаются ключи `domain:`, `domain_suffix:`, `ip:` и статусы
`russian`/`foreign`. Приоритет у ручных сведений с URL источника.
Автоматическая сборка запускает ограниченный аудит при обычном обновлении
списков. Это поэтапная проверка, а не заявление о полной проверке каждой записи.

Проверка RDAP также распознаёт организационные записи RIPE с идентификатором `ORG-*`
и полем `fn`. Для IP-сетей проверяется, покрывает ли найденная регистрационная
запись весь CIDR. Страна геолокации сети остаётся только подсказкой.
Схема кеша версионируется, поэтому старые результаты повторно проверяются;
неудачные сетевые запросы повторяются при следующем запуске.
