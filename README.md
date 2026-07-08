# IP Reputation Engine

A CLI tool that scores public IPv4 addresses using 10 data sources across 5
dimensions — modeled after how major firewalls (Palo Alto PAN-DB, Fortinet,
Cisco Talos) evaluate IP reputation from public information, **without** port
scanning.

## Quick Start

```bash
pip install requests
python3 ip_reputation.py 8.8.8.8            # Google DNS
python3 ip_reputation.py 8.8.8.8 --source-country DE
```

## API Keys (optional)

The tool works without any keys using free public APIs.  For deeper threat
intelligence, register at these services and store your keys in a `.env` file:

```bash
cp .env.example .env
# Edit .env with your keys
```

### Supported keys

| Service       | Env var          | Free tier                    |
|---------------|------------------|------------------------------|
| AbuseIPDB     | `ABUSEIPDB_KEY`  | 1,000 checks/day             |
| ipinfo.io     | `IPINFO_TOKEN`   | 50,000 requests/month        |
| AlienVault OTX| `OTX_KEY`        | Unlimited                    |
| MaxMind GeoLite2 | `MAXMIND_KEY` | Free account required        |

Keys can also be passed via CLI flags (`--abuseipdb-key`, etc.) or real
environment variables.  The **precedence order** is:

1. CLI flags (highest)
2. Real environment variables
3. `.env` file (lowest)

## Traceroute via Globalping

Traceroute runs through [Globalping](https://globalping.io/), a free distributed
probe network with 4,800+ probes worldwide.  No root/sudo needed, works on any
platform.

- If `--source-country DE` is set, the probe originates from Germany — giving you
  the actual route a German user would see.
- Without `--source-country`, a random global probe is used.
- Rate limit: 500 tests/hour (registered).  Lower when unauthenticated.
- Enabled with `--traceroute` (skipped by default to avoid the ~5-15s poll delay).

### Why Globalping?

| | Local `traceroute` | Globalping |
|---|---|---|
| Requires root on macOS | ✅ yes | ❌ no |
| Route from source country | ❌ impossible | ✅ built-in |
| Cross-platform | ❌ macOS-only quirks | ✅ HTTP API |
| Realistic routing | ❌ your machine's ISP | ✅ local ISP in target country |

## Options

```
python3 ip_reputation.py <IP> [options]

  --source-country, -s CC    Your country code (DE, US, CN).  Enables
                             source-location consistency check.
  --traceroute               Enable traceroute via Globalping's distributed
                             probe network (free, no root required).
                             Originates from --source-country if provided.
  --json FILE                Export full report as JSON.
  --abuseipdb-key KEY        AbuseIPDB API key.
  --ipinfo-key TOKEN         ipinfo.io API token.
  --otx-key KEY              AlienVault OTX API key.
  --maxmind-key KEY          MaxMind GeoLite2 license key.
```

## Data Sources

| # | Source             | Free | What it provides                     |
|---|--------------------|------|--------------------------------------|
| 1 | ip-api.com         | Yes  | Geolocation, ISP, ASN, privacy flags |
| 2 | Team Cymru (whois) | Yes  | BGP ASN, prefix, allocation date     |
| 3 | RIPEstat           | Yes  | RPKI validation, BGP visibility, abuse contacts |
| 4 | System whois       | Yes  | Registration details, RegDate        |
| 5 | System DNS         | Yes  | PTR record, FCrDNS verification      |
| 6 | GreyNoise Community| Yes  | Scan classification (25 req/week)    |
| 7 | AbuseIPDB          | Key  | Abuse confidence score, report count |
| 8 | AlienVault OTX     | Key  | Threat pulses, malware associations  |
| 9 | ipinfo.io          | Key  | Supplemental geo + privacy flags     |
|10 | Globalping         | Yes  | Hop count, latency, routing loops, loss rate |

## Scoring Dimensions (100 total)

| Dimension               | Max | What it measures                              |
|--------------------------|-----|-----------------------------------------------|
| Registration & Entity   | 30  | ASN type, allocation age, FCrDNS, RPKI, abuse contact, BGP visibility |
| Geo-Registration Consistency | 25 | IP geo vs BGP registration country, privacy flags, high-risk country |
| Source-Location Consistency | 15 | Source country vs IP geo vs BGP origin — **three-way** consistency check |
| Traceroute Quality      | 15  | Hop count, latency, packet loss, routing loops |
| Threat Intelligence      | 20  | GreyNoise, AbuseIPDB, OTX pulses and malware  |

## Grade Scale

| Grade | Score | Meaning                        |
|-------|-------|--------------------------------|
| A     | 80+   | Excellent — clean, established |
| B     | 65-79 | Good — minor flags             |
| C     | 50-64 | Caution — notable concerns     |
| D     | 35-49 | Suspicious — multiple warnings |
| F     | <35   | High risk — likely malicious   |

## Example Output

```
$ python3 ip_reputation.py 8.8.8.8 --source-country US

  ── IP Reputation Report ──────────────────────────────────
  IP: 8.8.8.8  |  Score: 80/100  |  Grade: A
  ──────────────────────────────────────────────────────────

  Registration & Entity      [███████████████████████████ ]  28/30
  Geo-Registration           [████████████████████████    ]  22/25
  Source-Location            [█████████████████           ]  15/15
  Traceroute                 [████████                    ]   8/15
  Threat Intelligence        [███████████                 ]  11/20

  + source (US) matches IP geolocation (US)
  + source (US) matches BGP registration (US)
  + Google — established ISP
```
