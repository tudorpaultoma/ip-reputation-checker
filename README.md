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
intelligence, register at these services and store your keys in a `.env` file
alongside the script:

```bash
cp .env.example .env
# Edit .env with your keys
```

### Supported keys

| Service       | Env var          | Free tier                    |
|---------------|------------------|------------------------------|
| AbuseIPDB     | `ABUSEIPDB_KEY`  | 1,000 checks/day             |
| AlienVault OTX| `OTX_KEY`        | Unlimited                    |

Keys can also be passed via CLI flags (`--abuseipdb-key`, etc.) or real
environment variables.  The **precedence order** is:

1. CLI flags (highest)
2. Real environment variables
3. `.env` file (lowest)

The `.env` file is searched first in the script's own directory, then in
ancestor directories from the current working directory.  You can also set
`SOURCE_COUNTRY` (e.g. `SOURCE_COUNTRY=DE`) in `.env`.

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
| Requires root on macOS | yes | no |
| Route from source country | impossible | built-in |
| Cross-platform | macOS-only quirks | HTTP API |
| Realistic routing | your machine's ISP | local ISP in target country |

## Options

```
python3 ip_reputation.py <IP> [options]

  --source-country, -s CC    Your country code (DE, US, CN).  Enables
                             source-location consistency check.
                             Can also be set via SOURCE_COUNTRY in .env.
  --traceroute               Enable traceroute via Globalping's distributed
                             probe network (free, no root required).
                             Originates from --source-country if provided.
  --json FILE                Export full report as JSON.
  --abuseipdb-key KEY        AbuseIPDB API key.
  --otx-key KEY              AlienVault OTX API key.
```

## Data Sources

| # | Source             | Free | What it provides                     |
|---|--------------------|------|--------------------------------------|
| 1 | ip-api.com         | Yes  | Geolocation, ISP, ASN, privacy flags |
| 2 | Team Cymru (whois) | Yes  | BGP ASN, prefix, allocation date     |
| 3 | RIPEstat           | Yes  | RPKI validation, BGP visibility + first_seen date, abuse contacts |
| 4 | System whois       | Yes  | Registration details, RegDate        |
| 5 | System DNS         | Yes  | PTR record, FCrDNS verification      |
| 6 | GreyNoise Community| Yes  | Scan classification (25 req/week)    |
| 7 | AbuseIPDB          | Key  | Abuse confidence score, report count |
| 8 | AlienVault OTX     | Key  | Threat pulses, malware associations  |
| 9 | Globalping         | Yes  | Hop count, latency, routing loops, loss rate |

## Scoring Dimensions (100 total)

| Dimension                   | Max | What it measures                                     |
|-----------------------------|-----|------------------------------------------------------|
| Registration & Entity       | 25  | ASN type, allocation age (BGP first-seen), FCrDNS, RPKI, abuse contact, BGP visibility |
| Geo & Source Consistency    | 15  | IP geo vs BGP country, source country checks, high-risk countries |
| Anonymization & Privacy     | 15  | Tor, proxy, VPN, hosting flags from PTR/ip-api/AS name |
| Traceroute Quality          |  5  | Hop count, latency, packet loss, routing loops (diagnostic only) |
| Threat Intelligence         | 40  | GreyNoise, AbuseIPDB, OTX pulses and malware |

## Scoring Logic (detailed)

Every scoring line shows explicit `(+N)` or `(-N)` values for full traceability.

### Registration & Entity (max 25, starts at 16)

| Signal | Points |
|--------|--------|
| Educational institution AS | +3 |
| Government AS | +3 |
| Corporate/enterprise AS | +2 |
| Residential/ISP AS | +2 |
| Recognized cloud provider (AWS, Azure, GCP, Tencent Cloud, Ali Cloud, Oracle Cloud, OVH) | 0 (neutral) |
| IP block established (BGP first-seen >= 15 years ago) | +6 |
| IP block established (8-14 years) | +3 |
| FCrDNS confirmed | +7 |
| RPKI valid — route origin authorized | +8 |
| Abuse contact published | +2 |
| BGP visibility >= 90% | +2 |
| | |
| Bulletproof/offshore hosting AS | -10 |
| Hosting/datacenter AS | -5 |
| IP block recently allocated (BGP first-seen <= 2 years ago) | -3 |
| IP block moderately aged (3-7 years) | -2 |
| Age unknown | -1 |
| No reverse DNS (PTR) record | -5 |
| Reverse DNS set but no FCrDNS match | -2 |
| No published abuse contact | -3 |
| RPKI invalid — possible route hijack | -15 |
| Prefix not announced in BGP | -8 |
| Low BGP visibility (< 50%) | -3 |
| BGP prefix missing from WHOIS | -5 |

**BGP first-seen age**: prefers RIPEstat's BGP routing-status `first_seen`
timestamp over RIR allocation date or WHOIS RegDate.  Young IP blocks
(<= 2 years) are penalized because they are statistically more likely to host
ephemeral/churn infrastructure.  Output shows the exact date:
`BGP first seen 2025-03-12 (1y ago, RIPEstat)`.

### Geo & Source Consistency (max 15, starts at 10)

| Signal | Points |
|--------|--------|
| Geo country matches BGP registration country | +5 |
| | |
| Geo differs from BGP registration — possible VPN/proxy/hosting | -8 |
| IP in high-risk/sanctioned country (CN, RU, IR, KP, ...) | -8 |
| Source vs IP geo — different continent | -3 |
| Source vs IP geo — same continent, different country | -2 |

**Source-location consistency**: checks whether your `--source-country` matches
the IP's geolocation and BGP registration.  Source country is now informational
(not separately scored) within this merged dimension.

**Source-vs-IP continent mismatch**: if the user is in Germany (EU) and the IP
geolocates to Singapore (AS), the penalty is -3 (different continent).  If the
user is in Germany and the IP is in France (both EU), the penalty is -2 (same
continent, cross-country).  Mapping uses the `_COUNTRY_CONTINENT` dictionary
covering 80+ countries.

### Anonymization & Privacy (max 15, starts at 15)

Privacy/anonymization signals are industry consensus as the #2 reputation factor
after threat intelligence.  This dimension starts clean (15) and applies
deductions only — there is no "bonus" for not being a Tor exit.

| Signal | Points |
|--------|--------|
| Tor exit node (ip-api flag or PTR hostname) | -15 |
| Proxy/VPN (ip-api flag or PTR hostname) | -10 |
| Hosting/public-cloud flag (ip-api) | -5 |
| AS name contains proxy/VPN indicator | -5 |

Flags from multiple sources stack.  **GreyNoise RIOT** overrides and clears
all anonymization flags if the IP is a known benign service (e.g. 8.8.8.8).

### Traceroute Quality (max 5, starts at 5)

Minimal weight — routing health is a diagnostic, not a trust signal.  Industry
consensus: all 9 firewall vendors surveyed ignore traceroute metrics in
reputation scoring.  No traceroute → neutral baseline (5/5), no penalty for
skipping.

| Signal | Points |
|--------|--------|
| Hop count > 20 | -1 |
| Avg latency > 150ms | -1 |
| Packet loss > 10% | -2 |
| Packet loss 6-10% | -1 |
| Routing loop | -2 |
| Unexpected country hops (each) | -1 |

### Threat Intelligence (max 40, starts at 20)

Industry consensus: threat intelligence is the #1 signal — every firewall vendor
weighs abuse reports, blocklists, and malware associations most heavily.  This
dimension was doubled from 20 to 40 pts as part of the recalibration.

| Signal | Points |
|--------|--------|
| GreyNoise: known benign | +8 |
| GreyNoise: no scan data (typical for clean IPs) | +5 |
| | |
| GreyNoise: malicious | -15 |
| GreyNoise: background scanner (noise) | -5 |
| AbuseIPDB >= 80% confidence | -20 |
| AbuseIPDB 50-79% confidence | -12 |
| AbuseIPDB 20-49% confidence | -6 |
| OTX >= 10 threat pulses | -12 |
| OTX 5-9 threat pulses | -6 |
| OTX 1-4 threat pulses | -3 |
| OTX malware associations (each, max -12) | -3 |

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

  [1/8] ip-api.com — geolocation ... OK (United States, GOOGLE)
  [2/8] Team Cymru — BGP origin ASN ... OK (AS15169, US)
  [3/8] RIPEstat — RPKI ... ROA valid
  ...

  Scoring ...
    [+] residential/ISP AS (+2)
    [+] IP block established (BGP first seen 2020-01-15 (6y ago, RIPEstat)) (+3)
    [+] FCrDNS confirmed: dns.google (+7)
    [+] RPKI valid — route origin authorized (+8)
    [+] abuse contact published (+2)
    [+] BGP visibility 100% — widely routed (+2)
    [+] geo country (US) matches BGP registration (US) (+5)
    [+] GreyNoise: no scan data — typical for clean IPs (+5)

    Registration & Entity: 22/25
    Geo & Source Consistency: 15/15
    Anonymization & Privacy: 15/15
    Traceroute Quality: 5/5
    Threat Intelligence: 25/40

  IP: 8.8.8.8  |  Score: 82/100  |  Grade: A
```
