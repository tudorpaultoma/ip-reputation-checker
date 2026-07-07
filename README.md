# IP Reputation Scoring Engine

A firewall-aligned tool that scores any public IPv4 address on a **0–100 scale** based on registration identity, geo-routing consistency, traceroute quality, source-location relevance, and multi-source threat intelligence. Modeled after how enterprise firewalls (Palo Alto PAN-DB, Fortinet, Cisco Talos, BrightCloud) evaluate IP reputation — not by scanning ports, but by analyzing **who owns the IP, how it's routed, where it claims to be, and what the threat intelligence community says about it**.

## Quick Start

```bash
# Install the one dependency
pip install requests

# Basic scan (7 free data sources, no API keys needed)
python ip_reputation.py 8.8.8.8 --no-traceroute

# Full scan with traceroute (needs sudo on macOS for raw ICMP)
sudo python ip_reputation.py 8.8.8.8

# Export structured JSON report
python ip_reputation.py 8.8.8.8 --json report.json
```

**Output example:**

```
============================================================
  IP REPUTATION ANALYSIS — 8.8.8.8
============================================================

  ┌──────────────────────────────────────────────────────────┐
  │  SCORE: 90/100  [██████████████████░░]  GRADE: A  │
  └──────────────────────────────────────────────────────────┘

  Breakdown:
    Registration Entity    ███████████████ 30
    Geo Consistency        ███████████████ 25
    Source Location        █░░░░░░░░░░░░░░░  0
    Traceroute Quality     ███████████████ 15
    Threat Intelligence    ███████████████ 20

  ✓ Positives:
    ✓ BGP first seen 23y ago — well-established (+5)
    ✓ forward-confirmed reverse DNS (+3)
    ✓ abuse contact registered (+2)
    ✓ IP geo matches BGP origin (+5)
    ✓ high BGP visibility 100% (+3)

  ⚠ Warnings:
    ⚠ source (DE) differs from IP geolocation (US) (-5)
    ⚠ source (DE) differs from BGP registration (US) (-5)
```

---

## CLI Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `ip` | — | Target IPv4 address (required) | — |
| `--source-country` | `-s` | Your country as 2-letter ISO code (e.g. `DE`, `US`, `CN`) | `$SOURCE_COUNTRY` env var |
| `--no-traceroute` | `-n` | Skip traceroute (no root/sudo needed) | `false` |
| `--abuseipdb-key` | — | AbuseIPDB API v2 key | `$ABUSEIPDB_KEY` env var |
| `--ipinfo-key` | — | ipinfo.io access token | `$IPINFO_TOKEN` env var |
| `--otx-key` | — | AlienVault OTX API key | `$OTX_KEY` env var |
| `--json` | `-j` | Export structured JSON report to file | — |
| `--help` | `-h` | Show help message | — |

### Environment Variables

```bash
export SOURCE_COUNTRY=DE           # default source country
export ABUSEIPDB_KEY="your-key"    # AbuseIPDB v2 key
export IPINFO_TOKEN="your-token"   # ipinfo.io token
export OTX_KEY="your-key"          # AlienVault OTX key
```

Set `SOURCE_COUNTRY` once and the tool will automatically use a three-way consistency check for every IP you analyze.

---

## Scoring Model (5 Dimensions, 100 Total)

Each dimension is scored independently and capped at its maximum. Penalties and bonuses are applied within each dimension. The final score is the sum.

### 1. Registration & Entity Identity (30 pts)

*What firewalls care about: is this IP owned by a legitimate organization?*

| Signal | Effect |
|--------|--------|
| ASN type: residential ISP / mobile / academic / government | +3 to +5 |
| ASN type: hosting, datacenter, cloud (unless known provider) | -5 |
| ASN type: bulletproof hosting, proxy, anonymous | -10 |
| Allocation age ≥ 15 years (via BGP first-seen) | +5 |
| Allocation age ≥ 8 years | +3 |
| Allocation age ≤ 2 years (recently allocated) | -8 |
| Forward-confirmed reverse DNS (PTR → A record match) | +3 |
| RPKI Route Origin Validation: valid | +5 |
| RPKI Route Origin Validation: invalid | -8 |
| Abuse contact registered in WHOIS/RIR | +2 |

**Known benign providers** (Google, Cloudflare, AWS, Akamai, Fastly, Microsoft, etc.) are recognized and their hosting/datacenter flags are ignored — reducing false positives.

### 2. Geo-Routing Consistency (25 pts)

*What firewalls care about: does the IP's physical location match what routing says?*

| Signal | Effect |
|--------|--------|
| IP geolocation country matches BGP origin country | +5 |
| IP geolocation country mismatches BGP origin country | -10 |
| IP in a high-risk country (sanctioned states, known malicious hubs) | -8 |
| Proxy flag detected (ip-api.com) | -5 |
| Hosting/public-cloud flag detected (ip-api.com) | -5 |
| PTR hostname contains tor-exit, vpn, proxy keywords | -5 |
| GreyNoise RIOT: known benign service | +5 (clears all flags) |

### 3. Source-Location Consistency (10 pts)

*What firewalls care about: does the traffic origin make sense for this IP?*

| Signal | Effect |
|--------|--------|
| Source country matches IP geolocation country | +5 |
| Source country mismatches IP geolocation country | -5 |
| Source country matches BGP registration country | +5 |
| Source country mismatches BGP registration country | -5 |

This creates a **three-way consistency check**: your location → IP geolocation → BGP origin. A German user hitting a German-registered IP in Germany gets full credit. A German user hitting an IP geolocated in Singapore but BGP-registered in the Seychelles gets heavily penalized.

**Without `--source-country`:** this dimension is skipped (0 points, not counted).

### 4. Traceroute Quality (15 pts)

*What firewalls care about: is the path to this IP clean and direct?*

| Signal | Effect |
|--------|--------|
| Hop count < 10 | +5 |
| Hop count 10–15 | +3 |
| Hop count > 20 | -3 |
| Average latency < 50ms | +5 |
| Average latency 50–100ms | +3 |
| Average latency > 200ms | -3 |
| 0% packet loss | +5 |
| Packet loss > 10% | -5 |
| Routing loops detected | -5 |
| Transit through high-risk countries | -8 |

**On macOS:** traceroute requires `sudo` for raw ICMP sockets. Use `--no-traceroute` to skip.

### 5. Threat Intelligence (20 pts)

*What firewalls care about: does the threat intel community flag this IP?*

| Signal | Effect |
|--------|--------|
| GreyNoise: classified as malicious | -12 |
| GreyNoise: classified as noise (benign scanner) | -2 |
| GreyNoise: classified as benign | +3 |
| GreyNoise RIOT: known benign service | +3 |
| AbuseIPDB confidence > 80% | -12 |
| AbuseIPDB confidence > 50% | -8 |
| AbuseIPDB confidence > 20% | -4 |
| AlienVault OTX: > 10 threat pulses | -10 |
| AlienVault OTX: > 3 threat pulses | -5 |
| BGP visibility < 50% (shadow routing) | -5 |
| BGP visibility ≥ 95% | +3 |

### Letter Grades

| Score Range | Grade | Meaning |
|-------------|-------|---------|
| 90–100 | **A** | Clean — no concerning signals |
| 80–89 | **B** | Mostly clean — minor flags |
| 70–79 | **C** | Some concern — investigate |
| 60–69 | **D** | Suspicious — likely problematic |
| < 60 | **F** | High risk — avoid |

---

## Data Sources

The engine queries up to **10 data sources**. The first 7 work without any API keys.

### Free Tier (No API Key Required)

| # | Source | What It Provides | Rate Limit |
|---|--------|-----------------|------------|
| 1 | **ip-api.com** | Country, city, ISP, ASN, proxy/hosting flags, reverse DNS | 45 req/min |
| 2 | **Team Cymru IP-to-ASN** | BGP origin ASN, prefix, registry country, allocation date | Unlimited (whois port 43) |
| 3 | **RIPEstat** | RPKI validation, BGP routing visibility, prefix consistency, abuse contacts | ~1,000/day |
| 4 | **GreyNoise Community** | Malicious / noise / benign classification, RIOT (known benign) flag | ~50/day |
| 5 | **AlienVault OTX** | Threat pulse count, malware family associations | Generous |
| 6 | **system whois** | Full WHOIS registration data | Unlimited (local) |
| 7 | **system traceroute** | Hop count, latency, packet loss, routing anomalies | Unlimited (local) |

### Optional (Free API Key Required)

| # | Source | What It Provides | Free Limit |
|---|--------|-----------------|------------|
| 8 | **AbuseIPDB** | Abuse confidence score (0–100), total reports, reporter count | 1,000/day |
| 9 | **ipinfo.io** | Enhanced geolocation, VPN/Tor/relay/proxy detection, company data | 50,000/month |
| 10 | **AlienVault OTX (keyed)** | Higher rate limits for threat pulse lookups | Generous |

### Resilience

- **Team Cymru HTTP fallback:** if the whois port 43 connection is blocked (common on corporate networks), the engine falls back to RIPEstat's AS-overview HTTP endpoint using the ASN from ip-api.com.
- **GreyNoise 404 handling:** well-known IPs like Google DNS return 404 from GreyNoise — handled gracefully.
- **GreyNoise rate-limit handling:** 429 responses are detected and the source is skipped.
- **ip-api.com failure:** gracefully degrades — the engine continues with remaining sources.

---

## JSON Output Schema

When using `--json report.json`, the engine exports a structured report:

```json
{
  "ip": "8.8.8.8",
  "source_country": "DE",
  "score": 90,
  "grade": "A",
  "breakdown": {
    "registration_entity": 30,
    "geo_consistency": 25,
    "source_location": 0,
    "traceroute_quality": 15,
    "threat_intelligence": 20
  },
  "positives": ["BGP first seen 23y ago — well-established (+5)", "..."],
  "warnings": ["source (DE) differs from IP geolocation (US) (-5)", "..."],
  "details": ["Registration & Entity: 30/30", "..."],
  "geolocation": { "country": "United States", "country_code": "US", "..." },
  "asn_origin": { "asn": "15169", "cc": "US", "..." },
  "rpki": { "status": "no_roas", "..." },
  "bgp_routing": { "announced": true, "visibility": 100.0, "..." },
  "abuse_contact": { "email": "network-abuse@google.com" },
  "threat_intel": { "greynoise_class": "unknown", "abuseipdb_score": 0, "..." },
  "traceroute": { "hop_count": 12, "avg_latency_ms": 23.5, "..." },
  "whois_raw": "inetnum: 8.0.0.0 - 8.255.255.255\n...",
  "sources_used": ["ip-api.com", "Team Cymru", "RIPEstat BGP", "..."],
  "sources_failed": []
}
```

---

## Example Scenarios

### Clean IP — Google DNS from the US (everything consistent)

```bash
python ip_reputation.py 8.8.8.8 --source-country US --no-traceroute
# → 100/100 A
```

### Same IP tested from Germany (source mismatch)

```bash
python ip_reputation.py 8.8.8.8 --source-country DE --no-traceroute
# → 90/100 A (source-location flags: -10)
```

### Tor exit node

```bash
python ip_reputation.py 185.220.101.1 --no-traceroute
# → 76/100 C (GreyNoise malicious, proxy flag, tor-exit PTR)
```

---

## How It Compares to Enterprise Firewalls

Enterprise firewalls (Palo Alto PAN-DB, Fortinet FortiGuard, Cisco Talos) classify IPs using:

| Firewall Signal | How This Tool Replicates It |
|----------------|---------------------------|
| **Netblock Owner** | ASN type classification + BGP origin via Team Cymru/RIPEstat |
| **Anonymizers & Proxies** | ip-api.com proxy flag + PTR hostname keyword detection + GreyNoise |
| **High Risk Infrastructure** | Suspicious AS keyword detection, high-risk country check |
| **Infrastructure Attributes** | Allocation age, reverse DNS, RPKI validation, abuse contact |
| **Abuse / Malware** | GreyNoise classification + AbuseIPDB + AlienVault OTX |
| **Routing Anomalies** | BGP visibility check, traceroute loop detection, 3-way country consistency |

The key difference from typical IP scanners: **this tool does not scan ports**. It evaluates *identity and routing trust* — the same signals that firewalls weigh most heavily.

---

## Requirements

- Python 3.8+
- `requests` library
- macOS, Linux, or WSL (traceroute uses system binary)
- `sudo` access (optional, only for traceroute with ICMP)

## Installation

```bash
git clone <repo-url> && cd ip-reputation
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Limitations

- **IPv6 not supported** — the tool validates for IPv4 only.
- **Traceroute on macOS requires `sudo`** — without it, only UDP traceroute works (limited). Use `--no-traceroute` as a workaround.
- **API rate limits** — rapid repeated scanning of the same IP may hit GreyNoise or ip-api.com limits. The tool handles this gracefully by skipping sources rather than crashing.
- **Team Cymru port 43** — some corporate firewalls block outbound whois (TCP/43). The tool falls back to RIPEstat HTTP in this case.
- **Not a real-time blocklist** — this is a reputation scoring tool, not a firewall. Use it for investigation, triage, and threat hunting.
