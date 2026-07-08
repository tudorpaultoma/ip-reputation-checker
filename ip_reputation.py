#!/usr/bin/env python3
"""
IP Reputation Engine — firewall-aligned scoring across 10 data sources.

Models how major firewalls (Palo Alto PAN-DB, Fortinet, Cisco Talos, BrightCloud)
evaluate IP reputation using registration data, entity identity, BGP routing
quality, and threat intelligence — without port scanning.

Now includes SOURCE-LOCATION CONSISTENCY: if you're testing from Germany and the
IP is registered in Singapore, that mismatch lowers the score — just like a real
firewall checking whether traffic originating from your region actually belongs there.

Usage:
    python3 ip_reputation.py 8.8.8.8
    python3 ip_reputation.py 185.220.101.1
    python3 ip_reputation.py 45.33.32.156 --source-country DE
    python3 ip_reputation.py 8.8.8.8 --json result.json

API keys can be passed via CLI flags, environment variables, or a .env file.
Copy .env.example to .env and fill in your keys:

    cp .env.example .env
    # Edit .env with your keys, then:
    python3 ip_reputation.py 8.8.8.8

Free (no key):  Team Cymru, RIPEstat, ip-api, GreyNoise, whois, DNS, Globalping traceroute
Free API key:  AbuseIPDB, ipinfo.io, AlienVault OTX, MaxMind GeoLite2
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# optional dependency —  graceful degradation
# ---------------------------------------------------------------------------
try:
    import requests

    _SESSION = requests.Session()
    _SESSION.headers["User-Agent"] = "ip-reputation-cli/2.0"
    _SESSION.timeout = 10
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    _SESSION = None  # type: ignore


# ---------------------------------------------------------------------------
# .env file loader — no python-dotenv dependency needed
# ---------------------------------------------------------------------------
def _load_dotenv(path: str | None = None) -> None:
    """Load KEY=VALUE pairs from a .env file into os.environ.

    Search order (first match wins, does NOT overwrite existing env vars):

    1. Explicit *path* (if given)
    2. Script directory + ``.env``  (where the script lives — most predictable)
    3. Parent of script directory + ``.env``  (project/.env + project/src/script.py)
    4. Walk up from ``cwd`` to the filesystem root looking for ``.env``
       (like ``git`` does — finds ``.env`` in any ancestor of where you ran from)

    This means ``.env`` placed next to the script is always found, no matter
    which directory you run from.  Cwd-ancestor ``.env`` files only act as
    overrides when no script-local ``.env`` exists.
    """
    candidates: list[str] = []

    # 1 — explicit path
    if path:
        candidates.append(path)

    # 2 — script directory (priority: always find the project's own .env)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(script_dir, ".env"))

    # 3 — parent of script directory (common for project/.env + project/src/script.py)
    script_parent = os.path.dirname(script_dir)
    if script_parent != script_dir:
        candidates.append(os.path.join(script_parent, ".env"))

    # 4 — walk up from cwd (fallback: your working directory or its ancestors)
    cwd = os.getcwd()
    while True:
        candidates.append(os.path.join(cwd, ".env"))
        parent = os.path.dirname(cwd)
        if parent == cwd:  # reached filesystem root
            break
        cwd = parent

    for fp in candidates:
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip()
                    # Strip optional surrounding quotes
                    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                        val = val[1:-1]
                    # Only set if not already in the environment
                    if key and key not in os.environ:
                        os.environ[key] = val
            return  # first match wins
        except OSError:
            continue


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
HIGH_RISK_COUNTRIES = {
    "CN", "RU", "IR", "KP", "SY", "CU", "VE", "BY", "MM",
    "SD", "SO", "YE", "ZW",
}

# ---------------------------------------------------------------------------
# Country → continent mapping for source-vs-IP geo mismatch penalty.
# Used by country_to_continent().
# ---------------------------------------------------------------------------
_COUNTRY_CONTINENT: dict[str, str] = {
    # Europe
    "DE": "EU", "FR": "EU", "GB": "EU", "IT": "EU", "ES": "EU",
    "NL": "EU", "BE": "EU", "CH": "EU", "AT": "EU", "PL": "EU",
    "SE": "EU", "NO": "EU", "DK": "EU", "FI": "EU", "IE": "EU",
    "PT": "EU", "GR": "EU", "CZ": "EU", "RO": "EU", "HU": "EU",
    "BG": "EU", "SK": "EU", "HR": "EU", "SI": "EU", "LT": "EU",
    "LV": "EU", "EE": "EU", "LU": "EU", "MT": "EU", "CY": "EU",
    "IS": "EU", "UA": "EU", "RS": "EU", "MD": "EU",
    # Asia
    "SG": "AS", "CN": "AS", "JP": "AS", "KR": "AS", "IN": "AS",
    "HK": "AS", "TW": "AS", "TH": "AS", "VN": "AS", "MY": "AS",
    "ID": "AS", "PH": "AS", "PK": "AS", "BD": "AS", "KZ": "AS",
    "AE": "AS", "SA": "AS", "QA": "AS", "KW": "AS", "OM": "AS",
    "BH": "AS", "IL": "AS", "JO": "AS", "LB": "AS", "TR": "AS",
    "IR": "AS", "MM": "AS", "KH": "AS", "LA": "AS",
    # North America
    "US": "NA", "CA": "NA", "MX": "NA", "PA": "NA", "CR": "NA",
    "GT": "NA", "HN": "NA", "SV": "NA", "NI": "NA", "BZ": "NA",
    # South America
    "BR": "SA", "AR": "SA", "CL": "SA", "CO": "SA", "PE": "SA",
    "UY": "SA", "PY": "SA", "EC": "SA", "BO": "SA", "VE": "SA",
    # Oceania
    "AU": "OC", "NZ": "OC",
    # Africa
    "ZA": "AF", "NG": "AF", "KE": "AF", "EG": "AF", "MA": "AF",
    "GH": "AF", "TZ": "AF", "UG": "AF", "SD": "AF", "ET": "AF",
}

# Recognized cloud providers — treated as corporate/enterprise (+2).
MAJOR_CLOUD_KEYWORDS = [
    "aws", "ec2", "amazon web services", "amazon technologies",
    "amazon data services", "azure", "google cloud", "gcp",
    "oracle cloud", "tencent cloud", "alibaba cloud", "ali cloud",
    "ovh",
]

# Generic / obscure hosting — heavier penalty (-5).  These are the VPS mills
# and anonymising-friendly providers.
KNOWN_HOSTING_ASN_KEYWORDS = [
    "hosting", "vps", "dedicated", "colocation", "data center",
    "cloud", "server", "infrastructure", "noc", "internet service",
    "broadband", "telecom", "communications", "network",
    "digitalocean", "linode", "vultr", "ovh", "hetzner",
]

KNOWN_ISP_ASN_KEYWORDS = [
    "telecom", "broadband", "dsl", "fiber", "cable", "mobile",
    "isp", "internet service provider", "communications",
]

KNOWN_BULLETPROOF_KEYWORDS = [
    "bulletproof", "offshore", "anonymous", "dmca", "abuse resistant",
    "privacy", "no log",
]

EDUCATIONAL_KEYWORDS = [
    "university", "college", "education", "school", "academic",
    "research", "institute of technology", "campus",
]

GOVERNMENT_KEYWORDS = [
    "government", "federal", "state", "municipal", "ministry",
    "department of", "agency",
]

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, params: dict | None = None) -> dict | None:
    """HTTP GET with error handling. Returns parsed JSON or None."""
    if not HAS_REQUESTS:
        return None
    try:
        r = _SESSION.get(url, params=params, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _whois_raw(query: str, server: str = "whois.cymru.com", port: int = 43) -> str:
    """Raw whois query over TCP port 43 with short timeout."""
    try:
        sock = socket.create_connection((server, port), timeout=3)
        sock.sendall((query + "\r\n").encode())
        chunks: list[str] = []
        sock.settimeout(3)
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data.decode(errors="replace"))
        sock.close()
        return "".join(chunks)
    except Exception:
        return ""


def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str]:
    """Run a subprocess, return (stdout, stderr).  Both empty on failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "", r.stderr or "")
    except FileNotFoundError:
        return ("", f"command not found: {cmd[0]}")
    except Exception as e:
        return ("", str(e))


def _resolve_ptr(ip: str) -> str:
    """DNS reverse lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _resolve_forward(hostname: str) -> list[str]:
    """DNS forward lookup."""
    try:
        _, _, ips = socket.gethostbyname_ex(hostname)
        return ips
    except Exception:
        return []


def years_since(date_str: str) -> int | None:
    """Rough years since a date string like '2023-12-28' or '2002'."""
    if not date_str:
        return None
    try:
        # Strip ISO 8601 time portion (e.g. "2002-11-06T16:00:00" → "2002-11-06")
        clean = date_str.strip().split("T")[0].split(" ")[0]
        parts = clean.split("-")
        year = int(parts[0])
        month = int(parts[1]) if len(parts) > 1 else 1
        day = int(parts[2]) if len(parts) > 2 else 1
        dt = datetime(year, month, day, tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - dt
        return int(age.days / 365.25)
    except Exception:
        try:
            return datetime.now().year - int(date_str.strip())
        except Exception:
            return None


def country_name_to_code(name: str) -> str:
    """Convert 'Germany' → 'DE', 'United States' → 'US', or pass-through codes."""
    mapping = {
        "germany": "DE", "deutschland": "DE",
        "france": "FR", "italy": "IT", "spain": "ES",
        "netherlands": "NL", "belgium": "BE", "switzerland": "CH",
        "austria": "AT", "poland": "PL", "sweden": "SE",
        "norway": "NO", "denmark": "DK", "finland": "FI",
        "united kingdom": "GB", "uk": "GB", "england": "GB",
        "united states": "US", "usa": "US", "america": "US",
        "canada": "CA", "australia": "AU", "japan": "JP",
        "china": "CN", "russia": "RU", "brazil": "BR",
        "india": "IN", "south korea": "KR", "korea": "KR",
        "singapore": "SG", "hong kong": "HK",
        "romania": "RO", "bulgaria": "BG", "ukraine": "UA",
    }
    upper = name.strip().upper()
    if len(upper) == 2:
        return upper
    return mapping.get(name.strip().lower(), upper[:2])


def country_to_continent(cc: str) -> str:
    """Return continent code for a 2-letter country code.

    Returns ``"EU"``, ``"AS"``, ``"NA"``, ``"SA"``, ``"OC"``, ``"AF"``,
    or ``""`` if unrecognised.
    """
    return _COUNTRY_CONTINENT.get(cc.upper(), "")


# ---------------------------------------------------------------------------
# data classes
# ---------------------------------------------------------------------------

@dataclass
class GeoResult:
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    lat: float = 0.0
    lon: float = 0.0
    isp: str = ""
    org: str = ""
    as_number: str = ""
    as_name: str = ""
    is_proxy: bool = False
    is_hosting: bool = False
    source: str = ""


@dataclass
class AsnResult:
    asn: str = ""
    prefix: str = ""
    cc: str = ""
    registry: str = ""
    allocated: str = ""
    as_name: str = ""
    source: str = ""


@dataclass
class RpkiResult:
    status: str = "unknown"
    prefix: str = ""
    asn: str = ""
    source: str = ""


@dataclass
class BgpRouting:
    announced: bool = False
    prefix_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    visibility: float = 0.0
    prefix_in_whois: bool = False
    source: str = ""


@dataclass
class AbuseContact:
    email: str = ""
    source: str = ""


@dataclass
class DnsInfo:
    ptr: str = ""
    fwd_ips: list[str] = field(default_factory=list)
    fcrdns_ok: bool = False


@dataclass
class TracerouteData:
    hops: int = 0
    avg_latency_ms: float = 0.0
    loss_pct: float = 0.0
    countries: list[str] = field(default_factory=list)
    has_loop: bool = False
    unexpected_countries: list[str] = field(default_factory=list)
    raw_output: str = ""


@dataclass
class ThreatResult:
    greynoise_class: str = ""
    greynoise_riot: bool = False
    abuseipdb_score: int = 0
    abuseipdb_total: int = 0
    abuseipdb_country: str = ""
    abuseipdb_isp: str = ""
    otx_pulses: int = 0
    otx_malware: list[str] = field(default_factory=list)


@dataclass
class Report:
    ip: str = ""
    timestamp: str = ""
    score: int = 0
    grade: str = "N/A"
    source_country: str = ""
    breakdown: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    positives: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    geo: GeoResult = field(default_factory=GeoResult)
    asn: AsnResult = field(default_factory=AsnResult)
    rpki: RpkiResult = field(default_factory=RpkiResult)
    bgp: BgpRouting = field(default_factory=BgpRouting)
    abuse: AbuseContact = field(default_factory=AbuseContact)
    dns: DnsInfo = field(default_factory=DnsInfo)
    trace: TracerouteData = field(default_factory=TracerouteData)
    threat: ThreatResult = field(default_factory=ThreatResult)

    whois_raw: str = ""
    api_keys: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# 1 — ip-api.com  (free, no key)
# ---------------------------------------------------------------------------
def lookup_geo(ip: str) -> GeoResult:
    data = _http_get(f"http://ip-api.com/json/{ip}")
    if not data or data.get("status") != "success":
        return GeoResult()
    return GeoResult(
        country=data.get("country", ""),
        country_code=data.get("countryCode", ""),
        region=data.get("regionName", ""),
        city=data.get("city", ""),
        lat=float(data.get("lat", 0)),
        lon=float(data.get("lon", 0)),
        isp=data.get("isp", ""),
        org=data.get("org", ""),
        as_number=data.get("as", "").split()[0] if data.get("as") else "",
        as_name=" ".join(data.get("as", "").split()[1:]) if data.get("as") else "",
        is_proxy=bool(data.get("proxy", False)),
        is_hosting=bool(data.get("hosting", False)),
        source="ip-api.com",
    )


# ---------------------------------------------------------------------------
# 2 — Team Cymru IP-to-ASN  (free, no key, TCP whois)
# ---------------------------------------------------------------------------
def lookup_cymru(ip: str) -> AsnResult:
    raw = _whois_raw(f"-v {ip}")
    if not raw:
        return AsnResult()
    lines = [l.strip() for l in raw.split("\n") if l.strip() and not l.strip().startswith("Bulk") and not l.strip().startswith("AS")]
    if len(lines) < 2:
        return AsnResult()
    parts = lines[-1].split("|")
    if len(parts) < 7:
        return AsnResult()
    return AsnResult(
        asn=parts[0].strip(),
        prefix=parts[1].strip(),
        cc=parts[2].strip(),
        registry=parts[3].strip(),
        allocated=parts[4].strip(),
        as_name=parts[5].strip() if len(parts) > 5 else "",
        source="Team Cymru IP-to-ASN",
    )


def lookup_asn_http_fallback(ip: str, geo: GeoResult) -> AsnResult:
    """HTTP-based ASN fallback using RIPEstat prefix-overview + ip-api geo.

    Used when Team Cymru's port 43 whois is blocked by the network firewall."""
    # Use RIPEstat prefix-overview to get ASN + holder
    data = _http_get("https://stat.ripe.net/data/prefix-overview/data.json",
                     params={"resource": ip})
    if data and data.get("status") == "ok":
        dd = data.get("data", {})
        asns = dd.get("asns", [])
        resource = dd.get("resource", "")
        if asns:
            asn_info = asns[0]
            # Try to get country from abuse contact finder
            cc = geo.country_code or ""
            return AsnResult(
                asn=str(asn_info.get("asn", "")),
                prefix=resource,
                cc=cc,
                registry=geo.as_number.split("AS")[1] if not cc and geo.as_number else "",
                allocated="",
                as_name=asn_info.get("holder", geo.as_name),
                source="RIPEstat prefix-overview (HTTP fallback)",
            )
    # Last resort: build from ip-api data
    if geo.as_number:
        return AsnResult(
            asn=geo.as_number.replace("AS", ""),
            prefix="",
            cc=geo.country_code or "",
            registry="",
            allocated="",
            as_name=geo.as_name or geo.isp,
            source="ip-api.com ASN (HTTP fallback)",
        )
    return AsnResult()


# ---------------------------------------------------------------------------
# 3 — RIPEstat  (free, no key, 1000+ calls/day)
# ---------------------------------------------------------------------------
def lookup_ripestat_rpki_asn(asn: str) -> Optional[RpkiResult]:
    data = _http_get("https://stat.ripe.net/data/rpki-validation/data.json",
                      params={"resource": f"AS{asn}", "prefix_limit": "20"})
    if not data or data.get("status") != "ok":
        return None
    roas = data.get("data", {}).get("validating_roas", [])
    if not roas:
        return None
    roa = roas[0]
    return RpkiResult(
        status=roa.get("status", "unknown"),
        prefix=roa.get("prefix", ""),
        asn=str(roa.get("origin", "")),
        source="RIPEstat RPKI",
    )


def lookup_ripestat_prefix_consistency(ip: str) -> BgpRouting:
    """Check whether the BGP-announced prefix matches WHOIS registration."""
    data = _http_get("https://stat.ripe.net/data/prefix-routing-consistency/data.json",
                      params={"resource": ip})
    if not data or data.get("status") != "ok":
        return BgpRouting(source="RIPEstat")
    rd = data.get("data", {})
    routes = rd.get("routes", [])
    if routes:
        best = routes[0]  # first route is the most-specific prefix
        return BgpRouting(
            announced=True,
            prefix_in_whois=best.get("in_whois", False),
            source="RIPEstat prefix-consistency",
        )
    return BgpRouting(source="RIPEstat prefix-consistency")


def lookup_ripestat_bgp(ip: str) -> BgpRouting:
    data = _http_get("https://stat.ripe.net/data/routing-status/data.json",
                      params={"resource": ip})
    if not data or data.get("status") != "ok":
        return BgpRouting(source="RIPEstat")
    rd = data.get("data", {})
    vis = rd.get("visibility", {})
    # visibility can be: int, dict {"v4": int}, dict {"v4": {"ris_peers_seeing": N, "total_ris_peers": M}}, ...
    if isinstance(vis, dict):
        v4 = vis.get("v4", 0)
        if isinstance(v4, dict):
            seen = v4.get("ris_peers_seeing", 0)
            total = v4.get("total_ris_peers", 1)
            vis = (seen / total * 100) if total > 0 else 0.0
        else:
            vis = float(v4) if v4 else 0.0
    elif isinstance(vis, (int, float)):
        vis = float(vis)
    else:
        vis = 0.0
    first_seen = rd.get("first_seen", {})
    last_seen = rd.get("last_seen", {})
    fs = first_seen.get("time", "") if isinstance(first_seen, dict) else str(first_seen)
    ls = last_seen.get("time", "") if isinstance(last_seen, dict) else str(last_seen)
    return BgpRouting(
        announced=bool(first_seen),
        first_seen=fs,
        last_seen=ls,
        visibility=vis,
        source="RIPEstat BGP",
    )


def lookup_ripestat_abuse(ip: str) -> Optional[AbuseContact]:
    data = _http_get("https://stat.ripe.net/data/abuse-contact-finder/data.json",
                      params={"resource": ip})
    if not data or data.get("status") != "ok":
        return None
    abuse = data.get("data", {}).get("abuse_contacts", [])
    if not abuse:
        return None
    return AbuseContact(email=abuse[0], source="RIPEstat Abuse")


# ---------------------------------------------------------------------------
# 4 — DNS reverse  (system)
# ---------------------------------------------------------------------------
def lookup_dns(ip: str) -> DnsInfo:
    ptr = _resolve_ptr(ip)
    if not ptr:
        return DnsInfo()
    fwd = _resolve_forward(ptr)
    return DnsInfo(
        ptr=ptr,
        fwd_ips=fwd,
        fcrdns_ok=ip in fwd,
    )


# ---------------------------------------------------------------------------
# 5 — system whois  (built-in)
# ---------------------------------------------------------------------------
def lookup_whois(ip: str) -> str:
    stdout, _ = _run(["whois", ip], timeout=12)
    return stdout


# ---------------------------------------------------------------------------
# 6 — GreyNoise Community  (free, no key)
# ---------------------------------------------------------------------------
def lookup_greynoise(ip: str) -> dict:
    if not HAS_REQUESTS:
        return {}
    try:
        # GreyNoise returns 404 for IPs with no scan data — that's normal
        r = _SESSION.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=10)
        if r.status_code == 404:
            return {"classification": "unknown", "message": "no-scan-data"}
        if r.status_code == 429:
            return {"rate_limited": True, "classification": None}
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 7 — AbuseIPDB  (free key: 1000/day)
# ---------------------------------------------------------------------------
def lookup_abuseipdb(ip: str, key: str) -> dict | None:
    """Returns data dict on success, empty dict on 4xx, None on network error."""
    if not HAS_REQUESTS or not key:
        return None
    try:
        r = _SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 401 or r.status_code == 403:
            return {}  # bad key — distinguishable from network failure
        r.raise_for_status()
        data = r.json().get("data", {})
        return data
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 8 — ipinfo.io  (free key: 50k/month)
# ---------------------------------------------------------------------------
def lookup_ipinfo(ip: str, token: str) -> dict:
    if not HAS_REQUESTS or not token:
        return {}
    return _http_get(f"https://ipinfo.io/{ip}?token={token}") or {}


# ---------------------------------------------------------------------------
# 9 — AlienVault OTX  (free key)
# ---------------------------------------------------------------------------
def lookup_otx(ip: str, key: str) -> dict:
    if not HAS_REQUESTS or not key:
        return {}
    try:
        r = _SESSION.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 10 — traceroute via Globalping  (free, no key, 500 tests/hour)
# ---------------------------------------------------------------------------
def run_traceroute_globalping(ip: str, source_country: str = "",
                              max_hops: int = 30) -> TracerouteData:
    """Run traceroute via Globalping's distributed probe network.

    If *source_country* is given (e.g. ``"DE"``), the measurement originates
    from a probe in that country — realistic routing from the user's location.
    Without it, a random global probe is used.

    Globalping is free (500 tests/hour authenticated, less unauthenticated).
    No API key required.  No root / sudo needed.
    """
    if not HAS_REQUESTS:
        return TracerouteData(raw_output="requests not installed — traceroute unavailable")

    # ------------------------------------------------------------------
    # Step 1 — Build location filter from source country
    # ------------------------------------------------------------------
    locations: list[dict] = []
    if source_country:
        cc = country_name_to_code(source_country)
        if len(cc) == 2:
            locations = [{"country": cc}]

    # ------------------------------------------------------------------
    # Step 2 — POST /v1/measurements to create the measurement
    # ------------------------------------------------------------------
    payload: dict = {
        "type": "traceroute",
        "target": ip,
        "limit": 1,
        "measurementOptions": {
            "protocol": "ICMP",
            "port": 80,  # TCP/80 — less likely filtered than ICMP
        },
    }
    if locations:
        payload["locations"] = locations

    try:
        r = _SESSION.post(
            "https://api.globalping.io/v1/measurements",
            json=payload,
            timeout=15,
        )
        if r.status_code == 422:
            loc_desc = source_country or "worldwide"
            return TracerouteData(
                raw_output=f"Globalping: no probes available in {loc_desc}"
            )
        if r.status_code == 429:
            return TracerouteData(
                raw_output="Globalping: rate limited — try again later"
            )
        r.raise_for_status()
        data = r.json()
        measurement_id = data.get("id", "")
        if not measurement_id:
            return TracerouteData(raw_output="Globalping: no measurement ID returned")
    except Exception as exc:
        return TracerouteData(raw_output=f"Globalping: create failed ({exc})")

    # ------------------------------------------------------------------
    # Step 3 — Poll GET /v1/measurements/{id} until finished
    # ------------------------------------------------------------------
    result_url = f"https://api.globalping.io/v1/measurements/{measurement_id}"
    data = {}
    for _attempt in range(20):  # max ~40 s
        time.sleep(2)
        try:
            r = _SESSION.get(result_url, timeout=10)
            r.raise_for_status()
            data = r.json()
            status = data.get("status", "")
            if status == "finished":
                break
        except Exception:
            continue
    else:
        return TracerouteData(raw_output="Globalping: measurement timed out")

    # ------------------------------------------------------------------
    # Step 4 — Parse results
    # ------------------------------------------------------------------
    results = data.get("results", [])
    if not results:
        return TracerouteData(raw_output="Globalping: no probe results")

    result_entry = results[0]
    probe = result_entry.get("probe", {})
    trace_result = result_entry.get("result", {})
    raw_output = trace_result.get("rawOutput", "")
    structured_hops: list[dict] = trace_result.get("hops", [])

    probe_country = probe.get("country", "")
    probe_city = probe.get("city", "")
    probe_location = f"{probe_city}, {probe_country}" if probe_city else probe_country

    # Parse structured hops (only reachable hops)
    parsed_hops: list[dict] = []
    for idx, hop in enumerate(structured_hops):
        hop_ip = (hop.get("resolvedAddress") or hop.get("resolvedHostname") or "")
        hostname = hop.get("resolvedHostname", "")
        timings = hop.get("timings", [])
        if timings:
            rtt_vals = [t.get("rtt", 0) for t in timings if t.get("rtt")]
            latency = sum(rtt_vals) / len(rtt_vals) if rtt_vals else None
        else:
            latency = None
        parsed_hops.append({
            "hop": idx + 1,
            "ip": hop_ip,
            "hostname": hostname,
            "latency": latency,
        })

    # Count total attempted hops from rawOutput (includes timeouts)
    total_hop_lines = 0
    for line in raw_output.split("\n"):
        if re.match(r"^\s*\d+", line):
            total_hop_lines += 1
    if total_hop_lines == 0:
        total_hop_lines = len(parsed_hops)  # fallback

    reachable = len(parsed_hops)
    latencies = [h["latency"] for h in parsed_hops if h["latency"] is not None]

    # Detect routing loops (same IP re-appearing non-consecutively)
    ips_in_order = [h["ip"] for h in parsed_hops if h["ip"]]
    has_loop = False
    if ips_in_order:
        seen: dict[str, int] = {}
        for pos, ip_val in enumerate(ips_in_order):
            if ip_val in seen and (pos - seen[ip_val] > 1):
                has_loop = True
                break
            seen[ip_val] = pos

    return TracerouteData(
        hops=reachable,
        avg_latency_ms=sum(latencies) / len(latencies) if latencies else 0.0,
        loss_pct=round((1 - reachable / total_hop_lines) * 100, 1)
        if total_hop_lines else 0.0,
        countries=[],
        has_loop=has_loop,
        unexpected_countries=[],
        raw_output=f"Globalping → {ip}"
                    f" from {probe_location} ({probe.get('network', '')})\n"
                    f"{raw_output}",
    )


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

def _score_asn_type(asn: AsnResult | None, geo: GeoResult) -> tuple[int, list[str], list[str]]:
    """Score ASN/entity type. Returns (score, positives, warnings)."""
    pos: list[str] = []
    warn: list[str] = []

    org_text = (
        (geo.org + " " + geo.isp + " " + geo.as_name + " " +
         (asn.as_name if asn else "")).lower()
    )

    is_edu = any(kw in org_text for kw in EDUCATIONAL_KEYWORDS)
    is_gov = any(kw in org_text for kw in GOVERNMENT_KEYWORDS)
    is_bulletproof = any(kw in org_text for kw in KNOWN_BULLETPROOF_KEYWORDS)
    is_hosting = any(kw in org_text for kw in KNOWN_HOSTING_ASN_KEYWORDS)
    is_major_cloud = any(kw in org_text for kw in MAJOR_CLOUD_KEYWORDS)
    is_isp = any(kw in org_text for kw in KNOWN_ISP_ASN_KEYWORDS)

    if is_bulletproof:
        warn.append("bulletproof/offshore hosting AS (-10)")
        return -10, pos, warn

    if is_edu:
        pos.append("educational institution AS (+3)")
        return 3, pos, warn
    elif is_gov:
        pos.append("government AS (+3)")
        return 3, pos, warn
    elif is_isp:
        pos.append("residential/ISP AS (+2)")
        return 2, pos, warn
    elif is_major_cloud:
        pos.append("recognized cloud provider (+2)")
        return 2, pos, warn
    elif is_hosting:
        warn.append("hosting/datacenter AS — common for VPNs/proxies (-5)")
        return -5, pos, warn

    # Corporate/enterprise AS (has org name, not hosting/ISP/edu/gov)
    if geo.org or (asn and asn.as_name):
        pos.append("corporate/enterprise AS (+2)")
        return 2, pos, warn

    return 0, pos, warn


def compute_score(report: Report) -> int:
    """Main scoring function. 5 dimensions, 100 points total."""
    score = 100
    warn: list[str] = []
    pos: list[str] = []
    det: list[str] = []

    geo = report.geo
    asn = report.asn
    dns = report.dns
    trace = report.trace
    threat = report.threat
    src_cc = report.source_country

    asn_org_lower = (geo.org + " " + geo.isp + " " + geo.as_name + " " +
                     (asn.as_name if asn else "")).lower()

    # ====================================================================
    # DIMENSION 1 — Registration & Entity (30 pts)
    #   Start at midpoint (15). Bad signals drag down; good signals lift up.
    #   This prevents every cloud IP from hitting the 30-point cap.
    # ====================================================================
    reg_score = 18  # start above midpoint — earn extras, lose on bad signals

    # ASN type scoring
    type_pts, type_pos, type_warn = _score_asn_type(asn, geo)
    reg_score += type_pts
    pos.extend(type_pos)
    warn.extend(type_warn)

    # Allocation age — prefer BGP first_seen over RIR allocation
    alloc_age_for_scoring: int | None = None
    age_source = ""
    if report.bgp and report.bgp.first_seen:
        alloc_age_for_scoring = years_since(report.bgp.first_seen)
        # Show actual first-seen date + age for context
        first_date = report.bgp.first_seen.split("T")[0]
        age_source = f"BGP first seen {first_date} ({alloc_age_for_scoring}y ago, RIPEstat)"
    elif asn and asn.allocated:
        alloc_age_for_scoring = years_since(asn.allocated)
        age_source = f"RIR allocated {alloc_age_for_scoring}y ago"
    elif report.whois_raw:
        # Parse RegDate from system whois as final fallback
        m = re.search(r'RegDate:\s*(\d{4}-\d{2}-\d{2})', report.whois_raw)
        if m:
            alloc_age_for_scoring = years_since(m.group(1))
            age_source = f"whois RegDate {alloc_age_for_scoring}y ago"

    if alloc_age_for_scoring is not None and alloc_age_for_scoring >= 15:
        pos.append(f"IP block established ({age_source}) (+5)")
        reg_score += 5
    elif alloc_age_for_scoring is not None and alloc_age_for_scoring >= 8:
        pos.append(f"IP block established ({age_source}) (+3)")
        reg_score += 3
    elif alloc_age_for_scoring is not None and alloc_age_for_scoring >= 3:
        det.append(f"IP block moderately aged ({age_source}) (-2)")
        reg_score -= 2
    elif alloc_age_for_scoring is not None and alloc_age_for_scoring <= 2:
        reg_score -= 8
        warn.append(f"IP block recently allocated ({age_source}) (-8)")
    else:
        det.append("allocation age unknown (-1)")
        reg_score -= 1

    # FCrDNS
    if dns.fcrdns_ok:
        pos.append(f"FCrDNS confirmed: {dns.ptr} (+3)")
        reg_score += 3
    elif dns.ptr:
        det.append(f"reverse DNS set ({dns.ptr}) but no forward match")
    else:
        det.append("no reverse DNS (PTR) record (-3)")
        reg_score -= 3

    # RPKI
    rpki = report.rpki
    if rpki:
        if rpki.status == "valid":
            pos.append(f"RPKI valid — route origin authorized (+5)")
            reg_score += 5
        elif rpki.status == "invalid":
            reg_score -= 10
            warn.append("RPKI invalid — possible route hijack (-10)")
        else:
            det.append("RPKI status: unknown")
    else:
        det.append("RPKI: no ROAs published — not necessarily suspicious")

    # Abuse contact
    if report.abuse and report.abuse.email:
        pos.append(f"abuse contact published (+2)")
        reg_score += 2
    else:
        det.append("no published abuse contact (-2)")
        reg_score -= 2

    # BGP visibility
    if report.bgp and report.bgp.announced:
        vis = report.bgp.visibility
        if vis >= 90:
            pos.append(f"BGP visibility {vis:.0f}% — widely routed (+2)")
            reg_score += 2
        elif vis >= 50:
            det.append(f"BGP visibility {vis:.0f}%")
        else:
            det.append(f"low BGP visibility ({vis:.0f}%) (-3)")
            reg_score -= 3
    elif report.bgp:
        det.append("prefix not announced in BGP (-8)")
        reg_score -= 8

    # Prefix in WHOIS?  (only penalize when we actually confirmed it's missing)
    ck = report.bgp
    if (ck and ck.source == "RIPEstat prefix-consistency"
            and ck.announced and not ck.prefix_in_whois):
        warn.append("BGP prefix missing from WHOIS registration (-5)")
        reg_score -= 5

    # PTR hostname intelligence — detect Tor/VPN/proxy from reverse DNS
    ptr_lower = dns.ptr.lower() if dns.ptr else ""
    ptr_suspicious = any(kw in ptr_lower for kw in [
        "tor-exit", "tor-relay", "tor-node", "torexit", "tor-proxy",
        "vpn-gateway", "vpn-server", "vpn-node", "proxy-exit", "proxy-node",
        "anonymous-proxy", "anon-proxy",
    ])
    if ptr_suspicious:
        warn.append(f"PTR hostname indicates anonymizing service: {dns.ptr} (-10)")
        reg_score -= 10

    reg_score = max(0, min(reg_score, 30))
    det.append(f"Registration & Entity: {reg_score}/30")
    report.breakdown["registration_entity"] = reg_score

    # ====================================================================
    # DIMENSION 2 — Geo-Registration Consistency (25 pts)
    # ====================================================================
    geo_score = 18
    geo_ip_cc = geo.country_code.upper()
    geo_bgp_cc = (asn.cc or "").upper() if asn else ""

    # IP geo vs BGP registration country
    if geo_bgp_cc and geo_ip_cc:
        if geo_ip_cc == geo_bgp_cc:
            pos.append(f"geo country ({geo_ip_cc}) matches BGP registration ({geo_bgp_cc}) (+7)")
            geo_score += 7
        else:
            geo_score -= 10
            warn.append(f"geo ({geo_ip_cc}) differs from BGP registration ({geo_bgp_cc}) — possible VPN/proxy/hosting (-10)")

    # IP in high-risk country?
    if geo_ip_cc in HIGH_RISK_COUNTRIES:
        geo_score -= 8
        warn.append(f"IP in high-risk/sanctioned country ({geo_ip_cc}) (-8)")

    # Proxy / VPN / hosting flags
    flags = []
    if geo.is_proxy:
        flags.append("proxy")
    if geo.is_hosting:
        flags.append("hosting/public-cloud")
    # PTR-based anonymizer detection
    ptr_lower_geo = dns.ptr.lower() if dns.ptr else ""
    if any(kw in ptr_lower_geo for kw in ["tor-exit", "tor-relay", "tor-node",
                                             "torexit", "tor-proxy", "vpn-gateway",
                                             "vpn-server", "vpn-node", "proxy-exit",
                                             "proxy-node", "anonymous-proxy"]):
        if "tor-exit" not in flags:
            flags.append("tor-exit (PTR)")
    if threat.greynoise_riot:
        flags.clear()
        pos.append("GreyNoise RIOT: known benign service")
    if flags:
        # Calculate penalty: tor-exit/vpn flags are more severe
        penalty = 0
        for f in flags:
            if "tor-exit" in f:
                penalty += 10
            elif "proxy" in f:
                penalty += 8
            else:
                penalty += 3
        geo_score -= penalty
        warn.append(f"privacy flags: {'/'.join(flags)} (-{penalty})")

    # AS organization keywords check
    has_bad_kw = any(kw in asn_org_lower for kw in ["proxy", "anonymous", "vpn"])
    if has_bad_kw:
        geo_score -= 5
        warn.append("AS name contains proxy/VPN indicator (-5)")

    # Source country vs IP geo — large mismatch signals suspicious routing
    if src_cc and geo_ip_cc and src_cc != geo_ip_cc:
        src_continent = country_to_continent(src_cc)
        geo_continent = country_to_continent(geo_ip_cc)
        if src_continent and geo_continent and src_continent != geo_continent:
            geo_score -= 7
            warn.append(
                f"IP in {geo_ip_cc} ({geo_continent}) vs source {src_cc}"
                f" ({src_continent}) — different continent (-7)"
            )
        else:
            geo_score -= 3
            det.append(
                f"IP in {geo_ip_cc} differs from source {src_cc}"
                f" — cross-country routing (-3)"
            )

    geo_score = max(0, min(geo_score, 30))
    det.append(f"Geo-Registration Consistency: {geo_score}/25")
    report.breakdown["geo_match"] = geo_score

    # ====================================================================
    # DIMENSION 3 — Source-Location Consistency (10 pts)
    #   Staged penalties: a CDN/server in a neighbouring country is normal;
    #   an IP registered on a different continent from the user is not.
    # ====================================================================
    src_score = 10

    if src_cc:
        src_cc = country_name_to_code(src_cc)
        det.append(f"source location: {src_cc}")

        src_matches_geo = (src_cc == geo_ip_cc) if geo_ip_cc else None
        src_matches_bgp = (src_cc == geo_bgp_cc) if geo_bgp_cc else None

        # Three-way: source, IP location, and BGP registration ALL differ
        three_way = (
            geo_ip_cc and geo_bgp_cc
            and src_cc != geo_ip_cc
            and src_cc != geo_bgp_cc
            and geo_ip_cc != geo_bgp_cc  # geo and BGP must also disagree
        )

        if src_matches_geo and src_matches_bgp:
            # Perfect: everything lines up
            pos.append(f"source ({src_cc}) consistent with IP location and BGP registration")
        elif src_matches_geo and src_matches_bgp is False:
            # IP geolocated near user but ASN registered elsewhere — mild
            src_score -= 3
            det.append(f"source ({src_cc}) matches IP location but not BGP registration ({geo_bgp_cc}) (-3)")
        elif src_matches_geo is False and src_matches_bgp:
            # ASN registered near user but IP geolocated elsewhere — mild
            src_score -= 3
            det.append(f"source ({src_cc}) matches BGP but IP geolocated in {geo_ip_cc} (-3)")
        elif three_way:
            # All three disagree — strongest signal
            src_score -= 7
            warn.append(f"three-way mismatch: source ({src_cc}) vs IP location ({geo_ip_cc}) vs BGP ({geo_bgp_cc}) (-7)")
        elif src_matches_geo is False and src_matches_bgp is False:
            # Source doesn't match either geo or BGP, but geo=BGP — CDN scenario
            src_score -= 7
            det.append(f"CDN/hosting: IP ({geo_ip_cc}) consistent with BGP but differs from source ({src_cc}) (-7)")

        # Source in high-risk country? (unusual but worth noting)
        if src_cc in HIGH_RISK_COUNTRIES:
            det.append(f"note: source country ({src_cc}) is on high-risk list")
    else:
        src_score = 0
        det.append("Source-Location: not provided (use --source-country to enable)")

    src_score = max(-10, src_score)
    det.append(f"Source-Location Consistency: {src_score}/10")
    report.breakdown["source_consistency"] = src_score

    # ====================================================================
    # DIMENSION 4 — Traceroute Quality (15 pts)
    #   No traceroute data → 0 points. No data is not a perfect score.
    # ====================================================================
    trace_score = 15

    if trace.hops > 0:
        # Hop count
        if trace.hops <= 10:
            det.append(f"hop count: {trace.hops} — excellent")
        elif trace.hops <= 15:
            det.append(f"hop count: {trace.hops} — normal")
        elif trace.hops <= 20:
            trace_score -= 2
            det.append(f"hop count: {trace.hops} — above average (-2)")
        else:
            trace_score -= 5
            det.append(f"hop count: {trace.hops} — high (-5)")

        # Latency
        if trace.avg_latency_ms > 0:
            if trace.avg_latency_ms <= 30:
                det.append(f"avg latency: {trace.avg_latency_ms:.0f}ms — excellent")
            elif trace.avg_latency_ms <= 80:
                det.append(f"avg latency: {trace.avg_latency_ms:.0f}ms — normal")
            elif trace.avg_latency_ms <= 150:
                trace_score -= 3
                det.append(f"avg latency: {trace.avg_latency_ms:.0f}ms — elevated (-3)")
            else:
                trace_score -= 5
                det.append(f"avg latency: {trace.avg_latency_ms:.0f}ms — very high (-5)")

        # Packet loss
        if trace.loss_pct > 10:
            trace_score -= 5
            det.append(f"packet loss: {trace.loss_pct:.0f}% — high (-5)")
        elif trace.loss_pct > 5:
            trace_score -= 3
            det.append(f"packet loss: {trace.loss_pct:.0f}% — elevated (-3)")

        # Routing loops
        if trace.has_loop:
            trace_score -= 5
            warn.append("routing loop detected in traceroute (-5)")

        # Unexpected country hops
        if trace.unexpected_countries:
            penalty = len(trace.unexpected_countries) * 3
            trace_score -= penalty
            warn.append(f"unexpected country hops: {', '.join(trace.unexpected_countries)} (-{penalty})")
    else:
        trace_score = 8
        det.append("traceroute: not available — 8/15 (use --traceroute via Globalping)")

    trace_score = max(0, trace_score)
    det.append(f"Traceroute Quality: {trace_score}/15")
    report.breakdown["traceroute"] = trace_score

    # ====================================================================
    # DIMENSION 5 — Threat Intelligence (20 pts)
    #   Without API keys: neutral midpoint (7/20). No reports ≠ clean.
    # ====================================================================
    threat_score = 11  # slightly conservative neutral — real threat hits penalise hard

    # GreyNoise
    gn_class = threat.greynoise_class
    if gn_class:
        det.append(f"GreyNoise: {gn_class} (RIOT={threat.greynoise_riot})")
        if gn_class == "malicious":
            threat_score -= 12
            warn.append("GreyNoise classifies IP as malicious (-12)")
        elif gn_class == "noise":
            threat_score -= 3
            det.append("GreyNoise: background internet scanner — low concern (-3)")
        elif gn_class == "benign":
            threat_score += 5
            pos.append("GreyNoise: known benign (+5)")
        else:  # "unknown" — no scan data, typical for clean IPs
            threat_score += 3
            pos.append("GreyNoise: no scan data — typical for clean IPs (+3)")
    else:
        det.append("GreyNoise: no data")

    # AbuseIPDB
    abuse_score = threat.abuseipdb_score
    if abuse_score > 0:
        det.append(f"AbuseIPDB: {abuse_score}% confidence ({threat.abuseipdb_total} reports)")
        if abuse_score >= 80:
            threat_score -= 15
            warn.append(f"AbuseIPDB high confidence ({abuse_score}%) — likely malicious (-15)")
        elif abuse_score >= 50:
            threat_score -= 8
            warn.append(f"AbuseIPDB moderate confidence ({abuse_score}%) (-8)")
        elif abuse_score >= 20:
            threat_score -= 4
            det.append(f"AbuseIPDB low confidence ({abuse_score}%) — minor concern (-4)")
    else:
        if "AbuseIPDB" in report.api_keys:
            det.append("AbuseIPDB: no reports (API key OK) — no threat data")
        else:
            det.append("AbuseIPDB: no data (API key not provided)")

    # OTX pulses
    otx = threat.otx_pulses
    if otx > 0:
        det.append(f"OTX: {otx} threat pulses")
        if otx >= 10:
            threat_score -= 8
            warn.append(f"OTX: {otx} threat pulses — high (-8)")
        elif otx >= 5:
            threat_score -= 4
            warn.append(f"OTX: {otx} threat pulses — moderate (-4)")
        elif otx >= 1:
            threat_score -= 2
            det.append(f"OTX: {otx} threat pulses — low (-2)")
    else:
        if "OTX" in report.api_keys:
            det.append("OTX: no threat pulses (API key OK) — clean")
        else:
            det.append("OTX: no data (API key not provided)")

    # OTX malware associations
    if threat.otx_malware:
        penalty = min(len(threat.otx_malware) * 2, 6)
        threat_score -= penalty
        warn.append(f"OTX malware associations: {', '.join(threat.otx_malware)} (-{penalty})")

    threat_score = max(0, threat_score)
    det.append(f"Threat Intelligence: {threat_score}/20")
    report.breakdown["threat_intel"] = threat_score

    # ====================================================================
    # Final
    # ====================================================================
    score = reg_score + geo_score + src_score + trace_score + threat_score
    score = max(0, min(score, 100))

    report.warnings = warn
    report.positives = pos
    report.details = det

    if score >= 80:
        report.grade = "A"
    elif score >= 65:
        report.grade = "B"
    elif score >= 50:
        report.grade = "C"
    elif score >= 35:
        report.grade = "D"
    else:
        report.grade = "F"

    return score


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"


def grade_color(grade: str) -> str:
    if grade == "A":
        return f"{GREEN}{grade}{RESET}"
    elif grade == "B":
        return f"{CYAN}{grade}{RESET}"
    elif grade == "C":
        return f"{YELLOW}{grade}{RESET}"
    else:
        return f"{RED}{grade}{RESET}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    # Load .env file BEFORE argparse — env vars feed argparse defaults
    _load_dotenv()

    parser = argparse.ArgumentParser(
        description="IP Reputation Engine — firewall-aligned scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 ip_reputation.py 8.8.8.8
  python3 ip_reputation.py 45.33.32.156 --source-country DE
  python3 ip_reputation.py 185.220.101.1 --json report.json

API keys can be stored in a .env file (copy .env.example → .env and edit).
CLI flags and real env vars override .env values.
        """,
    )
    parser.add_argument("ip", help="target IPv4 address")
    parser.add_argument("--source-country", "-s",
                        help="your country (e.g. DE, Germany). Enables source-location consistency check. "
                             "Also settable via SOURCE_COUNTRY env var.")
    parser.add_argument("--traceroute", action="store_true",
                        help="enable traceroute via Globalping (free, no root required)")
    parser.add_argument("--no-traceroute", action="store_true",
                        help=argparse.SUPPRESS)  # deprecated — kept for backwards compat
    parser.add_argument("--json", metavar="FILE",
                        help="export full report as JSON to FILE")
    parser.add_argument("--abuseipdb-key",
                        default=os.environ.get("ABUSEIPDB_KEY", ""),
                        help="AbuseIPDB API key (env: ABUSEIPDB_KEY)")
    parser.add_argument("--ipinfo-key",
                        default=os.environ.get("IPINFO_TOKEN", ""),
                        help="ipinfo.io API token (env: IPINFO_TOKEN)")
    parser.add_argument("--otx-key",
                        default=os.environ.get("OTX_KEY", ""),
                        help="AlienVault OTX API key (env: OTX_KEY)")
    parser.add_argument("--maxmind-key",
                        default=os.environ.get("MAXMIND_KEY", ""),
                        help="MaxMind GeoLite2 license key (env: MAXMIND_KEY)")

    args = parser.parse_args()
    ip = args.ip.strip()

    # Validate IP format
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except (OSError, AttributeError):
        print(f"error: '{ip}' is not a valid IPv4 address", file=sys.stderr)
        sys.exit(1)

    # Source country: CLI overrides env var
    source_country = args.source_country or os.environ.get("SOURCE_COUNTRY", "")

    # Track which API keys the user provided (for smarter scoring messages)
    api_keys = set()
    if args.abuseipdb_key:
        api_keys.add("AbuseIPDB")
    if args.otx_key:
        api_keys.add("OTX")
    if args.ipinfo_key:
        api_keys.add("ipinfo")

    report = Report(
        ip=ip,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_country=source_country,
        api_keys=api_keys,
    )

    sources_used: list[str] = []
    sources_failed: list[str] = []

    # ------------------------------------------------------------------
    # Phase 1 — Data Collection
    # ------------------------------------------------------------------
    print()

    # 1. ip-api.com
    print("  [1/8] ip-api.com — geolocation ...", end=" ", flush=True)
    report.geo = lookup_geo(ip)
    if report.geo.country:
        sources_used.append("ip-api.com")
        flags = []
        if report.geo.is_proxy:
            flags.append("proxy")
        if report.geo.is_hosting:
            flags.append("hosting")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        print(f"OK ({report.geo.country}, {report.geo.org or report.geo.isp}){flag_str}")
    else:
        sources_failed.append("ip-api.com")
        print("FAIL")

    # 2. Team Cymru (with HTTP fallback if port 43 is blocked)
    print("  [2/8] Team Cymru — BGP origin ASN ...", end=" ", flush=True)
    report.asn = lookup_cymru(ip)
    if report.asn.asn:
        sources_used.append("Team Cymru")
        print(f"OK (AS{report.asn.asn}, {report.asn.cc}, alloc {report.asn.allocated})")
    else:
        # Fallback: HTTP-based ASN lookup (RIPEstat + ip-api)
        report.asn = lookup_asn_http_fallback(ip, report.geo)
        if report.asn.asn:
            sources_used.append(report.asn.source)
            print(f"OK (AS{report.asn.asn}, {report.asn.cc}, {report.asn.source})")
        else:
            sources_failed.append("Team Cymru")
            print("FAIL")

    # 3. RIPEstat (4 calls)
    # 3a. RPKI by ASN
    print("  [3/8] RIPEstat — RPKI (by ASN) ...", end=" ", flush=True)
    if report.asn and report.asn.asn:
        report.rpki = lookup_ripestat_rpki_asn(report.asn.asn)
        if report.rpki:
            sources_used.append("RIPEstat RPKI")
            print(f"OK ({report.rpki.status})")
        else:
            print("no ROAs found")
    else:
        print("skipped (no ASN)")

    # 3b. Prefix routing consistency
    print("  [3b]   RIPEstat — prefix routing consistency ...", end=" ", flush=True)
    report.bgp = lookup_ripestat_prefix_consistency(ip)
    consistency_ok = report.bgp.announced
    if consistency_ok:
        print(f"OK (in BGP{'+WHOIS' if report.bgp.prefix_in_whois else ', missing from WHOIS'})")
    else:
        print("FAIL")

    # 3c. BGP visibility (separate call for first_seen, visibility)
    print("  [3c]   RIPEstat — BGP visibility ...", end=" ", flush=True)
    bgp_detail = lookup_ripestat_bgp(ip)
    if bgp_detail.announced:
        sources_used.append("RIPEstat BGP")
        # Merge BGP detail into report.bgp
        report.bgp.announced = bgp_detail.announced
        report.bgp.first_seen = bgp_detail.first_seen
        report.bgp.last_seen = bgp_detail.last_seen
        report.bgp.visibility = bgp_detail.visibility
        report.bgp.source = "RIPEstat BGP"
        print(f"OK (announced, {report.bgp.visibility:.0f}% visibility)")
    elif bgp_detail.source:
        print("OK (not announced)")
    else:
        print("FAIL")

    # 3d. Abuse contact
    print("  [3d]   RIPEstat — abuse contact ...", end=" ", flush=True)
    report.abuse = lookup_ripestat_abuse(ip) or AbuseContact()
    if report.abuse and report.abuse.email:
        sources_used.append("RIPEstat Abuse")
        print(f"OK ({report.abuse.email})")
    else:
        print("not found")

    # 4. DNS reverse
    print("  [4/8] DNS — reverse PTR lookup ...", end=" ", flush=True)
    report.dns = lookup_dns(ip)
    if report.dns.fcrdns_ok:
        sources_used.append("DNS reverse")
        print(f"OK ({report.dns.ptr}, FCrDNS OK)")
    elif report.dns.ptr:
        print(f"OK ({report.dns.ptr}, no forward match)")
    else:
        print("no PTR record")

    # 5. system whois
    print("  [5/8] system whois — registration ...", end=" ", flush=True)
    report.whois_raw = lookup_whois(ip)
    if report.whois_raw:
        sources_used.append("system whois")
        # Extract first meaningful non-referral line
        shown = False
        for line in report.whois_raw.split("\n"):
            line = line.strip()
            if not line or line.startswith("%") or line.startswith("#"):
                continue
            if line.lower().startswith("refer:") or line.lower().startswith("whois:"):
                continue
            print(f"OK ({line[:70]})")
            shown = True
            break
        if not shown:
            print("OK")
    else:
        print("FAIL")

    # 6. GreyNoise
    print("  [6/8] GreyNoise Community — classification ...", end=" ", flush=True)
    gn = lookup_greynoise(ip)
    if gn.get("rate_limited"):
        report.threat.greynoise_class = None
        print("rate limited (25 req/week free tier)")
    elif gn.get("message") == "Success" or gn.get("classification"):
        report.threat.greynoise_class = gn.get("classification", "unknown")
        report.threat.greynoise_riot = gn.get("riot", False)
        sources_used.append("GreyNoise")
        riot_str = " (RIOT — known benign)" if report.threat.greynoise_riot else ""
        print(f"OK ({report.threat.greynoise_class}{riot_str})")
    elif gn.get("classification") == "unknown":
        report.threat.greynoise_class = "unknown"
        sources_used.append("GreyNoise")
        print("OK (no scan data)")
    else:
        print("unavailable (network) — score unaffected")

    # 7. AbuseIPDB (optional key)
    if args.abuseipdb_key:
        print("  [7/8] AbuseIPDB — abuse confidence ...", end=" ", flush=True)
        ab = lookup_abuseipdb(ip, args.abuseipdb_key)
        if ab is not None and ab:
            report.threat.abuseipdb_score = ab.get("abuseConfidenceScore", 0)
            report.threat.abuseipdb_total = ab.get("totalReports", 0)
            report.threat.abuseipdb_country = ab.get("countryCode", "")
            report.threat.abuseipdb_isp = ab.get("isp", "")
            sources_used.append("AbuseIPDB")
            print(f"OK ({report.threat.abuseipdb_score}% confidence, "
                  f"{report.threat.abuseipdb_total} reports)")
        elif ab is not None:
            # Empty dict = auth failure (401/403)
            print("FAIL (check API key)")
        else:
            print("FAIL (network/API down)")

    # 8. OTX (optional key)
    if args.otx_key:
        print("  [8/8] AlienVault OTX — threat pulses ...", end=" ", flush=True)
        otx = lookup_otx(ip, args.otx_key)
        if otx:
            pulses = otx.get("pulse_info", {}).get("count", 0)
            report.threat.otx_pulses = pulses
            malware = otx.get("malware", [])
            if isinstance(malware, list):
                report.threat.otx_malware = [m.get("name", "") for m in malware if isinstance(m, dict)]
            sources_used.append("AlienVault OTX")
            print(f"OK ({pulses} pulses)" + (
                f", malware: {', '.join(report.threat.otx_malware)}"
                if report.threat.otx_malware else ""))
        else:
            print("FAIL")

    # ipinfo.io (optional key — supplemental geo)
    if args.ipinfo_key:
        print("  [opt]  ipinfo.io — supplemental geo ...", end=" ", flush=True)
        ii = lookup_ipinfo(ip, args.ipinfo_key)
        if ii:
            sources_used.append("ipinfo.io")
            # Merge privacy flags from ipinfo if ip-api missed them
            privacy = ii.get("privacy", {})
            if privacy:
                if privacy.get("vpn") and not report.geo.is_proxy:
                    report.geo.is_proxy = True
                if privacy.get("hosting") and not report.geo.is_hosting:
                    report.geo.is_hosting = True
            print(f"OK ({ii.get('city', '?')}, {ii.get('country', '?')})")
        else:
            print("FAIL")

    # Traceroute via Globalping (opt-in — no root required)
    if args.traceroute:
        print("  [8/8] Globalping traceroute ...", end=" ", flush=True)
        report.trace = run_traceroute_globalping(ip, source_country=source_country)
        if report.trace.hops > 0:
            sources_used.append("Globalping traceroute")
            loc_info = ""
            # Extract probe location from raw_output header line
            first_line = report.trace.raw_output.split("\n")[0] if report.trace.raw_output else ""
            if " from " in first_line:
                loc_info = first_line.split(" from ", 1)[1].split("\n")[0]
            print(f"OK ({report.trace.hops} hops, "
                  f"{report.trace.avg_latency_ms:.0f}ms avg, "
                  f"{report.trace.loss_pct:.0f}% loss" +
                  (" [LOOP]" if report.trace.has_loop else "") +
                  (f", {loc_info}" if loc_info else "") +
                  ")")
        else:
            err = report.trace.raw_output or "unknown error"
            print(f"FAIL — {err}")
    else:
        print("  [8/8] Globalping traceroute: skipped (enable with --traceroute)")

    # ------------------------------------------------------------------
    # Phase 2 — Scoring
    # ------------------------------------------------------------------
    print()
    print(f"  {BOLD}Scoring ...{RESET}")
    score = compute_score(report)
    report.score = score

    for d in report.details:
        indent = "    "
        if d.startswith("source-location") or d.startswith("Source-Location"):
            print(f"    {YELLOW}{d}{RESET}")
        elif any(kw in d.lower() for kw in ["registration", "entity", "geo-registration",
                                              "traceroute", "threat intelligence"]):
            print(f"    {CYAN}{d}{RESET}")
        else:
            print(f"    {d}")

    for w in report.warnings:
        print(f"    {RED}[!] {w}{RESET}")

    for p in report.positives:
        print(f"    {GREEN}[+] {p}{RESET}")

    # ------------------------------------------------------------------
    # Phase 3 — Output
    # ------------------------------------------------------------------
    print()
    print(f"  IP: {ip}  |  Score: {BOLD}{score}/100{RESET}  |  Grade: {grade_color(report.grade)}")
    print(f"  Sources used: {', '.join(sources_used)}")
    if sources_failed:
        print(f"  {YELLOW}Sources failed: {', '.join(sources_failed)}{RESET}")
    if not HAS_REQUESTS:
        print(f"  {YELLOW}Note: install 'requests' for API lookups: pip install requests{RESET}")

    # JSON export
    if args.json:
        out = {
            "ip": report.ip,
            "timestamp": report.timestamp,
            "source_country": report.source_country,
            "score": report.score,
            "grade": report.grade,
            "breakdown": report.breakdown,
            "warnings": report.warnings,
            "positives": report.positives,
            "details": report.details,
            "geo": asdict(report.geo),
            "asn": asdict(report.asn),
            "rpki": asdict(report.rpki) if report.rpki else None,
            "bgp": asdict(report.bgp),
            "abuse_contact": asdict(report.abuse) if report.abuse else None,
            "dns": asdict(report.dns),
            "traceroute": {
                "hops": report.trace.hops,
                "avg_latency_ms": report.trace.avg_latency_ms,
                "loss_pct": report.trace.loss_pct,
                "has_loop": report.trace.has_loop,
                "unexpected_countries": report.trace.unexpected_countries,
            },
            "threat": asdict(report.threat),
            "sources_used": sources_used,
        }
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"\n  Report saved to {args.json}")


if __name__ == "__main__":
    main()
