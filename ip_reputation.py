#!/usr/bin/env python3
"""
IP Reputation Scoring Engine

A firewall-aligned tool that scores any public IP address (0-100) based on
registration/entity identity, geo-routing consistency, traceroute quality,
source-location relevance, and multi-source threat intelligence.

Queries up to 10 data sources. No API keys needed for the 7 free sources.

Author: WorkBuddy (built for tudortoma)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from typing import Optional

import requests

# ── Constants ────────────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 10  # seconds per HTTP call
SESSION = requests.Session()
SESSION.headers["User-Agent"] = "IP-Reputation-Engine/2.0"

# Known benign provider keywords (reduce false positives in hosting/port checks)
KNOWN_PROVIDER_KEYWORDS = {
    "google", "cloudflare", "akamai", "fastly", "amazon", "aws",
    "microsoft", "azure", "facebook", "apple", "netflix", "twitter",
    "github", "cloudfront", "edgecast", "cachefly", "incapsula",
    "digitalocean", "linode", "ovh", "hetzner", "vultr",
}

# High-risk countries: sanctioned states + known malicious hosting hubs
HIGH_RISK_COUNTRIES = {
    "KP", "IR", "SY", "CU", "RU", "BY", "MM",
}

# ASN keywords that suggest bulletproof / shady hosting
SUSPICIOUS_AS_KEYWORDS = {
    "bulletproof", "proxy", "anonymous", "vpn provider",
    "dedicated ddos", "offshore hosting", "pirate",
    "spamhaus", "criminal",
}

# PTR hostname keywords for VPN/proxy/Tor detection
PTR_SUSPICIOUS_KEYWORDS = {
    "tor-exit", "tor-relay", "torexit", "tor.relay",
    "vpn", "proxy", "anonymous", "anon",
}

# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class GeoData:
    country: str = ""
    country_code: str = ""
    city: str = ""
    region: str = ""
    isp: str = ""
    org: str = ""
    as_number: str = ""
    as_name: str = ""
    is_proxy: bool = False
    is_hosting: bool = False
    latitude: float = 0.0
    longitude: float = 0.0
    reverse_dns: str = ""
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
    status: str = "unknown"  # valid / invalid / unknown
    prefix: str = ""
    asn: str = ""
    source: str = ""


@dataclass
class BgpRouting:
    announced: bool = False
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
class ThreatIntel:
    greynoise_class: str = ""       # malicious, noise, unknown, benign
    greynoise_riot: bool = False    # RIOT = known benign service
    greynoise_name: str = ""
    abuseipdb_score: int = 0
    abuseipdb_total: int = 0
    otx_pulse_count: int = 0
    otx_malware: list[str] = field(default_factory=list)


@dataclass
class TracerouteResult:
    hop_count: int = 0
    avg_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    packet_loss_pct: float = 0.0
    has_loops: bool = False
    transit_countries: list[str] = field(default_factory=list)
    raw: str = ""
    error: str = ""


@dataclass
class Report:
    ip: str = ""
    source_country: str = ""
    geo: Optional[GeoData] = None
    asn: Optional[AsnResult] = None
    rpki: Optional[RpkiResult] = None
    bgp: Optional[BgpRouting] = None
    abuse_contact: Optional[AbuseContact] = None
    threat: ThreatIntel = field(default_factory=ThreatIntel)
    traceroute: Optional[TracerouteResult] = None
    whois_raw: str = ""
    score: int = 0
    grade: str = ""
    breakdown: dict = field(default_factory=dict)
    positives: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get(url: str, params: dict | None = None) -> dict | None:
    """HTTP GET with timeout, returns parsed JSON or None."""
    try:
        r = SESSION.get(url, params=params, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def years_since(date_str: str) -> Optional[int]:
    """Return whole years since a date-like string (YYYY-MM-DD, ISO timestamp, etc)."""
    if not date_str:
        return None
    try:
        # Handle ISO timestamps like "2002-11-06T16:00:00"
        clean = date_str.strip().split("T")[0]
        parts = clean.split("-")
        year = int(parts[0])
        month = int(parts[1]) if len(parts) > 1 else 1
        day = int(parts[2]) if len(parts) > 2 else 1
    except (ValueError, IndexError):
        return None
    d = date(year, month, day)
    return date.today().year - d.year - ((date.today().month, date.today().day) < (d.month, d.day))


def _whois_raw(query: str, server: str = "whois.cymru.com", port: int = 43) -> str:
    """Raw whois query over TCP port 43."""
    try:
        sock = socket.create_connection((server, port), timeout=8)
        sock.sendall((query + "\r\n").encode())
        chunks: list[str] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data.decode(errors="replace"))
        sock.close()
        return "".join(chunks)
    except Exception:
        return ""


# ── Data Source Functions ────────────────────────────────────────────────────

# ── 1. ip-api.com (free tier, no key) ───────────────────────────────────────

def lookup_ip_api(ip: str) -> Optional[GeoData]:
    """Query ip-api.com for geolocation and proxy/hosting flags."""
    data = _get(f"http://ip-api.com/json/{ip}",
                params={"fields": "country,countryCode,city,regionName,isp,org,as,"
                                  "proxy,hosting,lat,lon,reverse,query"})
    if not data or data.get("country") is None:
        return None
    as_raw = data.get("as", "").split()
    asn = as_raw[0] if as_raw else ""
    as_name = " ".join(as_raw[1:]) if len(as_raw) > 1 else ""
    return GeoData(
        country=data.get("country", ""),
        country_code=data.get("countryCode", ""),
        city=data.get("city", ""),
        region=data.get("regionName", ""),
        isp=data.get("isp", ""),
        org=data.get("org", ""),
        as_number=asn,
        as_name=as_name,
        is_proxy=bool(data.get("proxy", False)),
        is_hosting=bool(data.get("hosting", False)),
        latitude=float(data.get("lat", 0)),
        longitude=float(data.get("lon", 0)),
        reverse_dns=data.get("reverse", ""),
        source="ip-api.com",
    )


# ── 2. Team Cymru IP-to-ASN (whois port 43, no key) ─────────────────────────

def lookup_cymru(ip: str) -> AsnResult:
    """Query Team Cymru IP-to-ASN via whois protocol."""
    raw = _whois_raw(f"-v {ip}")
    if not raw:
        return AsnResult(source="Team Cymru (failed)")
    lines = [l.strip() for l in raw.split("\n") if l.strip() and not l.startswith("%")]
    # Team Cymru -v output: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    for line in reversed(lines):
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 6:
            return AsnResult(
                asn=parts[0],
                prefix=parts[2],       # BGP Prefix column
                cc=parts[3],            # CC column
                registry=parts[4],      # Registry column
                allocated=parts[5],     # Allocated column
                as_name=parts[6] if len(parts) > 6 else "",
                source="Team Cymru IP-to-ASN",
            )
    return AsnResult(source="Team Cymru (no data)")


# ── 2b. RIPEstat ASN overview (HTTP fallback for Team Cymru) ─────────────────

def lookup_ripestat_asn_overview(asn: str) -> dict:
    """HTTP fallback — get ASN holder, country, registration dates from RIPEstat."""
    data = _get(f"https://stat.ripe.net/data/as-overview/data.json",
                params={"resource": f"AS{asn}"})
    if not data or data.get("status") != "ok":
        return {}
    d = data.get("data", {})
    # Build a synthetic AsnResult-like dict
    holder = d.get("holder", "")
    country = d.get("country", "")
    first = d.get("first_seen", {})
    last = d.get("last_seen", {})
    allocated = ""
    if isinstance(first, dict):
        allocated = first.get("date", "")
    return {
        "asn": str(d.get("asn", asn)),
        "cc": country,
        "allocated": allocated,
        "as_name": holder,
    }


# ── 3. RIPEstat — RPKI validation (by ASN) ───────────────────────────────────

def lookup_ripestat_rpki_asn(asn: str) -> Optional[RpkiResult]:
    """Check RPKI Route Origin Validation by ASN via RIPEstat."""
    data = _get(f"https://stat.ripe.net/data/rpki-validation/data.json",
                params={"resource": f"AS{asn}", "max_roas": "5"})
    if not data or data.get("status") != "ok":
        return None
    roas = data.get("data", {}).get("validating_roas", [])
    if not roas:
        return RpkiResult(status="no_roas", source="RIPEstat RPKI")
    roa = roas[0]
    return RpkiResult(
        status=roa.get("status", "unknown"),
        prefix=roa.get("prefix", ""),
        asn=str(roa.get("origin", "")),
        source="RIPEstat RPKI",
    )


# ── 4. RIPEstat — prefix-routing-consistency ─────────────────────────────────

def lookup_ripestat_prefix_consistency(ip: str) -> Optional[BgpRouting]:
    """Check if BGP prefix exists in WHOIS registries."""
    data = _get(f"https://stat.ripe.net/data/prefix-routing-consistency/data.json",
                params={"resource": ip})
    if not data or data.get("status") != "ok":
        return None
    rd = data.get("data", {})
    consistencies = rd.get("consistencies", [])
    if consistencies:
        c = consistencies[0]
        return BgpRouting(
            announced=True,
            prefix_in_whois=c.get("in_whois", False),
            source="RIPEstat prefix-consistency",
        )
    return BgpRouting(source="RIPEstat prefix-consistency")


# ── 5. RIPEstat — BGP routing status ─────────────────────────────────────────

def lookup_ripestat_bgp(ip: str) -> Optional[BgpRouting]:
    """Get BGP routing visibility and history from RIPEstat."""
    data = _get("https://stat.ripe.net/data/routing-status/data.json",
                params={"resource": ip})
    if not data or data.get("status") != "ok":
        return None
    rd = data.get("data", {})
    # visibility: {v4: {ris_peers_seeing: N, total_ris_peers: N}, v6: {...}}
    vis_raw = rd.get("visibility", {})
    if isinstance(vis_raw, dict):
        v4 = vis_raw.get("v4", {})
        if isinstance(v4, dict) and v4.get("total_ris_peers", 0) > 0:
            vis = (v4.get("ris_peers_seeing", 0) / v4["total_ris_peers"]) * 100.0
        else:
            vis = 0.0
    elif isinstance(vis_raw, (int, float)):
        vis = float(vis_raw)
    else:
        vis = 0.0
    status = rd.get("status", "")
    first_seen = rd.get("first_seen", {})
    last_seen = rd.get("last_seen", {})
    fs = ""
    ls = ""
    if isinstance(first_seen, dict):
        fs = first_seen.get("time", first_seen.get("date", ""))
    if isinstance(last_seen, dict):
        ls = last_seen.get("time", last_seen.get("date", ""))
    return BgpRouting(
        announced=vis > 0,
        first_seen=fs,
        last_seen=ls,
        visibility=vis,
        source="RIPEstat BGP",
    )


# ── 6. RIPEstat — abuse contact ──────────────────────────────────────────────

def lookup_ripestat_abuse(ip: str) -> Optional[AbuseContact]:
    """Look up abuse contact email via RIPEstat."""
    data = _get("https://stat.ripe.net/data/abuse-contact-finder/data.json",
                params={"resource": ip})
    if not data or data.get("status") != "ok":
        return None
    rd = data.get("data", {})
    contacts = rd.get("abuse_contacts", [])
    if contacts:
        return AbuseContact(
            email=contacts[0],
            source="RIPEstat Abuse",
        )
    return None


# ── 7. GreyNoise Community API (no key, rate-limited) ────────────────────────

def lookup_greynoise(ip: str) -> dict:
    """Query GreyNoise Community API. Handles 404 for well-known IPs gracefully."""
    try:
        r = SESSION.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 404:
            return {"classification": "unknown", "message": "No data"}
        if r.status_code == 429:
            return {"classification": "unknown", "rate_limited": True}
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


# ── 8. AbuseIPDB (free API key required) ─────────────────────────────────────

def lookup_abuseipdb(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB v2 for abuse confidence score."""
    data = _get("https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
                )
    # AbuseIPDB uses a custom header, not a query param
    try:
        r = SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


# ── 9. AlienVault OTX (free API key required) ────────────────────────────────

def lookup_otx(ip: str, api_key: str = "") -> dict:
    """Query AlienVault OTX for threat pulses associated with this IP."""
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    try:
        r = SESSION.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


# ── 10. System whois ─────────────────────────────────────────────────────────

def lookup_whois(ip: str) -> str:
    """Run system `whois` command to get registration data."""
    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout
    except Exception:
        return ""


# ── 11. System traceroute ────────────────────────────────────────────────────

def run_traceroute(ip: str, max_hops: int = 30) -> TracerouteResult:
    """Run macOS traceroute and parse hop count, latency, and transit countries."""
    result = TracerouteResult()
    try:
        proc = subprocess.run(
            ["traceroute", "-n", "-m", str(max_hops), "-q", "2", "-w", "3", ip],
            capture_output=True, text=True, timeout=90,
        )
        raw = proc.stderr + "\n" + proc.stdout
        result.raw = raw
        if proc.returncode != 0:
            result.error = raw.strip()
            return result
        raw = proc.stdout
    except subprocess.TimeoutExpired:
        result.error = "traceroute timed out"
        return result
    except FileNotFoundError:
        result.error = "traceroute command not found"
        return result

    # Parse hops
    latencies: list[float] = []
    hop_lines = 0
    seen_ips: set[str] = set()

    for line in raw.strip().split("\n"):
        if not line.strip() or line.startswith("traceroute"):
            continue
        hop_lines += 1
        # Extract IPs and latencies
        ip_matches = re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", line)
        time_matches = re.findall(r"(\d+\.\d+)\s*ms", line)

        for t in time_matches:
            latencies.append(float(t))

        # Detect loops (same IP appearing on multiple hops)
        unique_before = len(seen_ips)
        seen_ips.update(ip_matches)
        if len(seen_ips) == unique_before and ip_matches:
            continue  # same IP on a later line is suspicious
        elif len(seen_ips) < unique_before + len(ip_matches):
            result.has_loops = True

    result.hop_count = hop_lines
    if latencies:
        result.avg_latency_ms = round(sum(latencies) / len(latencies), 1)
        result.max_latency_ms = round(max(latencies), 1)

    # Packet loss approximation: missing reply = "* *"
    expected_replies = hop_lines * 2
    missing = raw.count("*")
    if expected_replies > 0:
        result.packet_loss_pct = round((missing / expected_replies) * 100, 1)

    result.packet_loss_pct = min(result.packet_loss_pct, 100.0)
    return result


# ── Scoring Engine ────────────────────────────────────────────────────────────

def _asn_type_score(asn: Optional[AsnResult], geo: Optional[GeoData]) -> tuple[int, str]:
    """Classify ASN type and return penalty + description."""
    if not asn or not asn.as_name:
        return 0, ""
    name = (asn.as_name + " " + (geo.as_name if geo else "") +
            " " + (geo.isp if geo else "") + " " + (geo.org if geo else "")).lower()

    # Check for suspicious AS keywords first
    for kw in SUSPICIOUS_AS_KEYWORDS:
        if kw in name:
            return -10, f"suspicious AS keyword: '{kw}' (-10)"

    # Hosting / data center
    hosting_kw = {"hosting", "server", "datacenter", "cloud", "vps", "dedicated",
                  "colo", "colocation", "transit"}
    for hk in hosting_kw:
        if hk in name:
            # Penalize unless known provider
            if not any(p in name for p in KNOWN_PROVIDER_KEYWORDS):
                return -5, f"hosting/datacenter AS (-5)"

    # Residential ISP → positive
    isp_kw = {"broadband", "dsl", "fiber", "cable", "telecom", "residential",
              "mobile", "wireless", "cellular", "isp", "communications"}
    for ik in isp_kw:
        if ik in name:
            return 3, "residential/ISP AS (+3)"

    # Government / academic
    edu_gov = {"university", "college", "academic", "government",
               "federal", "municipal", "institute", "research"}
    for eg in edu_gov:
        if eg in name:
            return 5, "academic/government AS (+5)"

    return 0, ""


def score_report(report: Report) -> Report:
    """Run the full scoring engine against a populated Report. Modifies in-place."""
    geo = report.geo
    asn = report.asn
    rpki = report.rpki
    bgp = report.bgp
    abuse = report.abuse_contact
    threat = report.threat
    trace = report.traceroute
    source_cc = report.source_country.upper()

    pos: list[str] = []    # positive findings
    warn: list[str] = []   # warnings / penalties
    det: list[str] = []    # neutrals / info

    # ── DIMENSION 1: Registration & Entity (30 pts) ──────────────────────
    reg_score = 30

    # ASN type classification
    asn_penalty, asn_note = _asn_type_score(asn, geo)
    reg_score += asn_penalty
    if asn_note:
        if asn_penalty < 0:
            warn.append(asn_note)
        else:
            pos.append(asn_note)

    # Allocation age (prefer BGP first_seen; fall back to RIR allocated date)
    alloc_age = None
    age_source = ""
    if bgp and bgp.first_seen:
        alloc_age = years_since(bgp.first_seen)
        age_source = f"BGP first seen {alloc_age}y ago"
    elif asn and asn.allocated:
        alloc_age = years_since(asn.allocated)
        age_source = f"RIR allocated {alloc_age}y ago"

    if alloc_age is not None and alloc_age >= 15:
        pos.append(f"{age_source} — well-established (+5)")
        reg_score += 5
    elif alloc_age is not None and alloc_age >= 8:
        pos.append(f"{age_source} (+3)")
        reg_score += 3
    elif alloc_age is not None and alloc_age >= 3:
        det.append(f"{age_source} (neutral)")
    elif alloc_age is not None and alloc_age <= 2:
        reg_score -= 8
        warn.append(f"{age_source} — recently allocated (-8)")
    else:
        det.append("allocation age unknown")

    # Forward-confirmed reverse DNS
    if geo and geo.reverse_dns:
        try:
            fwd = socket.getaddrinfo(geo.reverse_dns, None)
            resolved = {a[4][0] for a in fwd}
            if report.ip in resolved:
                pos.append("forward-confirmed reverse DNS (+3)")
                reg_score += 3
            else:
                det.append("reverse DNS exists but not forward-confirmed")
        except Exception:
            det.append("reverse DNS exists but unresolvable")
    else:
        det.append("no reverse DNS record")

    # RPKI
    if rpki:
        if rpki.status == "valid":
            pos.append("RPKI valid — route origin authorized (+5)")
            reg_score += 5
        elif rpki.status == "invalid":
            reg_score -= 8
            warn.append("RPKI invalid — possible route hijack (-8)")
        else:
            det.append(f"RPKI status: {rpki.status} (neutral)")

    # Abuse contact
    if abuse and abuse.email:
        pos.append(f"abuse contact registered: {abuse.email} (+2)")
        reg_score += 2
    else:
        det.append("no abuse contact found")

    reg_score = max(0, min(reg_score, 30))
    det.insert(0, f"Registration & Entity: {reg_score}/30")
    report.breakdown["registration_entity"] = reg_score

    # ── DIMENSION 2: Geo Consistency (25 pts) ────────────────────────────
    geo_score = 25

    # IP geolocation country vs BGP origin country
    ip_cc = geo.country_code.upper() if geo else ""
    bgp_cc = asn.cc.upper() if asn else ""

    if ip_cc and bgp_cc:
        if ip_cc == bgp_cc:
            pos.append(f"IP geo ({ip_cc}) matches BGP origin (+5)")
            geo_score += 5
        else:
            geo_score -= 10
            warn.append(f"IP geo ({ip_cc}) mismatches BGP origin ({bgp_cc}) (-10)")

    # High-risk country in either geo or BGP origin
    for cc in [ip_cc, bgp_cc]:
        if cc in HIGH_RISK_COUNTRIES:
            geo_score -= 8
            warn.append(f"high-risk country: {cc} (-8)")
            break  # only penalize once

    # Proxy / VPN / Tor flags
    flags = []
    if geo and geo.is_proxy:
        flags.append("proxy")
    if geo and geo.is_hosting:
        flags.append("hosting/public-cloud")

    # PTR hostname keyword detection for VPN/proxy/Tor
    if geo and geo.reverse_dns:
        rdns_lower = geo.reverse_dns.lower()
        for kw in PTR_SUSPICIOUS_KEYWORDS:
            if kw in rdns_lower:
                flags.append(kw)
                break

    # GreyNoise RIOT = known benign, override flags
    if threat.greynoise_riot:
        flags.clear()
        pos.append("GreyNoise RIOT: known benign service (+5)")
        geo_score += 5

    # Known provider → hosting flag is expected, so clear it
    is_known = threat.greynoise_riot or (
        geo and any(
            kw in (geo.org + " " + geo.isp + " " + geo.as_name).lower()
            for kw in KNOWN_PROVIDER_KEYWORDS
        )
    )
    if is_known and "hosting/public-cloud" in flags:
        flags.remove("hosting/public-cloud")
        det.append("hosting flag ignored — known benign provider")

    if flags:
        geo_score -= len(flags) * 5
        warn.append(f"privacy/infra flags: {'/'.join(flags)} (-{len(flags)*5})")

    geo_score = max(0, min(geo_score, 25))
    det.append(f"Geo Consistency: {geo_score}/25")
    report.breakdown["geo_consistency"] = geo_score

    # ── DIMENSION 3: Source-Location Consistency (10 pts) ────────────────
    src_score = 10
    if source_cc:
        if ip_cc and source_cc == ip_cc:
            pos.append(f"source ({source_cc}) matches IP geolocation (+5)")
            src_score += 5
        elif ip_cc and source_cc != ip_cc:
            src_score -= 5
            warn.append(f"source ({source_cc}) differs from IP geolocation ({ip_cc}) (-5)")

        if bgp_cc and source_cc == bgp_cc:
            pos.append(f"source ({source_cc}) matches BGP registration (+5)")
            src_score += 5
        elif bgp_cc and source_cc != bgp_cc:
            src_score -= 5
            warn.append(f"source ({source_cc}) differs from BGP registration ({bgp_cc}) (-5)")
    else:
        src_score = 0
        det.append("source country not provided — skipped")

    src_score = max(0, min(src_score, 10))
    det.append(f"Source Location: {src_score}/10" if source_cc else "Source Location: skipped")
    report.breakdown["source_location"] = src_score

    # ── DIMENSION 4: Traceroute Quality (15 pts) ─────────────────────────
    route_score = 15
    if trace and trace.hop_count > 0:
        # Hop count
        if trace.hop_count < 10:
            pos.append(f"low hop count ({trace.hop_count}) (+5)")
            route_score += 5
        elif trace.hop_count <= 15:
            det.append(f"moderate hop count ({trace.hop_count}) (+3)")
            route_score += 3
        elif trace.hop_count <= 20:
            det.append(f"high hop count ({trace.hop_count})")
        else:
            route_score -= 3
            warn.append(f"very high hop count ({trace.hop_count}) (-3)")

        # Latency
        if trace.avg_latency_ms < 50:
            pos.append(f"low avg latency ({trace.avg_latency_ms}ms) (+5)")
            route_score += 5
        elif trace.avg_latency_ms <= 100:
            det.append(f"moderate avg latency ({trace.avg_latency_ms}ms) (+3)")
            route_score += 3
        elif trace.avg_latency_ms <= 200:
            det.append(f"high avg latency ({trace.avg_latency_ms}ms)")
        else:
            route_score -= 3
            warn.append(f"very high avg latency ({trace.avg_latency_ms}ms) (-3)")

        # Packet loss
        if trace.packet_loss_pct == 0:
            pos.append("0% packet loss (+5)")
            route_score += 5
        elif trace.packet_loss_pct < 5:
            det.append(f"minor packet loss ({trace.packet_loss_pct}%)")
        elif trace.packet_loss_pct <= 10:
            route_score -= 2
            warn.append(f"moderate packet loss ({trace.packet_loss_pct}%) (-2)")
        else:
            route_score -= 5
            warn.append(f"high packet loss ({trace.packet_loss_pct}%) (-5)")

        # Loops
        if trace.has_loops:
            route_score -= 5
            warn.append("routing loops detected (-5)")

        # Transit through high-risk countries
        risky_transit = [c for c in trace.transit_countries if c in HIGH_RISK_COUNTRIES]
        if risky_transit:
            route_score -= 8
            warn.append(f"route transits high-risk country: {', '.join(risky_transit)} (-8)")
    elif trace and trace.error:
        det.append(f"traceroute failed: {trace.error[:60]}")
    else:
        det.append("traceroute not run (use sudo for ICMP on macOS)")

    route_score = max(0, min(route_score, 15))
    det.append(f"Traceroute Quality: {route_score}/15")
    report.breakdown["traceroute_quality"] = route_score

    # ── DIMENSION 5: Threat Intelligence (20 pts) ────────────────────────
    threat_score = 20

    # GreyNoise
    if threat.greynoise_class == "malicious":
        threat_score -= 12
        warn.append("GreyNoise classifies IP as malicious (-12)")
    elif threat.greynoise_class == "noise":
        det.append("GreyNoise: background scanner — low concern (-2)")
        threat_score -= 2
    elif threat.greynoise_class == "benign":
        pos.append("GreyNoise: classified as benign (+3)")
        threat_score += 3
    elif threat.greynoise_riot:
        pos.append("GreyNoise RIOT: known benign service (+3)")
        threat_score += 3

    if threat.greynoise_name:
        det.append(f"GreyNoise actor: {threat.greynoise_name}")

    # AbuseIPDB
    if threat.abuseipdb_score > 80:
        threat_score -= 12
        warn.append(f"AbuseIPDB confidence {threat.abuseipdb_score}% ({threat.abuseipdb_total} reports) (-12)")
    elif threat.abuseipdb_score > 50:
        threat_score -= 8
        warn.append(f"AbuseIPDB confidence {threat.abuseipdb_score}% (-8)")
    elif threat.abuseipdb_score > 20:
        threat_score -= 4
        det.append(f"AbuseIPDB confidence {threat.abuseipdb_score}% — moderate (-4)")
    elif threat.abuseipdb_score > 0:
        det.append(f"AbuseIPDB confidence {threat.abuseipdb_score}% — low")

    # OTX pulses
    if threat.otx_pulse_count > 10:
        threat_score -= 10
        warn.append(f"OTX: {threat.otx_pulse_count} threat pulses (-10)")
    elif threat.otx_pulse_count > 3:
        threat_score -= 5
        warn.append(f"OTX: {threat.otx_pulse_count} threat pulses (-5)")
    elif threat.otx_pulse_count > 0:
        det.append(f"OTX: {threat.otx_pulse_count} threat pulses")

    if threat.otx_malware:
        det.append(f"OTX malware families: {', '.join(threat.otx_malware[:5])}")

    # BGP visibility
    if bgp and bgp.visibility < 50:
        threat_score -= 5
        warn.append(f"low BGP visibility ({bgp.visibility:.0f}%) — possible shadow routing (-5)")
    elif bgp and bgp.visibility >= 95:
        pos.append(f"high BGP visibility ({bgp.visibility:.0f}%) (+3)")
        threat_score += 3

    threat_score = max(0, min(threat_score, 20))
    det.append(f"Threat Intelligence: {threat_score}/20")
    report.breakdown["threat_intelligence"] = threat_score

    # ── Final score ──────────────────────────────────────────────────────
    total = reg_score + geo_score + src_score + route_score + threat_score
    report.score = total
    report.positives = pos
    report.warnings = warn
    report.details = det

    if total >= 90:
        report.grade = "A"
    elif total >= 80:
        report.grade = "B"
    elif total >= 70:
        report.grade = "C"
    elif total >= 60:
        report.grade = "D"
    else:
        report.grade = "F"

    return report


# ── Main Pipeline ────────────────────────────────────────────────────────────

def analyze_ip(ip: str, source_country: str = "", no_traceroute: bool = False,
               abuseipdb_key: str = "", vt_key: str = "",
               ipinfo_key: str = "", otx_key: str = "") -> Report:
    """Run the full IP reputation analysis pipeline."""
    report = Report(ip=ip, source_country=source_country.upper())
    sources_used: list[str] = []
    sources_failed: list[str] = []

    # Validate IP format
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except (OSError, ValueError):
        print(f"ERROR: '{ip}' is not a valid IPv4 address.", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  IP REPUTATION ANALYSIS — {ip}")
    if source_country:
        print(f"  Source location: {source_country.upper()}")
    print(f"{'='*60}\n")

    # ── 1. ip-api.com (always) ────────────────────────────────────────────
    print("  [1/10] ip-api.com — geolocation ...", end=" ", flush=True)
    report.geo = lookup_ip_api(ip)
    if report.geo:
        sources_used.append("ip-api.com")
        flags = []
        if report.geo.is_proxy:
            flags.append("proxy")
        if report.geo.is_hosting:
            flags.append("hosting")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        print(f"OK ({report.geo.country}, {report.geo.isp[:40] if report.geo.isp else '?'}){flag_str}")
    else:
        sources_failed.append("ip-api.com")
        print("FAIL")

    # ── 2. Team Cymru with HTTP fallback ──────────────────────────────────
    print("  [2/10] Team Cymru — BGP origin ASN ...", end=" ", flush=True)
    report.asn = lookup_cymru(ip)
    if report.asn.asn:
        sources_used.append("Team Cymru")
        print(f"OK (AS{report.asn.asn}, {report.asn.cc}, alloc {report.asn.allocated})")
        # Enrich with RIPEstat ASN overview for better holder info
        asn_extra = lookup_ripestat_asn_overview(report.asn.asn)
        if asn_extra:
            if asn_extra.get("as_name") and not report.asn.as_name:
                report.asn.as_name = asn_extra["as_name"]
            if asn_extra.get("allocated") and not report.asn.allocated:
                report.asn.allocated = asn_extra["allocated"]
    else:
        # HTTP fallback: use ip-api's ASN data with RIPEstat
        if report.geo and report.geo.as_number:
            asn_clean = report.geo.as_number.lstrip("AS")
            asn_extra = lookup_ripestat_asn_overview(asn_clean)
            if asn_extra:
                report.asn = AsnResult(
                    asn=asn_extra.get("asn", asn_clean),
                    cc=asn_extra.get("cc", ""),
                    allocated=asn_extra.get("allocated", ""),
                    as_name=asn_extra.get("as_name", report.geo.as_name),
                    source="RIPEstat AS-overview (fallback)",
                )
                sources_used.append("RIPEstat AS-overview")
                print(f"OK via HTTP fallback (AS{report.asn.asn})")
            else:
                sources_failed.append("Team Cymru")
                print("FAIL (no HTTP fallback either)")
        else:
            sources_failed.append("Team Cymru")
            print("FAIL")

    # ── 3. RIPEstat — multiple endpoints ──────────────────────────────────
    # 3a. Prefix routing consistency
    print("  [3/10] RIPEstat — prefix-consistency ...", end=" ", flush=True)
    report.bgp = lookup_ripestat_prefix_consistency(ip)
    if report.bgp and report.bgp.announced:
        sources_used.append("RIPEstat prefix-consistency")
        print(f"OK (in_whois={report.bgp.prefix_in_whois})")
    elif report.bgp:
        print("OK (no BGP data)")
    else:
        print("FAIL")

    # 3b. BGP routing status (enrich prefix-consistency result)
    print("  [4/10] RIPEstat — BGP routing ...", end=" ", flush=True)
    bgp_detail = lookup_ripestat_bgp(ip)
    if bgp_detail and bgp_detail.announced:
        sources_used.append("RIPEstat BGP")
        # Merge into existing BgpRouting
        if report.bgp is None:
            report.bgp = bgp_detail
        else:
            report.bgp.announced = bgp_detail.announced
            report.bgp.first_seen = bgp_detail.first_seen
            report.bgp.last_seen = bgp_detail.last_seen
            report.bgp.visibility = bgp_detail.visibility
            report.bgp.source += " + BGP"
        print(f"OK (announced, {report.bgp.visibility:.0f}% visibility, "
              f"first seen {report.bgp.first_seen[:10] if report.bgp.first_seen else '?'})")
    elif bgp_detail:
        print("OK (not announced)")
    else:
        print("FAIL")

    # 3c. RPKI by ASN
    print("  [5/10] RIPEstat — RPKI (by ASN) ...", end=" ", flush=True)
    if report.asn and report.asn.asn:
        report.rpki = lookup_ripestat_rpki_asn(report.asn.asn)
        if report.rpki:
            sources_used.append("RIPEstat RPKI")
            print(f"OK ({report.rpki.status})")
        else:
            print("no ROAs found")
    else:
        print("skipped (no ASN)")

    # 3d. Abuse contact
    print("  [6/10] RIPEstat — abuse contact ...", end=" ", flush=True)
    report.abuse_contact = lookup_ripestat_abuse(ip)
    if report.abuse_contact:
        sources_used.append("RIPEstat Abuse")
        print(f"OK ({report.abuse_contact.email})")
    else:
        print("not found")

    # ── 4. GreyNoise Community ────────────────────────────────────────────
    print("  [7/10] GreyNoise Community ...", end=" ", flush=True)
    gn = lookup_greynoise(ip)
    if gn.get("rate_limited"):
        print("rate-limited — skipping")
    elif gn.get("classification"):
        report.threat.greynoise_class = gn.get("classification", "")
        report.threat.greynoise_riot = gn.get("riot", False)
        report.threat.greynoise_name = gn.get("name", "")
        sources_used.append("GreyNoise Community")
        print(f"OK ({report.threat.greynoise_class}" +
              (" + RIOT" if report.threat.greynoise_riot else "") + ")")
    else:
        print("no data — skipping")

    # ── 5. AbuseIPDB (keyed) ──────────────────────────────────────────────
    if abuseipdb_key:
        print("  [8/10] AbuseIPDB ...", end=" ", flush=True)
        ab_data = lookup_abuseipdb(ip, abuseipdb_key)
        if ab_data:
            ab = ab_data.get("data", {})
            report.threat.abuseipdb_score = ab.get("abuseConfidenceScore", 0)
            report.threat.abuseipdb_total = ab.get("totalReports", 0)
            sources_used.append("AbuseIPDB")
            print(f"OK (score={report.threat.abuseipdb_score}, "
                  f"reports={report.threat.abuseipdb_total})")
        else:
            print("FAIL")

    # ── 6. AlienVault OTX ─────────────────────────────────────────────────
    if otx_key:
        print("  [9/10] AlienVault OTX ...", end=" ", flush=True)
    else:
        print("  [9/10] AlienVault OTX ...", end=" ", flush=True)
    otx = lookup_otx(ip, otx_key)
    if otx and "pulse_info" in otx:
        pulses = otx.get("pulse_info", {}).get("count", 0)
        report.threat.otx_pulse_count = pulses
        malware_raw = otx.get("malware_families", [])
        report.threat.otx_malware = [m.get("display_name", "") for m in malware_raw[:5]
                                     if m.get("display_name")]
        sources_used.append("AlienVault OTX")
        print(f"OK ({pulses} pulses)")
    else:
        print("no data")

    # ── 7. System whois ───────────────────────────────────────────────────
    print("  [10/10] system whois ...", end=" ", flush=True)
    report.whois_raw = lookup_whois(ip)
    if report.whois_raw:
        sources_used.append("system whois")
        # Extract first meaningful line
        found = False
        for line in report.whois_raw.split("\n"):
            line = line.strip()
            if line and not line.startswith("%") and not line.startswith("#"):
                if not line.startswith("refer:") and "ReferralServer" not in line:
                    print(f"OK ({line[:60]})")
                    found = True
                    break
        if not found:
            print("OK")
    else:
        print("(empty)")

    # ── Traceroute ─────────────────────────────────────────────────────────
    if not no_traceroute:
        print("\n  Running traceroute (this may take 30-90s) ...")
        report.traceroute = run_traceroute(ip)
        if report.traceroute.error:
            print(f"  ⚠  {report.traceroute.error[:80]}")
        else:
            print(f"  ✓  {report.traceroute.hop_count} hops, "
                  f"avg {report.traceroute.avg_latency_ms}ms, "
                  f"loss {report.traceroute.packet_loss_pct:.0f}%")
        sources_used.append("traceroute")

    report.sources_used = sources_used
    report.sources_failed = sources_failed
    return score_report(report)


# ── Output Formatters ────────────────────────────────────────────────────────

# ANSI color codes
C_RESET = "\033[0m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"


def _colorize(text: str, color: str) -> str:
    """Wrap text in ANSI color if stdout is a tty."""
    if sys.stdout.isatty():
        return f"{color}{text}{C_RESET}"
    return text


def print_report(report: Report) -> None:
    """Print a color-coded human-readable report to stdout."""
    DIMENSION_MAX = {"registration_entity": 30, "geo_consistency": 25,
                     "source_location": 10, "traceroute_quality": 15,
                     "threat_intelligence": 20}

    # Grade color
    grade_color = C_GREEN if report.grade in ("A", "B") else (
        C_YELLOW if report.grade == "C" else C_RED
    )

    bar = "█" * (report.score // 5) + "░" * (20 - report.score // 5)
    print(f"\n  {_colorize('┌' + '─'*58 + '┐', C_DIM)}")
    print(f"  {_colorize('│', C_DIM)}  {_colorize(f'SCORE: {report.score}/100  [{bar}]  GRADE: {report.grade}', grade_color + C_BOLD)}  {_colorize('│', C_DIM)}")
    print(f"  {_colorize('└' + '─'*58 + '┘', C_DIM)}")

    # Breakdown
    print(f"\n  {_colorize('Breakdown:', C_BOLD)}")
    for label, pts in report.breakdown.items():
        dim_max = DIMENSION_MAX.get(label, 30)
        pct = pts / dim_max if dim_max > 0 else 0
        bar = "█" * max(1, int(pct * 15)) + "░" * max(0, 15 - int(pct * 15))
        print(f"    {label.replace('_', ' ').title():<22s} {bar} {pts}")

    # Positives
    if report.positives:
        print(f"\n  {_colorize('✓ Positives:', C_GREEN)}")
        for p in report.positives:
            print(f"    {_colorize('✓', C_GREEN)} {p}")

    # Warnings
    if report.warnings:
        print(f"\n  {_colorize('⚠ Warnings:', C_YELLOW)}")
        for w in report.warnings:
            print(f"    {_colorize('⚠', C_YELLOW)} {w}")

    # Details
    if report.details:
        print(f"\n  {_colorize('Details:', C_DIM)}")
        for d in report.details:
            print(f"    {_colorize('·', C_DIM)} {d}")

    # Sources
    if report.sources_used:
        print(f"\n  {_colorize('Data sources ({0}):'.format(len(report.sources_used)), C_CYAN)}")
        for s in report.sources_used:
            print(f"    {_colorize('✓', C_GREEN)} {s}")
    if report.sources_failed:
        for s in report.sources_failed:
            print(f"    {_colorize('✗', C_RED)} {s} (failed)")

    print()


def export_json(report: Report, path: str) -> None:
    """Write structured JSON report to file."""
    data = {
        "ip": report.ip,
        "source_country": report.source_country,
        "score": report.score,
        "grade": report.grade,
        "breakdown": report.breakdown,
        "positives": report.positives,
        "warnings": report.warnings,
        "details": report.details,
        "geolocation": asdict(report.geo) if report.geo else None,
        "asn_origin": asdict(report.asn) if report.asn else None,
        "rpki": asdict(report.rpki) if report.rpki else None,
        "bgp_routing": asdict(report.bgp) if report.bgp else None,
        "abuse_contact": asdict(report.abuse_contact) if report.abuse_contact else None,
        "threat_intel": asdict(report.threat),
        "traceroute": asdict(report.traceroute) if report.traceroute else None,
        "whois_raw": report.whois_raw[:5000] if report.whois_raw else None,
        "sources_used": report.sources_used,
        "sources_failed": report.sources_failed,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    print(f"  JSON report written to {path}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="IP Reputation Scoring Engine — firewall-aligned reputation analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ip_reputation.py 8.8.8.8
  python ip_reputation.py 8.8.8.8 --source-country DE --no-traceroute
  python ip_reputation.py 45.33.32.156 --json report.json
  python ip_reputation.py 185.220.101.1 --abuseipdb-key KEY --otx-key KEY

Environment variables:
  ABUSEIPDB_KEY     AbuseIPDB API v2 key
  IPINFO_TOKEN      ipinfo.io access token
  OTX_KEY           AlienVault OTX API key
  SOURCE_COUNTRY    Default source country (2-letter ISO code)
""",
    )
    parser.add_argument("ip", help="Target IPv4 address")
    parser.add_argument("--source-country", "-s", default=os.environ.get("SOURCE_COUNTRY", ""),
                        help="Your country (2-letter ISO code, e.g. DE, US, CN)")
    parser.add_argument("--no-traceroute", "-n", action="store_true",
                        help="Skip traceroute (no sudo needed)")
    parser.add_argument("--abuseipdb-key", default=os.environ.get("ABUSEIPDB_KEY", ""),
                        help="AbuseIPDB API key")
    parser.add_argument("--ipinfo-key", default=os.environ.get("IPINFO_TOKEN", ""),
                        help="ipinfo.io API token")
    parser.add_argument("--otx-key", default=os.environ.get("OTX_KEY", ""),
                        help="AlienVault OTX API key")
    parser.add_argument("--json", "-j", default="",
                        help="Export structured JSON report to file")

    args = parser.parse_args()

    report = analyze_ip(
        ip=args.ip,
        source_country=args.source_country,
        no_traceroute=args.no_traceroute,
        abuseipdb_key=args.abuseipdb_key,
        ipinfo_key=args.ipinfo_key,
        otx_key=args.otx_key,
    )

    print_report(report)

    if args.json:
        export_json(report, args.json)


if __name__ == "__main__":
    main()
