#!/usr/bin/env python3
"""
ioc_triage.py — SOC alert-triage helper.

Given an indicator of compromise (IP, domain, URL, or file hash), this script:
  1. Detects the IOC type automatically.
  2. Enriches it via VirusTotal and AbuseIPDB (API keys read from environment
     variables; without keys it runs in clearly-labelled DEMO mode with
     synthetic data so the workflow is testable offline).
  3. Computes a heuristic severity score.
  4. Emits a Markdown incident note suitable for pasting into a ticket/SIEM.

Usage:
    export VT_API_KEY="..."            # optional
    export ABUSEIPDB_API_KEY="..."     # optional
    python3 ioc_triage.py --ioc 185.220.101.4
    python3 ioc_triage.py --ioc evil.example --out note.md
    python3 ioc_triage.py --ioc d41d8cd98f00b204e9800998ecf8427e --demo

Exit codes: 0 = note generated; 2 = bad input.
Stdlib only — no pip dependencies.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# --------------------------------------------------------------------------
# IOC type detection
# --------------------------------------------------------------------------

_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)


def detect_ioc_type(ioc: str) -> str:
    value = ioc.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _MD5.match(value) or _SHA1.match(value) or _SHA256.match(value):
        return "hash"
    if value.lower().startswith(("http://", "https://", "hxxp://", "hxxps://")):
        return "url"
    if _DOMAIN.match(value):
        return "domain"
    return "unknown"


# --------------------------------------------------------------------------
# Enrichment (live API when keys exist, labelled demo stubs otherwise)
# --------------------------------------------------------------------------

def _http_get(url: str, headers: dict | None = None, timeout: int = 15) -> dict:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"_error": f"request failed: {exc}"}


def vt_lookup(ioc: str, ioc_type: str, api_key: str | None) -> dict:
    """VirusTotal v3 lookup. Demo stub when no key is configured."""
    if not api_key:
        return {
            "source": "virustotal (DEMO — no VT_API_KEY set, synthetic data)",
            "malicious": 3,
            "suspicious": 1,
            "harmless": 68,
            "undetected": 12,
            "reputation": -10,
            "tags": ["demo"],
        }
    endpoints = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ioc)}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(ioc)}",
        "url": f"https://www.virustotal.com/api/v3/urls/{urllib.parse.quote(ioc, safe='')}",
        "hash": f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(ioc)}",
    }
    url = endpoints.get(ioc_type)
    if not url:
        return {"source": "virustotal", "_error": "unsupported IOC type"}
    data = _http_get(url, {"x-apikey": api_key})
    if "_error" in data:
        return {"source": "virustotal", **data}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "virustotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "tags": attrs.get("tags", [])[:10],
    }


def abuseipdb_lookup(ip: str, api_key: str | None) -> dict:
    """AbuseIPDB check (IP only). Demo stub when no key is configured."""
    if not api_key:
        return {
            "source": "abuseipdb (DEMO — no ABUSEIPDB_API_KEY set, synthetic data)",
            "abuse_confidence": 25,
            "total_reports": 4,
            "country": "DEMO",
            "isp": "demo-isp",
        }
    params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    data = _http_get(
        f"https://api.abuseipdb.com/api/v2/check?{params}",
        {"Key": api_key, "Accept": "application/json"},
    )
    if "_error" in data:
        return {"source": "abuseipdb", **data}
    inner = data.get("data", {})
    return {
        "source": "abuseipdb",
        "abuse_confidence": inner.get("abuseConfidenceScore", 0),
        "total_reports": inner.get("totalReports", 0),
        "country": inner.get("countryCode", "n/a"),
        "isp": inner.get("isp", "n/a"),
    }


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def score_severity(vt: dict, abuse: dict, ioc_type: str) -> tuple[str, int, list[str]]:
    """Heuristic 0–100 score -> severity band. Returns (band, score, reasons)."""
    score = 0
    reasons: list[str] = []

    malicious = int(vt.get("malicious", 0) or 0)
    if malicious >= 10:
        score += 45
        reasons.append(f"VirusTotal: {malicious} vendors flag malicious")
    elif malicious >= 3:
        score += 25
        reasons.append(f"VirusTotal: {malicious} vendors flag malicious")
    elif malicious >= 1:
        score += 10
        reasons.append(f"VirusTotal: {malicious} vendor flags malicious")
    if int(vt.get("suspicious", 0) or 0) >= 2:
        score += 10
        reasons.append(f"VirusTotal: {vt['suspicious']} suspicious verdicts")
    if int(vt.get("reputation", 0) or 0) < 0:
        score += 5
        reasons.append("VirusTotal: negative community reputation")

    conf = int(abuse.get("abuse_confidence", 0) or 0)
    if conf >= 75:
        score += 35
        reasons.append(f"AbuseIPDB: confidence {conf}% ({abuse.get('total_reports', 0)} reports)")
    elif conf >= 25:
        score += 15
        reasons.append(f"AbuseIPDB: confidence {conf}%")

    if ioc_type == "hash" and malicious >= 5:
        score += 10
        reasons.append("File hash with multiple AV detections — treat as malware")
    if ioc_type == "url" and malicious >= 3:
        score += 10
        reasons.append("URL flagged — likely phishing/malware delivery")

    score = min(score, 100)
    if score >= 70:
        band = "Critical"
    elif score >= 40:
        band = "High"
    elif score >= 15:
        band = "Medium"
    else:
        band = "Low"
    if not reasons:
        reasons.append("No enrichment hits — insufficient evidence of maliciousness")
    return band, score, reasons


# --------------------------------------------------------------------------
# Markdown incident note
# --------------------------------------------------------------------------

RESPONSE_PLAYBOOK = {
    "Critical": [
        "Isolate affected host(s) in EDR immediately.",
        "Block IOC at proxy/firewall and email gateway.",
        "Open IR ticket; preserve memory/disk images before remediation.",
        "Hunt for lateral movement (see hunt-04) and check for successful logons (see hunt-05).",
    ],
    "High": [
        "Block IOC at perimeter controls.",
        "Scope: search SIEM for the IOC over the last 30 days.",
        "If any internal host communicated with it, escalate to Critical and start IR.",
    ],
    "Medium": [
        "Monitor for 7 days; add IOC to watchlist.",
        "Correlate with user-reported phishing or EDR telemetry before closing.",
    ],
    "Low": [
        "No immediate action. Document and close; re-triage if new intel arrives.",
    ],
}


def build_note(ioc: str, ioc_type: str, vt: dict, abuse: dict | None,
               band: str, score: int, reasons: list[str], demo: bool) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# IOC Triage Note — `{ioc}`",
        "",
        f"- **Type:** {ioc_type}",
        f"- **Triaged:** {now}",
        f"- **Severity:** {band} ({score}/100)",
        f"- **Mode:** {'DEMO (synthetic enrichment data)' if demo else 'LIVE enrichment'}",
        "",
        "## Evidence",
        "",
    ]
    for r in reasons:
        lines.append(f"- {r}")
    lines += ["", "## Enrichment", ""]
    for label, payload in (("VirusTotal", vt), ("AbuseIPDB", abuse)):
        if payload is None:
            continue
        lines.append(f"### {label}")
        for k, v in payload.items():
            if k == "source":
                lines.append(f"- source: {v}")
            else:
                lines.append(f"- {k}: {v}")
        lines.append("")
    lines += ["## Recommended next steps", ""]
    for step in RESPONSE_PLAYBOOK[band]:
        lines.append(f"- [ ] {step}")
    lines += [
        "",
        "> Generated by ioc_triage.py. Verify enrichment against live intel before",
        "> taking disruptive action (isolation/blocks).",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Triage an IOC (IP/domain/URL/hash): enrich, score, emit a Markdown incident note."
    )
    parser.add_argument("--ioc", required=True, help="Indicator to triage")
    parser.add_argument("--type", choices=["ip", "domain", "url", "hash"],
                        help="Override auto-detected IOC type")
    parser.add_argument("--out", help="Write the Markdown note to this file (default: stdout)")
    parser.add_argument("--demo", action="store_true",
                        help="Force demo mode (synthetic enrichment) even if API keys are set")
    args = parser.parse_args(argv)

    ioc_type = args.type or detect_ioc_type(args.ioc)
    if ioc_type == "unknown":
        print(f"error: could not determine IOC type for {args.ioc!r}; "
              "pass --type explicitly.", file=sys.stderr)
        return 2

    vt_key = os.environ.get("VT_API_KEY")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
    demo = args.demo or not (vt_key or abuse_key)

    vt = vt_lookup(args.ioc, ioc_type, None if demo else vt_key)
    abuse = abuseipdb_lookup(args.ioc, None if demo else abuse_key) if ioc_type == "ip" else None

    band, score, reasons = score_severity(vt, abuse or {}, ioc_type)
    note = build_note(args.ioc, ioc_type, vt, abuse, band, score, reasons, demo)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(note)
        print(f"note written to {args.out} [{band} {score}/100]")
    else:
        print(note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
