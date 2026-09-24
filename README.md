# Sentinel Detection Pack — SOC Analytics & Triage

A production-style detection engineering pack for **Microsoft Sentinel**, built from
real SOC analyst workflows: scheduled analytic rules, companion threat-hunting
queries, and an IOC triage helper. The detections reflect techniques I triage
daily — impossible travel, data staging, IAM privilege escalation, lateral
movement, and password spraying.

## Detection philosophy

1. **Alert on behavior chains, not single events.** The lateral-movement rule
   requires ≥2 distinct techniques before firing; the spray rule requires both
   account and failure thresholds.
2. **Every rule ships with a triage pivot.** Password-spray alerts include a
   `spraySucceeded` flag — the single field that decides whether this is noise
   or an active compromise.
3. **Tunable by design.** Thresholds live in `let` statements at the top of each
   query with baselining guidance in comments — no hardcoded magic numbers.
4. **False positives are documented, not discovered.** Each rule lists its known
   FP sources and how to suppress them.

## MITRE ATT&CK coverage

| Rule | Tactic | Technique |
|---|---|---|
| Impossible Travel Sign-In | Initial Access | T1078 Valid Accounts |
| Mass File Download (SharePoint/OneDrive) | Collection | T1213, T1039 |
| AWS IAM Privilege Escalation (CloudTrail) | Persistence, Privilege Escalation | T1098, T1078 |
| CrowdStrike Lateral Movement Pattern | Lateral Movement, Execution | T1021, T1047 |
| Password Spraying after Phishing | Credential Access | T1110 |

## Repository layout

```
sentinel-detection-pack/
├── detections/   # 5 Sentinel analytic rules (Scheduled kind, YAML)
├── kql/          # 5 companion threat-hunting queries (KQL)
├── triage/       # ioc_triage.py — IOC enrichment + severity scoring + incident note
└── README.md
```

## Importing into Sentinel

1. In the Azure portal go to **Microsoft Sentinel → Analytics → Create →
   Scheduled query rule**.
2. Open the matching file under `detections/` and copy the `query:` block into
   the rule logic; set the **Rule query**, **Entity mapping**, and **Custom
   details** from the YAML fields (names map 1:1).
3. Set **Run query every** = `queryFrequency` and **Lookup data from the last** =
   `queryPeriod`.
4. Baseline for 1–2 weeks, then tune the `let` parameters (thresholds, excluded
   accounts/IPs) per the comments and the false-positive notes.
5. Wire the incident to your SOAR playbook (Logic App) for auto-enrichment —
   `triage/ioc_triage.py` shows the enrichment logic such a playbook would call.

## Using the hunting queries

The `kql/` queries are ad-hoc companions to the rules — run them in **Logs**
or save under **Hunting → Queries**. Set the `suspectUser` / `compromisedHost`
variables at the top before running.

## Using the triage script

Stdlib only — no dependencies to install.

```bash
# Demo mode (synthetic enrichment, works offline):
python3 triage/ioc_triage.py --ioc 185.220.101.4

# Live enrichment (keys read from environment):
export VT_API_KEY="<your-key>"
export ABUSEIPDB_API_KEY="<your-key>"
python3 triage/ioc_triage.py --ioc evil.example --out incident-note.md
```

Supports IPs, domains, URLs, and MD5/SHA1/SHA256 hashes. Emits a Markdown
incident note with evidence, enrichment, severity (Critical/High/Medium/Low),
and a response checklist.

## Disclaimer

These queries encode detection patterns developed and tested in lab
environments. Validate every rule against your own telemetry before enabling it
in production — table schemas, connector field names, and baselines differ
between tenants. Provided as-is for learning and demonstration; no warranty is
made about detection efficacy in any specific environment.

## Author

Anush Niranchan Anandh — SOC Analyst (SIEM, EDR, Cloud Security)
