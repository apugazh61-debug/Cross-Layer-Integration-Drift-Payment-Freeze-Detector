# Cross-Layer Integration Drift & Payment-Freeze Detector
### CRIMEATHON'26 — Team Thendral | DEFENSE Track | Case CR-26-047

---

## 🎯 What This Does

Detects unauthorized vendor bank-account mutations made through integration API keys **before** scheduled payment runs at Harbor & Finch Freight Pvt. Ltd.

**The decisive event it catches:**  
On 3 Sep 2026 at 01:44 UTC, `key-tb-07` (TallyBridge integration key) patched `V-0412` (Coastal Packaging Ltd) bank account from `****4417 → ****9083` with **no approval reference**, from an **abnormal host** (`tb-build-02`, IP `10.20.4.77`) — 5 days before the Sep 8 payment run.

---

## 🚨 Results on Supplied Evidence

| Tier | Count | Detail |
|------|-------|--------|
| 🚨 ALERT | 1 | V-0412, Coastal Packaging Ltd, 3 Sep 2026, score=7 |
| ⚠️ REVIEW | 3 | UI changes by m.sundar, f.hegde, g.sethi — missing approval_ref |
| ✅ OK | 36 | All legitimate (bulk imports, approved UI edits) |

**Self-test (5 unseen variations): 5/5 PASS**

---

## 📁 Evidence Files Required

Place all evidence files in a single folder. The detector uses:

| File Pattern | Contents |
|---|---|
| `E01*.csv` | LedgerOne API access log (Jun–Aug) |
| `E04*.json` | Connected software / API key register |
| `E15*.csv` | Network link flow log (host labels) |
| `E18*.csv` | LedgerOne API access log (Sep 1–7) |
| `E19*.csv` | Vendor master change log |

---

## ⚙️ Setup & Run

### 1. Install dependency
```bash
pip install pandas
```

### 2. Place evidence files in a folder (e.g., `case_data/`)

### 3. Run the detector
```bash
python detector.py --data case_data --out alerts.csv
```

### 4. Run with self-test (recommended for verification)
```bash
python detector.py --data case_data --out alerts.csv --selftest
```

### Expected output
```
Bank-account changes checked: 40
tier
OK        36
REVIEW     3
ALERT      1

== ALERT ==
ts_utc: 2026-09-03T01:44:30Z | vendor_id: V-0412 | channel: API
by: key-tb-07 | score: 7
why: no approval_ref | key-tb-07 never did PATCH /v2/vendors/{vendor}/bank-details before
     | 10.20.4.77 never made a write with key-tb-07 before
     | host label 'tb-build-02' not among usual writers [tb-sync-01..tb-sync-06]

== Unseen-variation self-test ==
case 1: expected ALERT  got ALERT  PASS
case 2: expected ALERT  got ALERT  PASS
case 3: expected ALERT  got ALERT  PASS
case 4: expected OK     got OK     PASS
case 5: expected OK     got OK     PASS
```

---

## 🔍 How It Works

### Detection Logic (3 joins, 6 signals)

```
E19 (vendor changes)  ──┐
E01 + E18 (API logs)  ──┼──► Filter bank_account changes
E15 (host labels)     ──┤         │
E04 (key scopes)      ──┘         ▼
                           Join by request_id to API log
                                   │
                                   ▼
                     Build per-key behavioral baseline
                     (what hosts/endpoints this key normally uses)
                                   │
                                   ▼
              Score 6 signals:
              • no_approval   (+2) — blank approval_ref
              • new_endpoint  (+2) — key never used this endpoint before
              • new_host      (+2) — IP never made a write with this key
              • host_role     (+1) — host label not in usual writer set
              • new_agent     (+1) — new user-agent string
              • public_ip     (+2) — caller IP is public (not RFC-1918)
              • out_of_scope  (+2) — key scope doesn't cover this endpoint
                                   │
                                   ▼
              Score ≥ 4 → ALERT  |  Score 2–3 → REVIEW  |  Score 0–1 → OK
```

### Why Behavioral (not IP blocklist)?

The decisive Sep 3 change came from `10.20.4.77` — a **private IP** in TallyBridge's network range. Static IP blocklists (the obvious approach) would have missed it completely because:
- The host IP is private and trusted
- The API key `key-tb-07` is a valid, registered key
- The TallyBridge agent version `3.5.0` matches known software

Our behavioral baseline detects that **this key had never patched bank details before** from **this host**, with **no approval** — a combination that equals fraud.

---

## ⚠️ Known Limitations

| Limitation | Impact |
|------------|--------|
| Attacker uses a normal sync host (tb-sync-01..06) with forged approval_ref | Detector misses it |
| E15 flow log ends 31 Aug — Sep 3 host label identified by IP persistence | Assumption, not verified log |
| Thresholds (10 writes for host baseline, 3 for endpoint) tuned on supplied data | May need adjustment on other datasets |
| Cannot verify vendor confirmation calls (no out-of-band callback log) | Legitimate change possible |
| No real-time streaming — runs as a batch before each payment run | Not continuous monitoring |

---

## 📂 Output File: alerts.csv

| Column | Description |
|--------|-------------|
| `ts_utc` | Timestamp of change |
| `vendor_id` | Vendor ID (e.g., V-0412) |
| `vendor` | Vendor name |
| `channel` | API / UI / IMPORT |
| `by` | Key or username that made the change |
| `request_id` | API request ID (for tracing back to E01/E18) |
| `approval_ref` | Approval ticket reference (blank = suspicious) |
| `score` | Risk score (0–14) |
| `tier` | ALERT / REVIEW / OK |
| `why` | Human-readable reasons |

---

## 🏗️ Evidence IDs Referenced

`E01`, `E04`, `E15`, `E18`, `E19` — primary evidence used by detector  
`E03`, `E05`, `E06`, `E10`, `E11`, `E12`, `E13`, `E16`, `E20` — referenced in analysis (see proof pack)

---

## 👥 Team

**Team Thendral** | CRIMEATHON'26 | DEFENSE Track  
SIMATS Engineering, Chennai | 19–20 November 2026  
Case: CR-26-047 | Harbor & Finch Freight Pvt. Ltd.
