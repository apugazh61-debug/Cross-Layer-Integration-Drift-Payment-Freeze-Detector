# Proof Pack — Team Thendral | CRIMEATHON'26 | Case CR-26-047

**Approach:** DEFENSE  
**Solution:** Cross-Layer Integration Drift & Payment-Freeze Detector  
**Date:** 20 November 2026

---

## 1. How to Run (Step-by-Step)

### Prerequisites
- Python 3.8 or higher
- pip

### Step 1: Install dependency
```bash
pip install pandas
```

### Step 2: Prepare evidence folder
Place these files in one folder (e.g., `case_data/`):
- `E01_ledgerone_api_access*.csv`
- `E04_connected_software_register*.json`
- `E15_network_link_flow_log*.csv`
- `E18_ledgerone_api_access_1_to_7_sep*.csv`
- `E19_vendor_master_change_log*.csv`

### Step 3: Run detector
```bash
python detector.py --data case_data --out alerts.csv
```

### Step 4: Run with self-test
```bash
python detector.py --data case_data --out alerts.csv --selftest
```

---

## 2. Input Files and Formats

| Argument | File | Format | Time Zone |
|----------|------|--------|-----------|
| `--data` folder | E01 | CSV, UTC timestamps | UTC |
| `--data` folder | E04 | JSON, `integrations` array | — |
| `--data` folder | E15 | CSV, UTC timestamps | UTC |
| `--data` folder | E18 | CSV, UTC timestamps | UTC |
| `--data` folder | E19 | CSV, UTC timestamps | UTC |
| `--out` | alerts.csv | CSV output | UTC |

---

## 3. Results on Supplied Evidence

### Summary
```
Bank-account changes checked: 40
tier
OK        36
REVIEW     3
ALERT      1
```

### ALERT (1)
| Field | Value |
|-------|-------|
| Timestamp | 2026-09-03T01:44:30Z |
| Vendor | V-0412 — Coastal Packaging Ltd |
| Channel | API |
| Changed by | key-tb-07 |
| Approval ref | (blank) |
| Score | 7 |
| Reasons | no approval_ref \| key-tb-07 never did PATCH /v2/vendors/{vendor}/bank-details before \| 10.20.4.77 never made a write with key-tb-07 before \| host label 'tb-build-02' not among usual writers ['tb-sync-01'..'tb-sync-06'] |

### REVIEW (3)
| Timestamp | Vendor | Changed by | Reason |
|-----------|--------|------------|--------|
| 2026-06-09T04:43:33Z | V-0298 | m.sundar | no approval_ref (UI edit) |
| 2026-07-20T07:23:40Z | V-0162 | f.hegde | no approval_ref (UI edit) |
| 2026-08-04T07:31:51Z | V-0128 | g.sethi | no approval_ref (UI edit) |

> Note: These 3 are real governance gaps — UI staff editing bank details without approval reference. Not false positives.

### OK (36)
All 36 include: 12 bulk imports under BULK-0731 (approved, by f.dsouza), 24 approved UI edits (APR-xxxx references present).

---

## 4. Self-Test Results (Unseen Variations)

```
case 1: expected ALERT  got ALERT  PASS
case 2: expected ALERT  got ALERT  PASS
case 3: expected ALERT  got ALERT  PASS
case 4: expected OK     got OK     PASS
case 5: expected OK     got OK     PASS
```

| Case | Scenario | Expected | Result |
|------|----------|----------|--------|
| 1 | key-tb-07, normal sync host (10.20.4.12), no approval | ALERT | ✅ PASS |
| 2 | key-app-11 (scope: not vendors), internal IP | ALERT | ✅ PASS |
| 3 | key-tb-07, public IP (198.18.7.58), new user-agent | ALERT | ✅ PASS |
| 4 | f.dsouza, internal IP, approved bulk import | OK | ✅ PASS |
| 5 | g.sethi, internal IP, approved UI edit | OK | ✅ PASS |

---

## 5. False Positives / False Alarms

**False positives on supplied data: 0**

The 3 REVIEW items are genuine governance findings (missing approval_ref in UI channel), not false alarms. They correctly surface a real control gap: Finance staff editing bank details without attaching approval ticket references.

---

## 6. What the Solution Misses

| Missed Scenario | Why | Likelihood |
|-----------------|-----|------------|
| Attacker uses normal sync host (tb-sync-01..06) with forged approval_ref | Passes all 3 rules | Low (requires insider access to sync host) |
| Attacker uses a new, unregistered API key | Key not in E04 baseline | Low (key creation leaves audit trail) |
| Gradual baseline poisoning (attacker slowly trains baseline) | Historical writes shift threshold | Very low (requires months of patience) |
| UI channel attack with fake approval ticket | Detector only scores UI on approval_ref | Medium (relies on approval system integrity) |

---

## 7. Evidence IDs Supporting Findings

| Finding | Evidence IDs |
|---------|-------------|
| Attack occurred via API (channel=API) | E19 row: chg-... V-0412 |
| key-tb-07 details (scope, no IP restriction, no expiry) | E04 |
| API request matching the bank change | E18 — req-5f61b0de8 |
| Historical baseline for key-tb-07 | E01 (Jun–Aug API logs) |
| Host tb-build-02 at 10.20.4.77 | E15 flow log |
| No monitoring alert existed | E10 §4.1, E11 Finding 6 |
| TallyBridge claims vs. log contradiction | E16 vs E05, E15, E19 |
| Previous recon activity | E01, E02, E06 |

---

## 8. Known Limitations (Reiterated)

1. **E15 ends 31 Aug** — Sep 3 host label (tb-build-02) identified by IP address persistence, not a live log entry
2. **Thresholds** (MIN_HOST=10, MIN_EP=3) calibrated on supplied data — may need tuning on other datasets
3. **No streaming** — batch script, must be run before each payment cycle (8th and 23rd)
4. **Cannot verify verbal confirmations** — if Coastal Packaging genuinely requested the change via phone, detector still flags it (correct behavior: freeze and verify)
5. **Contract gap** — E08 §9.1 means TallyBridge internal build logs are not accessible for deeper investigation
