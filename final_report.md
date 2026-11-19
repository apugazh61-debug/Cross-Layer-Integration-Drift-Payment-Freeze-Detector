# Final Technical Report — Team Thendral | CRIMEATHON'26 | Case CR-26-047

**Harbor & Finch Freight Pvt. Ltd. | Unauthorized Vendor Bank Redirection via Integration Key**  
**Team:** Thendral | **Approach:** DEFENSE | **Date:** 20 November 2026

---

## 1. Reconstructed Investigation Timeline

### Phase 1 — Reconnaissance (9–12 August 2026)

Between 9 and 12 August, an actor operating from external IP addresses in the `198.18.7.0/24` range used `key-tb-07` (TallyBridge Connect integration key) to query LedgerOne's API. The activity retrieved approximately 19,675 vendor records across multiple paginated calls and queried payment-related endpoints — behaviour inconsistent with TallyBridge's documented sync function. During the same window, 10 HelpDeskr ticket export jobs were created and deleted from the same external IP range, generating an anomalous billing charge flagged by Finance in late August (E02, E06, E01).

### Phase 2 — Credential Exposure (14–16 August 2026)

A BlueVault access key (`bvk-7f3a`) was present in a HelpDeskr support ticket in plaintext — a practice the case file notes IT was evaluating alternatives for (E13). Between 14 and 16 August, this key was used to read 36 BlueVault files, of which 24 were in the `/finance/bank-instructions/` path. This provided the actor with knowledge of vendor payment file structures and formats (E05).

On 15 August, three failed login attempts were made against the `a.kapoor` admin account from `198.18.7.77` (Mumbai-registered IP). Multi-factor authentication blocked all three attempts (E03, E13).

### Phase 3 — Build Host Re-Provisioning (16–17 August 2026)

TallyBridge's build server `tb-build-02` (IP `10.20.4.77`) was re-provisioned on 16 August — four days after the peak recon activity. From 17 August onward, this host began making daily API calls to LedgerOne's `/v2/vendors/*/bank-details` read endpoint. The re-provisioning potentially overwrote forensic evidence on the host. This is noted as an assumption: the case file (E20-B) records the event date, but no internal build logs are accessible under contract terms (E08 §9.1).

### Phase 4 — The Decisive Mutation (3 September 2026, 01:44 UTC)

At 01:44 UTC on 3 September, `key-tb-07` sent a PATCH request (`req-5f61b0de8`) to `/v2/vendors/V-0412/bank-details` from IP `10.20.4.77`. This changed Coastal Packaging Ltd's bank account from `****4417` to `****9083`. The change record in E19 carries no approval reference and no approval ticket. The host (`tb-build-02`) had never previously made a write call with `key-tb-07`. The endpoint (`PATCH /v2/vendors/{vendor}/bank-details`) had never previously been called by this key. The normal sync hosts for `key-tb-07` are `tb-sync-01` through `tb-sync-06` (IPs `.11` through `.16`), all in the same `10.20.4.0/24` subnet.

The next vendor payment run was scheduled for 8 September. Without intervention, funds payable to Coastal Packaging Ltd would have been directed to the account ending `9083`.

---

## 2. Assumptions Made

| Assumption | Basis | Confidence |
|------------|-------|------------|
| IP `10.20.4.77` = host `tb-build-02` on 3 Sep | E15 label valid through Aug 31; IP unchanged post re-provision | Medium |
| 198.18.x activity is from the same actor | IP range is shared; dynamic IPs confirmed in E20 — cannot prove single actor | Low |
| BlueVault bvk-7f3a reads were unauthorized | Key present in ticket; access timing follows recon; no work order found | Medium |
| Payment run would use altered account | Standard company process; Finance prepares run days before 8th/23rd | High |

---

## 3. Alternative Explanations Considered and Ruled Out

**TallyBridge v3.6.0 "vendor contact sync" (released 1 Sep):** The new feature syncs contact email and phone fields only. PATCH to `/bank-details` is outside the documented feature scope. The API log confirms `method=PATCH` on the bank-details endpoint, not a contact field. *Set aside.*

**Genuine vendor-initiated bank change:** Coastal Packaging may have requested the change through a legitimate channel that bypassed the UI approval flow. This cannot be ruled out without a callback to the vendor — it is listed as the primary open question. The detector correctly flags the event for freeze-and-verify, not automatic rejection.

**f.dsouza bulk import BULK-0731 (31 July):** Twelve bank-account changes by bulk import with approval reference BULK-0731. All carry a valid batch reference and were made via IMPORT channel from an internal IP. *Set aside as legitimate.*

**Rohan Menon (terminated 30 June):** A warehouse kiosk login on 13 August from an internal IP (E03, E14). No link to any API activity or bank-change record. *Set aside as unrelated.*

**s.iyer weekly exports:** Regular Tuesday pattern across the full log period, consistent with documented weekly service review process. *Set aside as normal.*

---

## 4. Conclusions

The evidence supports the conclusion that an unauthorized actor — operating partly through external infrastructure and partly through TallyBridge's internal network range — altered Coastal Packaging Ltd's bank account in LedgerOne five days before a scheduled payment run, using a valid integration API key with no IP restriction, no expiry date, and no multi-factor authentication requirement.

The company's existing controls did not detect or prevent this event because: (a) no alerting existed for integration-channel writes to vendor bank fields (E10 §4.1, E11 Finding 6); (b) the CISO position has been vacant since September 2025 (E07); (c) `key-tb-07` had not been reviewed since its creation in June 2024 (E04); and (d) no approval was required for API-channel bank changes in the same way UI changes nominally required one.

The detector built by Team Thendral identifies this event with a risk score of 7 and zero false positives across 109 legitimate bank-account changes in the supplied evidence. Five synthetic unseen-variation cases all produce the expected outcome.

The most significant remaining uncertainty is whether the Sep 3 change was genuinely requested by Coastal Packaging. The correct response — freeze the payment, call the vendor, verify — is built into the detector's output design.

---

*All findings are based on the supplied synthetic evidence (CR-26-047). No real systems, organizations, or persons are referenced.*
