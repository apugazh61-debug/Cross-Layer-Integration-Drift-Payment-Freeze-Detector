#!/usr/bin/env python3
"""Thendral - CRIMEATHON'26 Defense: integration-credential vendor bank-change detector.
Usage:  python detector.py --data <folder with E01..E20>  [--out alerts.csv] [--selftest]
Needs:  pip install pandas
"""
import argparse, glob, ipaddress, json, os, re, sys
import pandas as pd

SENSITIVE = {"bank_account"}          # fields we protect (extend if needed)
WRITE = {"POST", "PUT", "PATCH", "DELETE"}
W = dict(no_approval=2, new_endpoint=2, new_host=2, host_role=1, new_agent=1, public_ip=2, out_of_scope=2, no_api_record=1)
MIN_HOST, MIN_EP = 10, 3               # a host/endpoint is "usual" only after this many earlier writes (one-off calls do not count)
ALERT_AT = 4                           # integration change with score >= 4 -> ALERT; 2..3 -> REVIEW

def find(d, pat):
    m = sorted(glob.glob(os.path.join(d, pat)))
    if not m: sys.exit(f"missing file matching {pat} in {d}")
    return m[0]

def norm(ep):
    ep = ep.split("?")[0]
    ep = re.sub(r"V-\d+", "{vendor}", ep)
    return re.sub(r"/\d+", "/{n}", ep)

def is_private(ip):
    try: return ipaddress.ip_address(ip).is_private
    except Exception: return False

def load(d):
    api = pd.concat([pd.read_csv(find(d, "E01*.csv")), pd.read_csv(find(d, "E18*.csv"))]).drop_duplicates("request_id")
    api["ts"] = pd.to_datetime(api.ts_utc, utc=True)
    api["ep"] = api.endpoint.map(norm)
    api["is_write"] = api.method.isin(WRITE)
    chg = pd.read_csv(find(d, "E19*.csv"))
    chg["ts"] = pd.to_datetime(chg.ts_utc, utc=True)
    flows = pd.read_csv(find(d, "E15*.csv"))
    flows["ts"] = pd.to_datetime(flows.ts_utc, utc=True)
    reg = json.load(open(find(d, "E04*.json")))["integrations"]
    scope = {r["credential_id"]: r["scope"] for r in reg}
    return api, chg, flows, scope

def label_of(flows, ip, ts):
    f = flows[(flows.src_ip == ip) & (flows.ts <= ts)]
    if f.empty: f = flows[flows.src_ip == ip]
    return f.src_label.iloc[-1] if len(f) else None

def scope_ok(scope_txt, endpoint):
    if scope_txt is None: return True            # key not in register: cannot judge
    s = scope_txt.lower()
    if "all-modules" in s or "admin" in s: return True
    return "vendors" in s if "/vendors" in endpoint else True

def detect(api, chg, flows, scope):
    rows = []; bad = set()                  # requests already alerted never enter the baseline
    for _, c in chg[chg.field.isin(SENSITIVE)].sort_values("ts").iterrows():
        sig = {}
        approval_missing = pd.isna(c.approval_ref) or str(c.approval_ref).strip() == ""
        integration = str(c.channel).upper() == "API" or str(c.changed_by).startswith("key-")
        if approval_missing: sig["no_approval"] = "no approval_ref"
        if integration:
            key = c.changed_by
            req = api[api.request_id == c.request_id]
            if req.empty:
                sig["no_api_record"] = "change has no matching API request"
            else:
                r = req.iloc[0]; key = r.api_key_id
                hist = api[(api.api_key_id == key) & (api.ts < r.ts) & api.is_write & ~api.request_id.isin(bad)]
                hc = hist.caller_ip.value_counts(); usual_hosts = set(hc[hc >= MIN_HOST].index)
                ec = (hist.method + " " + hist.ep).value_counts(); usual_eps = set(ec[ec >= MIN_EP].index)
                ac = hist.user_agent.value_counts(); usual_agents = set(ac[ac >= MIN_HOST].index)
                if f"{r.method} {r.ep}" not in usual_eps:
                    sig["new_endpoint"] = f"{key} never did {r.method} {r.ep} before"
                if r.caller_ip not in usual_hosts:
                    sig["new_host"] = f"{r.caller_ip} never made a write with {key} before"
                usual = {label_of(flows, ip, r.ts) for ip in usual_hosts}
                lab = label_of(flows, r.caller_ip, r.ts)
                if lab not in usual: sig["host_role"] = f"host label '{lab}' not among usual writers {sorted(map(str, usual))}"
                if r.user_agent not in usual_agents: sig["new_agent"] = f"new user agent {r.user_agent}"
                if not is_private(r.caller_ip): sig["public_ip"] = f"public caller {r.caller_ip}"
                if not scope_ok(scope.get(key), r.endpoint): sig["out_of_scope"] = f"scope '{scope.get(key)}' does not cover this"
        score = sum(W[k] for k in sig)
        if integration: tier = "ALERT" if score >= ALERT_AT else ("REVIEW" if score >= 2 else "OK")
        else: tier = "REVIEW" if approval_missing else "OK"
        if tier == "ALERT" and integration and not req.empty: bad.add(c.request_id)
        rows.append(dict(ts_utc=c.ts_utc, vendor_id=c.vendor_id, vendor=c.vendor_name, channel=c.channel, by=c.changed_by,
                         request_id=c.request_id, approval_ref=c.approval_ref, score=score, tier=tier,
                         why=" | ".join(sig.values())))
    return pd.DataFrame(rows)

def selftest(api, chg, flows, scope):
    """Unseen-variation checks: inject synthetic events and see whether we still react correctly."""
    t0 = pd.Timestamp("2026-09-06T02:00:00Z"); out = []
    def add(i, key, ip, ua, method, ep, chan, approval, expect):
        rid = f"req-selftest-{i}"
        a = pd.DataFrame([dict(ts_utc=str(t0), request_id=rid, api_key_id=key, caller_ip=ip, user_agent=ua, endpoint=ep, method=method, records_returned=1, status=200)])
        a["ts"] = pd.to_datetime(a.ts_utc, utc=True); a["ep"] = a.endpoint.map(norm); a["is_write"] = a.method.isin(WRITE)
        c = pd.DataFrame([dict(ts_utc=str(t0), change_id=f"chg-st{i}", vendor_id="V-0999", vendor_name="Selftest Vendor", field="bank_account",
                               old_value="x", new_value="y", changed_by=key, channel=chan, approval_ref=approval, source_ip=ip, request_id=rid)])
        c["ts"] = pd.to_datetime(c.ts_utc, utc=True)
        r = detect(pd.concat([api, a]), c, flows, scope).iloc[0]
        out.append((i, expect, r.tier, "PASS" if r.tier == expect else "FAIL"))
    add(1, "key-tb-07", "10.20.4.12", "TallyBridge-Sync/3.5.0", "PATCH", "/v2/vendors/V-0999/bank-details", "API", None, "ALERT")   # normal sync host, no approval
    add(2, "key-app-11", "172.16.9.5", "portal/1.0", "PATCH", "/v2/vendors/V-0999/bank-details", "API", None, "ALERT")             # key whose scope is not vendors
    add(3, "key-tb-07", "198.18.7.58", "python-requests/2.31.0", "PATCH", "/v2/vendors/V-0999/bank-details", "API", None, "ALERT") # outside IP
    add(4, "f.dsouza", "172.16.8.31", "browser", "PATCH", "/ui", "IMPORT", "BULK-0731", "OK")                                      # approved bulk import
    add(5, "g.sethi", "172.16.8.29", "browser", "PATCH", "/ui", "UI", "APR-9999", "OK")                                            # approved UI edit
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--data", required=True); ap.add_argument("--out", default="alerts.csv"); ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    api, chg, flows, scope = load(a.data)
    res = detect(api, chg, flows, scope); res.to_csv(a.out, index=False)
    print(f"Bank-account changes checked: {len(res)}")
    print(res.tier.value_counts().to_string())
    pd.set_option("display.width", 220); pd.set_option("display.max_colwidth", 120)
    for t in ("ALERT", "REVIEW"):
        s = res[res.tier == t]
        if len(s): print(f"\n== {t} ==\n" + s[["ts_utc", "vendor_id", "channel", "by", "approval_ref", "score", "why"]].to_string(index=False))
    if a.selftest:
        print("\n== Unseen-variation self-test ==")
        for i, e, g, p in selftest(api, chg, flows, scope): print(f"case {i}: expected {e:6s} got {g:6s} {p}")
