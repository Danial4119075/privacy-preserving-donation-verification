#!/usr/bin/env python3
"""
Privacy-preserving verification of charitable donations: research prototype (v4).

DEMONSTRATION ONLY. This is NOT a zero-knowledge proof system. It is auditor-attested
(delegated) verification:
- Public ledger stores only: donation ID, commitment C = SHA-256(m || r), and an auditor
  attestation (a signed, versioned statement) over (donation ID, C).
- The authorised auditor receives the opening (m, r) privately, recomputes C and checks the
  rules: integer amount in cents, 0 < amount <= limit, approved charity, exact schema.
- A public verifier checks the auditor signature, the statement fields and a SHARED,
  PERSISTENT replay registry (SQLite). It never sees amount, donor ID, charity ID or nonce.
- The auditor also keeps its own replay set (_seen), in memory only. The shared registry is
  what makes replay protection persistent and common to all verifiers.
- Baseline A: transparent record, public rule check only.
- Baseline B: transparent record signed by the charity, with signature and replay checks
  (same authenticity and replay protection as the design, but no privacy).

Reproduce every table and figure:
    python3 donation_verify.py
Outputs: results.json, results.md, fig_timing.png, fig_breakdown.png, fig_scaling.png
(next to this file).
Requires: Python 3.10+, cryptography (Ed25519), matplotlib (figures only).
"""
import gc, hashlib, json, math, os, platform, secrets, sqlite3, statistics, sys, tempfile, threading, time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROTOCOL = "donation-attest/1"
POLICY_VERSION = "rules-2026-11"
REGISTRY_VERSION = "registry-1"
AUDITOR_ID = "auditor-01"
APPROVED_CHARITIES = {"CH-001", "CH-002", "CH-003"}   # registry version REGISTRY_VERSION
MAX_CENTS = 100_000_000                                # AUD 1,000,000 per donation
SCHEMA = {"donationID", "amountCents", "currency", "charityID", "donorID"}
WARMUP, TRIALS, RUNS = 50, 1000, 5
OUT = os.path.dirname(os.path.abspath(__file__))
DISABLED = set()   # used only by mutation testing: names of checks switched off


# ---------------------------------------------------------------- primitives
def encode(obj: dict) -> bytes:
    """Canonical JSON: sorted keys, no spaces, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def commit(m: bytes, r: bytes) -> bytes:
    """Hash commitment C = SHA-256(m || r), r = 32 random bytes."""
    return hashlib.sha256(m + r).digest()


def key_id(public_key) -> str:
    """Short fingerprint naming a public key in statements and trust lists."""
    from cryptography.hazmat.primitives import serialization as s
    raw = public_key.public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def new_donation_id() -> str:
    """Random 64-bit donation ID: reveals nothing about charity, donor or order."""
    return "D-" + secrets.token_hex(8)


def valid_amount(a) -> bool:
    """Integer cents only: rejects bool, float (incl. NaN, inf), str, <= 0, > MAX_CENTS."""
    return type(a) is int and 0 < a <= MAX_CENTS


class ReplayRegistry:
    """Shared, persistent record of accepted donation IDs (SQLite PRIMARY KEY)."""

    def __init__(self, path):
        self.path = path
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE IF NOT EXISTS accepted (donation_id TEXT PRIMARY KEY)")
        con.commit()
        con.close()
        self._con = sqlite3.connect(path, check_same_thread=False, timeout=30)

    def claim(self, donation_id) -> bool:
        """Atomically record the ID; False if it was already accepted by anyone."""
        try:
            with self._con:
                self._con.execute("INSERT INTO accepted VALUES (?)", (donation_id,))
            return True
        except sqlite3.IntegrityError:
            return False


# ---------------------------------------------------------------- roles
class Auditor:
    """Authorised auditor: sees the opening privately, checks rules, signs a versioned statement.
    The signing key is persisted, so attestations stay verifiable after a restart."""

    def __init__(self, key_path=None):
        if key_path and os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self._sk = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self._sk = Ed25519PrivateKey.generate()
            if key_path:
                with open(key_path, "wb") as f:
                    f.write(self._sk.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
        self.public_key = self._sk.public_key()
        self.key_id = key_id(self.public_key)
        self._seen = set()

    def rotate_key(self):
        """Start signing with a fresh key (key rotation); returns the new public key."""
        self._sk = Ed25519PrivateKey.generate()
        self.public_key = self._sk.public_key()
        self.key_id = key_id(self.public_key)
        return self.public_key

    def attest(self, donation_id, c, m, r, policy=POLICY_VERSION):
        if "commitment" not in DISABLED and commit(m, r) != c:
            return None, "commitment does not match opening"
        try:
            d = json.loads(m)
        except (ValueError, UnicodeDecodeError):
            return None, "malformed record"
        if "schema" not in DISABLED and (not isinstance(d, dict) or set(d) != SCHEMA):
            return None, "record does not match schema"
        if "id_match" not in DISABLED and d.get("donationID") != donation_id:
            return None, "donation ID does not match opening"
        if "amount" not in DISABLED and not valid_amount(d.get("amountCents")):
            return None, "invalid amount"
        if "currency" not in DISABLED and d.get("currency") != "AUD":
            return None, "unsupported currency"
        if "registry" not in DISABLED and d.get("charityID") not in APPROVED_CHARITIES:
            return None, "charity not in approved registry"
        if "auditor_replay" not in DISABLED and donation_id in self._seen:
            return None, "donation ID already attested"
        self._seen.add(donation_id)
        statement = encode({"protocol": PROTOCOL, "donationID": donation_id, "commitment": c.hex(),
                            "policy": policy, "registry": REGISTRY_VERSION,
                            "auditor": AUDITOR_ID, "keyID": self.key_id, "result": "valid",
                            "issued": int(time.time())})
        return (statement, self._sk.sign(statement)), "attested"


class PublicVerifier:
    """Anyone: sees only donation ID, commitment and attestation; shares the replay registry."""

    def __init__(self, trusted_keys, registry: ReplayRegistry):
        # trusted_keys: list of auditor public keys (all keys of authorised auditors)
        self._keys = {key_id(k): k for k in trusted_keys}
        self._registry = registry
        self.revoked = set()               # key IDs revoked after compromise

    def revoke(self, kid):
        self.revoked.add(kid)

    def trust(self, public_key):
        self._keys[key_id(public_key)] = public_key

    def verify(self, donation_id, c, attestation):
        if attestation is None:
            return False, "no attestation"
        statement, sig = attestation
        try:
            s = json.loads(statement)
        except ValueError:
            return False, "malformed statement"
        kid = s.get("keyID")
        if "revocation" not in DISABLED and kid in self.revoked:
            return False, "auditor key revoked"
        if "signature" not in DISABLED:
            key = self._keys.get(kid)
            if key is None or s.get("auditor") != AUDITOR_ID:
                return False, "unknown auditor key"
            try:
                key.verify(sig, statement)
            except InvalidSignature:
                return False, "invalid attestation signature"
        if "version" not in DISABLED and (s.get("protocol"), s.get("policy"), s.get("registry"),
                                          s.get("result")) != (PROTOCOL, POLICY_VERSION, REGISTRY_VERSION, "valid"):
            return False, "statement version or result not accepted"
        if "binding" not in DISABLED and (s.get("donationID") != donation_id or s.get("commitment") != c.hex()):
            return False, "statement does not match ledger record"
        if "registry_replay" not in DISABLED and not self._registry.claim(donation_id):
            return False, "replay: donation ID already accepted"
        return True, "accepted"


def new_donation(i, amount=5000, charity="CH-001", donor="alice@example.org", **extra):
    details = {"donationID": new_donation_id(), "amountCents": amount, "currency": "AUD",
               "charityID": charity, "donorID": donor, **extra}
    m = encode(details) if "raw" not in extra else extra["raw"]
    r = secrets.token_bytes(32)
    return details, m, r, commit(m, r)


# ---------------------------------------------------------------- tests
def run_tests(tmp):
    auditor = Auditor(os.path.join(tmp, "auditor_key.pem"))
    keys = [auditor.public_key]
    reg_path = os.path.join(tmp, "registry.db")
    v1 = PublicVerifier(keys, ReplayRegistry(reg_path))
    rows = []

    def record(tc, scenario, expected, ok, reason, prop):
        actual = "accept" if ok else "reject"
        rows.append({"id": tc, "scenario": scenario, "expected": expected, "actual": actual,
                     "reason": reason, "property": prop, "pass": actual == expected})

    def full(i, verifier=v1, **kw):
        d, m, r, c = new_donation(i, **kw)
        att, why = auditor.attest(d["donationID"], c, m, r)
        ok, reason = verifier.verify(d["donationID"], c, att)
        return ok, (reason if att else why), (d["donationID"], c, att)

    ok, why, tc01 = full(1)
    record("TC01", "Valid donation, correct opening", "accept", ok, why, "Correctness")
    d, m, r, c = new_donation(2)
    att, why = auditor.attest(d["donationID"], c, encode(dict(d, amountCents=50000)), r)
    record("TC02", "Amount changed after commitment", "reject", *v1.verify(d["donationID"], c, att)[:1], why, "Binding")
    ok, why, _ = full(3, charity="CH-999")
    record("TC03", "Charity not in approved registry", "reject", ok, why, "Rule check")
    d, m, r, c = new_donation(4)
    (st, sig), _ = auditor.attest(d["donationID"], c, m, r)
    ok, why = v1.verify(d["donationID"], c, (st, bytes([sig[0] ^ 1]) + sig[1:]))
    record("TC04", "Attestation signature tampered", "reject", ok, why, "Authenticity")
    ok, why = v1.verify(*tc01)
    record("TC05", "Replay at the same verifier", "reject", ok, why, "Replay resistance")
    d, m, r, c = new_donation(6)
    att, why = auditor.attest(d["donationID"], c, m, secrets.token_bytes(32))
    record("TC06", "Wrong nonce in the opening", "reject", v1.verify(d["donationID"], c, att)[0], why, "Binding")
    v2 = PublicVerifier(keys, ReplayRegistry(reg_path))
    ok, why = v2.verify(*tc01)
    record("TC07", "Replay at a second, independent verifier", "reject", ok, why, "Shared replay state")
    d, m, r, c = new_donation(8)
    att, _ = auditor.attest(d["donationID"], c, m, r)
    results = []
    vs = [PublicVerifier(keys, ReplayRegistry(reg_path)) for _ in range(8)]
    ts = [threading.Thread(target=lambda v=v: results.append(v.verify(d["donationID"], c, att)[0])) for v in vs]
    [t.start() for t in ts]; [t.join() for t in ts]
    record("TC08", "Same donation sent to 8 verifiers concurrently", "accept",
           sum(results) == 1, f"{sum(results)} of 8 accepted", "Concurrency")
    v3 = PublicVerifier([Auditor(os.path.join(tmp, "auditor_key.pem")).public_key],
                        ReplayRegistry(reg_path))
    ok, why = v3.verify(*tc01)
    record("TC09", "Replay after restart (reloaded key and registry)", "reject", ok, why, "Persistence")
    rogue = Auditor()
    d, m, r, c = new_donation(10)
    att, _ = rogue.attest(d["donationID"], c, m, r)
    ok, why = v1.verify(d["donationID"], c, att)
    record("TC10", "Attestation signed by an unknown key", "reject", ok, why, "Authenticity")
    for tc, label, amt in [("TC11", "Zero amount", 0), ("TC12", "Negative amount", -500),
                           ("TC13", "Boolean amount (True)", True), ("TC14", "NaN amount", float("nan")),
                           ("TC15", "Infinite amount", float("inf")), ("TC16", "Amount as text", "5000"),
                           ("TC17", "Amount above limit", MAX_CENTS + 1)]:
        ok, why, _ = full(int(tc[2:]), amount=amt)
        record(tc, label, "reject", ok, why, "Input validation")
    d, m, r, c = new_donation(18)
    bad = encode({k: v for k, v in d.items() if k != "charityID"})
    c2 = commit(bad, r)
    att, why = auditor.attest(d["donationID"], c2, bad, r)
    record("TC18", "Missing field (charityID)", "reject", v1.verify(d["donationID"], c2, att)[0], why, "Input validation")
    ok, why, _ = full(19, extra="x")
    record("TC19", "Unknown extra field", "reject", ok, why, "Input validation")
    raw = b"{not json"
    rr = secrets.token_bytes(32)
    att, why = auditor.attest("D-0000020", commit(raw, rr), raw, rr)
    record("TC20", "Malformed record", "reject", att is not None, why, "Input validation")
    d, m, r, c = new_donation(21)
    att, _ = auditor.attest(d["donationID"], c, m, r, policy="rules-2025-01")
    ok, why = v1.verify(d["donationID"], c, att)
    record("TC21", "Attestation under an old policy version", "reject", ok, why, "Versioning")
    d, m, r, c = new_donation(22)
    att, _ = auditor.attest(d["donationID"], c, m, r)
    ok, why = v1.verify("D-0000099", c, att)
    record("TC22", "Valid attestation reused for another donation ID", "reject", ok, why, "Binding to record")
    v_rev = PublicVerifier([auditor.public_key], ReplayRegistry(reg_path))
    v_rev.revoke(auditor.key_id)
    d, m, r, c = new_donation(23)
    att, _ = auditor.attest(d["donationID"], c, m, r)
    ok, why = v_rev.verify(d["donationID"], c, att)
    record("TC23", "Attestation under a revoked auditor key", "reject", ok, why, "Key revocation")
    d, m, r, c = new_donation(24)
    old_att, _ = auditor.attest(d["donationID"], c, m, r)
    v1.trust(auditor.rotate_key())
    d2, m2, r2, c2 = new_donation(25)
    new_att, _ = auditor.attest(d2["donationID"], c2, m2, r2)
    ok_old, _ = v1.verify(d["donationID"], c, old_att)
    ok_new, _ = v1.verify(d2["donationID"], c2, new_att)
    record("TC24", "Key rotation: old and new attestations both verify", "accept",
           ok_old and ok_new, f"old key {'accepted' if ok_old else 'rejected'}; new key {'accepted' if ok_new else 'rejected'}",
           "Key rotation")
    ok, why, _ = full(25, currency="USD")
    record("TC25", "Unsupported currency (USD)", "reject", ok, why, "Rule check")
    d, m, r, c = new_donation(26)
    other = new_donation_id()
    att, why = auditor.attest(other, c, m, r)
    ok, reason = v1.verify(other, c, att)
    record("TC26", "Opening registered under a different donation ID", "reject", ok,
           reason if att else why, "Binding to ID")
    d, m, r, c = new_donation(27)
    auditor.attest(d["donationID"], c, m, r)
    att, why = auditor.attest(d["donationID"], c, m, r)
    record("TC27", "Same donation sent to the auditor twice", "reject", att is not None,
           why, "Replay resistance (auditor)")
    for row in rows:   # stricter pass rule: the intended check must be the one that decided
        row["pass"] = row["pass"] and EXPECT[row["id"]] in row["reason"]
    return rows


EXPECT = {"TC01": "accepted", "TC02": "commitment does not match", "TC03": "charity not in approved",
          "TC04": "invalid attestation signature", "TC05": "replay", "TC06": "commitment does not match",
          "TC07": "replay", "TC08": "1 of 8", "TC09": "replay", "TC10": "unknown auditor key",
          "TC11": "invalid amount", "TC12": "invalid amount", "TC13": "invalid amount",
          "TC14": "invalid amount", "TC15": "invalid amount", "TC16": "invalid amount",
          "TC17": "invalid amount", "TC18": "schema", "TC19": "schema", "TC20": "malformed",
          "TC21": "version", "TC22": "does not match ledger", "TC23": "revoked",
          "TC24": "old key accepted; new key accepted", "TC25": "unsupported currency",
          "TC26": "donation ID does not match opening", "TC27": "already attested"}
CHECKS = ["commitment", "schema", "id_match", "amount", "currency", "registry", "auditor_replay",
          "registry_replay", "revocation", "signature", "version", "binding"]


def mutation_matrix():
    """Switch off one defence at a time and report which tests then fail."""
    out = []
    for check in CHECKS:
        DISABLED.clear(); DISABLED.add(check)
        with tempfile.TemporaryDirectory() as tmp:
            failed = [t["id"] for t in run_tests(tmp) if not t["pass"]]
        out.append({"disabled": check, "failing_tests": failed})
    DISABLED.clear()
    return out


def privacy_scan():
    """Search the public record for every private value of a sample donation."""
    auditor = Auditor()
    d, m, r, c = new_donation(0, amount=4321, donor="alice@example.org", charity="CH-002")
    (st, sig), _ = auditor.attest(d["donationID"], c, m, r)
    public = {"donationID": d["donationID"], "commitment": c.hex(), "statement": json.loads(st), "signature": sig.hex()}
    values = set()
    def walk(o):
        if isinstance(o, dict):
            [walk(v) for v in o.values()]
        else:
            values.add(o)
    walk(public)
    text = encode(public).decode()
    def leaked(v):
        return v in values or (isinstance(v, str) and len(v) >= 8 and v in text)
    return [{"field": f, "leaked": leaked(v)} for f, v in
            [("amountCents", d["amountCents"]), ("donorID", d["donorID"]), ("charityID", d["charityID"]),
             ("currency", d["currency"]), ("nonce", r.hex())]]


# ---------------------------------------------------------------- timing
def summarize(samples_ns, run_means_us):
    us = sorted(s / 1000 for s in samples_ns)
    q = statistics.quantiles(us, n=4)
    rm = run_means_us
    half = 2.776 * statistics.stdev(rm) / math.sqrt(len(rm))   # t(0.975, df=4)
    return {"n": len(us), "median": statistics.median(us), "q1": q[0], "q3": q[2],
            "mean": statistics.fmean(us), "sd": statistics.stdev(us), "min": us[0], "max": us[-1],
            "run_means": rm, "run_mean_ci_low": statistics.fmean(rm) - half,
            "run_mean_ci_high": statistics.fmean(rm) + half}


def one_run(tmp, k):
    pc = time.perf_counter_ns
    auditor = Auditor()
    charity_sk = Ed25519PrivateKey.generate()
    charity_pk = charity_sk.public_key()
    verifier = PublicVerifier([auditor.public_key], ReplayRegistry(os.path.join(tmp, f"bench{k}.db")))
    reg_b = ReplayRegistry(os.path.join(tmp, f"benchB{k}.db"))
    t = {x: [] for x in ["commitment", "auditor_check_and_sign", "public_verification",
                         "baseline_A_rule_check", "baseline_B_signed_record_check", "end_to_end"]}
    n = WARMUP + TRIALS
    for i in range(n):
        details = {"donationID": new_donation_id(), "amountCents": 5000, "currency": "AUD",
                   "charityID": "CH-001", "donorID": "alice@example.org"}
        t0 = pc(); m = encode(details); r = secrets.token_bytes(32); c = commit(m, r); t1 = pc()
        att, _ = auditor.attest(details["donationID"], c, m, r); t2 = pc()
        ok, _ = verifier.verify(details["donationID"], c, att); t3 = pc()
        assert ok
        t["commitment"].append(t1 - t0); t["auditor_check_and_sign"].append(t2 - t1)
        t["public_verification"].append(t3 - t2); t["end_to_end"].append(t3 - t0)
        # Baseline A: plain public record, rule check only
        t0 = pc(); rec = json.loads(m)
        okA = valid_amount(rec["amountCents"]) and rec["charityID"] in APPROVED_CHARITIES; t1 = pc()
        assert okA
        t["baseline_A_rule_check"].append(t1 - t0)
        # Baseline B: plain record signed by the charity; public checks signature, rules, replay
        sig = charity_sk.sign(m)
        t0 = pc()
        charity_pk.verify(sig, m)
        rec = json.loads(m)
        okB = valid_amount(rec["amountCents"]) and rec["charityID"] in APPROVED_CHARITIES \
            and reg_b.claim(rec["donationID"])
        t1 = pc()
        assert okB
        t["baseline_B_signed_record_check"].append(t1 - t0)
    return {x: v[WARMUP:] for x, v in t.items()}


def verify_breakdown(tmp, k):
    """Time the parts of public verification (design) and of Baseline B separately."""
    pc = time.perf_counter_ns
    auditor = Auditor()
    charity_sk = Ed25519PrivateKey.generate()
    charity_pk = charity_sk.public_key()
    reg = ReplayRegistry(os.path.join(tmp, f"parts{k}.db"))
    reg_b = ReplayRegistry(os.path.join(tmp, f"partsB{k}.db"))
    con_mem = sqlite3.connect(":memory:")
    con_mem.execute("CREATE TABLE accepted (donation_id TEXT PRIMARY KEY)")
    t = {x: [] for x in ["design_signature_verify", "design_statement_checks", "design_registry_claim",
                         "B_signature_verify", "B_rule_checks", "B_registry_claim",
                         "registry_claim_in_memory"]}
    for i in range(WARMUP + TRIALS):
        details = {"donationID": new_donation_id(), "amountCents": 5000, "currency": "AUD",
                   "charityID": "CH-001", "donorID": "alice@example.org"}
        did = details["donationID"]
        m = encode(details); r = secrets.token_bytes(32); c = commit(m, r)
        (st, sig), _ = auditor.attest(did, c, m, r)
        t0 = pc(); auditor.public_key.verify(sig, st); t1 = pc()
        s_ = json.loads(st)
        ok = (s_["protocol"], s_["policy"], s_["registry"], s_["result"]) == \
             (PROTOCOL, POLICY_VERSION, REGISTRY_VERSION, "valid") \
             and s_["donationID"] == did and s_["commitment"] == c.hex(); t2 = pc()
        ok = ok and reg.claim(did); t3 = pc()
        assert ok
        t["design_signature_verify"].append(t1 - t0); t["design_statement_checks"].append(t2 - t1)
        t["design_registry_claim"].append(t3 - t2)
        sig_b = charity_sk.sign(m)
        t0 = pc(); charity_pk.verify(sig_b, m); t1 = pc()
        rec = json.loads(m)
        okB = valid_amount(rec["amountCents"]) and rec["charityID"] in APPROVED_CHARITIES; t2 = pc()
        okB = okB and reg_b.claim(rec["donationID"]); t3 = pc()
        assert okB
        t["B_signature_verify"].append(t1 - t0); t["B_rule_checks"].append(t2 - t1)
        t["B_registry_claim"].append(t3 - t2)
        t0 = pc()
        with con_mem:
            con_mem.execute("INSERT INTO accepted VALUES (?)", (did,))
        t1 = pc()
        t["registry_claim_in_memory"].append(t1 - t0)
    return {x: v[WARMUP:] for x, v in t.items()}


def scaling():
    """Full commitment (build record, encode, nonce, SHA-256) as a memo field grows.
    The first point has no memo: it is the same 122-byte record used in the timing runs."""
    out, pc = [], time.perf_counter_ns
    for size in [0] + [64 << j for j in range(15)]:          # 0, 64 B ... 1 MiB
        memo = "a" * size
        samples = []
        for i in range(WARMUP + TRIALS):
            details = {"donationID": new_donation_id(), "amountCents": 5000, "currency": "AUD",
                       "charityID": "CH-001", "donorID": "alice@example.org"}
            if size:
                details["memo"] = memo
            t0 = pc(); m = encode(details); r = secrets.token_bytes(32); commit(m, r); t1 = pc()
            samples.append(t1 - t0)
        us = sorted(s / 1000 for s in samples[WARMUP:])
        out.append({"memo_bytes": size, "record_bytes": len(m), "median": statistics.median(us),
                    "mean": statistics.fmean(us), "sd": statistics.stdev(us)})
    return out


def storage():
    auditor = Auditor()
    d, m, r, c = new_donation(9_999_999)
    (st, sig), _ = auditor.attest(d["donationID"], c, m, r)
    design = {"donationID": d["donationID"], "commitment": c.hex(), "statement": st.decode(), "signature": sig.hex()}
    base_a = d
    base_b = dict(d, signature=Ed25519PrivateKey.generate().sign(m).hex())
    return {"commitment_bytes": len(c), "signature_bytes": len(sig), "statement_bytes": len(st),
            "design_public_record_bytes": len(encode(design)),
            "baseline_A_public_record_bytes": len(encode(base_a)),
            "baseline_B_public_record_bytes": len(encode(base_b)),
            "private_opening_bytes": len(m) + len(r)}


PRIVACY = [("Donation ID", "Public", "Public", "Public"),
           ("Amount", "Public", "Public", "Hidden from public; auditor sees it"),
           ("Donor ID", "Public", "Public", "Hidden from public; auditor sees it"),
           ("Charity ID", "Public", "Public", "Hidden from public; auditor sees it"),
           ("Nonce", "Not used", "Not used", "Donor and auditor only"),
           ("Commitment", "Not used", "Not used", "Public"),
           ("Signed statement", "Not used", "Charity signature", "Auditor attestation")]


def environment():
    import cryptography
    mem = ""
    try:
        with open("/proc/meminfo") as f:
            mem = f.readline().split(":", 1)[1].strip()
    except OSError:
        pass
    return {"os": platform.platform(), "python": sys.version.split()[0], "machine": platform.machine(),
            "cpus": os.cpu_count(), "memory": mem, "cryptography": cryptography.__version__,
            "sqlite": sqlite3.sqlite_version}


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tests = run_tests(tmp)
    mutations = mutation_matrix()
    scan = privacy_scan()
    floor = []
    for _ in range(WARMUP + TRIALS):
        t0 = time.perf_counter_ns(); t1 = time.perf_counter_ns(); floor.append(t1 - t0)
    floor_us = statistics.median(floor[WARMUP:]) / 1000
    gc.collect(); gc.disable()      # pause garbage collection while timing, as timeit does
    try:
        with tempfile.TemporaryDirectory() as tmp:
            runs = [one_run(tmp, k) for k in range(RUNS)]
            parts = [verify_breakdown(tmp, k) for k in range(RUNS)]
    finally:
        gc.enable()
    timing = {}
    for op in runs[0]:
        pooled = [x for run in runs for x in run[op]]
        timing[op] = summarize(pooled, [statistics.fmean(run[op]) / 1000 for run in runs])
    breakdown = {}
    for op in parts[0]:
        pooled = [x for run in parts for x in run[op]]
        breakdown[op] = summarize(pooled, [statistics.fmean(run[op]) / 1000 for run in parts])
    scale, store, env = scaling(), storage(), environment()
    env["timer_floor_median_us"] = round(floor_us, 3)
    results = {"tests": tests, "mutations": mutations, "privacy_scan": scan, "timing_us": timing, "verification_breakdown_us": breakdown, "scaling_us": scale, "storage": store,
               "privacy": PRIVACY, "environment": env,
               "settings": {"warmup": WARMUP, "trials": TRIALS, "runs": RUNS}}
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(results, f, indent=2)
    L = ["## Functional tests", "", "| ID | Scenario | Property | Expected | Actual | Reason | Pass |", "|---|---|---|---|---|---|---|"]
    L += [f"| {t['id']} | {t['scenario']} | {t['property']} | {t['expected']} | {t['actual']} | {t['reason']} | {'yes' if t['pass'] else 'NO'} |" for t in tests]
    L += ["", "## Mutation testing (one defence switched off at a time)", "", "| Disabled check | Tests that then fail |", "|---|---|"]
    L += [f"| {x['disabled']} | {', '.join(x['failing_tests']) or 'NONE'} |" for x in mutations]
    L += ["", "## Privacy scan of the public record", "", "| Private field | Found in public record? |", "|---|---|"]
    L += [f"| {x['field']} | {'YES' if x['leaked'] else 'no'} |" for x in scan]
    L += ["", f"## Timing (µs; {RUNS} runs x {TRIALS} trials)", "",
          "| Operation | Median | IQR | Mean | SD | Max | 95% CI of mean (from 5 run means) |", "|---|---|---|---|---|---|---|"]
    L += [f"| {op} | {s['median']:.1f} | {s['q1']:.1f} to {s['q3']:.1f} | {s['mean']:.1f} | {s['sd']:.1f} | {s['max']:.1f} | {s['run_mean_ci_low']:.1f} to {s['run_mean_ci_high']:.1f} |" for op, s in timing.items()]
    L += ["", f"## Breakdown of verification (µs; separate loop, {RUNS} runs x {TRIALS} trials)", "",
          "| Part | Median | IQR | Mean | 95% CI of mean (from 5 run means) |", "|---|---|---|---|---|"]
    L += [f"| {op} | {s['median']:.1f} | {s['q1']:.1f} to {s['q3']:.1f} | {s['mean']:.1f} | {s['run_mean_ci_low']:.1f} to {s['run_mean_ci_high']:.1f} |" for op, s in breakdown.items()]
    L += ["", "## Scaling of full commitment (µs)", "", "| Memo bytes | Record bytes | Median | Mean | SD |", "|---|---|---|---|---|"]
    L += [f"| {s['memo_bytes']:,} | {s['record_bytes']:,} | {s['median']:.1f} | {s['mean']:.1f} | {s['sd']:.1f} |" for s in scale]
    L += ["", "## Storage", ""] + [f"- {k}: {v}" for k, v in store.items()]
    L += ["", "## Environment", ""] + [f"- {k}: {v}" for k, v in env.items()]
    with open(os.path.join(OUT, "results.md"), "w") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        lab = {"commitment": "Commitment", "auditor_check_and_sign": "Auditor\ncheck + sign",
               "public_verification": "Public\nverification", "baseline_A_rule_check": "Baseline A\nrule check",
               "baseline_B_signed_record_check": "Baseline B\nsigned record", "end_to_end": "End to end\n(design)"}
        ops = list(timing)
        med = [timing[o]["median"] for o in ops]
        err = [[timing[o]["median"] - timing[o]["q1"] for o in ops], [timing[o]["q3"] - timing[o]["median"] for o in ops]]
        fig, ax = plt.subplots(figsize=(7.2, 3.8))
        ax.bar([lab[o] for o in ops], med, yerr=err, capsize=4, color="#4C78A8")
        ax.set_yscale("log"); ax.set_ylabel("Time per operation (µs, log scale)")
        ax.set_title("Median time per operation (error bars: interquartile range)")
        ax.tick_params(axis="x", labelsize=8); fig.tight_layout()
        fig.savefig(os.path.join(OUT, "fig_timing.png"), dpi=200)
        fig, ax = plt.subplots(figsize=(6.4, 3.6))
        ax.plot([s["record_bytes"] for s in scale], [s["median"] for s in scale], marker="o", color="#4C78A8")
        ax.set_xscale("log", base=2); ax.set_yscale("log")
        ax.set_xlabel("Encoded donation record size (bytes, log scale)")
        ax.set_ylabel("Full commitment time (µs, log scale)")
        ax.set_title("Full commitment time vs record size (median)")
        fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_scaling.png"), dpi=200)
        parts = [("signature_verify", "Signature check", "#4C78A8"),
                 ("checks", "Statement or rule checks", "#9ECAE9"),
                 ("registry_claim", "Replay registry write (disk)", "#F58518")]
        rows = [("This design", "design_"), ("Baseline B", "B_")]
        fig, ax = plt.subplots(figsize=(7.2, 2.6))
        for y, (label, pre) in enumerate(rows):
            left = 0
            for key, name, col in parts:
                k = pre + ("statement_checks" if (key == "checks" and pre == "design_") else
                           "rule_checks" if key == "checks" else key)
                w = breakdown[k]["median"]
                ax.barh(y, w, left=left, color=col, label=name if y == 0 else None)
                left += w
        ax.set_yticks(range(len(rows))); ax.set_yticklabels([r[0] for r in rows]); ax.invert_yaxis()
        ax.set_xlabel("Median time per part of public verification (µs)")
        ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, frameon=False, fontsize=8)
        fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_breakdown.png"), dpi=200)
    except Exception as exc:
        print("figures skipped:", exc)


if __name__ == "__main__":
    main()
