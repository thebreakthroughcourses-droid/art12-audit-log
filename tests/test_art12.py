import datetime as dt
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from art12log import AuditLog, EvidenceAccess, verify, verify_bundle, coverage
from art12log.core import canon, sha, GENESIS

KEY = b"anchor-key-held-outside-the-log-store"


class FakeClock:
    def __init__(self):
        self.t = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    def __call__(self):
        self.t += dt.timedelta(minutes=1)
        return self.t

    def jump(self, days):
        self.t += dt.timedelta(days=days)


def make(n=120):
    d = Path(tempfile.mkdtemp())
    clock = FakeClock()
    log = AuditLog(d, "cv-screener-v3", KEY, checkpoint_every=25, clock=clock)
    for i in range(n):
        log.record(f"D{i:04d}", "inference", model_id="screen-1.4", params={"threshold": 0.7},
                   latency_ms=40 + i % 7,
                   content={"applicant": f"person-{i}", "score": round(0.5 + (i % 5) / 10, 2)})
    return d, log, clock


class T(unittest.TestCase):
    def setUp(self):
        self.d, self.log, self.clock = make()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def lines(self):
        return (self.d / "chain.jsonl").read_text().splitlines()

    def test_clean_chain_verifies(self):
        r = verify(self.d, KEY)
        self.assertTrue(r["ok"], r["errors"])
        self.assertEqual(r["entries"], 120)

    def test_edit_detected(self):
        ls = self.lines()
        e = json.loads(ls[10])
        e["params"]["threshold"] = 0.2
        ls[10] = canon(e)
        (self.d / "chain.jsonl").write_text("\n".join(ls) + "\n")
        self.assertFalse(verify(self.d, KEY)["ok"])

    def test_deleted_entry_detected(self):
        ls = self.lines()
        del ls[40]
        (self.d / "chain.jsonl").write_text("\n".join(ls) + "\n")
        self.assertFalse(verify(self.d, KEY)["ok"])

    def test_truncation_past_checkpoint_detected(self):
        ls = self.lines()[:60]
        (self.d / "chain.jsonl").write_text("\n".join(ls) + "\n")
        r = verify(self.d, KEY)
        self.assertTrue(any("truncation" in x for x in r["errors"]))

    def test_full_rehash_attack_caught_by_checkpoints(self):
        """Attacker edits an entry and recomputes every hash after it. The chain alone passes;
        the signed checkpoints do not."""
        es = [json.loads(x) for x in self.lines()]
        es[10]["params"]["threshold"] = 0.2
        prev = GENESIS
        for e in es:
            e["prev_hash"] = prev
            e.pop("hash", None)
            e["hash"] = sha(canon(e))
            prev = e["hash"]
        (self.d / "chain.jsonl").write_text("\n".join(canon(e) for e in es) + "\n")
        r = verify(self.d, KEY)
        self.assertFalse(r["ok"])
        self.assertFalse(any("broken link" in x or "entry hash" in x for x in r["errors"]))
        self.assertTrue(any("rewritten" in x for x in r["errors"]))

    def test_content_deleted_without_erasure_detected(self):
        ref = self.log.entries()[5]["content_ref"]
        (self.d / "content" / f"{ref}.json").unlink()
        self.assertTrue(any("no erasure event" in x for x in verify(self.d, KEY)["errors"]))

    def test_content_edited_detected(self):
        ref = self.log.entries()[5]["content_ref"]
        p = self.d / "content" / f"{ref}.json"
        o = json.loads(p.read_text())
        o["content"]["score"] = 0.99
        p.write_text(canon(o))
        self.assertTrue(any("altered" in x for x in verify(self.d, KEY)["errors"]))

    def test_erasure_blocked_inside_retention_floor(self):
        with self.assertRaises(PermissionError):
            self.log.erase_content("D0003", "subject request")

    def test_erasure_after_floor_keeps_chain_valid(self):
        self.clock.jump(200)
        self.log.erase_content("D0003", "subject request")
        r = verify(self.d, KEY)
        self.assertTrue(r["ok"], r["errors"])
        self.assertEqual(r["erased_refs"], 1)

    def test_access_control_and_logging(self):
        acc = EvidenceAccess(self.log)
        b = acc.export_bundle("dpo@client", "deployer_reviewer", "D0007", "annual review")
        self.assertEqual(set(b["content_status"].values()), {"withheld_by_policy"})
        b = acc.export_bundle("insp-17", "market_surveillance_authority", "D0007", "complaint 88")
        self.assertEqual(set(b["content_status"].values()), {"withheld_by_policy"})
        acc.grant("CASE-88", ["D0007"])
        b = acc.export_bundle("insp-17", "market_surveillance_authority", "D0007", "complaint 88",
                              case_id="CASE-88")
        self.assertEqual(set(b["content_status"].values()), {"included"})
        with self.assertRaises(PermissionError):
            acc.export_bundle("intern", "provider_admin", "D0007", "  ")
        accesses = [e for e in self.log.entries() if e["event_type"] == "evidence_access"]
        self.assertEqual(len(accesses), 4)  # three granted + one denied, all on the chain
        self.assertTrue(verify(self.d, KEY)["ok"])

    def test_bundle_verifies_offline_and_detects_tampering(self):
        acc = EvidenceAccess(self.log)
        b = acc.export_bundle("admin", "provider_admin", "D0050", "audit")
        self.assertTrue(verify_bundle(b, KEY)["ok"])
        ref = next(iter(b["content"]))
        b["content"][ref]["content"]["score"] = 0.01
        self.assertFalse(verify_bundle(b, KEY)["ok"])

    def test_coverage_finds_omissions(self):
        expected = [f"D{i:04d}" for i in range(125)]
        self.assertEqual(coverage(self.d, expected)["missing"], [f"D{i:04d}" for i in range(120, 125)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
