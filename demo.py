"""End-to-end demo: a hiring-screen AI (Annex III, employment) logs decisions; a regulator asks for evidence."""
import datetime as dt
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from art12log import AuditLog, EvidenceAccess, verify, verify_bundle, coverage

KEY = b"anchor-key-held-outside-the-log-store"
t = [dt.datetime(2026, 1, 5, 9, tzinfo=dt.timezone.utc)]


def clock():
    t[0] += dt.timedelta(minutes=3)
    return t[0]


root = Path(tempfile.mkdtemp(prefix="art12demo_"))
log = AuditLog(root, "cv-screener-v3", KEY, checkpoint_every=25, clock=clock)
ids = []
for i in range(60):
    did = f"D{i:04d}"
    ids.append(did)
    log.record(did, "inference", model_id="screen-1.4", params={"threshold": 0.7}, latency_ms=38 + i % 9,
               content={"applicant": f"applicant-{i}", "cv_hash_input": f"cv-{i}", "score": round(0.4 + (i % 6) / 10, 2)})
    if i % 12 == 0:
        log.record(did, "human_override", params={"reviewer": "hr-04", "from": "reject", "to": "interview"},
                   content={"note": "relevant experience not parsed"})
log.record("CFG-1", "config_change", params={"threshold": {"from": 0.7, "to": 0.65}, "by": "ml-lead"})

print(f"logged {log.seq} events in {root}")
print("verify:", verify(root, KEY))
print("coverage:", coverage(root, ids + ["D9999"]))

acc = EvidenceAccess(log)
acc.grant("CASE-2026-14", ["D0012"])
b = acc.export_bundle("inspector-17", "market_surveillance_authority", "D0012", "complaint 2026-14",
                      case_id="CASE-2026-14")
print("regulator bundle:", len(b["entries"]), "entries, content", set(b["content_status"].values()),
      "| offline verify:", verify_bundle(b, KEY))
b2 = acc.export_bundle("dpo-client", "deployer_reviewer", "D0012", "annual review")
print("deployer bundle content:", set(b2["content_status"].values()))

t[0] += dt.timedelta(days=200)
log.erase_content("D0012", "data subject request")
print("after erasure verify:", verify(root, KEY))
b3 = acc.export_bundle("inspector-17", "market_surveillance_authority", "D0012", "follow-up",
                       case_id="CASE-2026-14")
print("content status after erasure:", set(b3["content_status"].values()))
(root / "sample_bundle.json").write_text(json.dumps(b, indent=2))
print("sample files:", root)
