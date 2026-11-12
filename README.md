# art12-audit-log

A small Python library that records events from a high-risk AI system the way EU AI Act Article 12 asks, and lets a regulator check the record without trusting the operator. Built as the Build stage of a TKS focus project on AI regulation (liability and data control).

Standard library only. Python 3.9+.

## What it does

1. **Tamper-evident chain.** Each event is a JSON envelope (time, decision ID, model ID, parameters, latency, event type) hashed with SHA-256 and linked to the previous one.
2. **Content kept separate.** Personal data (applicant details, reviewer notes) lives in a content object. The chain stores only a salted commitment to it. Erase the object and the chain stays valid.
3. **Signed checkpoints.** Every N entries the head hash is signed with a key held outside the log store. This catches the attack where someone edits an entry and recomputes every later hash.
4. **Retention floor.** Erasure is refused inside 180 days (six months, Arts. 19 and 26(6)). After that it is allowed and recorded on the chain as an event.
5. **Evidence access (the twist).** Regulators, deployers and the provider see different things. Every request, granted or denied, is itself an event on the chain. Exports are bundles that verify offline.
6. **Coverage check.** Compares the log to the decision IDs the host application says it ran, because omissions are a bigger risk than edits.

## Run it

```
python3 tests/test_art12.py     # 12 tests, tamper and access scenarios
python3 demo.py                 # hiring-screen scenario end to end
python3 benchmark.py            # write and verify speed on 10,000 entries
```

## Use it

```python
from art12log import AuditLog, EvidenceAccess, verify, verify_bundle

log = AuditLog("./logstore", "my-system-v1", anchor_key=b"...kept elsewhere...")
log.record("D0001", "inference", model_id="m1", params={"threshold": 0.7},
           latency_ms=41, content={"applicant": "...", "score": 0.82})

access = EvidenceAccess(log)
access.grant("CASE-1", ["D0001"])
bundle = access.export_bundle("inspector-1", "market_surveillance_authority",
                              "D0001", "complaint 1", case_id="CASE-1")
print(verify_bundle(bundle, b"...kept elsewhere..."))
print(verify("./logstore", b"...kept elsewhere..."))
```

## Limits (read these before trusting it)

- **Tamper-evident, not tamper-proof.** Someone with write access plus the anchor key can forge a history. Put the log on write-once storage and hold the key elsewhere. A public-key signature or an external timestamp (RFC 3161, OpenTimestamps) would remove the shared-key weakness. Not built.
- **Tail truncation.** Entries added after the last checkpoint can be dropped undetected. Exports force a checkpoint; a timer-based one would shrink the window.
- **A bundle proves less than a full verify.** It proves the slice from the decision to the signed head, not the history before it.
- **Single process.** No locking for concurrent writers.
- **Not legal advice.** Whether this satisfies Article 12 for a given system is a question for a lawyer.
