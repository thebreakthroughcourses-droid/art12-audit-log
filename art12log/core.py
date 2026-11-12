"""Art. 12 audit log: hash-chained envelopes, separate content layer, signed checkpoints."""
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

GENESIS = "0" * 64
RETENTION_DAYS = 180  # six-month floor (EU AI Act Arts. 19 and 26(6))


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sign(key: bytes, seq: int, head: str) -> str:
    return hmac.new(key, f"{seq}:{head}".encode(), hashlib.sha256).hexdigest()


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def _read_jsonl(path: Path):
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class AuditLog:
    """Append-only log. The chain hashes only a structural envelope; personal data
    lives in a separate content object that can be erased without breaking the chain."""

    def __init__(self, root, system_id, anchor_key: bytes, checkpoint_every=50,
                 retention_days=RETENTION_DAYS, clock=utcnow):
        self.root = Path(root)
        (self.root / "content").mkdir(parents=True, exist_ok=True)
        self.chain_path = self.root / "chain.jsonl"
        self.cp_path = self.root / "checkpoints.jsonl"
        self.system_id = system_id
        self.key = anchor_key
        self.every = checkpoint_every
        self.retention_days = retention_days
        self.clock = clock
        entries = _read_jsonl(self.chain_path)
        self.seq = entries[-1]["seq"] if entries else 0
        self.head = entries[-1]["hash"] if entries else GENESIS

    # -- writing -------------------------------------------------------------
    def _append(self, body: dict) -> dict:
        self.seq += 1
        entry = {"seq": self.seq, "ts": self.clock().isoformat(), "system_id": self.system_id,
                 **body, "prev_hash": self.head}
        entry["hash"] = sha(canon(entry))
        with self.chain_path.open("a", encoding="utf-8") as f:
            f.write(canon(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.head = entry["hash"]
        if self.seq % self.every == 0:
            self.checkpoint()
        return entry

    def checkpoint(self) -> dict:
        cp = {"seq": self.seq, "head": self.head, "ts": self.clock().isoformat(),
              "sig": sign(self.key, self.seq, self.head)}
        with self.cp_path.open("a", encoding="utf-8") as f:
            f.write(canon(cp) + "\n")
        return cp

    def record(self, decision_id, event_type, model_id=None, params=None,
               latency_ms=None, content=None) -> dict:
        body = {"decision_id": decision_id, "event_type": event_type, "model_id": model_id,
                "params": params or {}, "latency_ms": latency_ms,
                "content_ref": None, "content_commitment": None}
        if content is not None:
            ref, salt = secrets.token_hex(8), secrets.token_hex(16)
            (self.root / "content" / f"{ref}.json").write_text(
                canon({"salt": salt, "content": content}), encoding="utf-8")
            body["content_ref"] = ref
            body["content_commitment"] = sha(salt + canon(content))  # salted: not guessable
        return self._append(body)

    # -- lookup / erasure ----------------------------------------------------
    def entries(self):
        return _read_jsonl(self.chain_path)

    def find(self, decision_id):
        return [e for e in self.entries() if e["decision_id"] == decision_id
                and e["event_type"] != "evidence_access"]

    def erase_content(self, decision_id, reason):
        """GDPR-style erasure of the content layer. Refused inside the retention floor."""
        done = []
        for e in self.find(decision_id):
            ref = e.get("content_ref")
            if not ref:
                continue
            age = self.clock() - dt.datetime.fromisoformat(e["ts"])
            if age.days < self.retention_days:
                raise PermissionError(
                    f"retention floor: entry {e['seq']} is {age.days}d old, floor {self.retention_days}d")
            p = self.root / "content" / f"{ref}.json"
            if p.exists():
                p.unlink()
            self.record(decision_id, "content_erasure", params={"erased_ref": ref, "reason": reason})
            done.append(ref)
        return done

    def read_content(self, ref):
        p = self.root / "content" / f"{ref}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


# -- verification (static: needs only the files and the anchor key) ----------
def verify(root, anchor_key: bytes) -> dict:
    root = Path(root)
    entries = _read_jsonl(root / "chain.jsonl")
    cps = _read_jsonl(root / "checkpoints.jsonl")
    errors, prev, last_ts = [], GENESIS, None
    erased = set()
    by_seq = {}
    for i, e in enumerate(entries, 1):
        by_seq[e["seq"]] = e
        if e["seq"] != i:
            errors.append(f"seq gap or reorder at position {i} (seq {e['seq']})")
        if e["prev_hash"] != prev:
            errors.append(f"broken link at seq {e['seq']}")
        body = {k: v for k, v in e.items() if k != "hash"}
        if sha(canon(body)) != e["hash"]:
            errors.append(f"entry hash mismatch at seq {e['seq']}")
        if last_ts and e["ts"] < last_ts:
            errors.append(f"timestamp goes backwards at seq {e['seq']}")
        last_ts = e["ts"]
        prev = e["hash"]
        if e["event_type"] == "content_erasure":
            erased.add(e["params"]["erased_ref"])
    for cp in cps:
        if not hmac.compare_digest(cp["sig"], sign(anchor_key, cp["seq"], cp["head"])):
            errors.append(f"checkpoint signature invalid at seq {cp['seq']}")
        elif cp["seq"] > len(entries):
            errors.append(f"truncation: checkpoint at seq {cp['seq']} but chain ends at {len(entries)}")
        elif by_seq[cp["seq"]]["hash"] != cp["head"]:
            errors.append(f"chain rewritten before checkpoint seq {cp['seq']}")
    for e in entries:
        ref = e.get("content_ref")
        if not ref:
            continue
        p = root / "content" / f"{ref}.json"
        if not p.exists():
            if ref not in erased:
                errors.append(f"content {ref} (seq {e['seq']}) missing with no erasure event")
            continue
        obj = json.loads(p.read_text(encoding="utf-8"))
        if sha(obj["salt"] + canon(obj["content"])) != e["content_commitment"]:
            errors.append(f"content {ref} (seq {e['seq']}) altered")
    return {"ok": not errors, "entries": len(entries), "checkpoints": len(cps),
            "erased_refs": len(erased), "errors": errors}


def coverage(root, expected_decision_ids, max_gap_minutes=None) -> dict:
    """Omissions matter more than edits: compare the log to what the host app says it ran."""
    logged = {e["decision_id"] for e in _read_jsonl(Path(root) / "chain.jsonl")
              if e["event_type"] == "inference"}
    missing = sorted(set(expected_decision_ids) - logged)
    out = {"expected": len(set(expected_decision_ids)), "logged": len(logged & set(expected_decision_ids)),
           "missing": missing}
    if max_gap_minutes:
        ts = [dt.datetime.fromisoformat(e["ts"]) for e in _read_jsonl(Path(root) / "chain.jsonl")]
        out["time_gaps"] = [(a.isoformat(), b.isoformat()) for a, b in zip(ts, ts[1:])
                            if (b - a).total_seconds() > max_gap_minutes * 60]
    return out
