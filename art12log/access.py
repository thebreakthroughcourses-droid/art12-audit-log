"""Evidence-access layer: who may see what, every request logged in the same chain,
and exports that a regulator can verify offline."""
import hmac

from .core import AuditLog, GENESIS, canon, sha, sign

# role -> what it may read
POLICY = {
    "provider_admin": {"envelope": True, "content": "always"},
    "deployer_reviewer": {"envelope": True, "content": "never"},
    "market_surveillance_authority": {"envelope": True, "content": "with_case_grant"},
}


class EvidenceAccess:
    def __init__(self, log: AuditLog):
        self.log = log
        self.grants = {}  # case_id -> set(decision_ids)

    def grant(self, case_id, decision_ids):
        self.grants[case_id] = set(decision_ids)

    def _content_allowed(self, role, decision_id, case_id):
        rule = POLICY[role]["content"]
        if rule == "always":
            return True
        if rule == "with_case_grant":
            return decision_id in self.grants.get(case_id, set())
        return False

    def export_bundle(self, actor, role, decision_id, purpose, case_id=None):
        """Log the request (allowed or not), force a signed checkpoint, return a bundle."""
        if role not in POLICY:
            self.log.record(decision_id, "evidence_access",
                            params={"actor": actor, "role": role, "outcome": "denied_unknown_role",
                                    "purpose": purpose})
            raise PermissionError(f"unknown role {role}")
        if not purpose or not purpose.strip():
            self.log.record(decision_id, "evidence_access",
                            params={"actor": actor, "role": role, "outcome": "denied_no_purpose"})
            raise PermissionError("a purpose is required for every access")
        related = self.log.find(decision_id)
        if not related:
            raise KeyError(decision_id)
        want_content = self._content_allowed(role, decision_id, case_id)
        self.log.record(decision_id, "evidence_access",
                        params={"actor": actor, "role": role, "purpose": purpose, "case_id": case_id,
                                "content_released": want_content, "outcome": "granted"})
        cp = self.log.checkpoint()
        start = related[0]["seq"]
        entries = [e for e in self.log.entries() if e["seq"] >= start]
        content, status = {}, {}
        for e in related:
            ref = e.get("content_ref")
            if not ref:
                continue
            if not want_content:
                status[ref] = "withheld_by_policy"
                continue
            obj = self.log.read_content(ref)
            if obj is None:
                status[ref] = "erased"
            else:
                status[ref] = "included"
                content[ref] = obj
        return {"decision_id": decision_id, "start_seq": start, "claimed_prev_hash": entries[0]["prev_hash"],
                "entries": entries, "content": content, "content_status": status, "checkpoint": cp}


def verify_bundle(bundle, anchor_key: bytes) -> dict:
    """Offline check. Proves the slice from the decision to the signed head is internally
    consistent and was anchored by the key holder. It does not prove history before start_seq."""
    errors, prev = [], bundle["claimed_prev_hash"]
    for e in bundle["entries"]:
        if e["prev_hash"] != prev:
            errors.append(f"broken link at seq {e['seq']}")
        body = {k: v for k, v in e.items() if k != "hash"}
        if sha(canon(body)) != e["hash"]:
            errors.append(f"entry hash mismatch at seq {e['seq']}")
        prev = e["hash"]
    cp = bundle["checkpoint"]
    if not hmac.compare_digest(cp["sig"], sign(anchor_key, cp["seq"], cp["head"])):
        errors.append("checkpoint signature invalid")
    if bundle["entries"][-1]["hash"] != cp["head"]:
        errors.append("bundle does not end at the signed head")
    by_ref = {e["content_ref"]: e for e in bundle["entries"] if e.get("content_ref")}
    for ref, obj in bundle["content"].items():
        e = by_ref.get(ref)
        if not e or sha(obj["salt"] + canon(obj["content"])) != e["content_commitment"]:
            errors.append(f"content {ref} does not match its commitment")
    return {"ok": not errors, "errors": errors, "entries": len(bundle["entries"])}
