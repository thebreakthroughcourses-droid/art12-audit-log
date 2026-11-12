"""Shows each tampering attack and what verify() says. Output is saved as evidence."""
import datetime as dt, json, shutil, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from art12log import AuditLog, verify
from art12log.core import canon, sha, GENESIS
KEY = b"anchor-key-held-outside-the-log-store"

def fresh():
    d = Path(tempfile.mkdtemp()); t = [dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)]
    def clock(): t[0] += dt.timedelta(minutes=1); return t[0]
    log = AuditLog(d, "demo", KEY, checkpoint_every=25, clock=clock)
    for i in range(100):
        log.record(f"D{i:03d}", "inference", model_id="m", params={"threshold": 0.7},
                   content={"applicant": f"p{i}", "score": 0.6})
    return d, log

def lines(d): return (d / "chain.jsonl").read_text().splitlines()
def put(d, ls): (d / "chain.jsonl").write_text("\n".join(ls) + "\n")
def show(name, d):
    r = verify(d, KEY); print(f"\n[{name}] ok={r['ok']}")
    for e in r["errors"][:3]: print("   -", e)
    if len(r["errors"]) > 3: print(f"   ... {len(r['errors'])} errors total")

d, _ = fresh(); show("0. untouched log", d)
d, _ = fresh(); ls = lines(d); e = json.loads(ls[10]); e["params"]["threshold"] = 0.2; ls[10] = canon(e); put(d, ls)
show("1. edit one entry (threshold 0.7 -> 0.2)", d)
d, _ = fresh(); ls = lines(d); del ls[40]; put(d, ls); show("2. delete one entry", d)
d, _ = fresh(); put(d, lines(d)[:60]); show("3. cut the last 40 entries", d)
d, _ = fresh(); es = [json.loads(x) for x in lines(d)]; es[10]["params"]["threshold"] = 0.2; prev = GENESIS
for x in es:
    x["prev_hash"] = prev; x.pop("hash", None); x["hash"] = sha(canon(x)); prev = x["hash"]
put(d, [canon(x) for x in es]); show("4. edit one entry AND recompute every hash after it", d)
d, log = fresh(); ref = log.entries()[5]["content_ref"]; (d / "content" / f"{ref}.json").unlink()
show("5. delete a personal-data file without an erasure record", d)
