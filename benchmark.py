"""Measures this implementation only. It does NOT run aiact-audit-log (different language/runtime)."""
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from art12log import AuditLog, verify

KEY = b"bench-key"
N = 10_000
d = Path(tempfile.mkdtemp())
log = AuditLog(d, "bench", KEY, checkpoint_every=500)

t = time.perf_counter()
for i in range(N):
    log.record(f"B{i}", "inference", model_id="m", params={"t": 0.7}, latency_ms=5,
               content={"applicant": f"p{i}", "score": 0.5})
write_s = time.perf_counter() - t

t = time.perf_counter()
r = verify(d, KEY)
verify_s = time.perf_counter() - t

size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
print(f"entries              {N}")
print(f"write (fsync each)   {write_s:.2f}s  -> {N / write_s:,.0f} entries/s, {write_s / N * 1000:.2f} ms each")
print(f"full verify          {verify_s:.2f}s  ok={r['ok']}")
print(f"disk                 {size / 1e6:.1f} MB ({size / N:.0f} bytes/entry incl. content)")
shutil.rmtree(d)
