# Benchmark against systima aiact-audit-log

Reference tool: https://github.com/systima-ai/aiact-audit-log (v0.2.0, cloned 12 Nov 2026).

```
git clone --depth 1 https://github.com/systima-ai/aiact-audit-log comparison/aiact-audit-log
cd comparison/aiact-audit-log && npm install && npx tsup && cd ../..
node comparison/bench_systima.mjs     # their tool, HMAC chain, filesystem storage
python3 benchmark.py                  # this build
```

Same workload for both: 10,000 inference events, one record each, then verify the whole chain on disk.

Not like for like, and worth saying out loud:
- Their logger batches 100 entries in memory (or 5 seconds) before writing, and does not fsync. This build fsyncs every entry, so a crash loses nothing that was acknowledged. Their speed comes partly from that choice.
- Their runtime is Node, this build is Python.
- This build also stores a separate content file per entry that has personal data; theirs stores one file per entry.
