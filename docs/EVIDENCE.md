# Evidence

Every file below was produced by running the code in this repo on 11 Nov 2026 (Python 3, one machine). Re-run the command to reproduce.

| File | Command | What it shows |
|---|---|---|
| `evidence/01_test_output.txt` | `python3 tests/test_art12.py` | 12 of 12 tests pass: edits, deletions, truncation, the re-hash attack, content tampering, retention floor, erasure, access control, offline bundle check, coverage. |
| `evidence/02_benchmark_output.txt` | `python3 benchmark.py` | Early single run of this build only (2.61 s). Superseded by file 06: write speed varied from 2 s to 6 s across runs, so treat file 02 as one sample, not a result. |
| `evidence/06_benchmark_vs_systima.txt` | see `comparison/RUN.md` | Three runs each of systima's `aiact-audit-log` v0.2.0 and this build, same 10,000-event workload. Theirs: about 0.8 s to write, 0.13 s to verify. This build with fsync on every entry: 4.8 to 6.1 s to write, about 0.37 s to verify. With fsync off: 0.7 to 1.6 s. Their tool batches writes and does not fsync, so the gap is mostly a durability choice, not a verdict on the code. |
| `evidence/03_demo_output.txt` | `python3 demo.py` | Hiring-screen scenario: verify passes, coverage flags one missing decision, regulator bundle verifies offline, deployer sees no personal content, erasure keeps the chain valid. |
| `evidence/04_attack_demo_output.txt` | `python3 attack_demo.py` | Six cases. Untouched log passes. Edit, delete, truncate, re-hash-everything and silent content deletion are each flagged. |
| `evidence/05_sample_logstore/` | produced by `demo.py` | The real log files: `chain.jsonl`, `checkpoints.jsonl`, `content/`, `sample_bundle.json`. |

To check the sample log yourself:

```python
from art12log import verify
print(verify("evidence/05_sample_logstore", b"anchor-key-held-outside-the-log-store"))
```

The key above is the demo's placeholder, not a real secret.

## Limits of this evidence
- Timings are from one shared cloud machine and swing a lot between runs. Only the pattern is reliable: the reference tool is faster, mainly because it batches and skips fsync.
- Tests were written by the same author as the code, so they cover the attacks I thought of.
- Nothing here has been reviewed by a lawyer or an independent security reviewer.
