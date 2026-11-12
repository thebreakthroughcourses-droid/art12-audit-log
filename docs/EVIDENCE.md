# Evidence

Every file below was produced by running the code in this repo on 11 Nov 2026 (Python 3, one machine). Re-run the command to reproduce.

| File | Command | What it shows |
|---|---|---|
| `evidence/01_test_output.txt` | `python3 tests/test_art12.py` | 12 of 12 tests pass: edits, deletions, truncation, the re-hash attack, content tampering, retention floor, erasure, access control, offline bundle check, coverage. |
| `evidence/02_benchmark_output.txt` | `python3 benchmark.py` | 10,000 entries: 2.61 s to write with fsync each (about 3,800/s), 0.31 s to verify, 530 bytes per entry. An earlier run gave 2.07 s, so write speed varies run to run. Measures this implementation only. |
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
- Timings are from one machine and say nothing about the other tool.
- Tests were written by the same author as the code, so they cover the attacks I thought of.
- Nothing here has been reviewed by a lawyer or an independent security reviewer.
