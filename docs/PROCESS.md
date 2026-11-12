# Process: how this Build was made

TKS focus project, AI focus, Build stage. Builder: Richard Ji.

## 1. Where the Build came from
The AI-focus Learn article is about AI liability and data control: who pays when AI harms someone, and who controls the data that proves it. The Build had to turn that into something working.

| Step | Date | Decision |
|---|---|---|
| First plan | 23 Oct 2026 | Recreate the Winfield et al. exoskeleton accident investigation in simulation. |
| Rejected | 23 Oct 2026 | Richard judged it a copy of someone else's project with a small twist, and asked for a change. |
| Chosen | 23 Oct 2026 | Recreate an EU AI Act Article 12 audit log, benchmark it against an open-source one, and add an evidence-access twist of his own. ProPublica COMPAS replication kept as backup. |
| Built | 11 Nov 2026 | Code, tests, demo, benchmark, attack demo, write-up. |

## 2. Research
- Article 12 requires high-risk AI systems to technically allow automatic recording of events over their lifetime. Deployers keep logs at least six months (Art. 26(6)).
- Found the existing open-source tool, systima's `aiact-audit-log` (TypeScript, SHA-256 chain, 180-day floor, coverage command).
- First pass (11 Nov): I could not open its repository, so I worked from its author's Show HN description. That description undersold the tool.
- Second pass (12 Nov): cloned and read v0.2.0 (CHANGELOG, README, source), built it, and ran it. It already has an optional HMAC-keyed chain, S3 Object Lock, a `getChainHead()` hook for external anchoring, PII hashing and redaction, a 180-day lifecycle rule, a CLI and a test suite. It has no separate content layer and no access-control layer. Their own docs say a keyed chain does not survive compromise of the logging process, which is the same limit as this build's signed checkpoints.
- Correction: my 11 Nov report implied signed checkpoints were an advance on a plain chain. Against v0.2.0 they are roughly equivalent to its HMAC option. The difference that remains is the access layer and the erasable content layer.
- The thread raised two criticisms that shaped the design:
  1. Anyone with storage access can rebuild a plain hash chain. Answer here: signed checkpoints.
  2. Hash-chained personal data collides with GDPR erasure. Answer here: personal data in a separate content layer, chain holds only a salted commitment.

## 3. Design decisions
- Only a structural envelope is hashed into the chain. Personal data is not.
- Commitments are salted so a leaked chain cannot be used to guess applicant data.
- Erasure is refused inside 180 days and recorded as an event afterwards.
- The twist: roles (provider admin, deployer reviewer, market surveillance authority), case grants for personal content, and every access request, granted or denied, written to the same chain.
- Standard library only, so anyone can run it with no installs.

## 4. Build order
1. `art12log/core.py`: logger, verify, coverage.
2. `art12log/access.py`: roles, access logging, offline-verifiable bundles.
3. `tests/test_art12.py`: 12 tests written against the attacks above.
4. `demo.py`: hiring-screening scenario, end to end.
5. `benchmark.py`: write and verify speed.
6. `attack_demo.py`: each tampering attack and the verifier's response.

## 5. What did and did not work
- All 12 tests passed on the first full run.
- Most useful test: edit one entry and recompute every later hash. The chain alone passes; only the signed checkpoints catch it.
- Not done: public-key signatures or external timestamps (the checkpoint key is shared-secret), locking for concurrent writers, timer-based checkpoints, running the other tool side by side.
- Pushing to GitHub was blocked because the Claude GitHub App was not installed on the repo; files were delivered by upload instead.

## 6. Article 12 timing
Article 12 applies with the high-risk obligations. Those were due 2 August 2026. The Commission's AI Act FAQ page now says they apply from 2 December 2027 (embedded products 2 August 2028) following the Digital Omnibus, which it says entered into force on 27 July 2026. Sources that still say August 2026 are out of date for high-risk systems; Article 50 transparency duties did start on 2 August 2026. I read this on the Commission's web page, not in the Official Journal text, so check the regulation itself before quoting an exact article reference.

## 7. Not legal advice
Whether this satisfies Article 12 for a real system is a legal question this project does not answer.
