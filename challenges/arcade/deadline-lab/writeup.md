# Deadline Lab — Weighted Single-Machine Schedule

## Challenge summary

**Track:** Independent Arcade  
**Category:** Scheduling  
**Points:** 75  
**Result:** Solved and accepted  
**Answer:** `CBAEFD`  
**Minimum cost:** `351`  
**Flag:** `flag{rota_bfc9b384d4620514}`

## Approach

The artifact supplied six independent jobs with duration and weight plus two precedence rules: `A` must precede `D`, and `B` must precede `F`. The objective was to minimize the sum of each completion time multiplied by its weight, with alphabetic ordering as the tie-breaker.

Because only six jobs existed, exhaustive enumeration was the clearest proof. I generated all `6! = 720` orders, discarded any that violated precedence, computed cumulative completion times and retained the lexicographically earliest minimum.

The winning order and cost breakdown were:

| Job | Completion | Weight | Contribution |
|---|---:|---:|---:|
| C | 2 | 5 | 10 |
| B | 7 | 5 | 35 |
| A | 16 | 5 | 80 |
| E | 24 | 4 | 96 |
| F | 29 | 2 | 58 |
| D | 36 | 2 | 72 |

Total: `10+35+80+96+58+72 = 351`. Both precedence constraints are satisfied.

## Reproduction and proof

```powershell
python scripts/solve.py
```

Expected final lines:

```text
order=CBAEFD
cost=351
```

Artifact SHA-256: `a5a0bc486592e6e1e960607aa557504e955877fb2b62a1d426ddeb4c16e4d3a5`.

Verifier response:

```json
{"ok":true,"flag":"flag{rota_bfc9b384d4620514}"}
```

## Tools and AI disclosure

Codex implemented the exhaustive scheduler and explicit tie-break comparison. The accepted order was validated against every feasible permutation, rather than relying only on a scheduling heuristic. Playwright/CDP retrieved the puzzle and checked the final order in the authorized session.

## Required submission summary

### Root cause

This was a scheduling puzzle, not an exploitable defect. The principal correctness risk was applying a duration/weight heuristic without enforcing precedence or the required alphabetical tie-break.

### Reproducible PoC

Run `python scripts/solve.py`. It enumerates all 720 orders, rejects precedence violations and computes every weighted completion cost. The unique selected result is `CBAEFD` with cost `351`; the official verifier returned `ok:true`.

### Fix / mitigation

No service fix applies. A production scheduler should validate that the precedence graph is acyclic, use exact optimization when the problem size permits, make tie-breaking deterministic and recompute the objective from the emitted schedule.

### AI usage

Codex produced the exhaustive comparison and breakdown. Playwright/CDP retrieved and verified the puzzle. Full feasible-order enumeration, not AI confidence, established optimality.
