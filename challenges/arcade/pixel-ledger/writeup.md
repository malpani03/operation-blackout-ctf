# Pixel Ledger — 4×4 Nonogram

## Challenge summary

**Track:** Independent Arcade  
**Category:** Nonogram  
**Points:** 75  
**Result:** Solved and accepted  
**Answer:** `1110100011110001`  
**Flag:** `flag{badge_391d9e9b56cb40a1}`

## Evidence and reasoning

The 4×4 puzzle supplied row clues `[3], [1], [4], [1]` and column clues `[3], [1,1], [1,1], [2]`. A clue gives the lengths of consecutive filled runs; separate runs require at least one empty cell.

The third row was forced to `1111`. The first row required three consecutive cells. Matching column 1's single run of three forced rows 1–3 in that column to be filled and row 4 empty. Column 4 required a run of two; because row 3 was filled, row 4 also had to be filled and rows 1–2 empty there. The remaining split-run columns then fixed the unique grid:

```text
1110
1000
1111
0001
```

Column verification:

```text
1110 -> [3]
1010 -> [1,1]
1010 -> [1,1]
0011 -> [2]
```

Flattening row-major produced `1110100011110001`.

## Reproduction and proof

The solver enumerates all 65,536 possible grids and asserts uniqueness:

```powershell
python scripts/solve.py
```

Artifact SHA-256: `9922f702009c18de146b366e3065e52acd0be5e241f3c559487b0cbb20930194`.

The verifier returned:

```json
{"ok":true,"flag":"flag{badge_391d9e9b56cb40a1}"}
```

## Tools and AI disclosure

Codex assisted with encoding the clue checker and uniqueness test. The grid was also checked manually against every row and column clue. Playwright/CDP retrieved the authorized artifact and submitted only the final validated 16-bit answer.

## Required submission summary

### Root cause

This was a nonogram puzzle rather than a security vulnerability. The likely error condition was satisfying row clues while overlooking column constraints, or returning one plausible grid without proving uniqueness.

### Reproducible PoC

Run `python scripts/solve.py`. The solver enumerates all 65,536 grids, checks every row and column run and asserts that exactly one solution exists. It prints `answer=1110100011110001`, which the official verifier accepted.

### Fix / mitigation

No vulnerable service requires repair. Puzzle implementations should validate both axes, interpret `[0]` as an empty line, enforce separators between multiple runs and require a unique solution before accepting generated clues.

### AI usage

Codex implemented the exhaustive clue checker. Playwright/CDP retrieved the artifact and sent the final answer. Manual row/column verification and the official verifier independently controlled the result.
