# Afterlife — Three Conway Generations

## Challenge summary

**Track:** Independent Arcade  
**Category:** Cellular automata  
**Points:** 200  
**Result:** Solved and accepted  
**Answer:** `011000001000101011001111110000000000`  
**Flag:** `flag{iris_63dcc5c2ad77ec1d}`

## Approach

The artifact supplied a 6×6 Conway's Game of Life board, specified that outside cells were dead, and required exactly three simultaneous generations. “Simultaneous” was the important condition: every new cell must be calculated from the old complete grid, not from partially updated rows.

The evolution rules were standard:

- a live cell survives with two or three live neighbors;
- a dead cell becomes live with exactly three neighbors;
- all other cells are dead in the next generation.

The three generated boards were:

```text
step 1      step 2      step 3
010000      001000      011000
001100      011000      001000
100001      101010      101011
110001      110011      001111
010001      110000      110000
000000      000000      000000
```

Flattening step 3 in row-major order produced the 36-bit answer.

## Reproduction and proof

```powershell
python scripts/solve.py
```

Expected final line:

```text
answer=011000001000101011001111110000000000
```

Artifact SHA-256: `f4460afc16534b05c585cc7ff11d7238d86d4f51673a90583697f4514765be66`.

Verifier response:

```json
{"ok":true,"flag":"flag{iris_63dcc5c2ad77ec1d}"}
```

## Tools and AI disclosure

Codex implemented the explicit double-buffered evolution and printed every intermediate board for review. The final grid was checked against an independent local calculation. Playwright/CDP retrieved the initial board and verified only the derived 36-bit result.
