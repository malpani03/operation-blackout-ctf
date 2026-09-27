# Route Zero — Minimum Directed Route

## Challenge summary

**Track:** Independent Arcade  
**Category:** Graph search  
**Points:** 25  
**Result:** Solved and accepted  
**Answer:** `49`  
**Flag:** `flag{welcome_fdb3ed9c4339c847}`

The artifact described a directed weighted graph with start `A` and finish `F`. The task was to find the minimum total route cost; edge direction mattered.

## Evidence and approach

The graph contained eight directed edges:

```text
A->B 26   A->C 19   B->D 15   C->D 28
B->E 21   C->E 14   D->F 29   E->F 16
```

I used Dijkstra's algorithm. Starting at `A`, the tentative costs were `B=26` and `C=19`. Expanding `C` set `E=33` and `D=47`. Expanding `B` improved `D` to `41`, but its route to `E` cost `47`, so `E=33` remained better. Expanding `E` reached `F` at `33+16=49`. The alternative through `D` cost at least `41+29=70`.

The shortest route was therefore:

```text
A -> C -> E -> F
19 + 14 + 16 = 49
```

## Reproduction

```powershell
python scripts/solve.py
```

Expected output:

```text
path=A->C->E->F
cost=49
```

The exact artifact SHA-256 is `813c09da23b8fbda1b0dcbca2cd59c994ad887c6102fa4c89dde524e325ee65e`.

## Proof

Submitting answer `49` to `/s/welcome/verify` returned:

```json
{"ok":true,"flag":"flag{welcome_fdb3ed9c4339c847}"}
```

## Tools and AI disclosure

Codex helped preserve the graph as JSON and implement the small Dijkstra verifier. The result was independently checked by enumerating every available `A`-to-`F` path. Playwright/CDP used the already authenticated browser session to retrieve the artifact and verify the final decimal answer. No answer was guessed and no flag submission was used as an oracle.
