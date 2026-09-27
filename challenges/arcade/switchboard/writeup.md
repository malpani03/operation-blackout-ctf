# Switchboard — XOR State Reconstruction

## Challenge summary

**Track:** Independent Arcade  
**Category:** Boolean logic  
**Points:** 200  
**Result:** Solved and accepted  
**Answer:** `01110011`  
**Flag:** `flag{legacy_b81bde2dc1e65caf}`

## Evidence and reasoning

The relation value meant `0 = same` and `1 = different`, which is exactly an XOR constraint. The anchor fixed `A=0`. Propagating through the connected relation graph gave:

```text
A=0
A XOR B=1  -> B=1
B XOR C=0  -> C=1
C XOR D=0  -> D=1
D XOR E=1  -> E=0
E XOR F=0  -> F=0
F XOR G=1  -> G=1
G XOR H=0  -> H=1
```

Reading `A` through `H` produced `01110011`.

The solver adds both directions of every relation to a graph, propagates the anchor with breadth-first search and fails if any later relation contradicts an already assigned bit.

## Reproduction and proof

```powershell
python scripts/solve.py
```

Expected output:

```text
A=0 B=1 C=1 D=1 E=0 F=0 G=1 H=1
answer=01110011
```

Artifact SHA-256: `ac01fa6851752fea3a7de244f20e09a6b5b0ddb19215e39e64e13549c9e6bdfc`.

Verifier response:

```json
{"ok":true,"flag":"flag{legacy_b81bde2dc1e65caf}"}
```

## Tools and AI disclosure

Codex helped encode the relation graph and consistency check. The assignment was manually checked against all seven supplied equations. Playwright/CDP retrieved the exact artifact and verified the final ordered bit string.

## Required submission summary

### Root cause

This was a Boolean-constraint puzzle rather than a vulnerability. The central failure mode was confusing “same/different” with absolute values or propagating relations in only one direction.

### Reproducible PoC

Run `python scripts/solve.py`. Starting from `A=0`, it propagates bidirectional XOR constraints, rejects contradictions and prints `answer=01110011`. The official verifier accepted the ordered bits.

### Fix / mitigation

No service repair applies. Constraint processors should model equality/difference explicitly as XOR, traverse every connected component from a trusted anchor and reject inconsistent cycles or unanchored ambiguous components.

### AI usage

Codex built the relation graph and validation logic. Playwright/CDP retrieved and verified the artifact. Every resulting bit was manually substituted into all seven equations.
