# Custodian Records — Three-Share Recovery

## Challenge summary

**Track:** Independent Arcade  
**Category:** Secret sharing  
**Points:** 200  
**Result:** Solved and accepted  
**Answer:** `140`  
**Flag:** `flag{vending_48e272382e88a354}`

## Evidence and reasoning

The three custodian records were points `(1,15)`, `(3,198)` and `(5,16)` on a polynomial of degree at most two over the prime field `GF(257)`. With threshold three, all points determine the polynomial. The vault value is `f(0)`.

I used Lagrange interpolation directly at zero:

```text
f(0) = Σ yi × Π(-xj)/(xi-xj)  mod 257
```

The three basis coefficients at zero were `34`, `63` and `161`. Their field contributions were:

```text
15×34  mod 257 = 253
198×63 mod 257 = 138
16×161 mod 257 =   6
```

Therefore:

```text
(253 + 138 + 6) mod 257 = 140
```

## Reproduction and proof

```powershell
python scripts/solve.py
```

Expected final output: `answer=140`.

Artifact SHA-256: `cfa870fc2997f34301d0d6078bb8493c859ca6244114109645f0818fd3610edb`.

Verifier response:

```json
{"ok":true,"flag":"flag{vending_48e272382e88a354}"}
```

## Tools and AI disclosure

Codex assisted with the finite-field implementation. Python's modular inverse was used only after checking that every denominator was non-zero modulo the supplied prime. The intermediate basis values make the result independently auditable. Playwright/CDP retrieved and verified the authorized puzzle.

## Required submission summary

### Root cause

This was a finite-field secret-sharing reconstruction puzzle. The main correctness risk was performing ordinary rational interpolation instead of all addition, multiplication and inversion modulo the supplied prime 257.

### Reproducible PoC

Run `python scripts/solve.py`. It evaluates the three Lagrange basis polynomials at zero, prints basis values `34`, `63`, `161` and recovers `answer=140`. The official verifier returned `ok:true`.

### Fix / mitigation

No service remediation applies. Secret-sharing implementations should use a reviewed finite-field library, reject duplicate x-coordinates and non-invertible denominators, enforce the threshold and authenticate shares to prevent malicious substitution.

### AI usage

Codex implemented the field arithmetic and intermediate audit output. Playwright/CDP retrieved and verified the puzzle. The calculation was independently checked by hand modulo 257.
