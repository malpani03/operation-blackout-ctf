# Device Messages — RSA Shared-Prime Failure

## Challenge summary

**Track:** Independent Arcade  
**Category:** RSA  
**Points:** 300  
**Result:** Solved and accepted  
**Answer:** `760422`  
**Flag:** `flag{entropy_4f4121eb24ad9bce}`

## Vulnerability and recovery

The two devices published moduli `1123519` and `1060459` with public exponent `65537`. Independently generated RSA moduli should not share a prime. Computing their greatest common divisor found:

```text
gcd(1123519, 1060459) = 1051
1123519 = 1051 × 1069
1060459 = 1051 × 1009
```

The shared prime completely factors the first modulus. For the target modulus:

```text
φ(n1) = (1051-1)(1069-1) = 1,121,400
d = 65537^-1 mod φ(n1) = 766,673
```

Because the challenge specified raw textbook RSA with no padding, decryption was direct modular exponentiation:

```text
m = 342096^766673 mod 1123519 = 760422
```

The root cause represented here is insufficient randomness or duplicated prime material during RSA key generation. A batch GCD across public keys detects this class of failure.

## Reproduction and proof

```powershell
python scripts/solve.py
```

Artifact SHA-256: `1efd057c4386fa91c873555ea1fc78a714cb4cc55fd5986f5688ab8c5d153332`.

Verifier response:

```json
{"ok":true,"flag":"flag{entropy_4f4121eb24ad9bce}"}
```

## Mitigation

Generate keys with a cryptographically secure, health-tested random source; run pairwise/batch GCD checks over the public-key fleet; reject duplicated factors; and use a modern padding scheme such as OAEP for encryption.

## Tools and AI disclosure

Codex identified the batch-GCD test and implemented the transparent standard-library solver. Every value—factorization, totient, inverse and plaintext—was recomputed locally before verification. Playwright/CDP only retrieved the parameters and checked the final decimal plaintext.

## Required submission summary

### Root cause

The two RSA public moduli reused prime `1051`, indicating weak or repeated key-generation randomness. Their GCD factored both keys. Textbook RSA without padding then allowed direct recovery of the first plaintext.

### Reproducible PoC

Run `python scripts/solve.py`. It computes the GCD, factors `n1`, derives `φ(n1)=1121400` and `d=766673`, and prints `answer=760422`. The official verifier returned `ok:true`.

### Fix / mitigation

Use a health-tested cryptographic random source, run batch-GCD checks across generated public keys, regenerate every key sharing a factor, protect key-generation state and use an approved padding construction such as RSA-OAEP.

### AI usage

Codex proposed and implemented the batch-GCD recovery; Playwright/CDP retrieved and verified the parameters. Factorization, modular inverse, decryption and official acceptance independently validated the output.
