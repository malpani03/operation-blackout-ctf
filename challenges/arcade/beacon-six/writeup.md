# Beacon Six — Morse Identifier Recovery

## Challenge summary

**Track:** Independent Arcade  
**Category:** Signal analysis  
**Points:** 150  
**Result:** Solved and accepted  
**Answer:** `609637`  
**Flag:** `flag{voicemail_d94ada40a244926c}`

## Acquisition and analysis

The authoritative artifact is an 8.56-second, 8 kHz, mono, 16-bit PCM WAV file. Its SHA-256 is:

```text
4dfdf92ac3f26d6894aafabc10e39e0976d011b91522c69977f04eed3a73f2c9
```

The signal was a keyed constant tone rather than speech or DTMF. Measuring energy in 80 ms units exposed three timing classes:

- one active unit: dot;
- three active units: dash;
- one silent unit: intra-character separation;
- three silent units: digit separation.

Grouping the tone runs produced:

```text
-....   -----   ----.   -....   ...--   --...
  6       0       9       6       3       7
```

The recovered six-digit identifier was therefore `609637`.

## Reproduction

```powershell
python scripts/solve.py
```

Expected output:

```text
groups=-.... ----- ----. -.... ...-- --...
answer=609637
```

The decoder uses only Python's standard `wave` and `struct` modules. It derives symbols from timing and does not require listening by ear.

## Proof

Submitting `609637` to `/s/voicemail/verify` returned:

```json
{"ok":true,"flag":"flag{voicemail_d94ada40a244926c}"}
```

## Tools and AI disclosure

Codex assisted with waveform triage, energy-window measurement and the repeatable Morse decoder. An initial DTMF hypothesis was rejected because no standard low/high frequency pair was present; timing runs provided the correct model. Playwright/CDP downloaded the WAV byte-for-byte and verified the derived identifier in the authenticated challenge session.

## Required submission summary

### Root cause

This was a signal-decoding puzzle, not a security vulnerability. The main analysis failure was assuming DTMF from the six-digit objective instead of measuring the acquisition; the recording actually encoded Morse digits using keyed-tone duration.

### Reproducible PoC

Run `python scripts/solve.py`. The decoder reads the preserved WAV, classifies 80 ms energy units, converts one-unit and three-unit tone runs to dots and dashes and prints `answer=609637`. The official verifier returned `ok:true`.

### Fix / mitigation

No service remediation applies. A robust decoder should verify PCM format, derive or validate timing units, tolerate bounded noise, reject ambiguous runs and retain the acquisition hash with its decoded output.

### AI usage

Codex assisted with signal triage and decoder construction; Playwright/CDP downloaded the WAV and verified the answer. The initial DTMF hypothesis was rejected through frequency measurement, and Morse timing plus the official verifier established the result.
