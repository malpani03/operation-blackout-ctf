# Double Entry — Idempotent Ledger Replay

## Challenge summary

**Track:** Independent Arcade  
**Category:** Accounting  
**Points:** 100  
**Result:** Solved and accepted  
**Answer:** `30186` cents  
**Flag:** `flag{helpdesk_dc43606549c7d101}`

## Evidence and reasoning

The ledger opened at `27,761` cents. The contract said event ID—not row position—identified an accounting event, so repeated delivery of the same event had to be idempotent. Charges increase balance and refunds decrease it.

The 18 delivered rows contained 14 unique IDs. Events `12`, `4`, `8`, and `0` each appeared twice; their second deliveries were ignored. Unique charges totaled `11,559` cents and unique refunds totaled `9,134` cents:

```text
27,761 + 11,559 - 9,134 = 30,186
```

Counting each delivery independently would have applied four events twice and produced an incorrect ledger. De-duplicating by all fields rather than event ID would also be unsafe in the general case; the supplied rule specifically designated the ID as the accounting identity.

## Reproduction and proof

```powershell
python scripts/solve.py
```

Expected output includes:

```text
duplicate event 12 ignored
duplicate event 4 ignored
duplicate event 8 ignored
duplicate event 0 ignored
unique_events=14
final_balance_cents=30186
```

Artifact SHA-256: `7d6415b10d3528ac2d3f6d89d96a1f9d70c34cea17d1db7ab7c5493e9e0b89c3`.

Verifier response:

```json
{"ok":true,"flag":"flag{helpdesk_dc43606549c7d101}"}
```

## Tools and AI disclosure

Codex translated the idempotency rule into a deterministic replay keyed by event ID and checked the charge/refund subtotals. Playwright/CDP recovered the authorized JSON artifact and verified only the final integer-cent balance.
