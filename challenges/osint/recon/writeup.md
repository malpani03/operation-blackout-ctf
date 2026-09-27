# Operation Blackout — Recon Write-up

## Reception / Disputed Custody Transfer

**Category:** OSINT / digital forensics / evidence correlation  
**Difficulty:** Beginner-friendly, but detail-sensitive  
**Points:** 100  
**Final flag:** `flag{recon_e8f25be55df46671}`

## 1. Challenge overview

Reception released an archive immediately before an outage. Unfortunately, the surviving evidence did not agree about:

- which archive belonged to the badge holder;
- which room physically held the archive;
- which custody transfers were actually committed;
- which document revision was authorized; and
- which historical values belonged in the final manifest.

This challenge was not a conventional web exploit such as SQL injection or command injection. It modeled a **provenance and object-binding failure**: several records looked individually valid, but they could not be trusted until they were tied to the correct person, asset, transaction history, room and approval chain.

The verification endpoint expected two JSON fields:

```json
{
  "revision": "c",
  "manifest": "<sha256-of-compact-json-array>"
}
```

The server deliberately returned the same generic failure for every incorrect value. This meant the investigation had to be solved from evidence instead of by using the endpoint as a field-by-field oracle.

## 2. Evidence supplied

The extracted `mail` directory contained four evidence groups:

```text
mail/
├── image.png                    # surviving badge
├── voicemail.wav               # telephone acquisition
├── attachments/
│   ├── approval.json
│   ├── draft.json
│   ├── intake.json
│   ├── other.json
│   └── revision-a.json
├── collection/
│   ├── acquisition.txt
│   ├── photo-1.png
│   ├── photo-2.png
│   └── photo-3.png
├── custody/
│   ├── export-notes.txt
│   ├── origin.json
│   └── transactions.jsonl
└── export/
    ├── index.csv
    └── m-*.eml
```

A quick inventory can be produced in PowerShell:

```powershell
Get-ChildItem -Force -Recurse .\mail |
    Select-Object FullName, Length, LastWriteTime
```

The important lesson is that no single file solves the challenge. The answer appears only after the files are correlated.

## 3. Security issue represented by the challenge

The central issue is **authorization without sufficient context**.

An `approved` label alone was not enough because:

1. one approved file belonged to a different asset;
2. one revision in the correct mail chain had been revoked;
3. several custody transactions were rolled back;
4. several commits had stale generations or the wrong owner;
5. one final transfer was begun but never committed; and
6. a valid NASA release number existed, but it was not the release identifier retained by the approved JPL source.

In a real system, this class of mistake can appear as broken object-level authorization, confused-deputy behavior, stale-state acceptance, or failure to bind a signature/approval to the exact object and version being released.

The safe rule is:

> Validate the object, version, owner, transaction state and source provenance together. Never authorize an action merely because some nearby record says “approved.”

## 4. Linking the badge holder to the correct archive

### 4.1 Badge evidence

The badge photograph, `mail/image.png`, identified:

```text
Name: Maya Sen
Employee ID: HX-4821
Department: Reception Operations
```

![Surviving badge identifying Maya Sen](assets/mail/image.png)

This established the person, but it did not directly name a storage room.

### 4.2 Telephone evidence

The audio contained four ordinary Harvard test sentences. Speech transcription was useful for confirming that no room name was spoken, but the decisive evidence was in the WAV container metadata.

The RIFF `LIST/INFO` chunk contained:

```text
reception/transfer; mailbox=archive-17; record=call-2204
```

The following Python code reproduces extraction of RIFF chunks without requiring a specialist metadata tool:

```python
import struct

data = open("mail/voicemail.wav", "rb").read()
offset = 12  # Skip RIFF size and WAVE signature.

while offset + 8 <= len(data):
    chunk_id = data[offset:offset + 4]
    size = struct.unpack("<I", data[offset + 4:offset + 8])[0]
    chunk = data[offset + 8:offset + 8 + size]

    if chunk_id == b"LIST":
        print(chunk.rstrip(b"\x00").decode("utf-8", errors="replace"))

    offset += 8 + size + (size & 1)
```

### 4.3 Mail correlation

`export/index.csv` showed this thread:

```text
m-220 -> m-221 -> m-222
```

The messages established the following:

- `m-220` was from Maya Sen.
- Its subject was `call-2204`, matching the WAV metadata.
- It stated that asset `B04-21b0096b` moved to `archive-17`.
- `m-221` rejected revision `a` because it confused dates and hardware.
- `m-222` approved revision `c`.

This linked the evidence as follows:

```text
Maya Sen badge
    -> call-2204 in WAV metadata
        -> m-220 from Maya Sen
            -> mailbox archive-17
                -> asset B04-21b0096b
                    -> revision c approval in m-222
```

The file `other.json` also said `approved`, but it belonged to asset `B05-1709`. It was a deliberate decoy demonstrating why approval must be bound to the correct object.

## 5. Reconstructing committed custody

### 5.1 Initial state

`custody/origin.json` contained:

```json
{
  "generation": 0,
  "owner": "51fe89b97906",
  "location": "intake",
  "carrier": "none",
  "asset": "B04-21b0096b"
}
```

### 5.2 Journal rules

`export-notes.txt` defined optimistic transaction semantics:

- `begin` captures a base generation and owner;
- `set` stages changes inside that transaction;
- `commit` applies all staged writes only if the captured generation and owner still match the current object;
- each successful commit increments the generation exactly once;
- `rollback` changes nothing; and
- an unfinished transaction changes nothing.

Simply reading the last line of `transactions.jsonl` would therefore be wrong.

### 5.3 Replay script

The following script faithfully reproduces the journal:

```python
import json

with open("mail/custody/origin.json", encoding="utf-8") as handle:
    state = json.load(handle)

active = {}
applied = 0
rejected = 0
rolled_back = 0

with open("mail/custody/transactions.jsonl", encoding="utf-8") as handle:
    rows = [json.loads(line) for line in handle]

for row in sorted(rows, key=lambda item: item["sequence"]):
    txid = row["tx"]
    operation = row["op"]

    if operation == "begin":
        active[txid] = {
            "base": row["base"],
            "owner": row["owner"],
            "writes": {},
        }

    elif operation == "set" and txid in active:
        active[txid]["writes"][row["key"]] = row["value"]

    elif operation == "rollback":
        active.pop(txid, None)
        rolled_back += 1

    elif operation == "commit" and txid in active:
        transaction = active.pop(txid)

        if (
            transaction["base"] == state["generation"]
            and transaction["owner"] == state["owner"]
        ):
            state.update(transaction["writes"])
            state["generation"] += 1
            applied += 1
        else:
            rejected += 1

print(json.dumps(state, indent=2))
print("applied:", applied)
print("rejected:", rejected)
print("rolled back:", rolled_back)
print("unfinished:", len(active))
```

Output:

```json
{
  "generation": 39,
  "owner": "51fe89b97906",
  "location": "north-archive",
  "carrier": "f27f23a9",
  "asset": "B04-21b0096b"
}
```

```text
applied: 39
rejected: 14
rolled back: 20
unfinished: 1
```

The unfinished transaction attempted to replace the location with `south-archive`, but it had no commit operation. It therefore had to be ignored.

## 6. Identifying the north archive photograph

`collection/acquisition.txt` stated:

- `photo-1.png` and `photo-3.png` were room interiors;
- `photo-2.png` was the connecting corridor; and
- the north archive was the left corridor door.

The left door in the corridor carried a **green triangle**. The challenge instructed us to corroborate the room with the cabinet, pipe and trolley rather than using camera clocks.

![Connecting corridor: the left door has a green triangle and the right door has an orange circle](assets/mail/collection/photo-2.png)

The comparison was:

| Feature | Left corridor/north marker | Photo 1 | Photo 3 |
|---|---|---|---|
| Cabinet mark | Green triangle | Green triangle | Orange circle |
| Pipe | Red | Red | Blue |
| Trolley | Yellow | Yellow | Blue |

All three independent physical features matched `photo-1.png`. Therefore, photo 1 was the north archive interior.

![Photo 1: green-triangle cabinet, red pipe and yellow trolley](assets/mail/collection/photo-1.png)

For comparison, photo 3 contained the opposing orange-circle cabinet, blue pipe and blue trolley:

![Photo 3: orange-circle cabinet, blue pipe and blue trolley](assets/mail/collection/photo-3.png)

The original PNG had to be hashed without modification:

```powershell
(Get-FileHash .\mail\collection\photo-1.png -Algorithm SHA256).Hash.ToLowerInvariant()
```

Result:

```text
c287b6b0bdb55cc0f5c7d4ec3b4bfd093019bea82e0ef354336438430d1cdc90
```

## 7. Selecting the approved revision

The attachments represented different states and objects:

| Attachment | State | Meaning |
|---|---|---|
| `draft.json` | revoked | Old revision `a`; unusable |
| `revision-a.json` | superseded | Incorrect date/count interpretation |
| `approval.json` | approved | Correct revision `c` for the target mail chain |
| `other.json` | approved | Valid approval, but for different asset B05 |

`approval.json` specified the exact field order and types:

1. asset route — string
2. committed custody generation — integer
3. committed carrier identifier — string
4. SHA-256 of the matching north archive interior — string
5. record installation date — string
6. 1977 release identifier — string
7. greeting language count in the release — integer
8. greeting language count in the current catalog — integer
9. flight record diameter in inches — integer
10. master recording diameter in inches — integer
11. person advocating the handwritten inscription — string

It also specified the encoding:

```text
compact JSON array -> SHA256
```

## 8. Recovering the historical fields

Only the historical sources retained in `intake.json` were treated as approved provenance.

### 8.1 JPL’s 1977 release page

The JPL article [Voyager Will Carry Earth Sounds Record](https://www.jpl.nasa.gov/news/voyager-will-carry-earth-sounds-record/) established:

- the record was installed on July 29, 1977;
- the retained JPL release identifier was `1977-0800`;
- the historical release described 60 greeting languages; and
- the flight record was 12 inches in diameter.

The normalized values were:

```text
1977-07-29
1977-0800
60
12
```

### 8.2 Current NASA catalog

NASA’s current [Golden Record Contents](https://science.nasa.gov/mission/voyager/golden-record-contents/) page says the catalog contains greetings in 55 languages.

This was intentionally kept separate from the historical release’s count of 60. The correct value was:

```text
55
```

### 8.3 JPL archive blog

The JPL article [Voyager Golden Record Inscription — 1977](https://www.jpl.nasa.gov/blog/2015/10/voyager-golden-record-inscription-1977) established:

- the archive masters were 14 inches in diameter; and
- Timothy Ferris wanted an element made directly by a human hand.

The values were:

```text
14
Timothy Ferris
```

## 9. The failed attempt and why it failed

The first manifest used `77-159` as the release identifier. That is a real NASA news-release number, so it looked convincing. However, it was not the identifier printed on the approved JPL page retained in `intake.json`.

The first hash was:

```text
f8c8c6e2abf0c46f4aeab7f1da2a8fd93dfb42c5a2589b6dc4a97c335b3eca97
```

The server correctly returned:

```json
{"ok":false}
```

Rechecking the approved JPL source revealed `1977-0800` at the bottom of the page. Replacing only that field produced the correct result.

This was the challenge’s final provenance trap: **a fact can be genuine and still be wrong for a manifest if it comes from the wrong identifier system or source context.**

## 10. Constructing the final manifest

The final field array, in the exact approved order, was:

```json
["B04-21b0096b",39,"f27f23a9","c287b6b0bdb55cc0f5c7d4ec3b4bfd093019bea82e0ef354336438430d1cdc90","1977-07-29","1977-0800",60,55,12,14,"Timothy Ferris"]
```

The following Python code reproduces the compact encoding and SHA-256 digest:

```python
import hashlib
import json

fields = [
    "B04-21b0096b",
    39,
    "f27f23a9",
    "c287b6b0bdb55cc0f5c7d4ec3b4bfd093019bea82e0ef354336438430d1cdc90",
    "1977-07-29",
    "1977-0800",
    60,
    55,
    12,
    14,
    "Timothy Ferris",
]

compact = json.dumps(
    fields,
    ensure_ascii=False,
    separators=(",", ":"),
)

manifest = hashlib.sha256(compact.encode("utf-8")).hexdigest()

print(compact)
print(manifest)
```

Correct manifest digest:

```text
4f3bc799d152281d139bac1d2394eecb5656f4da1d7752ca76d8556d4e117c97
```

## 11. Reproducing the flag

After authenticating to the CTF site, the evidence was submitted from the challenge origin:

```javascript
fetch("/recon/verify", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    revision: "c",
    manifest: "4f3bc799d152281d139bac1d2394eecb5656f4da1d7752ca76d8556d4e117c97"
  })
}).then(async response => {
  console.log(response.status, await response.text());
});
```

Server response:

```json
{
  "ok": true,
  "flag": "flag{recon_e8f25be55df46671}",
  "notice": "Submit this flag on the case board."
}
```

The flag was then submitted once on the authenticated case board, which marked Recon solved for 100 points and unlocked the next stage.

## 12. How AI was used during the investigation

AI was used as an investigation assistant, not as a replacement for evidence validation.

### Visual analysis

The badge and three facility photographs were inspected with multimodal image understanding. AI helped read the badge and compare the green-triangle cabinet, red pipe and yellow trolley across separate images. The conclusion was checked against the written acquisition rule that defined the left corridor door as the north archive.

### Audio transcription and metadata triage

Automatic speech recognition initially produced a poor transcript because the recording was narrow-band telephone audio. A local Whisper model correctly recognized the four Harvard test sentences. More importantly, AI-assisted triage prompted inspection of the WAV container rather than relying only on audible speech, revealing the `archive-17` and `call-2204` metadata.

### Transaction replay

AI helped translate the journal rules into a deterministic replay script. The output was validated with counts for successful commits, rejected commits, rollbacks and unfinished transactions. This avoided the common mistake of accepting the last staged transfer.

### Source research

AI was used to locate and compare the exact official JPL and NASA pages listed in `intake.json`. The first attempt incorrectly selected the legitimate NASA identifier `77-159`. After the generic failure, the source scope was reviewed and the retained JPL identifier `1977-0800` was identified. This correction demonstrates why AI-generated conclusions still require source-level verification.

### Browser automation

Playwright MCP was used after manual login to:

1. confirm the authenticated investigation session;
2. select the Recon challenge tab;
3. submit the evidence to `/recon/verify`;
4. capture the successful JSON response; and
5. submit the confirmed flag on the case board.

No credentials were extracted, no account was created, and no external target was exploited. Login was completed manually by the authorized participant, while browser automation handled only the intended CTF workflow.

## 13. Key lessons

1. **Approval must be object-bound.** An approved record for asset B05 says nothing about asset B04.
2. **Transaction intent is not transaction state.** A staged or rolled-back transfer must not change custody.
3. **Optimistic concurrency matters.** A commit with a stale generation or wrong owner must be rejected.
4. **Use multiple independent visual features.** One matching color or symbol can be coincidental; cabinet, pipe and trolley together are strong corroboration.
5. **Metadata can be more valuable than content.** The voicemail’s spoken sentences were generic, while its RIFF metadata linked the evidence chain.
6. **Historical and current claims can both be correct.** The 1977 release said 60 languages, while the current catalog says 55.
7. **A true fact can still be the wrong field value.** `77-159` was legitimate, but `1977-0800` was the identifier retained by the approved JPL source.
8. **Hashing is exact.** Field order, integer versus string types, punctuation and JSON whitespace all affect the final digest.
9. **AI output must be verified.** AI accelerated image, audio, code and research work, but the evidence files and official sources remained authoritative.

## 14. Final answer

```text
flag{recon_e8f25be55df46671}
```

## Required submission summary

### Root cause

This challenge modeled a provenance and object-binding failure: individually plausible badge, mail, custody, photograph, revision and historical-source records could yield a wrong manifest if they were not bound to the same person, asset and committed state.

### Reproducible PoC

Replay `transactions.jsonl` using the rules in section 5, hash the corroborated north-archive photograph and build the exact compact JSON array in section 10. SHA-256 must equal `4f3bc799d152...d4e117c97`; `/recon/verify` accepted that digest with revision `c`.

### Fix / mitigation

Bind approvals to immutable asset and revision identifiers, enforce optimistic-commit checks, distinguish staged from committed state, retain authoritative source identifiers, hash exact acquisition bytes and require multiple physical features before accepting image attribution.

### AI usage

Codex assisted with visual comparison, RIFF metadata triage, custody replay and official-source correlation. Playwright handled the authorized browser workflow after manual login. Original artifacts, transaction counts, source context and verifier acceptance independently validated the result.
