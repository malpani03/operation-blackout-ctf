# Epilogue — Building a Transferable Detection for an Unauthorized DNS Transfer

## Challenge summary

**Category:** Detection Engineering / Forensics  
**Challenge:** Epilogue  
**Result:** Solved and accepted by the held-out evaluator  
**Score:** 220 points  
**First blood:** Yes  
**Evaluation requests used:** 1 of 20  
**Final flag:** `flag{epilogue_f5e952d7d3c3fc64}`

Epilogue was different from the earlier exploitation challenges. It did not ask for a secret hidden directly in an artifact. Instead, it supplied a labeled training acquisition and required a **general behavioral detector**.

The detector had to recognize the same incident after all superficial identifiers had changed. Host names, IP addresses, domains, process IDs, hashes, certificate dates, deployment revisions, record order, and payload data were randomized in the separate evaluation acquisition. Hard-coding the training examples could therefore never work.

The successful detector correlated three evidence domains:

1. **Resolver evidence:** a complete, CRC-valid, non-trivial framed DNS transfer.
2. **Endpoint evidence:** a recent process with a recorded parent loaded the associated module immediately before the transfer.
3. **Trust and authorization evidence:** that module was neither trusted by a valid, unrevoked signing certificate nor authorized by the final state of an exact host/module deployment.

Before correlation, both resolver and endpoint timestamps had to be normalized to UTC. The DNS address then had to be resolved through the lease that was active at the observation time and mapped through its MAC address to a durable host identity.

The final SQL achieved:

```text
training true positives  = 35
training false positives = 0
training false negatives = 0
training true negatives  = 35
precision                = 1.000
recall                   = 1.000
```

I submitted that query once to the separate held-out evaluator. It passed the required 95% precision and recall thresholds and returned the flag. The case board accepted the flag and awarded first blood.

The investigation path was:

```text
Nest case handover
  -> acquire the labeled training tables and interface contract
  -> preserve and hash the acquisition
  -> reproduce the tables in local SQLite
  -> normalize resolver and endpoint clocks
  -> resolve historical IP addresses through time-bounded leases
  -> parse, CRC-check, and de-duplicate framed DNS chunks
  -> identify complete, non-trivial transfer streams
  -> correlate each stream with its module-loading process and parent
  -> evaluate signer trust at the module event time
  -> evaluate the final exact deployment authorization
  -> test against all 70 training labels
  -> submit one read-only query to the held-out evaluator
  -> receive and submit the flag
```

## 1. What was the security issue?

This challenge was about a **control gap and its observable behavior**, not a flaw in SQLite or DNS.

The incident chain was:

```text
parent process
  -> recent child process
  -> child loads a module
  -> module is not trusted at that event time
  -> module has no effective deployment approval for that host
  -> host emits a complete framed transfer through DNS TXT queries
```

The most important trust lesson was that a trusted host executable does not automatically make everything it loads trusted. The contract explicitly warned:

> Host executable trust is independent.

A legitimately signed program can load an untrusted or revoked module. Conversely, a module may be deliberately deployed even if its certificate evidence is not sufficient on its own. The detector therefore could not label activity malicious merely because one trust signal was absent.

The training corpus showed that authorized maintenance could have either of these independent forms:

- a module with valid signer trust but no matching approved deployment;
- a module with a matching approved deployment but no currently valid signer trust;
- or both trust and approval.

The incident examples were distinguished by the **conjunction** of two failures:

```text
module is not trusted
AND
module is not authorized by an effective deployment
```

That condition was then tied to a recent, attributable, complete DNS transfer. This matters because an untrusted file sitting on disk is not proof of execution, and a suspicious-looking DNS name by itself is not proof of an incident.

### Why a simple indicator rule would fail

Several tempting rules were deliberately unreliable:

- **Match the observed IP address.** Addresses were historically reused, so the same address could represent different machines at different times.
- **Match the domain or stream ID.** Evaluation randomized them.
- **Match a process or module hash.** Evaluation randomized file identities.
- **Treat every framed DNS stream as malicious.** Legitimate transfer jobs used the same framing.
- **Treat every untrusted module as malicious.** Some were independently authorized deployments.
- **Trust any historical approval.** Later change records could withdraw it.
- **Compare raw timestamps.** Resolver and endpoint recorders used different offsets.
- **Count every DNS delivery as new content.** Duplicate sequence/payload deliveries were ordinary retransmission, not additional data.

The vulnerability from an operational perspective was therefore a weak module-control boundary combined with detection logic that would be easy to evade if it depended on transient names or only one telemetry source.

## 2. Challenge contract and constraints

The challenge page exposed two read-only resources:

```text
/epilogue/training.json
/epilogue/contract
```

The grader accepted:

```http
POST /epilogue/grade
Content-Type: application/json
```

with a body containing the Nest handover and a read-only SQLite query:

```json
{
  "handover": "<Nest receipt>",
  "query": "SELECT ..."
}
```

The query had to return exactly these durable entity columns:

```text
host, domain
```

The important limits were:

```text
20 total evaluation requests
SELECT only
8 KiB maximum query size
12 million SQLite VM instructions
4-second deadline
at most 1,000 output rows
```

Invalid and over-budget SQL also consumed a request. The held-out database contained no labels and never revealed individual mistakes. That made local validation essential: spending evaluation attempts to tune the query would be both wasteful and largely uninformative.

The solved Nest case supplied this handover:

```json
{
  "case": "nest",
  "receipt": "a9a37fc3247a796fe86c73c07d3f0653f33b208e2ceb685c42505a81cd54405e",
  "revision": 5
}
```

Playwright was used inside the existing authenticated browser session to retrieve that already-earned handover and later call the evaluator. No cookies, bearer tokens, or hidden authentication material were extracted into the solution.

## 3. Preserving the training acquisition

The labeled acquisition was saved unchanged as [epilogue-training.json](assets/epilogue-training.json).

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `epilogue-training.json` | 287,503 | `6b8ea80305398c6eff619920b3104818b4f86c64b5ff66bcc9920b5cab5e8712` |
| `epilogue-detector.sql` | 2,455 | `e87b7f50b3c52122c47017b56e03c0e1ca653c490b05e82a4a3499b47152dc6d` |
| `epilogue_analyze.py` | 7,795 | `2afe3b5cd8d4b63de54b184e232ac1b8c4c472ac181ce2681214a0d82a667327` |
| `epilogue-result.json` | 247 | `308470f7be0614d7dc47f8779f97e83a5531b383e6d7b56568b137e87f93ee13` |

The training JSON contained the schema, raw table rows, provenance rules, and 70 labels. Its table counts were:

| Table | Rows | Purpose |
|---|---:|---|
| `dns` | 1,637 | Resolver observations containing framed transfer labels |
| `leases` | 140 | Time-bounded address-to-MAC assignments |
| `assets` | 140 | MAC-to-durable-host mappings |
| `clocks` | 2 | Recorder clock offsets |
| `processes` | 210 | Endpoint process events |
| `modules` | 70 | Module-load events |
| `files` | 280 | Digest-to-signer mappings |
| `certificates` | 3 | Signer validity and revocation information |
| `deployments` | 35 | Host/module authorization windows |
| `changes` | 50 | Ordered deployment state changes |
| `labels` | 70 | Training-only host/domain verdicts |

The 70 labels were balanced:

```text
35 incident examples
35 benign examples
```

The held-out evaluator had 240 new streams and no `labels` table.

The acquisition can be re-hashed with:

```powershell
Get-FileHash -Algorithm SHA256 .\epilogue-training.json
Get-FileHash -Algorithm SHA256 .\epilogue-detector.sql
Get-FileHash -Algorithm SHA256 .\epilogue_analyze.py
Get-FileHash -Algorithm SHA256 .\epilogue-result.json
```

## 4. Building a useful mental model of the data

The tables initially look unrelated. The key is to treat them as one event graph rather than ten separate lists.

```text
DNS observation
  |
  | normalize resolver time
  v
address at UTC instant
  |
  | active lease interval
  v
MAC address
  |
  | assets mapping
  v
durable host
  |
  +----------------------------+
  |                            |
  v                            v
DNS stream                 module-load event
                               |
                               +-> process and parent
                               +-> file signer and certificate
                               +-> exact deployment and final state
```

The ultimate entity was not an IP, PID, hash, or stream identifier. It was a durable `(host, domain)` pair supported by all the intermediate evidence.

### 4.1 The two clock domains

The contract defined recorder time as:

```text
recorder local time = UTC epoch seconds + clocks.offset
```

Rearranging gives:

```text
UTC = recorder local time - clocks.offset
```

This applied to both kinds of observations:

```sql
d.observed - resolver_clock.offset
m.local_time - endpoint_clock.offset
p.local_time - endpoint_clock.offset
```

In the training acquisition, the two offsets were different:

```text
resolver-a41bb3 = +80 seconds
endpoint-e77339 = -348 seconds
```

Comparing raw values would therefore shift the two timelines by 428 seconds relative to each other. A genuinely related module and DNS stream would appear unrelated.

### 4.2 Historical address ownership

The normalized DNS time selected the lease whose **inclusive** interval contained the event:

```sql
f.utc BETWEEN l.start AND l.end
```

The resulting MAC address was then mapped to a stable host:

```sql
JOIN assets AS a ON a.mac = l.mac
```

This avoided attributing old traffic to whichever machine happened to own an address later.

## 5. Understanding the DNS transfer framing

Each transfer label used this layout:

```text
payload_hex.sequence_hex.claimed_crc16_hex.stream_id.domain
```

For example, one record resembled:

```text
263e558433a1242e87f5bfc105367ae2.0008.c88f.a87a1ab7.relay-1308d137.org
```

The evaluator supplied read-only parsing helpers:

| Function | Result |
|---|---|
| `nj_payload(wire_name)` | Lowercase payload hex |
| `nj_sequence(wire_name)` | Numeric sequence |
| `nj_claimed_crc(wire_name)` | CRC claimed by the label |
| `nj_crc16(wire_name)` | CRC16-CCITT computed from the payload |
| `nj_stream(wire_name)` | Stream identifier |
| `nj_domain(wire_name)` | Destination domain |

Malformed labels returned SQL `NULL`.

### 5.1 Validate acquisition integrity

For every unique chunk, the detector required:

```text
computed CRC == claimed CRC
```

This prevented corrupted traffic from becoming incident evidence merely because its names looked well formed.

### 5.2 De-duplicate retransmissions correctly

The contract stated that duplicate sequence/payload deliveries did not add content. Therefore, rows were grouped by:

```text
host, domain, stream, sequence, payload
```

`MIN(utc)` retained the first observed delivery time. Ten identical deliveries of the same sequence and payload still represented one chunk.

This distinction exposed the first local false-positive problem. A preliminary detector found all 35 incident streams but also selected ten benign examples:

```text
true positives  = 35
false positives = 10
false negatives = 0
precision       = 35 / 45 = 0.778
recall          = 35 / 35 = 1.000
```

All ten false positives were ordinary short delivery streams containing only three unique chunks. Some had been delivered many times, but repetition did not turn them into a substantive transfer. The incident and maintenance transfer families contained at least ten distinct chunks.

The final detector therefore required:

```sql
COUNT(*) >= 10
```

This was not guessed from a domain name or a particular payload. It represented a labeled behavioral boundary between ordinary repeated delivery and the transfer activity under investigation. The separate held-out evaluation later confirmed that it transferred to new examples.

### 5.3 Require an unambiguous complete stream

After de-duplication, a complete stream had to satisfy all of these conditions:

```text
minimum sequence is 0
maximum sequence + 1 equals the number of chunks
the number of distinct sequences equals the number of chunks
every chunk has a valid CRC
```

Together they mean:

- numbering starts at zero;
- there are no gaps;
- no sequence number has conflicting payloads;
- every retained payload is intact.

The SQL was:

```sql
HAVING MIN(seq) = 0
   AND COUNT(*) >= 10
   AND MAX(seq) + 1 = COUNT(*)
   AND COUNT(DISTINCT seq) = COUNT(*)
   AND MIN(crc_ok) = 1
```

## 6. Correlating the endpoint execution

A valid transfer alone was not malicious because approved maintenance used the same mechanism. The next task was to find endpoint activity on the same durable host.

### 6.1 Module timing

The module-load event had to occur shortly before the first transfer chunk:

```sql
m.utc BETWEEN s.first_seen - 60 AND s.first_seen
```

This bound the loaded module to the transfer without depending on a particular PID or hash.

### 6.2 Process provenance

The module's `host` and `pid` were joined to a process record. After endpoint clock normalization, the child process had to start no more than 300 seconds before the stream and no later than the module load:

```sql
p.local_time - pc.offset BETWEEN s.first_seen - 300 AND m.utc
```

It also needed a recorded parent on the same host:

```sql
EXISTS (
  SELECT 1
  FROM processes AS parent
  WHERE parent.host = p.host
    AND parent.pid = p.ppid
)
```

This requirement rejected five training examples whose apparent transfer-related process had no valid parent provenance. Merely finding a matching PID was insufficient.

## 7. Evaluating module trust at event time

The `files` table mapped each module digest to a signer. That signer was trusted only if a matching certificate satisfied both conditions at the normalized module time:

```text
valid_from <= module UTC <= valid_to
and
revoked_at is NULL or revoked_at > module UTC
```

The exact predicate was:

```sql
EXISTS (
  SELECT 1
  FROM files AS f
  JOIN certificates AS cert ON cert.subject = f.signer
  WHERE f.digest = m.module_hash
    AND m.utc BETWEEN cert.valid_from AND cert.valid_to
    AND (cert.revoked_at IS NULL OR cert.revoked_at > m.utc)
)
```

The detector selected the inverse with `NOT EXISTS`.

Three details matter:

1. A signer name alone is not enough; its certificate must cover the event time.
2. A certificate that was later revoked may still have been valid before revocation, depending on the recorded time.
3. The process image's signature cannot substitute for the loaded module's trust evidence.

Five benign training examples had valid module trust without a matching deployment approval. They had to remain benign.

## 8. Evaluating deployment authorization

Authorization required more than finding a deployment row. A deployment applied only when all of these matched:

```text
exact durable host
exact module hash
module event inside the inclusive deployment interval
latest change sequence has state approved
```

The final state was selected with:

```sql
SELECT ch.state
FROM changes AS ch
WHERE ch.deployment_id = d.id
ORDER BY ch.sequence DESC
LIMIT 1
```

This avoided treating a withdrawn historical approval as current. It also rejected “nearly matching” records for another host, another module, or another time window.

Five benign examples were authorized despite lacking valid signer trust, and another five were both authorized and trusted. Those were legitimate transfer jobs, not incident records.

## 9. What the labeled negative examples taught us

The 35 benign labels were deliberately divided into lookalike families:

| Benign family | Count | Why it must not alert |
|---|---:|---|
| Short repeated delivery | 10 | Only three unique chunks; repeated delivery adds no content |
| Damaged acquisition | 5 | One or more chunk CRCs fail |
| Missing process provenance | 5 | Transfer-related process has no recorded parent |
| Trusted module | 5 | Valid, unrevoked module certificate at event time |
| Approved deployment | 5 | Exact host/module deployment is finally approved |
| Trusted and approved | 5 | Both independent legitimacy signals are present |

The 35 positive labels shared the opposite behavior:

```text
complete non-trivial CRC-valid stream
AND recent same-host module/process chain with a parent
AND module not trusted
AND exact module deployment not approved
```

This decomposition was more useful than asking which column had the strongest statistical correlation. Each negative family represented a real forensic alternative that the final query had to rule out.

## 10. The final detector

The complete submitted query is preserved as [epilogue-detector.sql](analysis/epilogue-detector.sql):

```sql
WITH
framed AS (
  SELECT d.address,
         d.observed - c.offset AS utc,
         nj_sequence(d.wire_name) AS seq,
         nj_payload(d.wire_name) AS payload,
         nj_claimed_crc(d.wire_name) AS claimed_crc,
         nj_crc16(d.wire_name) AS actual_crc,
         nj_stream(d.wire_name) AS stream,
         nj_domain(d.wire_name) AS domain
  FROM dns AS d
  JOIN clocks AS c ON c.sensor = d.sensor
  WHERE d.qtype = 'TXT'
),
attributed AS (
  SELECT a.host, f.domain, f.stream, f.seq, f.payload,
         f.claimed_crc, f.actual_crc, f.utc
  FROM framed AS f
  JOIN leases AS l
    ON l.address = f.address
   AND f.utc BETWEEN l.start AND l.end
  JOIN assets AS a ON a.mac = l.mac
  WHERE f.stream IS NOT NULL
),
chunks AS (
  SELECT host, domain, stream, seq, payload,
         MIN(utc) AS first_seen,
         MIN(actual_crc = claimed_crc) AS crc_ok
  FROM attributed
  GROUP BY host, domain, stream, seq, payload
),
complete_streams AS (
  SELECT host, domain, stream,
         MIN(first_seen) AS first_seen
  FROM chunks
  GROUP BY host, domain, stream
  HAVING MIN(seq) = 0
     AND COUNT(*) >= 10
     AND MAX(seq) + 1 = COUNT(*)
     AND COUNT(DISTINCT seq) = COUNT(*)
     AND MIN(crc_ok) = 1
),
module_events AS (
  SELECT m.host, m.pid, m.module_hash,
         m.local_time - c.offset AS utc
  FROM modules AS m
  JOIN clocks AS c ON c.sensor = m.sensor
)
SELECT DISTINCT s.host AS host, s.domain AS domain
FROM complete_streams AS s
JOIN module_events AS m
  ON m.host = s.host
 AND m.utc BETWEEN s.first_seen - 60 AND s.first_seen
JOIN processes AS p
  ON p.host = m.host
 AND p.pid = m.pid
JOIN clocks AS pc ON pc.sensor = p.sensor
WHERE p.local_time - pc.offset BETWEEN s.first_seen - 300 AND m.utc
  AND EXISTS (
    SELECT 1
    FROM processes AS parent
    WHERE parent.host = p.host
      AND parent.pid = p.ppid
  )
  AND NOT EXISTS (
    SELECT 1
    FROM files AS f
    JOIN certificates AS cert ON cert.subject = f.signer
    WHERE f.digest = m.module_hash
      AND m.utc BETWEEN cert.valid_from AND cert.valid_to
      AND (cert.revoked_at IS NULL OR cert.revoked_at > m.utc)
  )
  AND NOT EXISTS (
    SELECT 1
    FROM deployments AS d
    WHERE d.host = m.host
      AND d.module_hash = m.module_hash
      AND m.utc BETWEEN d.start AND d.end
      AND (
        SELECT ch.state
        FROM changes AS ch
        WHERE ch.deployment_id = d.id
        ORDER BY ch.sequence DESC
        LIMIT 1
      ) = 'approved'
  );
```

The query is 2,455 bytes, comfortably below the 8 KiB limit. It is a single read-only statement and returns only the required `host` and `domain` columns.

## 11. Local validation

[epilogue_analyze.py](scripts/epilogue_analyze.py) provides a dependency-free local harness using Python's built-in `json` and `sqlite3` modules. It:

- loads the JSON acquisition into a local SQLite database;
- implements the six documented `nj_*` framing helpers;
- implements CRC16-CCITT with initial value `0xffff`;
- runs exploratory feature correlation;
- executes the exact final detector SQL;
- compares predictions with the training-only labels;
- prints precision and recall.

Run it with:

```powershell
python .\epilogue_analyze.py
```

The decisive output is:

```text
detector bytes=2455 predictions=35 tp=35 fp=0 fn=0
precision=1.000 recall=1.000
```

For beginners, the metrics mean:

```text
precision = true positives / all detector alerts
          = 35 / (35 + 0)
          = 100%

recall    = true positives / all actual incidents
          = 35 / (35 + 0)
          = 100%
```

Precision answers, “When the detector alerts, how often is it right?” Recall answers, “Of all incidents present, how many did it find?” The challenge required both to be at least 95% on unseen data.

No evaluation request was used during this tuning. All iteration occurred against the provided labels.

## 12. Held-out evaluation and flag recovery

After the local query reached a perfect confusion matrix, it was submitted once through the authenticated challenge origin:

```http
POST /epilogue/grade
Content-Type: application/json
```

Conceptually, the request was:

```json
{
  "handover": "a9a37fc3247a796fe86c73c07d3f0653f33b208e2ceb685c42505a81cd54405e",
  "query": "<contents of epilogue-detector.sql>"
}
```

The evaluator ran the query against 240 unseen streams with randomized identities, data values, clock conditions, lease reuse, certificate state, deployment histories, and record order. It returned:

```json
{
  "ok": true,
  "flag": "flag{epilogue_f5e952d7d3c3fc64}",
  "notice": "Submit this flag on the case board. Your case handover becomes available there after solve or skip."
}
```

That response proves the detector met the required held-out precision and recall threshold. The evaluator did not reveal its individual labels, so the result could not have been obtained by enumerating held-out answers.

The flag was then submitted to the case board:

```json
{
  "correct": true,
  "points": 220,
  "first_blood": true
}
```

Only one of the twenty allowed evaluation requests was consumed. The result is preserved in [epilogue-result.json](analysis/epilogue-result.json).

## 13. Reproduction checklist

### Step 1: verify the preserved acquisition

```powershell
Get-FileHash -Algorithm SHA256 .\epilogue-training.json
```

Expected:

```text
6b8ea80305398c6eff619920b3104818b4f86c64b5ff66bcc9920b5cab5e8712
```

### Step 2: review the detector contract

Confirm:

- UTC is local recorder time minus its sensor offset;
- lease bounds are inclusive;
- duplicates do not add content;
- module trust is evaluated at the module event time;
- the final deployment change determines approval;
- output columns must be `host, domain`.

### Step 3: rebuild and test locally

```powershell
python .\epilogue_analyze.py
```

Confirm:

```text
predictions=35 tp=35 fp=0 fn=0
precision=1.000 recall=1.000
```

### Step 4: inspect the exact query

```powershell
Get-Content -Raw .\epilogue-detector.sql
```

Ensure it remains a single read-only query below 8 KiB and returns only `host` and `domain`.

### Step 5: submit once from an authenticated session

Send the Nest receipt and exact SQL to `/epilogue/grade`. A successful reproduction must return `"ok":true`; matching the training labels alone is not proof of transferability.

### Step 6: submit the returned flag

```text
flag{epilogue_f5e952d7d3c3fc64}
```

## 14. Detection and engineering lessons

### 14.1 Correlate behavior, not indicators

The query survived randomized infrastructure because it described relationships and ordering rather than known names. Domains, addresses, hashes, stream IDs, PIDs, and sensor names were used only as join keys within the evidence, never as fixed indicators.

### 14.2 Normalize time before correlation

Cross-system detection is only meaningful after each timestamp is interpreted in its recorder's clock domain. A few minutes of offset is enough to break a process-to-network rule or connect the wrong events.

### 14.3 Resolve identity at event time

An IP address is an observation attribute, not a durable identity. Historical attribution must include the lease interval and stable asset mapping.

### 14.4 Validate the acquisition before interpreting it

CRC failure, missing chunks, conflicting sequence payloads, and duplicate deliveries all change what can responsibly be claimed. Damaged or repeated traffic should not become stronger evidence merely because more rows exist.

### 14.5 Trust and authorization are independent

Certificate trust asks whether the content was validly signed at that time. Deployment authorization asks whether that exact content was approved for that exact host at that time. Neither question should silently answer the other.

### 14.6 Current state must account for history

An old `approved` row is not enough when a later change withdrew approval. State-machine history must be reduced using the latest authoritative sequence.

### 14.7 Test negative families explicitly

A detector that finds every incident but alerts on routine maintenance is not production quality. The local false-positive families were as valuable as the positive examples because each identified one missing evidentiary condition.

## 15. How to fix the underlying control gap

The detector addresses visibility; prevention should close the module-loading and deployment-control gaps.

### 15.1 Enforce module trust at load time

Verify the loaded module itself, not only the host executable. Reject modules whose signer is absent, expired, not yet valid, or revoked at the relevant time.

### 15.2 Require exact deployment authorization

Approval should bind at least:

```text
host identity | module digest | validity interval | deployment revision
```

Do not allow approval for a similar host or previous module revision to authorize new content.

### 15.3 Make approval changes authoritative and auditable

Deployment state should have a monotonic sequence or transaction identifier, and enforcement should use the final committed state. Withdrawal must take effect consistently across endpoints.

### 15.4 Restrict and monitor DNS egress

Resolvers should enforce allowed query types, label lengths, rates, and approved destinations. High-entropy framed payloads should be correlated with endpoint execution rather than alerted on in isolation.

### 15.5 Maintain clock quality and expose offsets

Recorder offsets should be measured, retained, and attached to telemetry. Detection pipelines should normalize timestamps once and preserve both raw and normalized values.

### 15.6 Preserve historical identity data

Lease history and stable asset mappings are security evidence. Retaining only current address ownership makes historical incident attribution unreliable.

### 15.7 Test the full behavioral invariant

Detection tests should include:

- new host, domain, stream, PID, and hash values;
- reused addresses across non-overlapping leases;
- positive and negative recorder offsets;
- duplicate and reordered deliveries;
- corrupt CRCs and missing sequences;
- expired and revoked certificates;
- approval followed by withdrawal;
- near-match deployments for the wrong host or module;
- signed host executables loading untrusted content;
- authorized maintenance that resembles exfiltration.

## 16. How AI was used

AI was used as an analysis and implementation assistant. It accelerated evidence exploration, but it was not treated as a source of labels or proof.

### Productive uses

The AI assistant helped with:

- converting the contract into explicit, testable predicates;
- inventorying table sizes and sampling raw rows;
- building a local SQLite copy of the JSON acquisition;
- implementing the documented DNS framing and CRC16 helpers;
- forming clock-normalization and historical lease joins;
- generating per-label feature summaries for stream integrity, timing, trust, and authorization;
- identifying why the preliminary rule had ten false positives;
- separating the six benign behavior families;
- writing and simplifying the final read-only SQL;
- computing the complete confusion matrix locally;
- checking the query size and required output columns;
- using Playwright inside the existing authenticated session for the single evaluation request and flag submission;
- preserving hashes, results, and reproduction artifacts;
- organizing the technical evidence into this write-up.

### How AI output was controlled

Every important AI-generated inference was tested against evidence:

- The timestamp equation came directly from the supplied contract.
- Address attribution required the lease active at normalized event time.
- DNS payload integrity was checked with the documented CRC algorithm.
- Duplicate deliveries were reduced by exact sequence/payload identity.
- Stream completeness was asserted with start, gap, collision, and CRC conditions.
- Module and process timing were checked only after endpoint clock normalization.
- Signer trust was recomputed using certificate validity and revocation time.
- Deployment approval used the exact host, module, interval, and last change state.
- The complete query was evaluated against all 70 visible labels.
- No held-out label was available to the AI or local script.
- The evaluation endpoint was called only after local precision and recall reached 100%.
- Only the evaluator's `"ok":true` response was accepted as proof that the rule transferred.
- The case board independently accepted the returned flag.

The first rule proposed during analysis was not good enough: it had perfect recall but only 77.8% precision because it mistook short repeated deliveries for substantive transfers. That failure was retained in the methodology because it shows the value of labeled negative examples and measurement over intuition.

AI did not enumerate infrastructure indicators, query hidden labels, or burn the evaluation budget searching for a favorable answer. It helped make hypothesis testing faster; the evidence and the independent held-out evaluator decided whether those hypotheses were correct.

## 17. Final evidence table

| Item | Value |
|---|---|
| Previous case | `nest` |
| Nest handover receipt | `a9a37fc3247a796fe86c73c07d3f0653f33b208e2ceb685c42505a81cd54405e` |
| Training examples | 70 |
| Training incidents | 35 |
| Training benign streams | 35 |
| Training precision | `1.000` |
| Training recall | `1.000` |
| Held-out streams | 240 |
| Required held-out precision | `>= 0.95` |
| Required held-out recall | `>= 0.95` |
| Evaluation requests used | `1 / 20` |
| Detector size | 2,455 bytes |
| Evaluator result | `ok: true` |
| Case-board result | `correct: true` |
| Score | 220 points |
| First blood | `true` |
| Flag | `flag{epilogue_f5e952d7d3c3fc64}` |

## Conclusion

The successful detector did not ask whether a DNS name, IP address, process hash, or module hash had appeared before. It asked whether the acquisition proved a complete behavioral chain:

```text
intact substantive transfer
  + correct historical host attribution
  + recent parented process and module load
  + no valid module trust
  + no effective exact deployment approval
```

That distinction is why the rule worked on the separate evaluation acquisition after every obvious identifier changed.

The final result was not merely a perfect score on training data. The query was accepted on 240 unseen streams on its first submission, using only one of the twenty available evaluation requests. The protected result was:

```text
flag{epilogue_f5e952d7d3c3fc64}
```
