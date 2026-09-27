# The Tunnel - Retained Device Journal

## Challenge summary

**Category:** Network / protocol analysis / applied cryptography  
**Path:** Red, S3B  
**Points:** 350  
**Result:** Committed device material recovered through a valid live exchange  
**Final flag:** `flag{tunnel_af287b68618f8777}`

The challenge supplied a stripped maintenance client, its shared library, a short ABI description, and two laboratory transcripts. One transcript showed a failed attempt to recover a retained journal entry. The other showed a successful export of the ordinary current snapshot. The live appliance required a new, authenticated, 90-second TLS session, so neither recorded exchange could simply be replayed.

The vulnerability was a **partial-integrity cursor design that allowed generation rebinding**. A journal cursor contained three independently interpreted pieces:

```text
8-byte retained object reference | 4-byte generation | 8-byte session binding
```

The appliance required both an outer generation and the cursor's embedded generation to equal the current live generation. However, it did not cryptographically bind the cursor's retained object reference to that embedded generation. An authenticated maintenance client could therefore:

1. obtain a retained committed-journal cursor in a new live session;
2. preserve its first eight bytes, which selected the historical object;
3. replace only its four-byte historical generation with the live generation;
4. preserve its final eight-byte live session binding; and
5. submit the modified cursor with the same live generation in the outer continuation object.

The appliance accepted the recomposed cursor and exported the historical committed device key:

```text
64c5d828bac56fe9037c4a188d21652c0df5221c6118320ee36541d32c01dcf7
```

That key was then used to construct the protocol's final transcript proof. The server returned:

```json
{
  "ok": true,
  "flag": "flag{tunnel_af287b68618f8777}",
  "notice": "Submit this flag on the case board. Your case handover becomes available there after solve or skip."
}
```

No flag was guessed or brute-forced, and no case-board flag submission was consumed during this investigation.

---

## 1. Beginner-friendly background

Four concepts make the challenge much easier to understand.

### 1.1 Authentication and authorization are different

Authentication answers:

> Who is making this request?

Authorization answers:

> Is that identity allowed to perform this exact operation on this exact object?

Every request in this challenge had a valid HMAC made with the maintenance credential. The attacker therefore had to be an authenticated maintenance user. That did not mean the user should have been able to turn a historical journal reference into a current export request.

The bug was not an authentication bypass. It was an authorization and object-binding failure after authentication.

### 1.2 What is a cursor?

A cursor is a compact value that tells a server where to continue an operation. It can identify a database row, a point in a log, or a page in a result set.

A safe opaque cursor should normally be one of the following:

- a random handle whose meaning exists only in server-side state; or
- a self-contained structure protected by a MAC or authenticated encryption.

If a cursor contains security-sensitive fields that a client can edit independently, the server must not assume those fields still describe the object originally issued.

### 1.3 What is a generation number?

A generation number is a version counter. It prevents a reference created for an old state from being reused against a newer state.

For example:

```text
object generation when cursor was created:  15576
current live generation:                    81112
```

A secure server would reject the old cursor or issue a newly authenticated cursor that explicitly authorizes the transition. It should not accept a client changing `15576` to `81112` while leaving the referenced historical object unchanged.

### 1.4 What are HMAC and a transcript proof?

An HMAC is a message authentication code constructed from a secret key and a message. It proves that someone holding the key authenticated the exact bytes of that message.

This protocol used two levels of HMAC:

1. Every maintenance request was authenticated with the Insider handover receipt.
2. The final commit proof was authenticated with the recovered device key.

The final proof also included a hash of the complete conversation. This is called a transcript proof. It prevents a response from one conversation being copied into a different conversation.

HMAC did not prevent the vulnerability because the maintenance client legitimately knew the maintenance credential and could authenticate the modified cursor. Cryptography can prove who sent bytes; it cannot make incorrect authorization logic correct.

---

## 2. Evidence and prerequisites

### 2.1 Case-board values

The authenticated investigation console supplied:

```text
Player:          rupesh
Tunnel endpoint: 65.21.179.193:9405
TLS name:        ctf.roshancodes.com
Field token:     obtained from GET /api/fieldtoken (redacted here)
```

The solved Insider case supplied this handover:

```json
{
  "case": "insider",
  "receipt": "7f742f77f5d76059453a4b3e0b99e37628258eba8216d17a125da4676cc4544a",
  "revision": 5
}
```

The 32-byte receipt was the maintenance credential. The field token was only the connection bootstrap credential. These values served different purposes and were not interchangeable.

The live connection began with one text line:

```text
player:field_token\n
```

After that line, all network messages were raw binary frames.

### 2.2 Acquired artifacts

The public maintenance page exposed four files:

```text
/tunnel/sample.hex
/tunnel/maintenance.so
/tunnel/driver.txt
/tunnel/maintenance-client
```

Their SHA-256 hashes were:

```text
17282f59cb401974dde7743ada5351b0e754ee17f97dbcc8d2eb8ceda101499e  tunnel-sample.hex
9b78bc2952b1bb18eb9fe6dbc8da94126b0f952d64e5f25316ec79b9484b9736  tunnel-maintenance.so
7bb4914a231c1d3f4bf8a2f020fb122d391a259837743dbcb195cbd1bee5092c  tunnel-driver.txt
a380bed19cb86766d19ecbd35ba24fef85ba060ae6084b85f9f53bd84dbdfcc4  tunnel-maintenance-client
```

Hashing the artifacts made the investigation reproducible and ensured that later conclusions referred to exact bytes.

### 2.3 What the ABI told us

`driver.txt` described the important structures and functions:

```text
Context:
  session_id[4]
  nonce[8]
  challenge[16]
  credential[32]
  next_sequence uint8

maintenance_request(ctx, command, body, body_length, out)
maintenance_response(ctx, payload, length)
maintenance_continue(generation uint32, cursor[20], out[28])
maintenance_journal(payload, length, out[20])
maintenance_cursor(scan, out[20])
maintenance_finish(ctx, device_key[32], transcript_digest[32], out[32])
```

Two sentences were especially important:

```text
maintenance_journal(...) inspects a retained journal checkpoint while preserving its original reference.
maintenance_cursor(...) obtains the normal current snapshot reference.
```

This told us that a retained journal cursor and a current snapshot cursor were intentionally different objects.

---

## 3. Establishing the wire format

The stdio client read and wrote hexadecimal lines, but the acquisition host translated those lines into raw network frames. This distinction mattered later when talking to the appliance directly.

### 3.1 Frame layout

Every frame used this structure:

```text
Offset  Size  Meaning
0x00    2     Magic bytes: 4e 4a ("NJ")
0x02    1     Command
0x03    1     Sequence number
0x04    2     Payload length, little-endian
0x06    N     Payload
0x06+N  2     CRC-16/CCITT, little-endian
```

The CRC used polynomial `0x1021` and initial value `0xffff`.

The first recorded server frame began:

```text
4e4a 80 00 1c00 ...
```

It therefore meant:

```text
magic       = 4e4a
command     = 0x80
sequence    = 0
payload_len = 0x001c = 28 bytes
```

Those 28 greeting bytes were:

```text
session_id[4] || nonce[8] || initial_challenge[16]
```

### 3.2 Request authentication

For a command with an optional body, the client calculated:

```text
request_mac = HMAC-SHA256(
    key     = maintenance_credential,
    message = session_id || challenge || command || sequence || body
)
```

The frame payload was:

```text
body || request_mac
```

This construction tied each request to:

- the authenticated maintenance credential;
- the session identifier;
- the latest server challenge;
- the command number;
- the sequence number; and
- the request body.

It prevented replaying a recorded client frame in a new connection.

### 3.3 Response processing

A successful response payload was:

```text
next_challenge[16] || response_data
```

The client replaced its challenge with the new 16-byte value and incremented the sequence number. A client frame from an old capture therefore authenticated the wrong session ID, challenge, and sequence for a fresh session, even though the recorded frame's own CRC was still internally valid.

### 3.4 Command sequence

Disassembling the client's `main` function exposed the command bytes:

```text
10 20 21 22 23 24
```

The response strings gave them useful names:

| Command | Response marker | Purpose |
|---:|---|---|
| `0x10` | `OPEN` | Open a recovery conversation and receive the live generation |
| `0x20` | `BEGIN` | Begin against that generation with count `1` |
| `0x21` | `SCAN` | Obtain the ordinary current snapshot cursor |
| `0x22` | `SUSPEND` | Enumerate retained journal cursors |
| `0x23` | `EXPORT` | Continue with a cursor and export device material |
| `0x24` | final JSON | Prove possession of the exported key and finish |

---

## 4. Reversing the stripped client and library

The binaries were stripped, but `maintenance.so` retained its exported function names. That provided good anchors for static analysis.

### 4.1 Recovering `maintenance_request`

The function copied these values into a temporary message:

```text
session_id[4]
challenge[16]
command[1]
sequence[1]
body[variable]
```

It called OpenSSL's `HMAC(EVP_sha256(), ...)` with the 32-byte credential and appended the resulting 32-byte MAC to the body.

I reimplemented it as:

```python
message = session_id + challenge + bytes((command, sequence)) + body
mac = hmac.new(credential, message, hashlib.sha256).digest()
payload = body + mac
```

### 4.2 Recovering the `SUSPEND` parser

`maintenance_journal` checked for the seven-byte marker `SUSPEND`, read a one-byte count, and treated every entry as:

```text
cursor[20] || state[1]
```

The function returned the first cursor whose state byte was `3`.

Equivalent pseudocode is:

```python
assert data[:7] == b"SUSPEND"
count = data[7]

for i in range(count):
    entry = data[8 + i * 21 : 8 + (i + 1) * 21]
    cursor = entry[:20]
    state = entry[20]
    if state == 3:
        retained_journal_cursor = cursor
```

This established that state `3`, rather than states `1` or `2`, was the journal entry the maintenance library considered relevant.

### 4.3 Recovering `maintenance_continue`

The continuation body was exactly 28 bytes:

```text
generation uint32 little-endian
count      uint32 little-endian, always 1
cursor     20 bytes
```

In Python:

```python
body = struct.pack("<II", generation, 1) + cursor
```

The failed laboratory transcript used the current outer generation but copied the historical cursor unchanged. This resulted in `ERR cursor`.

### 4.4 Recovering `maintenance_finish`

The final function was easy to misread because the x86-64 calling convention placed arguments in registers. A careful second pass showed:

```text
key     = exported device_key[32]
message = session_id[4] || nonce[8] || transcript_digest[32]
```

Therefore:

```python
digest = hashlib.sha256(transcript).digest()
finish_message = session_id + nonce + digest
proof = hmac.new(device_key, finish_message, hashlib.sha256).digest()
```

The proof itself became the body of command `0x24`, which was then protected again by the ordinary maintenance-credential request HMAC.

---

## 5. What the two laboratory captures revealed

The two captures were not just examples. Their differences exposed the vulnerability.

### 5.1 Ordinary current snapshot

In the ordinary snapshot capture, `OPEN` returned generation:

```text
6a720100
```

Interpreted as a little-endian integer:

```text
0x0001726a
```

The `SCAN` response returned this current cursor:

```text
892462ba3ef64e88 | 6a720100 | 1ea8983ff9638ad5
```

The important observation was that bytes `8..11` of the cursor exactly matched the live `OPEN` generation.

The acquired client sent command `0x23` with:

```text
outer generation = 6a720100
embedded cursor generation = 6a720100
```

That path succeeded, but it exported only the ordinary current record.

### 5.2 Failed journal recovery

In the failed recovery capture, `OPEN` returned:

```text
4b9f0100 = 0x00019f4b
```

The selected state-`3` retained cursor was:

```text
58606f50ee1d72dd | 4b9f0000 | 393e6e8ead63c2a1
```

The outer continuation used the current generation:

```text
4b9f0100
```

But the cursor preserved its historical embedded generation:

```text
4b9f0000
```

The response was:

```text
ERR cursor
```

This showed that copying a retained cursor without transformation was invalid.

### 5.3 Deducing the cursor layout

Across both captures, every cursor naturally split into:

```text
bytes 0..7    object-specific reference
bytes 8..11   little-endian generation
bytes 12..19  live session binding
```

Evidence for this layout:

1. The middle four bytes of the `SCAN` cursor equaled the `OPEN` generation.
2. The three `SUSPEND` entries had different first-eight-byte references.
3. Their middle generation values represented neighboring historical generations.
4. Every cursor in the same exchange shared the same final eight bytes.
5. A different lab exchange had a different shared final eight bytes.

The final eight bytes therefore behaved like a session-specific binding. The first eight selected an object. The middle four were a generation field.

### 5.4 The key hypothesis

The current snapshot proved what a valid live cursor looked like:

```text
object reference | current generation | current session tail
```

The failed journal capture supplied:

```text
journal reference | historical generation | current session tail
```

The testable hypothesis was therefore:

```text
journal reference | current generation | current session tail
```

In other words, preserve the historical object reference and live session binding, but rebind only the embedded generation.

---

## 6. Reproducing the vulnerability in a live session

### 6.1 Why recorded frames could not be replayed

Every connection generated a new:

- session ID;
- nonce;
- initial challenge;
- challenge after every command;
- sequence state;
- live generation; and
- session tail inside each cursor.

The server also expired sessions after 90 seconds. Replaying either lab transcript would fail request authentication or cursor validation.

The exploit had to parse and respond to one fresh session in real time.

### 6.2 Connecting safely

The connection used TLS with normal certificate and hostname verification:

```python
context = ssl.create_default_context()

with socket.create_connection((host, port), timeout=10) as raw:
    with context.wrap_socket(raw, server_hostname="ctf.roshancodes.com") as tls:
        ...
```

The initial bootstrap line was sent before reading the 28-byte greeting:

```python
channel.write(f"{player}:{field_token}\n".encode())
```

### 6.3 Parsing raw network frames

The network did not send hexadecimal text. It sent a six-byte binary header followed by the declared payload and two-byte CRC:

```python
def read_network_frame(channel):
    header = channel.read(6)
    if len(header) != 6:
        raise RuntimeError("server closed during frame header")

    length = struct.unpack_from("<H", header, 4)[0]
    tail = channel.read(length + 2)
    if len(tail) != length + 2:
        raise RuntimeError("server closed during frame payload")

    return header + tail
```

Each received frame was checked for:

- magic bytes;
- exact declared length;
- expected command;
- expected sequence number; and
- correct CRC-16.

### 6.4 The decisive live values

In the successful live session, `OPEN` returned:

```text
current generation bytes: d83c0100
current generation value: 0x00013cd8 = 81112
```

The current `SCAN` cursor was:

```text
15334739c7d27f2a | d83c0100 | b6b1d1410fc841c3
```

`SUSPEND` returned three retained records. The state-`3` record was:

```text
69bd92377a533352 | d83c0000 | b6b1d1410fc841c3 | state 03
```

Its historical generation was:

```text
d83c0000 = 0x00003cd8 = 15576
```

The only modification was replacing bytes `8..11`:

```text
Before:
69bd92377a533352 | d83c0000 | b6b1d1410fc841c3

After:
69bd92377a533352 | d83c0100 | b6b1d1410fc841c3
```

The continuation body became:

```text
outer generation: d83c0100
count:            01000000
rebound cursor:   69bd92377a533352d83c0100b6b1d1410fc841c3
```

The exact implementation was:

```python
rebound_cursor = (
    journal_cursor[:8]
    + struct.pack("<I", open_generation)
    + journal_cursor[12:]
)

continue_body = (
    struct.pack("<II", open_generation, 1)
    + rebound_cursor
)
```

### 6.5 Server acceptance and proof of object identity

Command `0x23` returned `EXPORT` instead of an error:

```text
4558504f5254
69bd92377a533352d83c0000
64c5d828bac56fe9037c4a188d21652c0df5221c6118320ee36541d32c01dcf7
```

Breaking that response apart:

```text
4558504f5254                           "EXPORT"
69bd92377a533352                       original retained object reference
d83c0000                               original historical generation
64c5...dcf7                            32-byte committed device key
```

This was strong confirmation that the server had not returned the ordinary current snapshot. Although the request cursor had been rebound to generation `d83c0100`, the export metadata identified the original retained record at historical generation `d83c0000`.

### 6.6 Building the transcript

For every accepted command before `0x24`, the client appended:

```text
command[1] || sequence[1] || request_body || response_data
```

The 16-byte rolling challenge was not part of this transcript data. It was already involved in each request HMAC.

Equivalent Python:

```python
transcript.extend(bytes((command, sequence)))
transcript.extend(request_body)
transcript.extend(response_data)
```

After `EXPORT`:

```python
transcript_digest = hashlib.sha256(transcript).digest()
```

### 6.7 Completing the commit proof

The recovered device key was used as the HMAC key:

```python
finish_message = session_id + nonce + transcript_digest
commit_proof = hmac.new(
    device_key,
    finish_message,
    hashlib.sha256,
).digest()
```

That proof was sent as the body of command `0x24`, with the normal maintenance request HMAC added around it.

The final response decoded to:

```json
{
  "ok": true,
  "flag": "flag{tunnel_af287b68618f8777}",
  "notice": "Submit this flag on the case board. Your case handover becomes available there after solve or skip."
}
```

---

## 7. Reproducible solver

The complete solver is stored as `solve_tunnel.py` beside this write-up.

### 7.1 Offline verification first

Before contacting the live appliance, I verified the reconstructed framing, CRC, HMAC, command bodies, sequence changes, and response parsing against both acquisition transcripts:

```powershell
python solve_tunnel.py --verify
```

Output:

```text
verified tunnel-failed.hex (journal failure)
verified tunnel-current.hex (current snapshot)
```

The verifier regenerated every recorded client request byte-for-byte through command `0x23`. This was important because an incorrect CRC, byte order, body length, HMAC message, or sequence number would make a live failure ambiguous.

### 7.2 Live execution

With fresh console connection data, field token, and Insider receipt available in `tunnel-bootstrap.json`:

```powershell
python -u solve_tunnel.py
```

The successful progression was:

```text
0x10 -> OPEN
0x20 -> BEGIN
0x21 -> SCAN ordinary-current-record
0x22 -> SUSPEND with three retained entries
0x23 -> EXPORT of retained committed device key
0x24 -> {"ok": true, "flag": "flag{tunnel_af287b68618f8777}", ...}
```

The solver did not submit the returned flag to the case board. Recovery exchanges were separate from the case-board submission counter.

---

## 8. Failed approaches and why they failed

Documenting failures is useful because each one ruled out a plausible but incorrect interpretation.

### 8.1 Replaying the failed capture

This could not work because its session ID, challenges, sequence state, HMACs, live generation, and cursor session tail belonged to an expired laboratory session. The CRC could establish that the recorded frame was intact, but it could not make the stale authenticated state valid in a new session.

### 8.2 Using the acquired client's current `SCAN` cursor

This produced a valid export but selected `ordinary-current-record`. It did not meet the objective of recovering committed material from the retained journal.

### 8.3 Sending the retained cursor unchanged

This reproduced the laboratory failure:

```text
ERR cursor
```

The outer generation was current, but the embedded cursor generation was historical.

### 8.4 Using the historical generation everywhere

An early hypothesis was to use the generation embedded in the journal cursor as both the outer and inner generation. The live appliance rejected that with:

```text
ERR outer generation/count
```

This proved that the continuation envelope had to name the current live generation.

### 8.5 Rebinding both generation fields

Using the live generation in the outer object and replacing only the cursor's embedded generation succeeded. The historical reference and session tail remained unchanged.

### 8.6 Treating the network as hex-line transport

The acquired stdio client used hexadecimal lines, but the actual TLS appliance used raw binary frames. Reading its greeting as UTF-8 failed immediately on byte `0x80`. Switching to length-delimited binary reads fixed the transport without changing any cryptographic logic.

### 8.7 Using the wrong key for the final proof

My first reading of `maintenance_finish` treated the maintenance credential as the final HMAC key and placed the device key inside the message. The server returned:

```text
ERR commit proof
```

Rechecking the System V AMD64 argument registers showed that the exported device key was the HMAC key, while the message was only:

```text
session_id || nonce || SHA256(transcript)
```

Correcting that interpretation completed the exchange.

---

## 9. Root-cause analysis

### 9.1 Immediate technical cause

The server interpreted different parts of a client-supplied cursor independently:

```text
object reference | generation | session binding
```

It checked that the generation was current and that the session tail belonged to the live exchange, but it did not protect the semantic relationship between the object reference and generation. The first eight bytes continued to identify the historical journal object after the middle generation field was changed.

### 9.2 Why request HMAC did not help

The entire modified body was protected by the maintenance request HMAC. That only proved:

> An authenticated holder of the Insider maintenance credential sent this modified cursor in this live session.

It did not prove:

> The server originally issued this exact object-reference/generation combination as an authorized export cursor.

The server trusted a validly authenticated caller to supply a security-sensitive cursor transformation that should have been performed and authorized by the server.

### 9.3 Security impact

An authenticated maintenance operator who could enumerate retained journal checkpoints could recover committed historical device material that the normal current-snapshot flow did not expose.

The exploit did not require:

- guessing a key;
- breaking SHA-256 or HMAC;
- stealing the lab credential;
- replaying an old authenticated frame; or
- corrupting memory.

It required only a legitimate maintenance credential, a fresh live session, and modification of a field the server failed to bind to the referenced object.

### 9.4 Vulnerability classification

The issue is best described as:

```text
Partial cursor integrity / generation rebinding
```

Relevant general weakness families include:

- insufficient verification of data authenticity;
- improper input validation;
- insecure direct object reference or object-level authorization failure; and
- trusting client-controlled state across an authorization boundary.

The exact label matters less than the engineering lesson: all fields that jointly identify and authorize an object must be validated as one indivisible server-issued statement.

---

## 10. Recommended remediation

### 10.1 Make the cursor opaque and tamper-evident

The server should issue a cursor containing all security-relevant fields and authenticate them together:

```text
version
cursor purpose
object ID
object generation
session ID
principal ID
expiry
allowed operation
```

Then calculate:

```text
cursor_mac = HMAC(server_cursor_key, all_cursor_fields)
```

The server must verify that MAC before using any field. Changing the generation would then invalidate the cursor.

Authenticated encryption such as AES-GCM or ChaCha20-Poly1305 could also provide confidentiality and integrity, but integrity is the essential requirement here.

### 10.2 Prefer random server-side handles

A simpler design is:

```text
client receives: random 256-bit handle
server stores:   principal, session, object, generation, operation, expiry
```

The client cannot recombine fields it never receives separately.

### 10.3 Remove duplicated authority fields

The request carried the generation twice:

- once in the outer continuation structure; and
- once inside the cursor.

Duplicated security state creates ambiguity about which value is authoritative. If duplication is unavoidable, the server must require both values to match a server-side record, not merely each other or the current generation.

### 10.4 Separate enumeration from export authorization

The ability to list a retained checkpoint should not automatically grant permission to export it. The server should make a new authorization decision at `EXPORT`, using:

- the authenticated principal;
- requested object;
- historical/current status;
- policy-approved operation;
- session scope; and
- explicit journal-recovery permission.

### 10.5 Add negative tests

Regression tests should cover at least:

```text
- retained object reference + current generation
- current object reference + historical generation
- cursor from another session
- cursor from another principal
- cursor for another operation
- modified object reference with unchanged generation
- modified generation with unchanged object reference
- expired cursor
- valid HMAC over an unauthorized recombination
```

The final case is especially important. Authentication tests alone would not detect this bug.

### 10.6 Improve error handling and monitoring

Distinct errors such as `ERR cursor`, `ERR outer generation/count`, and `ERR commit proof` were useful during development but also revealed which validation stage failed. Production systems should consider generic client errors while preserving precise internal audit logs.

Rate limiting and alerting should detect repeated short-lived sessions that fail at successive validation stages. These controls would not fix the root cause, but they would improve detection.

---

## 11. How AI was used

An AI coding assistant was used throughout the investigation as an analysis and implementation aid. Its use was recorded transparently rather than presenting all work as unaided manual analysis.

### 11.1 Tasks performed with AI assistance

The AI assistant helped to:

- inventory the workspace and acquired artifacts;
- retrieve the unlocked case dossier, field token, Insider handover, and connection metadata from the already authenticated browser session;
- download and hash the four Tunnel artifacts;
- inspect ELF sections, dynamic symbols, strings, and x86-64 disassembly;
- translate the stripped `maintenance_request`, `maintenance_journal`, `maintenance_continue`, and `maintenance_finish` routines into readable pseudocode;
- compare the failed-journal and ordinary-current transcripts byte by byte;
- identify the apparent 8-byte / 4-byte / 8-byte cursor structure;
- implement the CRC-16, frame parser, HMAC request builder, transcript accumulator, TLS client, and offline verifier;
- propose testable hypotheses for the generation mismatch;
- interpret live protocol errors and revise those hypotheses; and
- draft and review this write-up.

### 11.2 What the AI did not do

The AI did not:

- guess or brute-force the flag;
- bypass the event login;
- invent credentials;
- disable TLS verification;
- submit candidate flags to use the case board as an oracle; or
- treat an unverified decompilation guess as proof.

The field token and maintenance receipt came from the authorized challenge workflow. Every protocol conclusion was checked against the supplied artifacts or a valid live appliance response.

### 11.3 AI mistakes and how they were caught

The AI made three useful, visible mistakes:

1. It initially assumed the network used the stdio client's hexadecimal-line framing. The live binary greeting disproved that assumption.
2. It initially tried the journal's historical generation as the outer generation. The appliance returned `ERR outer generation/count`.
3. It initially misread `maintenance_finish` and used the maintenance credential for the final proof. The appliance returned `ERR commit proof`; reviewing the calling convention showed that the exported device key was the HMAC key.

These errors were not hidden. Each was converted into evidence, the relevant code or disassembly was rechecked, and the solver was corrected. This is an important part of responsible AI-assisted security work: AI suggestions are hypotheses, not facts.

### 11.4 Verification controls

To keep the AI-assisted result trustworthy:

- all artifacts were hashed;
- frame lengths and CRCs were validated;
- generated client frames were compared byte-for-byte with both laboratory captures;
- all HMAC inputs were derived from disassembly rather than guessed;
- the live connection used certificate verification;
- the exploit used a fresh session rather than replay;
- the successful `EXPORT` returned the original historical reference and generation; and
- the final flag came from authenticated server JSON.

The human investigator remained responsible for authorizing the live connection, reviewing the evidence, and deciding which actions were in scope.

---

## 12. Lessons learned

1. **Authentication does not replace authorization.** A correctly authenticated request can still ask for an unauthorized object.
2. **Opaque security tokens must be indivisible.** If object ID, generation, purpose, and session can be recombined, a valid MAC elsewhere in the protocol may not save the design.
3. **Compare successful and failed traces.** The ordinary snapshot showed the valid current-generation relationship; the failed journal trace showed what was stale.
4. **Byte order matters.** The four-byte generations were little-endian, as were frame lengths and CRC storage.
5. **Stdio and network transports can differ.** The hex-line client was wrapped by a raw binary acquisition host.
6. **Reverse engineering should be verified dynamically.** `ERR commit proof` exposed an incorrect interpretation of register arguments.
7. **Protocol error messages are evidence.** Used carefully, they can distinguish framing, state, cursor, and proof failures without brute force.
8. **AI output must be tested.** The reliable result came from reproducible checks, not confidence in generated explanations.

---

## 13. Final answer

The retained committed device material was recovered by rebinding the state-`3` journal cursor's embedded generation to the current live generation while preserving its historical object reference and live session binding.

```text
Committed device key:
64c5d828bac56fe9037c4a188d21652c0df5221c6118320ee36541d32c01dcf7

Flag:
flag{tunnel_af287b68618f8777}
```

## Required submission summary

### Root cause

The cursor represented object reference, generation and session binding as separately interpreted fields without cryptographically binding them together. An authenticated client could preserve a historical reference and live session tail while replacing only the embedded generation.

### Reproducible PoC

Run `python scripts/solve_tunnel.py --verify` against both laboratory traces, then `python -u scripts/solve_tunnel.py` with fresh authorized bootstrap data. The live sequence OPEN, BEGIN, SCAN, SUSPEND, EXPORT and FINISH recovered the committed device key and returned `ok:true`.

### Fix / mitigation

Make cursors opaque and tamper-evident over reference, generation, purpose and session; prefer random server-side handles; remove duplicated authority fields; separate enumeration from export authorization; and add negative recombination tests.

### AI usage

Codex assisted with disassembly, trace comparison, CRC/HMAC framing, transcript logic and the TLS solver. Browser helpers recovered authorized bootstrap material. Offline byte-for-byte regeneration, verified TLS, historical EXPORT metadata and the authenticated final response controlled the result.
