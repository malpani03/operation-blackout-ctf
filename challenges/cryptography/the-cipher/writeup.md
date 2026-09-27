# The Cipher — Recovering and Forging an AES-GCM Recovery Journal

## Challenge summary

**Category:** Cryptography / Forensics  
**Challenge:** The Cipher  
**Result:** Solved and accepted by the live validator  
**Score:** 405 points after one approved 10% hint deduction  
**Final flag:** `flag{cipher_1c06b6f19064bf9d}`

The challenge began with a recovered archive credential and an authenticated handover receipt from the preceding Evidence case. Those values unlocked a packet capture containing what looked like ordinary sensor telemetry. One sensor, however, had thousands of extra packets, and its packet-arrival phase encoded a `TRP2` transport object one bit at a time.

After recovering the transport object, I derived its wrapping key from the archive credential and the sensors' registration-order calibration bytes. AES-CTR decryption followed by zlib inflation produced a 19-record recovery journal.

The cryptographic failure was then visible: journal records 7 and 14 used the same 96-bit nonce with the same AES-GCM key. The deployment's migration had preserved old records but had failed to preserve global nonce uniqueness. The retained activity log disclosed both records' exact 48-byte plaintext commands.

That single nonce collision had two consequences:

1. Reusing the GCM counter stream exposed the plaintext/ciphertext keystream, allowing a new command to be encrypted.
2. The two authentication tags exposed enough information to recover GCM's authentication subkey `H`, allowing a valid tag to be forged.

I forged a correctly authenticated `action=release` command, submitted it through the journal validator, and received the protected note—the flag.

The complete investigation path was:

```text
Evidence handover
  -> preserve and hash the Cipher acquisition
  -> identify the abnormal sensor flow
  -> decode its packet-arrival phase into a TRP2 object
  -> derive the transport wrapping key
  -> AES-CTR decrypt and zlib inflate the journal
  -> locate the repeated AES-GCM nonce
  -> reconstruct the exact retained plaintext commands
  -> recover the GCM keystream and authentication subkey
  -> forge an authenticated release record
  -> validate the record and receive the flag
```

## 1. What was the vulnerability?

The deployed journal used **AES-128-GCM with a repeated nonce**.

AES-GCM is an authenticated-encryption mode. It is intended to provide both:

- **Confidentiality:** an observer cannot read the encrypted command.
- **Integrity/authenticity:** an observer cannot alter or invent a command without the validator rejecting its authentication tag.

Those guarantees depend on a strict rule:

> A nonce must never repeat under the same GCM key.

The recovered journal violated that rule. Queue records 7 and 14 both used:

```text
18a36dba1453cb10180bc217
```

The collision was not harmless. Both records used the same key, nonce, AAD layout, and 48-byte command format. As a result, the same counter-mode keystream and the same authentication state were reused.

The vulnerable pair was:

| Queue sequence | Logged activity | Nonce | Ciphertext prefix | Tag |
|---:|---|---|---|---|
| 7 | `inspection` | `18a36dba1453cb10180bc217` | `1b944dd2b1309d97...` | `8eda894fdf7078d99d341428e3191b47` |
| 14 | `inventory` | `18a36dba1453cb10180bc217` | `1b944dd2b1309d8b...` | `614d8d08bea732084076df28e060184d` |

The challenge description warned that an interrupted recovery-journal migration had left old generations, normal entries, and recovery state together. The approved design may have required nonce uniqueness, but the acquired journal showed what the deployed implementation actually did: it reused a nonce across retained records.

### Root cause

The most likely implementation failure is a nonce allocator whose state was not migrated atomically with the encrypted records. A rollback, reset counter, or restored checkpoint caused a nonce that had already been used under the journal key to be issued again.

This distinction matters:

- Keeping old encrypted records is safe only if new records can never repeat any old `(key, nonce)` pair.
- Resetting a counter is safe only if the encryption key is rotated before the counter restarts.
- A design document saying nonces are unique is not evidence that the deployed migration preserved that invariant.

## 2. Beginner-friendly cryptography

### 2.1 Encryption is not the same as authentication

A ciphertext can sometimes be modified so that decryption produces readable text. That does **not** mean the modification is valid.

In GCM, the receiver also checks a 16-byte authentication tag. If the tag does not match the ciphertext and associated data, the receiver must reject the record without acting on its plaintext.

This challenge explicitly required that distinction. I therefore treated these as two separate milestones:

1. Construct a ciphertext that decrypts to the desired command.
2. Construct the exact tag that makes the validator authenticate that command.

The final `{"ok":true,...}` response proves the second condition. Merely seeing a readable `action=release` string locally would not.

### 2.2 What does a GCM nonce do?

GCM uses the nonce to initialize a counter stream. For a plaintext `P`, ciphertext `C`, and keystream `KS`:

```text
C = P XOR KS
```

If two messages use the same key and nonce, they get the same keystream:

```text
C1 = P1 XOR KS
C2 = P2 XOR KS
```

XORing them cancels the keystream:

```text
C1 XOR C2 = P1 XOR P2
```

If one plaintext is known, its entire keystream is also known:

```text
KS = C1 XOR P1
```

Then an attacker can encrypt a chosen plaintext of the same length:

```text
Cforged = Pchosen XOR KS
```

That solves confidentiality, but the forged record still needs a valid tag.

### 2.3 What does the GCM tag protect?

GCM authenticates the AAD and ciphertext with a polynomial hash called **GHASH**. Its secret hash subkey is:

```text
H = AES_K(0^128)
```

The tag is conceptually:

```text
Tag = AES_K(J0) XOR GHASH_H(AAD, Ciphertext)
```

`AES_K(J0)` is a fixed mask for a given key and nonce. When the nonce repeats, both records reuse that mask. XORing the tags cancels it, leaving an equation involving `H`.

Because these two ciphertexts had the same length and differed only in their first 16-byte block, the equation simplified enough to solve directly.

## 3. Starting evidence and chain of custody

The previous Evidence challenge returned this handover object:

```json
{
  "case": "evidence",
  "receipt": "be3f63da3765d3a093a77e6027271589cc5cc760d4d3ff657f440bed3a6177b9",
  "revision": 5,
  "archive_key": "a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e"
}
```

The recovered 177-byte document was:

```json
{"archive_key":"a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e","task":"db06efd5a7549b9e","template":"operation=read&archive=7ac51adc827f","owner":"reception"}
```

Its SHA-256 was:

```text
4484648495b0dab0b48e533c638cdc5224f5d86d7bedbfbf8fe4cf88283681de
```

The values needed in this challenge were therefore:

```text
archive identifier = 7ac51adc827f
archive credential = a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e
handover receipt    = be3f63da3765d3a093a77e6027271589cc5cc760d4d3ff657f440bed3a6177b9
```

I requested the Cipher acquisition through the authenticated challenge page using the handover receipt and archive credential. Browser automation ran inside the already authenticated Playwright session; it did not bypass login or invent authentication state. The downloaded ZIP was preserved unchanged, and analysis was performed on extracted or derived files.

### Acquisition hashes

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `cipher-acquisition.zip` | 581,701 | `32a85ead76f37959fad2fcdfe907426969895a7032f8bc7c71a1c327ef64193e` |
| `receiver.pcap` | 5,602,748 | `0113c8e94505825b3618b0c536d3675bf07b32b5593d8b614d5c4df804114f9e` |
| `registrations.log` | 1,343 | `d945e5e22a6830166f679b5b3cc007cdc39699934b3d9ea3484faac2c15cc5a0` |
| `sensors.yaml` | 1,161 | `9f8339aeed3327a164ed921b7a9aba593697d1073f9a3b62c0c2103369abecaf` |
| `custody.txt` | 248 | `075a39408a4a041028b66cf793053f69ed396f7dcfbf2ea59cfad92578c0d58b` |

One useful integrity observation was that downloading the package a second time changed the outer ZIP hash because the generated archive metadata differed. The hashes of all four files inside remained identical. For that reason, I retained and reported the first acquisition's exact ZIP bytes and used inner-file hashes to show that the evidentiary contents were stable.

On PowerShell, the hashes can be reproduced with:

```powershell
Get-FileHash -Algorithm SHA256 .\assets\cipher-acquisition.zip
Get-ChildItem .\assets\cipher-acquisition -File |
  Get-FileHash -Algorithm SHA256
```

## 4. Reading the acquisition clues

`custody.txt` established three facts:

```text
Packet timestamp domain is collector UTC.
Payload timestamp domain is registered transmitter UTC.
The receiver acquired a queued journal object during checkpoint migration.
Sensor values were ordinary.
Only checksum-valid objects are attributable.
```

The important phrase was **timestamp domain**. It directed attention away from sensor values and toward the difference between:

- the timestamp at which the collector captured each packet, and
- the transmitter timestamp carried inside the JSON payload.

`registrations.log` supplied the sensor registration order and two additional clues:

```text
delivery rejected: object transport is not journal envelope format
wrap-key policy: archive-bytes || registration calibration[0:16], SHA256 truncated128
```

That told me both how the wrapping key was derived and that the first decoded object would be a transport container, not the journal itself.

Finally, `sensors.yaml` mapped each sensor ID to a one-byte calibration value. The file was alphabetically ordered, but the policy said **registration calibration**, so the values had to be read in the order from `registrations.log`, not YAML order.

The first sixteen registration-order bytes were:

```text
38 8b 6e b5 95 bb e4 5a 34 13 78 49 ec fb eb ce
```

Concatenated:

```text
388b6eb595bbe45a34137849ecfbebce
```

## 5. Recovering the hidden transport from the PCAP

### 5.1 Finding the abnormal stream

I parsed the classic PCAP directly with [analyze_cipher_pcap.py](scripts/analyze_cipher_pcap.py). The capture contained 37,496 UDP JSON sensor messages sent to port 5510.

The flow counts exposed one clear anomaly:

- 23 registered sensors sent 900 packets each.
- `F-2F9E`, at `10.27.7.29:42019`, sent 16,796 packets.

Its visible sensor values and quality field still looked ordinary. The abnormality was in timing.

### 5.2 Converting arrival phase into bits

For every packet from `F-2F9E`, I calculated:

```text
phase_ms = collector_capture_time - payload_transmitter_time
```

The results formed two groups:

- normal samples near the expected jitter window, approximately `-12 ms` to `+12 ms`;
- delayed samples near `60 ms`.

A threshold of 40 ms separated them cleanly:

```python
bit = 1 if phase_ms > 40 else 0
```

This is the critical extraction loop from [recover_cipher_transport.py](scripts/recover_cipher_transport.py):

```python
transmitter = datetime.fromisoformat(
    record["ts"].replace("Z", "+00:00")
).timestamp()
phase_ms = (capture_time - transmitter) * 1000
samples.append(1 if phase_ms > 40 else 0)
```

The first 364 bits were zero/idle material. At bit offset 364, the stream contained the ASCII marker `TRP2` (`54 52 50 32`). This marker was not aligned to the start of the original bitstream, so searching for its bit representation before grouping bytes was important.

### 5.3 Parsing the TRP2 frame

Once aligned at the marker, the header decoded as:

| Field | Value |
|---|---|
| Magic | `TRP2` |
| Version | `2` |
| Flags | `0` |
| Big-endian payload length | `2001` bytes |
| Primary payload | 2,001 bytes |
| Following continuation | 20 bytes |
| Zero padding | 25 bytes |

The resulting artifacts were:

| Derived artifact | Bytes | SHA-256 |
|---|---:|---|
| `cipher-transport-frame.bin` | 2,029 | `ecf0c7596f148e56dc306af0891b48bbe00c934fde14c1a4c450e566865696b7` |
| `cipher-envelope.bin` | 2,001 | `f2ba4579283bbe333ea37a6b7778f477f6202841d776fad73c9da8faf1882f5c` |

The 20 bytes after the declared primary payload were:

```text
b0da83cbdf2914593aba06647fef90ed7b1d9214
```

My first extraction script called these bytes `cipher-transport-checksum.bin` because custody mentioned checksum-valid objects. That filename records the initial hypothesis, not the final interpretation. Strict decompression later proved that these were encrypted **continuation bytes**: omitting them truncated the zlib stream, while including them produced one complete stream with no trailing data.

This is a useful forensic lesson: preserve extracted bytes even when the initial label is wrong. The evidence can correct the interpretation later.

## 6. Unwrapping the journal

### 6.1 Deriving the AES-CTR wrapping key

The log gave this policy:

```text
archive-bytes || registration calibration[0:16], SHA256 truncated128
```

“Archive bytes” meant the 32 raw bytes obtained by hex-decoding the 64-character archive credential—not its ASCII characters.

The derivation was:

```text
archive bytes:
a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e

first 16 registration-order calibration bytes:
388b6eb595bbe45a34137849ecfbebce

SHA256(archive_bytes || calibration_bytes)[0:16]:
a018019148d17832c2965bb14c49a239
```

So the AES-128 wrapping key was:

```text
a018019148d17832c2965bb14c49a239
```

### 6.2 AES-CTR decryption and strict inflation

The first 16 bytes of `cipher-envelope.bin` were the CTR IV:

```text
c99b1ebfe105dcc54901aeb3ec6b87a6
```

The remaining 1,985 primary bytes plus the 20 continuation bytes formed the encrypted payload. Decrypting them with AES-128-CTR produced a 2,005-byte zlib stream:

```text
SHA-256(cipher-journal.zlib) =
e19acb6539a9b1a4f7b4fbbac399ed308ff5b7477e711c66e189fa211b386395
```

Strict zlib inflation produced 5,359 bytes of compact JSON:

```text
SHA-256(compact journal JSON) =
88806ac580f6a2859be29a2f8a548b5dedd96e12b38293d552e552e6391445b6
```

The formatted local copy [cipher-journal.json](analysis/cipher-journal.json) is 6,987 bytes and has a different hash because whitespace was added for readability. The semantic JSON is the same; the compact hash above is the byte-exact decompressed object.

The complete unwrap is implemented in [recover_cipher_journal.js](scripts/recover_cipher_journal.js). Its key operations are:

```javascript
const wrapKey = crypto
  .createHash('sha256')
  .update(Buffer.concat([archiveCredential, registrationCalibration]))
  .digest()
  .subarray(0, 16);

const iv = envelope.subarray(0, 16);
const decryptor = crypto.createDecipheriv('aes-128-ctr', wrapKey, iv);
const compressed = Buffer.concat([
  decryptor.update(Buffer.concat([envelope.subarray(16), continuation])),
  decryptor.final(),
]);
const journalBytes = zlib.inflateSync(compressed);
```

### 6.3 Journal contents

The journal contained:

```text
records = 19
epoch   = 20260927
AAD     = 48582d313937377c6a6f75726e616c7c376163353161646338323766
```

The AAD decoded to:

```text
HX-1977|journal|7ac51adc827f
```

Scanning all 19 nonces revealed exactly one duplicate:

```text
nonce 18a36dba1453cb10180bc217 -> queue_seq [7, 14]
```

The two complete records were:

```json
{
  "epoch": 20260927,
  "queue_seq": 7,
  "log": {"activity": "inspection", "archive": "7ac51adc827f"},
  "nonce": "18a36dba1453cb10180bc217",
  "ciphertext": "1b944dd2b1309d9798e385f0ed3c72055cf773a556e7281b599aed06e7f27f56aa9ca92889a76752f388a7b2259776c4",
  "tag": "8eda894fdf7078d99d341428e3191b47"
}
```

```json
{
  "epoch": 20260927,
  "queue_seq": 14,
  "log": {"activity": "inventory", "archive": "7ac51adc827f"},
  "nonce": "18a36dba1453cb10180bc217",
  "ciphertext": "1b944dd2b1309d8b94f59af0ed3c72055cf773a556e7281b599aed06e7f27f56aa9ca92889a76752f388a7b2259776c4",
  "tag": "614d8d08bea732084076df28e060184d"
}
```

## 7. Reconstructing the exact plaintext commands

The public worker build identified itself as:

```text
Helix envelope worker build 20260927b
Linked provider: OpenSSL EVP_aes_128_gcm. Tag storage width:128bits.
Command ABI:48bytes, action column16, context column32, ASCII spaces for unused capacity.
Action column grammar action=<verb>.
inventory verb=list; inspection verb=peek; recovery verb=release.
Read context |archive=<archive identifier>; release context |proof=<first24hex of archive credential>|.
Queue checkpoint migration preserves record epochs.
Read-command activity was logged separately from protected envelopes.
```

That build information converted the retained activity labels into exact commands. The byte lengths, spaces, delimiters, and absence or presence of a final pipe were all security-relevant.

The two known plaintexts were:

```python
peek = b"action=peek     |archive=7ac51adc827f           "
list = b"action=list     |archive=7ac51adc827f           "
```

Both are exactly 48 bytes:

- the first 16 bytes are the action column;
- the next 32 bytes are the context column;
- unused read-context capacity is filled with ASCII spaces;
- the read context does **not** end with `|`;
- the release context does end with `|` and fills its 32-byte column exactly.

The chosen release plaintext was:

```python
release = b"action=release  |proof=a7bcdb38d64c8b780d31fab5|"
```

The proof is the first 24 hexadecimal characters of the archive credential:

```text
a7bcdb38d64c8b780d31fab5
```

Before attempting a forgery, I submitted the two original tuples to the validator unchanged. Both authenticated successfully and returned read-only access to `recovery-note`:

```json
{"ok":true,"access":"read-only","entries":["recovery-note"]}
```

This check established that the recovered AAD, nonces, ciphertexts, and tags belonged to the live validator—not merely to a plausible local interpretation.

## 8. Exploiting the repeated nonce

### 8.1 Confirming keystream reuse

For the two colliding records:

```text
Cpeek XOR Clist = Ppeek XOR Plist
```

The equality held byte-for-byte. The only changed ciphertext bytes corresponded to the different `peek` and `list` verbs; the identical archive context produced identical ciphertext bytes.

Using the `peek` record, the 48-byte keystream was recovered as:

```text
KS = Cpeek XOR Ppeek
```

The release ciphertext was then:

```text
Crelease = Prelease XOR KS
```

This produced:

```text
1b944dd2b1309d9598ea8bb1be7972055ce673a951e8631f53cfef01b0f02656ff90f8278db07f42b79bb6f464d56398
```

At this point the forged ciphertext decrypted to the intended command, but it still lacked a valid authentication tag.

### 8.2 Recovering the GCM authentication subkey

The AAD is 28 bytes, which occupies two 16-byte GHASH blocks after zero padding. Each ciphertext is 48 bytes, which occupies three blocks. GCM also appends one length block. The GHASH input therefore has six blocks total:

```text
A1, A2, C1, C2, C3, Length
```

The two records differ only in ciphertext block `C1`. All other block differences cancel when the two GHASH values are XORed. Expanding the polynomial gives:

```text
Tag1 XOR Tag2 = (C1_1 XOR C1_2) * H^4
```

All operations are in the finite field `GF(2^128)` used by GCM. Define:

```text
ΔT = Tag1 XOR Tag2
ΔC = C1_1 XOR C1_2
```

Then:

```text
H^4 = ΔT / ΔC
```

Every non-zero field element has an inverse, so division means multiplication by `ΔC^-1`. The inverse of the fourth-power Frobenius map in this field is exponentiation by `2^126`, giving:

```text
H = (H^4)^(2^126)
```

The recovered authentication subkey was:

```text
H = 518ad05ada2c651572c5817c23a5d2f8
```

I verified the result instead of trusting the algebra blindly:

1. `H^4` recomputed from the candidate `H` matched the solved value.
2. The derived tag mask reproduced the original tag for record 7.
3. The same mask and `H` independently reproduced the original tag for record 14.

That double check would fail if the field multiplication, block order, AAD, or length encoding were wrong.

### 8.3 Computing the forged tag

With `H` known, the repeated nonce's tag mask was:

```text
mask = Tagpeek XOR GHASH_H(AAD, Cpeek)
```

The release tag was therefore:

```text
Tagrelease = mask XOR GHASH_H(AAD, Crelease)
```

The complete forged tuple was:

```text
nonce:
18a36dba1453cb10180bc217

ciphertext:
1b944dd2b1309d9598ea8bb1be7972055ce673a951e8631f53cfef01b0f02656ff90f8278db07f42b79bb6f464d56398

tag:
38ac1db1c473c0c8792867714c3da7f9
```

The reproducible implementation is [forge_cipher_release.py](scripts/forge_cipher_release.py). It includes:

- GCM's bit ordering and reduction polynomial;
- multiplication, exponentiation, and inversion in `GF(2^128)`;
- GHASH padding and length encoding;
- assertions for exact 48-byte commands;
- a ciphertext/plaintext XOR consistency test;
- validation against both known source tags;
- generation of the final ciphertext and tag.

Running it produces:

```powershell
python .\forge_cipher_release.py
```

```text
aad=48582d313937377c6a6f75726e616c7c376163353161646338323766
nonce=18a36dba1453cb10180bc217
H=518ad05ada2c651572c5817c23a5d2f8
ciphertext=1b944dd2b1309d9598ea8bb1be7972055ce673a951e8631f53cfef01b0f02656ff90f8278db07f42b79bb6f464d56398
tag=38ac1db1c473c0c8792867714c3da7f9
```

## 9. The failed attempt that clarified authenticity

One early candidate assumed that the read context was:

```text
|archive=7ac51adc827f|
```

That was a reasonable visual guess, but it was not the deployed 32-byte ABI. The actual read context had no closing pipe and used spaces for the remaining capacity.

This mistake is subtle because the same wrong byte was assumed in both known plaintexts. Their XOR still matched the two ciphertexts: equal wrong bytes cancel under XOR just as equal correct bytes do. Consequently, the nonce-reuse evidence remained visible, but the derived keystream byte and authentication state were wrong.

The validator returned:

```json
{"ok":false}
```

That rejection demonstrated exactly why readable plaintext is not enough. A locally plausible message is not an authenticated record.

After applying the build's literal fixed-width grammar—no closing pipe on reads, eleven trailing spaces—the original records authenticated, both source tags validated mathematically, and the corrected release tuple succeeded.

This failed hypothesis was not hidden from the methodology because it is an important part of the proof: the final result depended on exact bytes, not on guessing what the application probably meant.

## 10. Dispatching the authenticated record

The final record was sent through the live journal validator's same-origin endpoint:

```http
POST /cipher/dispatch
Content-Type: application/json
```

```json
{
  "handover": "be3f63da3765d3a093a77e6027271589cc5cc760d4d3ff657f440bed3a6177b9",
  "nonce": "18a36dba1453cb10180bc217",
  "ciphertext": "1b944dd2b1309d9598ea8bb1be7972055ce673a951e8631f53cfef01b0f02656ff90f8278db07f42b79bb6f464d56398",
  "tag": "38ac1db1c473c0c8792867714c3da7f9"
}
```

I used Playwright only as an authenticated browser transport: the user login/session was already present, and `fetch` ran from the challenge origin. No cookies or bearer tokens were copied into the write-up.

The validator responded:

```json
{
  "ok": true,
  "flag": "flag{cipher_1c06b6f19064bf9d}",
  "notice": "Submit this flag on the case board. Your case handover becomes available there after solve or skip."
}
```

The case board then accepted:

```text
flag{cipher_1c06b6f19064bf9d}
```

This response is the decisive cryptographic proof. The validator did not merely reveal the locally decrypted plaintext; it verified the forged GCM tag, parsed the authenticated `release` command, checked its proof, and returned the protected note.

## 11. Reproduction checklist

The included scripts use Python 3, Node.js, and Node's built-in `crypto`/`zlib` modules. No packet-analysis framework is required because the PCAP parser is included.

From the directory containing the preserved acquisition:

### Step 1: verify the acquisition

```powershell
Get-FileHash -Algorithm SHA256 .\assets\cipher-acquisition.zip
Get-ChildItem .\assets\cipher-acquisition -File |
  Get-FileHash -Algorithm SHA256
```

Compare the values with the table in section 3.

### Step 2: inspect network flows

```powershell
python .\analyze_cipher_pcap.py
```

Confirm that `F-2F9E` / `10.27.7.29:42019` has 16,796 messages while each other sensor has 900.

### Step 3: recover the timing frame

```powershell
python .\recover_cipher_transport.py
```

Expected critical output:

```text
frame_bit_offset = 364
version          = 2
flags            = 0
payload_bytes    = 2001
zero_padding     = 25
frame_sha256     = ecf0c7596f148e56dc306af0891b48bbe00c934fde14c1a4c450e566865696b7
payload_sha256   = f2ba4579283bbe333ea37a6b7778f477f6202841d776fad73c9da8faf1882f5c
```

### Step 4: unwrap and inflate the journal

```powershell
node .\recover_cipher_journal.js
```

Expected critical output:

```text
wrap_key       = a018019148d17832c2965bb14c49a239
iv             = c99b1ebfe105dcc54901aeb3ec6b87a6
compressed     = 2005 bytes
journal        = 5359 bytes
journal_sha256 = 88806ac580f6a2859be29a2f8a548b5dedd96e12b38293d552e552e6391445b6
records        = 19
duplicate      = nonce 18a36dba1453cb10180bc217 at sequences 7 and 14
```

### Step 5: forge the release tuple

```powershell
python .\forge_cipher_release.py
```

Compare the nonce, ciphertext, and tag with section 8.3.

### Step 6: validate, do not merely decrypt

Submit the tuple to `/cipher/dispatch` from an authenticated challenge session together with the evidence handover receipt. A successful reproduction must return `"ok":true`; a locally readable release command alone is not sufficient.

## 12. Security impact

The failure broke both primary promises of authenticated encryption:

- **Confidentiality failed.** Known plaintext from a retained activity entry exposed the counter stream for the repeated nonce.
- **Integrity failed.** Two tags under the repeated nonce exposed the GCM authentication subkey, making a valid tag for a chosen ciphertext computable.
- **Authorization was reached through cryptography.** The forged authenticated command changed an ordinary read-only journal action into a protected recovery release.
- **Migration expanded the blast radius.** Retaining old generations while reusing nonce state created the exact cross-generation collision that safe migration should prevent.

This was not a brute-force attack. The AES key was never recovered, and AES itself was not broken. The implementation violated GCM's uniqueness requirement, allowing the mode's algebra to be used as designed—but against the system.

## 13. How to fix it

### 13.1 Enforce nonce uniqueness across the entire key lifetime

For a 96-bit GCM nonce, use either:

- a securely random value with collision monitoring and an appropriate message limit, or
- a deterministic counter that is persisted transactionally and never rolls back.

The uniqueness scope is the encryption key, not a process, queue, checkpoint, generation, or deployment.

### 13.2 Rotate the key when migration state is uncertain

If a migration cannot prove the previous nonce high-water mark, it must rotate the encryption key before issuing any new nonce. Restarting a counter under the old key is unsafe even if the application labels the records as a new generation.

### 13.3 Make migration atomic

Encrypted records, key generation, and nonce allocator state should move in one atomic operation. Crash recovery and rollback tests must prove that the system cannot restore old key material with an earlier counter value.

### 13.4 Bind all security-relevant metadata into canonical AAD

Include and canonically encode fields such as:

```text
archive ID | journal version | epoch | key generation | queue sequence | command type
```

The receiver should reject stale generations, unexpected metadata, and repeated `(key_id, nonce)` pairs before command execution.

AAD does not make nonce reuse safe, but good AAD prevents records from being transplanted into a different context.

### 13.5 Separate cryptographic purposes

Transport wrapping and journal authentication should use distinct keys derived with a standard KDF such as HKDF and explicit context labels. Avoid ambiguous concatenation schemes unless every field has a fixed or length-prefixed encoding.

### 13.6 Do not use unauthenticated transport encryption

The outer object used AES-CTR plus compression. CTR provides no integrity by itself. A standard AEAD construction should authenticate the transport header, payload, continuation length, and version before decompression.

### 13.7 Minimize plaintext shadow logs

The separate activity log made exact known-plaintext recovery easy. Operational logging may be necessary, but sensitive command details should be minimized, access-controlled, and covered by retention policy.

Removing the plaintext log would not repair GCM nonce reuse—the tag algebraic failure would remain—but it would eliminate one immediate source of the keystream.

### 13.8 Test the invariant, not just the happy path

Automated tests should model:

- normal restart;
- interrupted checkpoint migration;
- partial restore;
- database rollback;
- concurrent writers;
- counter exhaustion;
- replay of an old journal;
- key rotation and generation changes.

For every test, assert that no `(key identifier, nonce)` pair appears twice.

## 14. How AI was used

AI was used as an analysis and coding assistant, not as a substitute for evidence or validator proof.

### Productive uses

The AI assistant helped with:

- rapidly inventorying the acquisition and proposing testable hypotheses;
- writing a small dependency-free PCAP parser and timing-channel extractor;
- comparing sensor flow counts and identifying the 16,796-packet outlier;
- implementing the documented key derivation and trying byte/ordering interpretations;
- recognizing and testing the AES-CTR-to-zlib layering;
- scanning all journal records for duplicate nonces;
- translating GCM's GHASH equations into reproducible `GF(2^128)` code;
- adding assertions that checked exact command widths and reproduced both source tags;
- using Playwright within the existing authenticated session to call the authorized acquisition and validation endpoints;
- organizing hashes, intermediate values, failed hypotheses, and successful outputs into this write-up.

### How AI output was controlled

Every important AI-generated hypothesis was checked against acquired bytes or the live validator:

- Artifact hashes anchored the files being discussed.
- Strict zlib inflation determined whether the extra 20 bytes were actually a checksum or continuation.
- `C1 XOR C2 == P1 XOR P2` checked the known-plaintext reconstruction.
- Both original GCM tags were recomputed before generating the forged tag.
- The original journal records were accepted by the live validator before the forged record was attempted.
- The first plausible but incorrectly delimited command was rejected; the evidence, not AI confidence, decided which interpretation was correct.
- Only the final `"ok":true` response was treated as proof of authentication and flag recovery.

No server source code, deployment key, or hidden secret was available to the AI. The result came from participant-visible challenge material, the acquired evidence, public build information, and authorized endpoints.

For transparency, one official 30-minute hint was deliberately approved and redeemed, applying a 10% score deduction. Its guidance was to compare authenticated journal records with the retained plaintext acquisition. The event's IRIS assistant was also asked limited, generic questions about the wrapping/AAD direction; it did not provide the archive credential, GCM subkey, forged tuple, or flag. No additional paid hints were used after the decision to continue independently.

The most valuable role of AI here was acceleration: it made it cheap to test many precise interpretations. The decisive work remained reproducible cryptographic verification. The assistant's first delimiter assumption was wrong, and the validator rejected it; the final solution succeeded only after the exact 48-byte ABI was reconstructed and both confidentiality and authentication were proven.

## 15. Final evidence table

| Item | Value |
|---|---|
| Archive ID | `7ac51adc827f` |
| Archive credential | `a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e` |
| Transport wrap key | `a018019148d17832c2965bb14c49a239` |
| Transport IV | `c99b1ebfe105dcc54901aeb3ec6b87a6` |
| Journal AAD | `HX-1977|journal|7ac51adc827f` |
| Colliding sequences | `7` and `14` |
| Reused nonce | `18a36dba1453cb10180bc217` |
| Recovered GCM `H` | `518ad05ada2c651572c5817c23a5d2f8` |
| Release proof | `a7bcdb38d64c8b780d31fab5` |
| Forged ciphertext | `1b944dd2b1309d9598ea8bb1be7972055ce673a951e8631f53cfef01b0f02656ff90f8278db07f42b79bb6f464d56398` |
| Forged tag | `38ac1db1c473c0c8792867714c3da7f9` |
| Validator result | `ok: true` |
| Protected note | `flag{cipher_1c06b6f19064bf9d}` |

## Conclusion

The journal's encryption algorithm was not the problem; its state management was. An interrupted migration preserved ciphertext records while losing the uniqueness guarantee required by AES-GCM. The retained plaintext activity log then made the reused counter stream immediately recoverable, and the two colliding tags exposed the GHASH authentication subkey.

The solution was therefore more than “decrypting a record.” It reconstructed a hidden transport from packet timing, preserved and verified the acquisition, unwrapped the journal, demonstrated the deployed nonce collision, forged both ciphertext **and** tag, and required the real validator to authenticate the result.

The released recovery note was:

```text
flag{cipher_1c06b6f19064bf9d}
```
