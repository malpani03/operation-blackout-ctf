# The Evidence - Gateway Acquisition

## Challenge summary

**Category:** Forensics  
**Path:** Blue, S3A  
**Points:** 350 base / 385 awarded (first blood)  
**Result:** Solved and accepted by the case board  
**Final flag:** `flag{evidence_23c52b9d18c24656}`

The export was made by `reception-17`, which held the `10.27.4.18` DHCP lease, under task `db06efd5a7549b9e`. The workstation's archive-export record was displayed as `2026-09-27 14:14:28`, but its clock was 137 seconds fast and the UI used UTC+05:30. The corrected export time is therefore `2026-09-27T08:42:11Z`.

Two independently acquired historian lanes reconstructed the exact 177-byte document. Its SHA-256 is:

```text
4484648495b0dab0b48e533c638cdc5224f5d86d7bedbfbf8fe4cf88283681de
```

The document, host task, corrected time, DHCP lease and network traffic all agree. The live evidence verifier accepted the complete tuple before the returned flag was submitted.

The investigation path was:

```text
Preserve and hash
  -> recover committed workstation state
  -> correct the clock and resolve the current DHCP lease
  -> correlate the PCAP
  -> recover deleted historian profiles
  -> reverse and validate both timing lanes
  -> XOR and decompress the exact document
  -> submit the corroborated evidence tuple
  -> receive and submit the flag
```

## 1. What was the vulnerability?

This is primarily a forensic challenge, so the word **vulnerability** does not mean a conventional SQL injection or buffer overflow. The security failure was a **covert export channel hidden inside apparently normal industrial telemetry**.

The collector did not place the document in a plain database column or obvious network payload. Instead, it encoded four-bit symbols in the **relative ordering of tiny gateway timestamp differences**. Groups of four sample-to-sample delays were deliberately arranged into permutations. To an operator, the sensor values still looked ordinary; to someone holding the correct profile, each ordering represented a hexadecimal symbol.

The export was made harder to recognize in three additional ways:

1. The compressed document was split into two 233-byte shares. A single share was meaningless; XORing both was required.
2. Each lane used a different transform, interleave pattern, scrambler and Hamming code.
3. The configuration migration deleted the active profiles before acquisition, apparently removing the information needed to decode the timing channel.

The anti-forensic cleanup was incomplete. `historian.db` recorded `secure_delete=OFF`, so deleting the profile rows removed SQLite's references to them but did not overwrite their bytes. Valid `R9CF` profile records, including their CRC-16 values, remained recoverable from unallocated database content. The supplied calibration captures then identified which recovered profiles actually belonged to the two live lanes.

In short, the central issue was:

> A recovery document crossed the boundary through a profile-controlled timing channel disguised as normal historian telemetry, while incomplete SQLite deletion left enough configuration residue to reconstruct it.

There were also attribution traps rather than vulnerabilities: clocks used different references, an IP address had been reassigned since the previous day, approved maintenance overlapped the incident, and the historian contained stale runtime-event timestamps. Treating any one artifact as authoritative would likely produce the wrong answer.

## 2. Beginner-friendly concepts

### 2.1 Why hash every artifact?

A cryptographic hash such as SHA-256 is a fingerprint of a file's exact bytes. Changing even one byte changes the fingerprint. Hashes let a reviewer confirm that analysis used the collected evidence and that reconstructed outputs did not silently change.

The bundle manifest supplied expected hashes. I calculated new hashes independently and compared them with the manifest before interpreting the evidence. I also hashed intermediate lane shares, the XOR result and the final document. This creates a chain from acquisition to answer.

### 2.2 What are a SQLite database and WAL?

SQLite can store recent committed changes in a **write-ahead log**, or WAL, beside its main database. The WAL is not an unrelated log file: SQLite expects a precise naming relationship. For `reception.db`, the companion must be named `reception.db-wal`.

Opening only `RECOV.DB` would omit recent committed events. Reading arbitrary strings from `RECOV.WAL` could include misleading or incomplete material. Restoring the two files under the expected names allowed SQLite itself to apply valid committed frames.

### 2.3 Why did the clocks need correction?

There were two separate effects:

- **Time-zone offset:** the workstation displayed local time at UTC+05:30.
- **Clock skew:** its clock was 137 seconds ahead of the reference clock.

Subtracting only the time zone would still leave a timestamp more than two minutes late. The known reference measurement made the skew measurable instead of guessed.

### 2.4 What does DHCP prove?

DHCP lease records map a hostname to an IP address during a specific interval. An IP address is not a permanent machine identity. Here, `10.27.4.44` belonged to `reception-17` the previous day but to `ops-22` during the incident. The relevant same-day lease mapped `reception-17` to `10.27.4.18`.

### 2.5 What is a PCAP?

A PCAP is a packet capture: a timestamped record of network frames. It can show which source transmitted at a particular time even when the payload is encoded. In this case, DNS labels contained seven-byte hexadecimal chunks from both `.18` and `.44`. Host leases and the change log were needed to decide which stream was suspicious and which was approved.

### 2.6 What is a historian and a timing channel?

An industrial historian stores measurements such as temperature, flow and their timestamps. A timing channel hides information in **when** events happen rather than in their visible values.

Imagine four delays sorted from shortest to longest. There are 24 possible orderings of four distinct values. The collector used a seeded table of orderings, selecting sixteen of them to represent hexadecimal symbols `0` through `f`. The exact nanosecond values could vary; their rank order carried the symbol.

### 2.7 Why use Hamming codes, CRCs, XOR and XZ?

- A **Hamming code** adds redundancy so individual bit errors can be detected and corrected.
- A **CRC** is an integrity check over a decoded lane. Matching the stored CRC is strong evidence that the whole lane was recovered correctly.
- **XOR secret sharing** makes either lane useless by itself. For equal-length byte strings, `share0 XOR share1` recovers the combined data.
- **XZ** is a compression format. Its magic bytes are `fd 37 7a 58 5a 00`. Successful decompression provides another structural validation.

These layers explain why a readable fragment was not enough. The defensible result required valid profiles, exact sync, error correction, two matching lane CRCs, successful XZ decompression and a final document hash.

## 3. Final evidence tuple

```json
{
  "source": "10.27.4.18",
  "task": "db06efd5a7549b9e",
  "exported_utc": "2026-09-27T08:42:11Z",
  "document_sha256": "4484648495b0dab0b48e533c638cdc5224f5d86d7bedbfbf8fe4cf88283681de"
}
```

The recovered document is exactly 177 bytes, with no trailing newline:

```json
{"archive_key":"a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e","task":"db06efd5a7549b9e","template":"operation=read&archive=7ac51adc827f","owner":"reception"}
```

The retained byte-exact copy is [recovered-document.json](analysis/recovered-document.json).

## 4. Acquisition and integrity

The evidence ZIP was downloaded through the participant's authenticated browser session after manual login. Authentication material was not printed or retained in the report.

The sealed ZIP was independently hashed as:

```text
bundle.zip
SHA-256 84bc1b7c9a5da42d58b2479c2933f7843585ef97cbad6312f95a4ee7e3b2a968
Size    674664 bytes
```

Fresh SHA-256 calculations over every primary artifact agreed with `manifest.json`:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `capture.pcap` | 26,394 | `7d3578440aaa46abccb147f7df83478838e669a3f1ff57e824f41522f98d28cc` |
| `workstation.img` | 1,474,560 | `935546cba24c28a079b486cfce2df6525fc728358201b78480e7a9f6ccae7609` |
| `historian.db` | 1,363,968 | `e878485888ebe683d64a1d521029b8dc57dccd2f9115ab33c66c3e322b3785bc` |
| `lane_0.cal` | 40 | `b8bfa4a9dd23e2d9949053a4b8d4d7e924a54293b24b4f843df74a47ca7b9765` |
| `lane_1.cal` | 40 | `028b201f370911179cd2b43cfcadd44878b604979946b9bc02c6fdbb4af7d257` |
| `r9sampler` | 14,464 | `d64430ce45979d6d9b3d6cb60bb81c9b813b5a6930f7bd32049025e727211c18` |
| `r9capture.so` | 14,112 | `0abec7cf086ce350b0a44c3e1088bdbd0f7df3d9ef938db899eb8f9ee887fe72` |
| `collector-abi.txt` | 488 | `be539e5744e752c844f1252257d7536a985b3483857e7101c8ebe05fd6d36959` |

The custody note warned that timestamps were source times and that the archive-export action, rather than process startup, was the value to submit. Originals were only read; reconstruction products were written under `analysis/`.

## 5. Workstation image

The workstation image is a 1.44 MB FAT12 volume. Its live files were extracted without mounting or modifying the source image. Key extraction hashes were:

| File | SHA-256 |
|---|---|
| `RECOV.DB` | `2e8eb1ba4083cd6393624e39749499f0d685beb8dad032b5747ae5c17ad61528` |
| `RECOV.WAL` | `1350f0a6e249460141dbA530D9B5F79B1784E7F62E35F4D062985AF42A6F078C` |
| `CLOCK.TXT` | `5527ba5a7eed8dadccc6c6e6835d72228df3ed33c0283b46ff457e8c19a022b5` |
| `DHCP.CSV` | `673c99087538991e99dd26a51b328ba00146a818d57fd668aec8f99ff53dda85` |
| `CHANGES.CSV` | `8e769cb45f83caa51af041f99f0b4bd2b03557824db63dc110dfd375f08f0263` |

The database and WAL were restored under their original basename, `reception.db` and `reception.db-wal`. Opening that pair caused SQLite to apply only committed WAL state. The four visible records were:

```text
2026-09-26 14:00:00  reception-17  retired-template    archive-export  previous shift
2026-09-27 14:11:10  reception-17  db06efd5a7549b9e  process-start   cache runner, unsigned
2026-09-27 14:14:28  reception-17  db06efd5a7549b9e  archive-export  recovery archive
2026-09-27 14:12:00  ops-22        scheduled-health  archive-export  Helix signed telemetry
```

This separates the target from two misleading records: a previous-shift export and an approved `ops-22` telemetry archive. The task to attribute is the archive-export row for `reception-17`, not its earlier process-start row.

### 5.1 Correcting the workstation clock

`CLOCK.TXT` recorded this measurement:

```text
Reference UTC:       2026-09-27T08:40:00Z
Workstation display: 2026-09-27 14:12:17
UI offset:           +05:30
```

At the reference instant, a correct +05:30 display would have shown `14:10:00`. The workstation was therefore 2 minutes 17 seconds, or 137 seconds, fast.

Applying both corrections to the export row:

```text
2026-09-27 14:14:28 displayed
- 05:30:00 UI offset
= 2026-09-27 08:44:28Z apparent UTC
- 00:02:17 clock lead
= 2026-09-27 08:42:11Z actual UTC
```

### 5.2 Resolving the source address

The lease table records:

```text
2026-09-27T07:00:00Z to 12:00:00Z  reception-17  10.27.4.18
2026-09-26T07:00:00Z to 12:00:00Z  reception-17  10.27.4.44
2026-09-27T07:00:00Z to 12:00:00Z  ops-22        10.27.4.44
```

Thus `.44` was `reception-17` only on the previous day. During the target interval it belonged to `ops-22`; `reception-17` was `.18`.

The change log separately accounts for other overlapping activity:

```text
10.27.4.66  08:35-09:00Z  approved port inventory
ops-22      08:39-08:43Z  approved compressed telemetry archive
```

## 6. Network corroboration

DNS queries used first labels of the form `s` followed by fourteen hexadecimal characters. Removing the `s`, hex-decoding each seven-byte label and concatenating by source produced:

| Source | Packets | Bytes | SHA-256 |
|---|---:|---:|---|
| `10.27.4.18` | 126 | 882 | `cc261494d371b192b77b4a569c243352b813101aede26ed9033716a2061b9b1f` |
| `10.27.4.44` | 64 | 448 | `91bd364fb001a576c39015d4ada5eaf7644b899001ebbb95a047fd913dc262c0` |

The `.18` transport begins at `08:41:02Z`, continues through `08:44:09Z`, and contains a packet at the corrected export second itself:

```text
2026-09-27T08:42:09Z  10.27.4.18:53068  s43aff6bff9c14d
2026-09-27T08:42:11Z  10.27.4.18:53070  s9b25f56f8cecc3
2026-09-27T08:42:12Z  10.27.4.18:53071  sf3ce72b5e50866
```

The concurrent `.44` stream is not contradictory: the same-day lease identifies it as `ops-22`, and `CHANGES.CSV` authorizes that host's compressed telemetry archive in the overlapping window. The port traffic from `.66` is similarly explained by the approved inventory change.

The transport evidence therefore corroborates both the source and the corrected second while the workstation records distinguish the originating task.

## 7. Historian reconstruction

The historian contains ordinary-looking sensor samples and runtime records from more than one time domain. The `runtime_events` export records name two target lanes and generation `24955`:

```text
lane 0  RX.55368F.TEMP
lane 1  RX.20B4AC.FLOW
generation 24955
```

The runtime-event timestamps around `08:34Z` are stale configuration/event-domain values and are not the archive time. The selected lane samples provide gateway timestamps beginning at:

```text
RX.55368F.TEMP  2026-09-27T08:42:11.000000000Z
RX.20B4AC.FLOW  2026-09-27T08:42:11.000910000Z
```

This is an independent acquisition that agrees with the corrected workstation time.

### 7.1 Recovering the active profiles

The migration had purged current profile rows, but SQLite secure deletion was disabled. Searching unallocated database content for the `R9CF` profile signature recovered neighboring generations and the generation-24955 profiles.

Each selected profile was checked against both calibration captures. The lane-0 profile matched all six lane-0 calibration vectors and none of the full lane-1 set. The lane-1 profile matched all six lane-1 vectors. Some neighboring profiles failed calibration, while the generation-24956 lane-0 remnant reused the same permutation and also matched lane-0 calibration. Calibration therefore had to be combined with the runtime event's generation `24955`; neither test was sufficient alone. This prevents choosing a profile merely because it produces readable output.

The recovery was not based on strings alone. Each candidate record supplied its own length and CRC-16. A candidate was accepted only when its complete record was present and its CRC-16 verified. Reverse engineering the profile parser's tag dispatch in `r9capture.so` then mapped the obfuscated TLV tags to twenty internal configuration slots.

The important recovered candidates were:

| Lane | Database offset | Generation field | Decimal generation | Permutation seed | Calibration result |
|---|---:|---:|---:|---:|---|
| 0 | `0x5e42` | `0x617b` | 24955 | `0x260892b8` | lane 0: 6/6, lane 1: 0/6 |
| 1 | `0x148608` | `0x617b` | 24955 | `0x19762afe` | lane 0: 1/6, lane 1: 6/6 |

Generation `0x617a` is 24954 and `0x617c` is 24956. Those neighboring profiles were useful controls: they were structurally valid remnants but did not satisfy both target conditions—generation 24955 and the appropriate lane calibration. This distinction matters because deleted database space contained more than one period.

### 7.2 Reversing the timing channel

Analysis of `r9sampler`, `r9capture.so`, the ABI note and calibration records established the inverse pipeline:

1. Take first differences of consecutive `gateway_time_ns` values.
2. Rank each group of four differences to obtain one rank symbol.
3. Undo the profile-seeded symbol permutation.
4. Reverse each lane's differential stage: modulo-16 subtraction for lane 0 and XOR for lane 1.
5. Locate the profile's exact synchronization sequence.
6. Undo the scrambler and matrix interleave.
7. Decode the Hamming(8,4) / Hamming(7,4) codewords.
8. Parse the lane frame and validate its stored CRC-32.

This was derived rather than guessed. The supplied ABI said that `r9_emit` consumed a profile, asset name, share, prefix bits and rank-group output buffer. Static analysis showed a 24-entry shuffle of the four-element permutations, while the calibration files linked known symbol numbers to expected rank vectors. The synchronization word was stored in profile slot 9 as `0x32e4dcdd2d228531`, producing the expected symbol sequence `c81a444bbbb372c4`.

Several possible carriers were tested: sensor values, device/gateway latency and low timestamp components. The long, exact synchronization sequence appeared only after taking consecutive differences of `gateway_time_ns`, grouping those differences in fours, ranking each group and reversing the lane differential operation. This is how the timing channel was identified.

The selected lane parameters were:

| Lane | Asset | Alignment | Differential inverse | ECC width | Interleave | Scrambler |
|---|---|---:|---|---:|---:|---|
| 0 | `RX.55368F.TEMP` | 3 | `(current - previous) mod 16` | Hamming(8,4) | 2 | asset/profile-seeded xorshift |
| 1 | `RX.20B4AC.FLOW` | 0 | `current XOR previous` | Hamming(7,4) | 1 | profile-seeded LFSR |

The exact synchronization points were symbol 139 for lane 0 and symbol 142 for lane 1. Both packets decoded without ambiguous bytes:

| Lane | Share bytes | Corrected codewords | Stored / calculated CRC-32 | Share SHA-256 |
|---|---:|---:|---|---|
| 0 | 233 | 17 | `8d01014f` / `8d01014f` | `46514354fd071f010dbf691cf62566036b663f7cde031b1bb977c281042a3e81` |
| 1 | 233 | 17 | `dcdf35b0` / `dcdf35b0` | `6ab0e57c12c265cd6f4289251593be38f129597f705aec4f0fe1525ce33737b3` |

Matching CRCs are independent integrity checks on both reconstructed lane packets. The corrected-codeword counts also explain why a visual or fragment-based recovery would be unsafe.

### 7.3 Combining the shares

XORing the two 233-byte shares produced a stream with an XZ header at offset 13. The combined 233-byte buffer hashes to:

```text
03448629aedd43f1ae96cc1a4756adb060741aac2526cd6588cb4d3a9eb3f280
```

The 220-byte XZ stream decompressed cleanly to the 177-byte JSON document. Two separately retained copies hash identically:

```text
recovered-document.bin   4484648495b0dab0b48e533c638cdc5224f5d86d7bedbfbf8fe4cf88283681de
recovered-document.json  4484648495b0dab0b48e533c638cdc5224f5d86d7bedbfbf8fe4cf88283681de
```

The embedded task `db06efd5a7549b9e` matches the workstation's archive-export task, and the embedded owner `reception` agrees with the attributed machine and DHCP lease.

### 7.4 Independent corroboration matrix

No conclusion rests on only one source:

| Claim | Workstation evidence | Historian/document evidence | Transport evidence |
|---|---|---|---|
| Source machine | `reception-17` owns the task; same-day DHCP maps it to `.18` | Document owner is `reception` | `.18` transmits across the corrected export time |
| Task | Committed archive-export row names `db06efd5a7549b9e` | Exact recovered JSON contains the same task | Traffic is tied to the attributed source and time window |
| UTC time | Local archive-export time corrected by UTC+05:30 and 137-second lead | Both target lanes begin at `08:42:11Z` gateway time | `.18` has a DNS packet at exactly `08:42:11Z` |
| Document integrity | Host task and owner agree with its contents | Two CRC-valid shares, XOR, valid XZ and final SHA-256 | Network activity confirms the boundary crossing rather than a historian-only fragment |

This matrix is why the result is stronger than finding readable JSON. A fragment could be stale or planted; the exact document is linked to a committed task, current lease, independent gateway clock and live transport.

## 8. Verification and case-board acceptance

Using the retained Insider receipt, one request was submitted to the documented `/evidence/verify` endpoint:

```json
{
  "handover": "7f742f77f5d76059453a4b3e0b99e37628258eba8216d17a125da4676cc4544a",
  "source": "10.27.4.18",
  "task": "db06efd5a7549b9e",
  "exported_utc": "2026-09-27T08:42:11Z",
  "document_sha256": "4484648495b0dab0b48e533c638cdc5224f5d86d7bedbfbf8fe4cf88283681de"
}
```

The verifier returned HTTP 200:

```json
{"ok":true,"flag":"flag{evidence_23c52b9d18c24656}","notice":"Submit this flag on the case board. Your case handover becomes available there after solve or skip."}
```

The confirmed flag was submitted once. The board changed from 13/19 to 14/19, marked **The Evidence** solved, awarded 385 points with first blood, and unlocked **The Cipher**.

The next-stage handover was recovered and retained as [evidence-case-handover.json](analysis/evidence-case-handover.json):

```json
{
  "case": "evidence",
  "receipt": "be3f63da3765d3a093a77e6027271589cc5cc760d4d3ff657f440bed3a6177b9",
  "revision": 5,
  "archive_key": "a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e"
}
```

## 9. Reproducing the result

The analysis is reproducible from the retained acquisition with these scripts:

| Script | Purpose |
|---|---|
| `triage_evidence.py` | Initial container, FAT, SQLite and PCAP triage |
| `extract_fat_files.py` | FAT12 extraction with file hashes |
| `inspect_reception_db.py` | Committed SQLite/WAL event inspection |
| `extract_dns_streams.py` | DNS label extraction, stream hashing and time correlation |
| `analyze_historian.py` | Historian schema, events and timestamp domains |
| `inspect_elf.py` / `disassemble_range.py` | Collector executable and module analysis |
| `decode_r9_profiles.py` | Recovery and calibration checking of `R9CF` profiles |
| `recover_rank_symbols.py` / `locate_r9_frames.py` | Timing-rank and sync analysis |
| `recover_r9_lanes.py` | Complete lane inversion, ECC, CRC, XOR and XZ reconstruction |

### 9.1 Reproduction procedure

The following commands are PowerShell commands run from the investigation directory. They do not modify the sealed originals.

First, verify the container and primary files:

```powershell
Get-FileHash -Algorithm SHA256 bundle.zip
Get-FileHash -Algorithm SHA256 `
  assets\evidence-acquisition\capture.pcap, `
  assets\evidence-acquisition\workstation.img, `
  assets\evidence-acquisition\historian.db, `
  assets\evidence-acquisition\lane_0.cal, `
  assets\evidence-acquisition\lane_1.cal, `
  assets\evidence-acquisition\r9sampler, `
  assets\evidence-acquisition\r9capture.so, `
  assets\evidence-acquisition\collector-abi.txt
```

Perform broad triage and extract the FAT12 files:

```powershell
python triage_evidence.py
python extract_fat_files.py
```

Restore the SQLite/WAL basename relationship in a separate analysis directory:

```powershell
New-Item -ItemType Directory -Force analysis\reception-db
Copy-Item analysis\fat-live\RECOV.DB analysis\reception-db\reception.db
Copy-Item analysis\fat-live\RECOV.WAL analysis\reception-db\reception.db-wal
python inspect_reception_db.py
```

Extract and time-correlate the DNS streams:

```powershell
python extract_dns_streams.py
```

Inspect the historian, reverse the profile format and locate both frames:

```powershell
python analyze_historian.py
python inspect_elf.py
python decode_r9_profiles.py
python recover_rank_symbols.py
python locate_r9_frames.py
```

Finally, decode both lanes and reconstruct the document:

```powershell
python recover_r9_lanes.py
Get-FileHash -Algorithm SHA256 analysis\recovered-document.json
```

The final decoder now performs the complete chain in one run: it extracts rank symbols from the historian timestamps, reverses both lane pipelines, validates both CRC-32 values, XORs the shares, locates the XZ stream, decompresses it and writes the exact document. Its expected final output includes:

```text
LANE 0 stored_crc32=8d01014f calculated_crc32=8d01014f
LANE 1 stored_crc32=dcdf35b0 calculated_crc32=dcdf35b0
combined_size=233
xz_offset=13
document_size=177
document_sha256=4484648495b0dab0b48e533c638cdc5224f5d86d7bedbfbf8fe4cf88283681de
```

The authenticated verification request can be reproduced with `node submit_evidence.js` after manual login and after confirming that the retained Insider handover is correct. It should not be used as a substitute for the local integrity checks because the challenge deliberately returns one generic failure for wrong evidence.

## 10. How AI was used

AI was used as an investigation and scripting assistant, not as a source of evidence and not to guess the flag.

### 10.1 Acquisition and evidence handling

The participant completed the site login manually. AI then used the authenticated browser session to read the evidence contract and download the designated bundle. The session cookie was used in memory and was not printed into the write-up.

AI generated small parsers for the FAT12 image, classic PCAP records, DNS labels and SQLite tables. It also added SHA-256 calculations at acquisition and reconstruction boundaries. These scripts made each transformation repeatable and reduced the chance of transcription errors.

### 10.2 Hypothesis generation and correlation

AI helped organize the investigation into four questions:

1. Which workstation event was the export?
2. What was the workstation's true UTC time?
3. Which current IP lease belonged to that workstation?
4. How did the historian encode the exact document?

It highlighted several hypotheses worth testing: that the WAL contained the decisive committed row, that IP reuse explained `.44`, that historian event time and sample time belonged to different clock domains, and that information might be carried by timestamp ranks rather than sensor values.

These were only hypotheses until checked against acquired records. The final conclusions came from SQLite's committed view, the measured clock pair, DHCP intervals, PCAP timestamps, calibration matches, exact synchronization, CRCs and decompression.

### 10.3 Reverse-engineering assistance

AI helped inspect the ELF files, trace the profile tag dispatch, translate the rank-permutation logic into Python and build inverse functions for the differential, scrambler, interleave and Hamming stages. It was especially useful for testing multiple alignments and transformations consistently rather than trying them manually.

The reverse-engineering result was validated independently at every layer:

- recovered profiles had valid CRC-16 values;
- the chosen profiles matched their calibration data;
- the profile sync sequence matched exactly;
- both frames had the expected header;
- Hamming decoding produced no ambiguous bytes;
- both stored CRC-32 values matched recomputation;
- the XOR output contained a valid XZ stream;
- decompression produced a complete JSON object;
- the embedded task and owner matched host evidence; and
- the server accepted the full evidence tuple.

### 10.4 Controlled submission and human verification

AI did not search for a flag string in the acquisition because the custody page explicitly said the artifacts contained no scoring flag. Only after all local checks agreed did it submit one evidence tuple to `/evidence/verify`. The server returned the flag, which was then submitted once on the case board.

Human judgment remained important. An AI can notice a suspicious timestamp or produce plausible JSON even when the selected record is wrong. The participant can audit every important conclusion here using the retained artifacts, scripts, hashes and server response. This separation between AI-assisted analysis and evidence-backed proof is essential for a credible prize write-up.

## 11. False leads, impact and defensive lessons

### 11.1 False leads that had to be rejected

- **The process-start record:** it belonged to the right task but was not the requested archive-export action.
- **The `08:34Z` runtime events:** these described stale configuration activity, not the gateway sample time of the export.
- **`10.27.4.44`:** it belonged to `reception-17` on the previous day, but the same-day lease assigned it to the approved `ops-22` task.
- **`10.27.4.66`:** its port activity was covered by an approved inventory window.
- **Sensor values:** they looked ordinary because the payload was carried by timestamp-delta ordering.
- **One lane or a readable fragment:** neither was enough; the challenge required two CRC-valid shares and the hash of the complete document.
- **Any structurally valid profile:** unallocated space contained neighboring generations, so calibration and generation `24955` were necessary selectors.

### 11.2 Security impact

The technique can bypass monitoring that inspects only measurement values or looks for recognizable file signatures in a single stream. The attacker can leak a document while the telemetry stays within a plausible numerical range. Splitting the export across two differently encoded lanes further weakens simple content inspection.

The clock and identity ambiguity also increases response time. Without DHCP history and clock correction, investigators could accuse the approved ops host or report a timestamp outside the true export second.

### 11.3 Recommended mitigations

1. Allow only signed, approved collector modules and verify their hashes at load time.
2. Monitor timestamp-delta rank distributions, not only sensor values; repeated constrained permutations can reveal a timing channel.
3. Correlate historian exports with immutable task, asset, module and network-flow audit records.
4. Keep hosts synchronized to an authenticated time source and record clock offset measurements centrally.
5. Retain DHCP/IPAM history so IP reuse cannot erase machine attribution.
6. Store sensitive profile material in a protected configuration store rather than ordinary SQLite pages.
7. When deletion is a security requirement, enable secure deletion and perform a verified purge or database rebuild; deleting rows alone is not sanitization.
8. Alert when a supposedly routine telemetry job emits DNS traffic inconsistent with its normal destination and cadence.

### 11.4 Main lessons

The strongest lesson is to correlate independent evidence instead of selecting the first plausible timestamp, IP or readable fragment. In this case, host state identified the task, the clock pair corrected its time, DHCP established current ownership, the PCAP showed transport at the corrected second, and two independently validated historian lanes reconstructed the exact document. Only their agreement justified requesting the flag.

## 12. Final answer

```text
Source:       10.27.4.18
Task:         db06efd5a7549b9e
Exported UTC: 2026-09-27T08:42:11Z
Document:     4484648495b0dab0b48e533c638cdc5224f5d86d7bedbfbf8fe4cf88283681de
Flag:         flag{evidence_23c52b9d18c24656}
```

## Required submission summary

### Root cause

A profile-controlled covert channel encoded a recovery document in historian timestamp-rank permutations. Incomplete deletion with SQLite `secure_delete=OFF` left valid profiles recoverable, while clock skew and IP reuse complicated attribution.

### Reproducible PoC

Run the scripts listed in section 9 from triage through `recover_r9_lanes.py`. Both stored lane CRC-32 values must match, XOR must expose an XZ stream, and decompression must produce the 177-byte document with SHA-256 `4484648495b0...288361de`. The complete evidence tuple was accepted by `/evidence/verify`.

### Fix / mitigation

Allow only signed collector modules, detect constrained timing-rank patterns, correlate immutable task/network audit data, synchronize clocks, retain DHCP history, protect configuration profiles, use verified secure deletion and monitor abnormal DNS telemetry.

### AI usage

Codex assisted with container, PCAP, SQLite and timing-channel parsers plus ELF-derived inverse transforms. Browser automation acquired the authorized bundle and submitted one verified tuple. Calibration, sync, ECC, CRC, XZ structure, document hash and server acceptance independently validated the output.
