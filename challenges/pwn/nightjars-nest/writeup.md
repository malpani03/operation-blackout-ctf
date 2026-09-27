# Nightjar's Nest — Document Spool Worker

## Result

**Category:** Pwn  
**Stage:** S5 / Finale  
**Points:** 600  
**Result:** Solved and accepted by the case board  
**Flag:** `flag{nest_83cacdb429a88413}`

The worker has a use-after-free in its queued-delivery lifetime handling. A queued job stores a raw pointer to a revision object without owning a reference. The document's pin check uses a mutable revision ID. `undo` changes that ID, after which `compact` no longer recognizes the queued revision as pinned and frees it. The still-live job can then be turned into an arbitrary read/write primitive through the documented `render` and `patch` compatibility operations.

No remote filesystem access, shell command, or code execution was used. The exploit uses only the documented spool protocol.

---

## Acquired evidence

The recovered executable was saved as `handler`.

```text
Size:    14,360 bytes
SHA-256: c670dc665e81e251965af8623083cc89fa812cc0c8083fd85506a777793d2030
Format:  ELF64, amd64, little endian, position-independent (ET_DYN), stripped
```

The public command contract defines four-byte request headers:

```text
u8  operation
u8  document_id
u16 argument       little endian
```

`create`, `replace`, `patch`, and `receipt` are followed by bytes. `render`, `preview`, and `status` return a two-byte little-endian length followed by data. Other operations return newline-terminated text.

The authenticated service used TLS on `65.21.179.193:9305`, with certificate verification for `ctf.roshancodes.com`. A completed Cipher branch receipt was accepted as the handover.

---

## Reconstructed in-process layout

Static analysis of the main dispatcher reconstructs these relevant structures:

```c
struct Revision {
    void    *data;       // +0x00
    uint64_t length;     // +0x08
    uint64_t revision;   // +0x10
};

struct RevisionSlot {
    Revision *object;    // +0x00
    uint32_t  id;        // +0x08
    uint32_t  refs;      // +0x0c
};

struct Document {
    RevisionSlot *current;       // +0x00
    RevisionSlot *saved;         // +0x08
    uint32_t      pinned_id;     // +0x10
    uint32_t      queued_jobs;   // +0x14
};

struct QueueJob {
    Revision *revision;          // +0x00
    Document *owner;             // +0x08
    uint32_t  revision_id;       // +0x10
    uint32_t  byte_count;        // +0x14
};
```

There are 12 documents and 24 queue jobs, matching the interface limits. The queue base is at image-relative address `0x40e0`, the revision-slot table at `0x4320`, and the document table at `0x4920`.

Important dispatcher observations:

- `queue` at `0x1af5–0x1b30` copies the raw `Revision *`, owner document, slot ID, and length into a 24-byte job. It increments `Document.queued_jobs`, but does not increment `RevisionSlot.refs`.
- `render` at `0x1c33–0x1c60` reads `job->byte_count` bytes from `job->revision->data`.
- `patch` at `0x1bd4–0x1c18` reads `job->byte_count` bytes from the connection and copies them to `job->revision->data`.
- `undo` at `0x1a46–0x1a95` swaps current and saved revisions, allocates a new sequence number, and writes that number into the old current slot's mutable `id` field.
- `compact` at `0x1b4e–0x1ba8` protects the saved revision only when `document->pinned_id == saved->id`. On inequality it decrements the slot reference and may free the revision.

This is a lifetime bug, not a bounds-check bypass. Each individual patch remains the queued byte count; the problem is that the queue can refer to an object whose lifetime has ended.

---

## Triggering the use-after-free

The following legal command sequence creates the stale queue job:

```text
create  doc 0, 32 bytes       -> current R0
save    doc 0                 -> current R0, saved R0
replace doc 0, 32 bytes       -> current R1, saved R0
queue   doc 0, job 0          -> job 0 points to R1; pinned_id = R1.id
undo    doc 0                 -> current R0, saved R1; R1.id is changed
compact doc 0                 -> pinned_id != R1.id, so R1 is freed
```

The queue record for job 0 is not cleared, so it still points to the freed `Revision` object.

The worker's allocator rounds allocations to 32-byte boundaries. A free block begins with:

```c
struct FreeBlock {
    FreeBlock *next;
    void      *arena_owner;
    uint64_t   size;
};
```

After `compact`, the freed 32-byte R1 data buffer, freed 32-byte R1 revision object, and following free extent coalesce. The dangling revision object's first word points back to the coalesced free block. Rendering job 0 therefore returns its 32-byte header.

A live leak was:

```text
0000000000000000 80fae9e6b2590000 c0ff000000000000 4242424242424242
```

The word at offset `+0x08` is the address of the arena global, whose image-relative offset is `0x4a80`. Subtracting `0x4a80` yields the PIE load base. The exploit checks that the result is page-aligned.

---

## Turning the stale job into read/write primitives

A new 64-byte document allocation consumes the coalesced free region. The old dangling revision address falls exactly 32 bytes into this controlled buffer.

The controlled bytes are arranged as:

```text
offset 0x00: 32 bytes of filler
offset 0x20: forged Revision.data pointer
offset 0x28: 24 bytes of filler
```

Job 0 still has a queued byte count of 32. Therefore:

- `render(job 0)` reads 32 bytes from the forged pointer; and
- `patch(job 0)` writes 32 bytes to the forged pointer.

The new 64-byte document is also queued as job 1. `patch(job 1)` legitimately rewrites the full controlled buffer, so it can repeatedly change the forged pointer at offset `0x20`.

The relevant image-relative globals are:

```text
0x4a50  completed-delivery state
0x4a58  randomized required-delivery state
0x4a60  successful receipt count
0x4a90  pointer to the 32-byte acquisition credential
```

The exploit proceeds as follows:

1. Point the fake revision at `base + 0x4a50` and render 32 bytes.
2. Copy the randomized value from offset `+0x08` over the completed-state value at offset `+0x00`, preserving the neighboring globals, then patch job 0.
3. Use job 1 to point the fake revision at `base + 0x4a90`; render the heap pointer to the credential buffer.
4. Use job 1 again to point the fake revision at that heap address; render the 32-byte credential.
5. Send operation 9 with argument 32 and the recovered credential.

Operation 9 verifies both conditions visible in the executable:

```text
memcmp(supplied_credential, acquisition_credential, 32) == 0
completed_delivery_state == required_delivery_state
```

When both are true, it emits the protected response.

---

## Live recovery evidence

One successful run produced these session-specific values:

```text
PIE base: 0x60b322fd5000
delivery state: current=0x0 required=0x7bd965ee7643401f receipts=0
credential buffer: 0x60b3330042b0
credential: dfa36d5dea71c59d7c89e7eb8e17b6850088bb893ee94f1aec40ef4a55e61d46
flag{nest_83cacdb429a88413}
```

ASLR addresses, the randomized delivery value, and the credential change for each fresh worker. The exploit derives all of them from the current process and does not rely on the example values.

Reproduction:

```powershell
python solve_nest.py
```

The case-board API accepted the recovered flag:

```json
{"correct":true,"points":600,"first_blood":false}
```

---

## Root cause and remediation

The invariant should be that every queued job holds a strong reference to the exact immutable revision it will render or patch. Instead, the implementation separates lifetime from queue ownership and validates the pin through a mutable identifier.

The direct fixes are:

1. Increment the revision-slot reference count when a job is queued and decrement it only when that job is cancelled or completed.
2. Store or compare stable object identity, not a mutable revision ID, when enforcing pins.
3. Do not mutate the identity of an already queued revision during `undo`.
4. Clear or invalidate every queue record before freeing its referenced revision.
5. Prefer opaque handles with generation counters over raw pointers in compatibility records.

## Required submission summary

### Root cause

A queue job stored a raw `Revision *` without taking a strong reference. `undo` changed the revision's mutable ID, so `compact` no longer recognized the queued revision as pinned and freed it while the job still referenced it. Controlled reallocation converted the dangling object into arbitrary 32-byte read/write primitives.

### Reproducible PoC

Run `python scripts/solve_nest.py`. The solver creates, saves, replaces, queues, undoes and compacts a revision; leaks the allocator pointer to derive the PIE base; overlaps a fake revision; copies the required delivery state; reads the session credential; and submits the documented receipt operation. The service returned the flag and the board accepted it for 600 points.

### Fix / mitigation

Increment a stable revision reference when queueing and release it only on completion/cancellation; never use mutable IDs for lifetime pins; invalidate queued records before free; and replace raw pointers with checked opaque handles plus generation counters.

### AI usage

Codex assisted with stripped-binary disassembly, C-structure reconstruction, allocator-layout reasoning, protocol implementation and exploit assertions. The exploit used only documented spool operations. Fresh ASLR/state values, service output and independent case-board acceptance verified the result.
