# Terminal Echo — Cursor-Control Emulation

## Challenge summary

**Track:** Independent Arcade  
**Category:** Terminal emulation  
**Points:** 150  
**Result:** Solved and accepted  
**Answer:** `AEYIOAKN`  
**Flag:** `flag{printq_0201cfbd05f9c743}`

## Evidence and approach

The artifact defined an initially blank eight-column line and only three operations:

- `ESC[nG` moves the cursor to one-based column `n`;
- backspace moves left without erasing;
- printable characters overwrite the current cell and advance the cursor.

Each segment first wrote a lowercase decoy, moved left with backspace and overwrote it with an uppercase character. For example:

```text
ESC[1G a BACKSPACE A  -> column 1 contains A
ESC[2G m BACKSPACE E  -> column 2 contains E
```

Applying all eight segments produced:

```text
column: 1 2 3 4 5 6 7 8
value:  A E Y I O A K N
```

The final visible line was `AEYIOAKN`. The lower-case stream was not an answer because every character was overwritten.

## Reproduction and proof

```powershell
python scripts/solve.py
```

Expected output:

```text
answer=AEYIOAKN
```

Artifact SHA-256: `7ea7d3e34111f5dcf20021001d941095be1876cec79000f614d78863d7a94a3d`.

Verifier response:

```json
{"ok":true,"flag":"flag{printq_0201cfbd05f9c743}"}
```

## Tools and AI disclosure

Codex helped implement the narrow terminal state machine and made unsupported escape sequences fail explicitly. The resulting eight cells were also checked manually. Playwright/CDP retrieved the transcript and verified the final uppercase text.

## Required submission summary

### Root cause

This was a terminal-emulation puzzle. The central interpretation error was treating backspace as erasure or reading the printable stream without applying cursor movement and overwrite semantics.

### Reproducible PoC

Run `python scripts/solve.py`. It emulates only the documented `ESC[nG`, backspace and printable-character behavior and prints `answer=AEYIOAKN`. The official verifier accepted that visible final line.

### Fix / mitigation

No vulnerable service requires a fix. Terminal parsers should use an explicit state machine, enforce cursor bounds, define backspace semantics, reject unsupported escape sequences and test final screen state rather than raw input text.

### AI usage

Codex implemented and reviewed the state machine. Playwright/CDP retrieved the artifact and verified the result. A manual eight-column trace independently matched the solver.
