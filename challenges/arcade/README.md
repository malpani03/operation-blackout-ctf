# Independent Arcade

The Independent Arcade was a set of ten standalone puzzles that could be opened in any order. All ten were solved and accepted under callsign `rupesh`.

| Slug | Challenge | Category | Points | Answer | Write-up |
|---|---|---|---:|---|---|
| `welcome` | Route Zero | Graph search | 25 | `49` | [Open](route-zero/writeup.md) |
| `badge` | Pixel Ledger | Nonogram | 75 | `1110100011110001` | [Open](pixel-ledger/writeup.md) |
| `rota` | Deadline Lab | Scheduling | 75 | `CBAEFD` | [Open](deadline-lab/writeup.md) |
| `helpdesk` | Double Entry | Accounting | 100 | `30186` | [Open](double-entry/writeup.md) |
| `voicemail` | Beacon Six | Signal analysis | 150 | `609637` | [Open](beacon-six/writeup.md) |
| `printq` | Terminal Echo | Terminal emulation | 150 | `AEYIOAKN` | [Open](terminal-echo/writeup.md) |
| `vending` | Custodian Records | Secret sharing | 200 | `140` | [Open](custodian-records/writeup.md) |
| `legacy` | Switchboard | Boolean logic | 200 | `01110011` | [Open](switchboard/writeup.md) |
| `entropy` | Device Messages | RSA | 300 | `760422` | [Open](device-messages/writeup.md) |
| `iris` | Afterlife | Cellular automata | 200 | `011000001000101011001111110000000000` | [Open](afterlife/writeup.md) |

The artifacts in each challenge directory are exact copies of the authorized puzzle downloads. `verify_arcade_answers.js` rechecks all derived answers through the authenticated browser session on CDP port 9222; it does not submit flags to the case board.
