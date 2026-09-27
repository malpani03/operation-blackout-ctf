# Operation Blackout CTF

This repository contains the completed Operation Blackout challenge material, grouped by the category shown on the case board. Each challenge keeps its write-up beside its acquired evidence, derived analysis, and helper scripts.

## Challenge index

| Stage | Track | Challenge | Category | Material |
| --- | --- | --- | --- | --- |
| S0 | Main chain | Recon | OSINT | [Open challenge](challenges/osint/recon/) |
| S1 | Main chain | The Portal | Web | [Open challenge](challenges/web/the-portal/) |
| S2 | Main chain | The Insider | Web | [Open challenge](challenges/web/the-insider/) |
| S3A | Blue path | The Evidence | Forensics | [Open challenge](challenges/forensics/the-evidence/) |
| S4A | Blue path | The Cipher | Cryptography | [Open challenge](challenges/cryptography/the-cipher/) |
| S3B | Red path | The Tunnel | Network | [Open challenge](challenges/network/the-tunnel/) |
| S4B | Red path | The Implant | Reversing | [Open challenge](challenges/reversing/the-implant/) |
| S5 | Finale | Nightjar's Nest | Pwn | [Open challenge](challenges/pwn/nightjars-nest/) |
| EP | Finale | Epilogue | Detection Engineering | [Open challenge](challenges/detection-engineering/epilogue/) |

## Progression

```text
Recon -> The Portal -> The Insider
                            |-- Blue: The Evidence -> The Cipher --|
                            |                                      |-> Nightjar's Nest -> Epilogue
                            |-- Red:  The Tunnel   -> The Implant -|
```

## Folder convention

```text
challenges/<category>/<challenge>/
|-- writeup.md     # Complete solution and findings
|-- assets/        # Supplied or directly acquired challenge evidence
|-- analysis/      # Recovered, decoded, or generated investigation output
`-- scripts/       # Acquisition, analysis, exploit, and submission helpers
```

Some challenges do not need every subfolder, so empty sections are omitted. Run relative-path scripts from their challenge directory, for example:

```powershell
Set-Location challenges/forensics/the-evidence
python scripts/triage_evidence.py
```

Reusable utilities and event-wide references live in [shared](shared/). Hidden browser profiles and `.tools` are local workspace state retained at the repository root because the acquisition helpers depend on them.
