# watson

Offline-first malware triage tool for a Windows or Linux executable file
(PE/ELF). Runs a safe, static analysis, no reverse-engineering or running
the file (detonating). A sandboxed dynamic mode is planned later. Produces
a plain text report and a JSON case file:

- a unique file fingerprint (hash)
- executable file details (PE/ELF metadata)
- known malicious-pattern matches (YARA)
- capabilities mapped to attacker techniques (capa, ATT&CK/MBC)
- suspicious text flagged from extracted strings (FLOSS, IOCs)
- those strings ranked by relevance (StringSifter)
- a best-guess type and risk level (heuristic classification)

See [Quick start](#quick-start).

## Requirements

- Python 3.10 or later (`install.sh` prefers 3.11).
- bash to run `install.sh` (WSL or Git Bash on Windows, or install
  manually, see [Install](#install)).
- Everything else is optional, fetched by `watson setup`, see
  [Quick start](#quick-start) for the full list.

## Install

```
git clone https://github.com/Ringoshiroku/watson.git
cd watson
./install.sh
```

Creates `.venv`, installs watson and its dev dependencies, and runs
`watson setup`. Safe to re-run.

`install.sh` prefers Python 3.11 (StringSifter's `numpy` build doesn't
support newer versions), offering to install it via pyenv if it's missing
and pyenv is available. It also checks the interpreter has the stdlib
modules (`bz2`, `sqlite3`, `readline`, `lzma`) capa/FLOSS need, and offers
to rebuild it if not.

Activate the environment before running watson:

```
source .venv/bin/activate
```

Leave it with:

```
deactivate
```

Prefer to manage the environment yourself, or on native Windows
(`install.sh` needs bash)?

```
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

Installs:

- watson itself and the `watson` console script
- `pytest`
- `yara-python`
- `signify`

capa, FLOSS, and StringSifter's `rank_strings` are separate CLIs: watson
shells out to whichever is on `PATH`.

## Quick start

```
watson setup
```

Checks every optional tool and offers to fetch/install whatever's
missing, cached under `~/.watson/`:

- YARA
- capa
- FLOSS
- signify
- Detect It Easy
- GoReSym
- pyinstxtractor-ng
- pyarmor-1shot
- StringSifter

Skip anything you don't want, `watson analyze` still runs, it just
reports that capability unavailable. Non-interactive runs only report
what's missing.

`watson setup`'s summary section opens with a `python` check for the stdlib
modules capa/FLOSS need, with the exact fix command if any are missing.

```
watson analyze <file-or-directory>
```

Watson asks which analyses to run:

```
anything not yet installed will be skipped; run 'watson setup' first to install it
which analyses do you want to run?
  y  YARA rule scanning
  c  capa capability / ATT&CK / MBC detection
  f  FLOSS string extraction and IOC flagging
  d  Detect It Easy packer/compiler/linker detection
  r  StringSifter relevance ranking of extracted strings
  a  all of the above
  n  none
type the letters you want (e.g. "yc"), or leave blank for none:
```

`a` also turns on full match detail (same as `-v`). If `--out` isn't
given, you're asked once for an output directory (default `cases`).

Non-interactive runs never prompt: anything not supplied via a flag is
reported unavailable.

## Usage

```
watson setup
watson analyze <file-or-directory> [-o DIR] [-y DIR] [-c DIR] [-s DIR] [-f] [-d] [-u] [-g] [-p] [-r] [-v]
```

`watson setup` takes no flags. `watson analyze` never fetches or installs
anything, only checks what's already there, run `watson setup` first.
Every flag has a short and long form.

| Flag | Required | Default | Purpose |
|---|---|---|---|
| `<file-or-directory>` | yes | | PE or ELF file, or a directory, see [Batch mode](#batch-mode) |
| `-o`, `--out DIR` | no | `cases`, asked if omitted | output directory |
| `-y`, `--rules-dir DIR` | no | tool cache | YARA rule directory |
| `-c`, `--capa-rules-dir DIR` | no | tool cache | capa rule directory |
| `-s`, `--capa-sigs-dir DIR` | no | tool cache | capa library-function signatures (FLIRT) |
| `-f`, `--floss` | no | asked | run FLOSS, flag IOCs, see [IOC flagging](#ioc-flagging) |
| `-d`, `--diec` | no | asked | run Detect It Easy, see [Detect It Easy](#detect-it-easy) |
| `-u`, `--unpack` | needs `-d` found UPX | asked | unpack UPX, re-analyze as a second case |
| `-g`, `--goresym` | no | asked | recover Go build info, no effect on non-Go files |
| `-p`, `--extract-pyinstaller` | needs `-d` found PyInstaller | asked | extract contents, auto-unpack PyArmor entries |
| `-r`, `--rank-strings` | needs `-f` | asked | rank FLOSS strings, see [String ranking](#string-ranking) |
| `-v`, `--verbose` | no | off | full match detail, addresses resolved to a Ghidra-ready virtual address |

Passing `-y`/`-c`/`-s`/`-f` skips the prompt for those. The rest are still
asked.

Each run prints a text report to stdout. The JSON case has everything the
report has, plus full match evidence regardless of `-v`.

### Output files

Every run writes `<out>/<timestamp>-<name>-<md5>-<flags>.json` (full case)
and a matching `.txt` (the printed report). `<name>` is the file's name
with dots swapped for dashes. `<flags>` is which of
`y`/`c`/`f`/`d`/`r`/`u`/`g`/`p` ran. Some flags also write a sidecar:

| Flag | Sidecar |
|---|---|
| `-f`, `--floss` | `..._floss.json`, full unfiltered string dump |
| `-r`, `--rank-strings` | `..._ranked_strings.json`, full ranking |
| `-g`, `--goresym` | `<out>/<basename>_goresym.json`, full raw recovery data |

### IOC flagging

FLOSS extracts every string in a file. `-f` only promotes IP addresses,
URLs, registry keys, Windows paths, and emails into the report, the full
dump goes to the sidecar. Regex-based, not a classifier: expect some false
positives (e.g. version numbers resembling IPs).

### String ranking

StringSifter (Mandiant's ML string relevance ranker) runs via `-r` as an
extra pass over FLOSS's output, surfacing strings IOC flagging would miss
(command lines, mutex names, ransom notes). Needs `-f`. Report shows the
top 20. Full ranking goes to the sidecar.

### Detect It Easy

Signature-based file type, compiler, linker, and packer detection,
complementing the entropy-only "Likely Packed" heuristic in PE Metadata.
Report-only for now, doesn't affect Classification.

### Batch mode

Pass a directory and watson recursively analyzes every PE or ELF file
inside, one at a time. Other files are skipped and counted. Prompts are
asked once and reused for the batch. Each file gets its own outputs. A
short progress line prints per file, plus a summary saved to
`<out>/<timestamp>-batch-summary.txt`. Failures are recorded and don't
stop the batch. The run exits `0` unless the given path doesn't exist.

### Classification

Every run produces:

- a type label: `ransomware`, `worm`, `infostealer`, `backdoor`,
  `downloader`, `adware`, `trojan`, or `unclassified`
- a risk tier: `low`, `medium`, or `high`
- a Defender-style detection name
- a reasoning list naming the rules that fired

Computed from YARA/capa signals already collected.

Risk is bumped by up to two independent signals (each one tier, capped at
`high`):
- Likely packed.
- Untrustworthy publisher identity: unsigned (PE only), a failed
  Authenticode signature, or an unsigned claim of a well-known publisher
  (these three count as one signal).

A filename mismatch, a `requireAdministrator` claim, or stripped Go build
info are reported but don't raise risk on their own.

This is a heuristic category, not malware family attribution or a numeric
score. `unclassified` means no evidence was collected, not that the
file is safe.

### Report layout

Progress prints to stderr, so redirecting stdout captures only the
report. Layout, top to bottom:

1. Summary
2. Overview (capa capabilities grouped by ATT&CK tactic)
3. full per-tool detail, grouped the same way

With `-v`, a PIE ELF file gets a note that addresses assume Ghidra's
image base of `0x0`.

## Current scope and limitations

Built, all through `watson analyze` (including batch mode across PE and
ELF), with `watson setup` handling fetch/install:

- hashing (md5/sha1/sha256/imphash)
- PE/ELF metadata
- YARA scanning
- capa capability/ATT&CK/MBC analysis
- FLOSS extraction with IOC flagging
- StringSifter ranking
- Detect It Easy detection
- PyInstaller/PyArmor extraction
- VERSIONINFO/manifest masquerade detection
- GoReSym Go build info recovery
- heuristic classification

Known limitations:
- Signature validity is checked for PE via `signify` only. For ELF, only
  the Linux kernel module signing trailer is detected. Revocation/OCSP
  checking is out of scope (needs network access).
- Masquerade detection's vendor list is short, not exhaustive:
  - Microsoft
  - Google
  - Adobe
  - Mozilla
  - Apple
  - Oracle
  - Intel
  - NVIDIA
  - VMware
- No imphash equivalent for ELF: telfhash isn't implemented yet.
- IOC flagging is regex-based, see [IOC flagging](#ioc-flagging).

Not yet built: dynamic analysis and static/dynamic correlation.
