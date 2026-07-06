# watson

Offline-first static (and, later, dynamic) malware triage tool. Analyzes a
PE file and produces an IOC dossier, capability findings, and a plain text
or JSON report, without reverse engineering or detonating the sample by
default.

## Install

Requires Python 3.10 or later.

```
pip install -e ".[dev]"
```

This installs the package, the `watson` console script, and the test
dependencies (including `yara-python`, since the test suite exercises real
YARA matching rather than skipping it).

## Usage

```
watson analyze <file> [--out DIR] [--rules-dir DIR] [--capa-rules-dir DIR]
```

- `<file>`, the PE file to analyze.
- `--out DIR`, directory to write the case JSON to (default `cases`).
- `--rules-dir DIR`, a directory of `.yar` YARA rule files to scan the
  sample with. Watson does not ship a ruleset; supply your own. Omit this
  flag to skip YARA scanning entirely (reported as unavailable, not an
  error).
- `--capa-rules-dir DIR`, a directory of capa's own YAML rule files, and
  the `capa` CLI must be on `PATH` (`pip install flare-capa`). Watson does
  not ship a capa ruleset or the FLIRT signatures capa's default backend
  wants; without signatures, capa still runs, just without
  library-function identification. Omit this flag to skip capa entirely.

Each run prints a report to stdout and writes `<out>/<sha256>.json`.

## Current scope and limitations

Built so far: hashing (md5/sha1/sha256/imphash), PE metadata (sections,
imports, timestamp, digital signature presence), YARA scanning, and capa
capability analysis, all wired through `watson analyze`.

Not yet built: FLOSS and Detect It Easy orchestration, malware
classification and risk scoring, batch/directory mode, dynamic analysis,
and static/dynamic correlation. See `docs/superpowers/specs/` for the full
phased plan (not checked into this repo; ask if you need a copy).
