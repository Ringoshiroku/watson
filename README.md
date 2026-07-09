# watson

Offline-first static (and, later, dynamic) malware triage tool for a PE
file. Produces hashes, PE metadata (with a packed-likely flag), YARA
matches, capa capability/ATT&CK/MBC findings, and FLOSS string/IOC
extraction, as a plain text report and a JSON case file, without reverse
engineering or detonating the sample.

## Install

Requires Python 3.10 or later.

```
pip install -e ".[dev]"
```

This installs watson itself, the `watson` console script, `pytest`, and
`yara-python` (needed for YARA scanning).

capa and FLOSS are separate CLIs, not Python dependencies, watson shells
out to whichever of them is on `PATH`.

## Quick start

```
watson analyze <file>
```

That's it, no setup required first. Each optional capability (YARA rules,
capa rules/signatures, FLOSS) is checked at run time, and if something's
missing, watson asks you right there whether to fetch or install it:

```
YARA rules not found locally. fetch it now with 'git clone https://github.com/Yara-Rules/rules'? [y/N]
```

Say yes and watson fetches it (a `git clone` for rule sets, a `pip
install` for the capa/FLOSS CLIs) into a cache under `~/.watson/rules/`
and continues. Say no and watson tells you what you'll be missing for
this run and keeps going with everything else. Once fetched, later runs
reuse the cache silently, no repeat prompts.

Non-interactive runs (scripts, CI, piped input) never prompt: anything
not explicitly supplied via a flag is just reported unavailable, same as
today.

## Usage

```
watson analyze <file> [--out DIR] [--rules-dir DIR] [--capa-rules-dir DIR] [--capa-sigs-dir DIR] [--floss]
```

- `<file>`, the PE file to analyze.
- `--out DIR`, directory to write output to (default `cases`). Always
  writes `<out>/<sha256>.json` (the full case); also writes
  `<out>/<sha256>_floss.json` (FLOSS's complete, unfiltered string dump,
  easily thousands of entries) when FLOSS runs.
- `--rules-dir DIR`, use this exact YARA rule directory instead of the
  interactive fetch/cache flow (recurses into subdirectories, matches
  both `.yar` and `.yara`). Explicit path, no prompt either way.
- `--capa-rules-dir DIR`, same, for capa's rule set.
- `--capa-sigs-dir DIR`, same, for capa's FLIRT signatures (identifies
  statically-linked library functions; capa still works without them,
  just with weaker library-function ID). Skipped by default unless you
  opt in, since it's a full extra clone for one subdirectory.
- `--floss`, run FLOSS and flag IOC-like matches (IP addresses, URLs,
  Windows registry keys, Windows paths, email addresses) in the report;
  only the flagged subset appears in the report and case JSON, the full
  dump goes to the sidecar file above. Omit to be asked interactively
  (or skipped, non-interactively).

Any of these flags skips that capability's prompt entirely and uses (or
requires) exactly the path you gave.

Each run prints a text report to stdout. The JSON case file has
everything the text report has.

## Current scope and limitations

Built so far: hashing (md5/sha1/sha256/imphash), PE metadata (sections,
imports, timestamp, digital signature presence, packed-likely heuristic),
YARA scanning, capa capability/ATT&CK/MBC analysis, and FLOSS string
extraction with IOC-pattern flagging, all wired through `watson analyze`,
with interactive setup for every optional rule set or tool.

Known limitations in what's built so far:
- Digital signature check is presence-only, not validity, signer, or
  trust chain.

Not yet built: Detect It Easy orchestration, malware classification and
risk scoring, batch/directory mode, dynamic analysis, and static/dynamic
correlation. See the project's internal design docs for the full phased
plan (not checked into this repo; ask if you need a copy).
