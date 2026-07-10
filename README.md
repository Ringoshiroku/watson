# watson

Offline-first static (and, later, dynamic) malware triage tool for a PE
file. Produces hashes, PE metadata (with a packed-likely flag), YARA
matches, capa capability/ATT&CK/MBC findings, FLOSS string/IOC
extraction, and a heuristic type/risk classification, as a plain text
report and a JSON case file, without reverse engineering or detonating
the sample.

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

That's it, no setup required first. Watson asks which analyses to run:

```
which analyses do you want to run?
  y  YARA rule scanning (needs a rule set, fetched if missing)
  c  capa capability / ATT&CK / MBC detection (needs capa + a rule set)
  f  FLOSS string extraction and IOC flagging
  d  Detect It Easy packer/compiler/linker detection (needs diec installed)
  a  all of the above
  n  none
type the letters you want (e.g. "yc"), or leave blank for none:
```

Pick what you want, and if the underlying rule set isn't on disk yet, it
asks again, per capability, whether to fetch it:

```
YARA rules not found locally. fetch it now with 'git clone https://github.com/Yara-Rules/rules'? [y/N]
```

Say yes and watson fetches it (a `git clone` for rule sets, a `pip
install` for the capa/FLOSS CLIs), streaming the real fetch/install
output as it happens, into a cache under `~/.watson/rules/` and
continues. Say no and watson tells you what you'll be missing for this
run and keeps going with everything else. Once fetched, later runs reuse
the cache silently, no repeat prompts. If `--out` isn't given either,
you're asked once whether to use a custom output directory instead of
the `cases` default.

Non-interactive runs (scripts, CI, piped input) never prompt: anything
not explicitly supplied via a flag is just reported unavailable, same as
today.

## Usage

```
watson analyze <file> [-o DIR] [-y DIR] [-c DIR] [-s DIR] [-f] [-d] [-v]
```

Every flag has a short and a long form, so once you know what you want
you never have to go through a prompt again:

- `<file>`, the PE file to analyze.
- `-o DIR`, `--out DIR`, directory to write output to (default `cases`,
  asked interactively if omitted). Always writes
  `<out>/<timestamp>-<name>-<md5>.json` (the full case); also writes
  `<out>/<timestamp>-<name>-<md5>_floss.json` (FLOSS's complete,
  unfiltered string dump, easily thousands of entries) when FLOSS runs.
  `<timestamp>` is `hh-mm-ss-DD-MM-YYYY` at the moment the run finished,
  `<name>` is the scanned file's own name with dots swapped for dashes
  (so `rb.exe` becomes `rb-exe`, never a `rb.exe.json`-style double
  extension), `<md5>` is the sample's MD5. Named this way instead of by
  hash alone so the filename itself tells you what it is. Also always
  writes `<out>/<timestamp>-<name>-<md5>.txt`, the same readable report
  printed to stdout, saved to disk so you don't have to open the JSON to
  read it back later.
- `-y DIR`, `--rules-dir DIR`, use this exact YARA rule directory instead
  of the interactive fetch/cache flow (recurses into subdirectories,
  matches both `.yar` and `.yara`, and skips over any individual rule
  file that fails to compile instead of losing the whole ruleset).
  Explicit path, no prompt either way.
- `-c DIR`, `--capa-rules-dir DIR`, same, for capa's rule set.
- `-s DIR`, `--capa-sigs-dir DIR`, same, for capa's FLIRT signatures
  (identifies statically-linked library functions; capa still works
  without them, just with weaker library-function ID).
- `-f`, `--floss`, run FLOSS and flag IOC-like matches (IP addresses,
  URLs, Windows registry keys, Windows paths, email addresses) in the
  report; only the flagged subset appears in the report and case JSON,
  the full dump goes to the sidecar file above. Omit to be asked
  interactively (or skipped, non-interactively).
- `-d`, `--diec`, run Detect It Easy for file type, compiler, linker, and
  packer/protector detection. Unlike YARA/capa/FLOSS, `diec` isn't
  pip-installable, install it with your OS package manager (`sudo apt
  install detect-it-easy` on Debian/Kali/Ubuntu, `choco install die` on
  Windows) or from https://github.com/horsicq/Detect-It-Easy. Omit to be
  asked interactively.
- `-v`, `--verbose`, show full YARA match detail (string identifier, hex
  offset, matched bytes) and capa match evidence (the specific feature,
  e.g. an API call, and the address it matched at) in the text report.
  Omitted by default so the report stays skimmable, this detail is always
  present in the case JSON regardless of this flag.

Passing any of `-y`/`-c`/`-s`/`-f` skips the analysis-selection prompt
entirely for the ones you specified and uses (or requires) exactly the
path you gave; the rest still get asked about normally unless you supply
those too.

Each run prints a text report to stdout. The JSON case file has
everything the text report has.

### IOC flagging (`-f`/`--floss`)

FLOSS extracts every string in a binary, easily thousands, so watson only
promotes a filtered subset (IP addresses, URLs, registry keys, Windows
paths, emails) into the report and case JSON; the complete raw dump
always goes to the sidecar file for when you need it. The filter is
regex-plus-validation, not a classifier, so treat it as a starting point:
version numbers that happen to look like a dotted-quad IP (`1.0.0.0`) are
a known, structurally-unavoidable false positive, and a handful of
well-known X.509/ASN.1 OID arcs are explicitly excluded since they'd
otherwise dominate the "ip" category in any binary that touches
certificates or crypto.

### Report layout

Each run prints scan progress as it happens (`running YARA scan... 3s`,
then `done: YARA scan (3.2s)`), so a long-running capa or FLOSS pass on a
real sample doesn't look hung. Progress goes to stderr, not stdout, so
redirecting output (`watson analyze sample.exe > report.txt`) captures
only the report.

The text report and case JSON both lead with a Summary section (counts
and highlights: matched YARA rule names, ATT&CK tactics touched, flagged
string reasons) ahead of the full per-tool detail. Capa capabilities are
grouped by ATT&CK tactic instead of listed flat, so you can scan tactics
first and drill into the rule that produced each one; capabilities with
no ATT&CK mapping land in an `Ungrouped` bucket at the end rather than
being dropped. Flagged strings are grouped by reason (ip, url,
registry_key, windows_path, email) the same way.

Report layout takes structural inspiration from capa's own tactic-grouped
terminal renderer (https://github.com/mandiant/capa), PEStudio's
indicator-first summaries (https://pestudiodownload.com/), and
CAPE/Cuckoo's summary-before-detail sandbox reports
(https://capev2.readthedocs.io/en/latest/usage/results.html). No text or
code from any of them is copied, only the general shape.

### Classification

Every run produces a coarse classification: a type label (`ransomware`,
`worm`, `infostealer`, `backdoor`, `downloader`, `adware`, `trojan`, or
`unclassified`), a risk tier (`low`/`medium`/`high`), a Defender-style
detection name (e.g. `Ransomware:Win64/CryptoImpact.capa`), and a
plain-language reasoning list that names the exact YARA or capa rule
that fired, plus a pointer to the Capabilities/YARA Matches sections
below for the full evidence. It's computed entirely from the YARA/capa
signals already collected, no extra tool, setup, or flag needed. It
leads the text report, and it's present in the saved case JSON alongside
every other finding.

The detection name isn't a new algorithm, it's a compact label built
from the same verdict and evidence already computed: verdict, a `Win32`/
`Win64` platform tag derived from the PE's machine type, a short token
for which specific signal fired (e.g. `CryptoImpact`, `LateralMovement`),
and which tool(s) contributed (`capa`, `yara`, or `capa+yara`).

This is a heuristic type category, not malware family attribution (it
won't tell you "Emotet", only "downloader") and not a numeric risk score.
`unclassified` means no capability evidence was collected (YARA and/or
capa weren't run, or ran and found nothing), it's a statement about
missing evidence, not a claim that the sample is safe.

### Detect It Easy (`-d`/`--diec`)

DIE gives a named signature-based read on the binary (file type,
compiler, linker, and any detected packer/protector), complementing the
entropy-only `Likely Packed` heuristic in PE Metadata with an actual
name and version when one's found. It's report-only in this version,
findings don't yet feed the Classification section's verdict or risk
tier, that's a natural follow-up once real-world DIE output has been
observed.

## Current scope and limitations

Built so far: hashing (md5/sha1/sha256/imphash), PE metadata (sections,
imports, timestamp, digital signature presence, packed-likely heuristic),
YARA scanning, capa capability/ATT&CK/MBC analysis, FLOSS string
extraction with IOC-pattern flagging, a heuristic type/risk
classification, and Detect It Easy file type/compiler/packer detection,
all wired through `watson analyze`, with interactive setup for every
optional rule set or tool.

Known limitations in what's built so far:
- Digital signature check is presence-only, not validity, signer, or
  trust chain.
- IOC flagging is regex-based; see "IOC flagging" above for its known
  false-positive shape.

Not yet built: batch/directory mode, dynamic analysis, and
static/dynamic correlation. See the project's internal design docs for
the full phased plan (not checked into this repo; ask if you need a
copy).
