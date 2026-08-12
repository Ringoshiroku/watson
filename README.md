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
git clone https://github.com/Ringoshiroku/watson.git
cd watson
./install.sh
```

This creates a `.venv` virtual environment, installs watson and its
dev dependencies into it, and runs `watson setup` to check/install the
optional analysis tools (yara-python, capa, FLOSS, DIE, StringSifter).
Safe to re-run.

`install.sh` prefers an already pyenv-installed 3.11, then 3.10,
looked up directly by path (not the `python3.11`/`python3.10` shims,
which only dispatch correctly when that version is pyenv's active
one), then `python3.11`/`python3.10`/`python3` on `PATH`, in that
order, for the venv. This matters because StringSifter's pinned
`numpy` build has no wheel past Python 3.11 and fails to build from
source on newer versions (a 3.12+ change broke the old
setuptools/`pkg_resources` shim it relies on). If none of those are
found and only a newer Python is on `PATH`, and `pyenv` is installed,
`install.sh` offers to `pyenv install` 3.11 for you (`[y/N]` prompt,
skipped in non-interactive shells); otherwise it warns and points at
installing Python 3.11 yourself, giving the exact `pyenv install 3.11`
command if `pyenv` is already there, or the official `curl -fsSL
https://pyenv.run | bash` installer command first if it isn't, then
re-running `install.sh`, which will pick it up automatically. On Kali,
`python3.11` isn't packaged in apt (rolling release, current Python
only); see
https://www.kali.org/docs/general-use/using-eol-python-versions/ for
installing `pyenv` itself and its build dependencies first.

`install.sh` also recreates `.venv` whenever the selected Python
version doesn't match the one `.venv` was already built with (e.g.
after installing 3.11 via pyenv on a rerun), rather than silently
reusing a stale venv built under the wrong interpreter.

Before running `pyenv install`, `install.sh` also checks (on
Debian/Kali/Ubuntu, via `dpkg`) for the build headers a full Python
build needs (`libssl-dev`, `zlib1g-dev`, `libbz2-dev`,
`libreadline-dev`, `libsqlite3-dev`, `libffi-dev`, `liblzma-dev`,
`tk-dev`, `build-essential`), and warns with the exact `apt install`
command if any are missing. Without them, `python-build` doesn't fail,
it silently skips that module (e.g. `bz2`, breaking FLOSS's `networkx`
import) and still exits successfully, so the gap otherwise only
surfaces later as an obscure `ModuleNotFoundError` from an unrelated
tool.

Whichever pyenv-managed Python ends up selected, freshly built above
or already installed from an earlier run, is also checked for
`bz2`/`sqlite3`/`readline`/`lzma` completeness every time `install.sh`
runs, not just right after a build; an already-installed but incomplete
interpreter (e.g. one built before its `-dev` headers were installed)
would otherwise go unnoticed on every later rerun that just reuses it.
This warning names the exact missing modules and the matching
`sudo apt install` command for them, not just a link to read, and
offers (`[y/N]`, skipped in non-interactive shells) to rebuild that
interpreter right there with `pyenv uninstall <version> && pyenv
install <version>`, recreating `.venv` afterward so it picks up the
rebuilt interpreter. Installing the headers alone doesn't fix an
already-compiled interpreter, only a rebuild does; declining just
prints the same commands to run yourself later.

In future shells, activate the virtual environment before running
watson:

```
source .venv/bin/activate
```

When you're done, leave it with:

```
deactivate
```

Prefer to manage the environment yourself, or on native Windows
(`install.sh` needs bash: use WSL or Git Bash, or install manually)?

```
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

This installs watson itself, the `watson` console script, `pytest`, and
`yara-python` (needed for YARA scanning).

capa, FLOSS, and StringSifter's `rank_strings` are separate CLIs, not
Python dependencies, watson shells out to whichever of them is on `PATH`.

## Quick start

One-time (or whenever you want) setup:

```
watson setup
```

Walks through YARA, capa, FLOSS, DIE, and StringSifter, offering to fetch
or install whatever isn't already available (a `git clone` for rule sets,
a `pip install` for the capa/FLOSS/StringSifter CLIs, an official
portable-build download for DIE on Windows), streaming the real
fetch/install output as it happens, into caches under `~/.watson/`. Skip
anything you don't want; `watson analyze` still works, it just reports
that capability as unavailable. Non-interactive runs (scripts, CI, piped
input) just report what's missing without fetching anything.

The Summary's first line is always `python`: a check that this
interpreter has the stdlib modules (`bz2`, `sqlite3`, `readline`,
`lzma`) that capa/FLOSS's own dependencies need. A pyenv-managed
interpreter built without the matching system `-dev` headers still
installs and runs fine, it just silently lacks these, so capa/FLOSS
fail later with an unrelated-looking `ModuleNotFoundError`. This line
surfaces that root cause up front, every time `watson setup` or
`watson analyze` runs (not just right after `install.sh` builds a new
interpreter), instead of it being visible only once, at the top of a
possibly long `install.sh` run, easy to scroll past. It's a single
compact line: `missing stdlib module(s): bz2, readline. fix: sudo apt
install libbz2-dev libreadline-dev && pyenv uninstall <version> &&
pyenv install <version>` (the real pyenv version substituted in when
it can be detected from the interpreter's own path), one command you
can copy and run, rather than several sentences pointing at a doc
page.

Then, for each file (or a whole directory of files, analyzed recursively
one by one):

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

Picking `a` also turns on full match detail (the same detail `-v` shows)
for that run, on the theory that asking for everything usually means you
want to see everything; picking individual letters, or passing explicit
flags, doesn't. If `--out` isn't given either, you're asked once whether
to use a custom output directory instead of the `cases` default.

Non-interactive runs (scripts, CI, piped input) never prompt: anything
not explicitly supplied via a flag is just reported unavailable, same as
today.

## Usage

```
watson setup
watson analyze <file-or-directory> [-o DIR] [-y DIR] [-c DIR] [-s DIR] [-f] [-d] [-r] [-v]
```

`watson setup` takes no flags: it checks every optional tool and offers
to fetch/install whatever's missing, purely interactively.

`watson analyze` never fetches or installs anything itself, only checks
what's already there; run `watson setup` first for anything you want
available. Every flag below has a short and a long form, so once you know
what you want you never have to go through a prompt again:

- `<file-or-directory>`, the PE or ELF file to analyze, or a directory to
  recursively analyze every file inside. For a directory, every prompt
  below (which analyses to run, output directory) is asked once and reused
  for every file in the batch; each file still gets its own JSON case and
  text report, plus one combined `<out>/<timestamp>-batch-summary.txt` for
  the whole run. See "Batch/directory mode" below.
- `-o DIR`, `--out DIR`, directory to write output to (default `cases`,
  asked interactively if omitted). Always writes
  `<out>/<timestamp>-<name>-<md5>-<flags>.json` (the full case); also
  writes `<out>/<timestamp>-<name>-<md5>-<flags>_floss.json` (FLOSS's
  complete, unfiltered string dump, easily thousands of entries) when
  FLOSS runs. `<timestamp>` is `hh-mm-ss-DD-MM-YYYY` at the moment the
  run finished, `<name>` is the scanned file's own name with dots
  swapped for dashes (so `rb.exe` becomes `rb-exe`, never a
  `rb.exe.json`-style double extension), `<md5>` is the sample's MD5,
  `<flags>` is which of `y`/`c`/`f`/`d`/`r`/`u`/`g`/`p` were selected for
  this run (e.g. `yc`, `ycfdr`, omitted entirely along with its leading dash when
  nothing was selected). Named this way instead of by hash alone so the
  filename itself tells you what it is and what was run on it. Also
  always writes `<out>/<timestamp>-<name>-<md5>-<flags>.txt`, the same
  readable report printed to stdout, saved to disk so you don't have to
  open the JSON to read it back later.
- `-y DIR`, `--rules-dir DIR`, use this exact YARA rule directory instead
  of the cache `watson setup` manages (recurses into subdirectories,
  matches both `.yar` and `.yara`, and skips over any individual rule
  file that fails to compile instead of losing the whole ruleset).
  Explicit path, no prompt either way. Some community rules (loose
  regexes with no length/word-boundary constraints, or authoring bugs
  like a trailing empty alternative) can otherwise flood a match with
  useless single-character or zero-length instances, so matches are
  filtered before they reach the report or case JSON: instances shorter
  than 4 characters are dropped, a rule whose own metadata sets
  `hide = true` is skipped entirely, and any one string identifier is
  capped at 20 reported instances (with a "+N more instance(s)
  suppressed" note) so one overly broad rule can't blow up the report.
  The same overly broad rules can also hit libyara's own internal
  per-string match cap mid-scan; its `RuntimeWarning` for that is
  suppressed too, since it's noise from a known-bad rule with no
  actionable count to recover, not a scan failure.
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
  pip-installable; run `watson setup` first to have it fetched
  automatically on Windows (the official portable build, no installer
  needed, cached under `~/.watson/tools/diec/`), or to see manual install
  instructions for other platforms (`sudo apt install detect-it-easy` on
  Debian/Kali/Ubuntu, `choco install die` on Windows, or
  https://github.com/horsicq/Detect-It-Easy). `watson analyze -d` itself
  only checks whether `diec` is already available, it never fetches or
  installs. Omit to be asked interactively.
- `-u`, `--unpack`, if Detect It Easy identifies UPX packing, unpack the
  sample with UPX and automatically re-analyze the unpacked binary as a
  second case (needs `-d`/`--diec` to have run and identified UPX). Unlike
  GoReSym/pyinstxtractor-ng, `watson setup` only auto-fetches `upx` on
  Windows (the official portable build, cached under
  `~/.watson/tools/upx/`); on Linux, install it yourself (`sudo apt install
  upx-ucl` on Debian/Kali/Ubuntu) and it's picked up from PATH. Omit to be
  asked interactively.
- `-g`, `--goresym`, run GoReSym to recover Go build info (module path,
  dependencies with exact versions, and the sample's own function names)
  from Go binaries. Has no effect on non-Go samples. Unlike YARA/capa/FLOSS,
  `GoReSym` isn't pip-installable; run `watson setup` first to have it
  fetched automatically on Linux/Windows (the official portable build, no
  installer needed, cached under `~/.watson/tools/goresym/`); macOS has no
  auto-fetch and falls through to manual install guidance. `watson analyze
  -g` itself only checks whether `GoReSym` is already available, it never
  fetches or installs. Omit to be asked interactively. The complete raw
  recovery data (including Go/runtime-internal symbols this report
  intentionally leaves out) is written to `<out>/<basename>_goresym.json`.
- `-p`, `--extract-pyinstaller`, if Detect It Easy identifies PyInstaller
  framing, extract the sample's bundled contents with `pyinstxtractor-ng`
  and record a manifest (file list, sizes, and which entries look
  PyArmor-protected) in the report; needs `-d`/`--diec` to have run and
  identified PyInstaller. This is a manifest step only, it does not
  recursively re-analyze extracted files. If any extracted entry looks
  PyArmor-protected, watson automatically decrypts and decompiles it
  with `pyarmor-1shot` and records a second manifest ("PyArmor Unpack"
  in the report); this has no flag of its own, it rides entirely on
  `-p` finding protected content. `pyarmor-1shot` needs `pycryptodome`
  (offered for interactive pip install, same as `yara-python`) plus its
  own release bundle; `watson setup` fetches that automatically on
  Linux x86_64, Windows x86_64, and macOS arm64 (cached under
  `~/.watson/tools/pyarmor1shot/`), other platforms fall through to
  manual install guidance. Unlike YARA/capa/FLOSS, `pyinstxtractor-ng`
  isn't pip-installable; run `watson setup` first to have it fetched
  automatically on Linux/Windows (cached under
  `~/.watson/tools/pyinstxtractor/`); macOS has no auto-fetch and falls
  through to manual install guidance. Omit `-p` to be asked
  interactively.
- `-r`, `--rank-strings`, rank FLOSS's extracted strings by relevance
  using StringSifter's real ML model (needs `-f`/`--floss` to have also
  run; without it, reported unavailable with a clear reason). The top 20
  ranked strings appear in the report, the complete ranking goes to
  `<out>/<timestamp>-<name>-<md5>-<flags>_ranked_strings.json`. Omit to be asked
  interactively.
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

### String ranking (`-r`/`--rank-strings`)

StringSifter is Mandiant's real ML-based string relevance ranker (a small
LightGBM model trained on human-labeled interesting/junk strings), run as
an optional extra pass over FLOSS's output rather than a replacement for
the regex-based IOC flagging above: the two catch different things. IOC
flagging only recognizes known shapes (an IP, a URL, a registry key);
StringSifter's ranking surfaces strings that look relevant for a different
reason entirely (a suspicious command line, a mutex name, a ransom note)
without needing to match a fixed pattern. The report shows the top 20
ranked strings (score plus source); the complete ranking of every string
FLOSS extracted is written to
`<out>/<timestamp>-<name>-<md5>-<flags>_ranked_strings.json`. Needs FLOSS to have
also run; picking `-r` without `-f` reports it unavailable with a clear
reason instead of silently doing nothing.

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

An Overview section sits between Classification and Sample in the text
report, and under an `overview` key (a sibling of `summary`) in the case
JSON. It's a high-level grouping of the same matched capa capabilities by
ATT&CK tactic, deterministic and capa-only, no LLM involved.

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

A likely-packed reading always raises the risk tier by one step; once a
sample additionally has a non-`unclassified` verdict, an unsigned reading
(PE only) raises it by one more, and the two stack independently (still
capped at `high`). A signed PE whose signature fails Authenticode
verification (untrusted chain, tampered digest, malformed signature)
raises risk the same one tier an unsigned sample does, they represent
the same thing for risk purposes: the publisher-identity signal for this
sample can't be trusted. Each applied bump is called out in the reasoning list.

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

### Batch/directory mode

Pass a directory instead of a single file and watson recursively analyzes
every file inside it (any depth, sorted for a deterministic order), one at
a time. Files that are neither PE nor ELF are skipped quietly and counted, not treated as an
error. Any capability-selection or output-directory prompt that would
normally show once per file is asked exactly once, up front, and the same
answer is reused for every file in the batch, so a large batch doesn't turn
into a wall of repeated prompts.

Each file still gets the same per-file outputs as single-file mode (its own
JSON case, text report, and FLOSS sidecar when applicable). Instead of
printing the full text report per file, batch mode prints one short line
per file as it runs (`sample.exe: trojan (medium risk)`, or `skipped`/
`failed` with a reason), followed by a summary at the end, also saved to
`<out>/<timestamp>-batch-summary.txt`:

```
Batch summary
-------------
scanned: 50 files
  analyzed: 42
  skipped (not a valid PE or ELF): 6
  failed: 2

Failed:
  corrupt.exe: unexpected error parsing PE headers
  locked.exe: permission denied
```

A file failing unexpectedly (a scan tool crash, a permission error) doesn't
stop the batch, it's recorded as failed and the run continues with the
rest. The run itself exits `0` regardless of how many files were skipped
or failed; only a directory/file path that doesn't exist at all is a
run-level error.

## Current scope and limitations

Built so far: hashing (md5/sha1/sha256/imphash), PE metadata (sections,
imports, timestamp, digital signature presence, packed-likely heuristic),
ELF metadata (sections, needed libraries, dynamic symbols, interpreter,
PIE/stripped flags, packed-likely heuristic), YARA scanning, capa
capability/ATT&CK/MBC analysis, FLOSS string extraction with IOC-pattern
flagging, StringSifter relevance ranking of extracted strings, a
heuristic type/risk classification, Detect It Easy file
type/compiler/packer detection, and PyInstaller extraction with
PyArmor-protection flagging and automatic pyarmor-1shot unpacking
(`-p`), all wired through `watson analyze`
(including batch/directory mode, which now handles a mix of PE and ELF
files in the same run), with `watson setup` handling interactive
fetch/install for every optional rule set or tool.

Known limitations in what's built so far:
- Digital signature validity (signer identity, certificate trust,
  tampered-digest detection) is checked for PE via `signify`, when it's
  installed and the sample has a signature at all; see "Classification"
  below for how a failed verification affects risk. For ELF, this only
  detects the Linux kernel module signing facility's trailer (relevant to
  `.ko` files); regular userspace ELF binaries are essentially never
  signed this way, since distros sign packages, not individual binaries,
  so a `False` reading there is expected, not a gap. Revocation/OCSP
  checking is out of scope, that needs network access and contradicts
  offline-first.
- No imphash equivalent for ELF samples (`Identity.imphash` is always
  `None` for them); the community-standard analog, telfhash, isn't
  implemented yet.
- IOC flagging is regex-based; see "IOC flagging" above for its known
  false-positive shape.

Not yet built: dynamic analysis and static/dynamic correlation. See the
project's internal design docs for the full phased plan (not checked into
this repo; ask if you need a copy).
