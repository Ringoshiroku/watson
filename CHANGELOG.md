# Changelog

All notable changes to watson are documented here, newest first. Versions
follow semantic versioning (MAJOR.MINOR.PATCH): a minor bump adds a new
capability, a patch bump is a fix or docs-only change, and a major bump is
reserved for completing a whole phase (static engine, dynamic engine,
correlation).

## [Unreleased]

### Added
- capa evidence addresses and YARA string match offsets in the text report
  (`-v`/verbose) now resolve to a virtual address ready to paste into
  Ghidra's "Go To Address" (`VA 0x...`), instead of an unlabeled hex
  number that was sometimes a file offset and sometimes already a VA with
  no way to tell which. An address that falls outside any known
  section/segment (e.g. header bytes, overlay data) is shown as an
  unmapped file offset instead of a guessed VA. For a PIE ELF sample, the
  report adds a note that the addresses assume Ghidra imported the file
  with an image base of 0x0, since Ghidra otherwise applies its own,
  version-dependent default base for such binaries.

## [0.10.0] - 2026-08-12

### Added
- Classification signal for a Go binary with stripped build info: when
  GoReSym confirms a Go binary (via `pclntab`) but recovers no module
  path or dependency metadata, the reasoning list now notes this,
  consistent with build info stripped or removed (e.g. by an obfuscator
  such as Gobfuscator). Informational only, doesn't affect the risk tier.

## [0.9.0] - 2026-08-12

### Added
- VERSIONINFO/manifest masquerade detection: a PE's claimed publisher
  (CompanyName), claimed original filename, and manifest
  requestedExecutionLevel are checked against reality. A claimed
  well-known vendor uncorroborated by the Authenticode signer bumps risk
  classification the same one tier an unsigned/invalidly-signed sample
  does; a bare filename mismatch or execution-level claim is report-only.

## [0.8.0] - 2026-08-12

### Added
- Authenticode signature validity verification: a signed PE's signature is
  checked with `signify` (digest, chain, self-signed/expired), not just
  detected as present, and an invalid signature bumps the risk
  classification. Optional; degrades gracefully when `signify` isn't
  installed, offered by `watson setup`.

## [0.7.0] - 2026-08-11

### Added
- Automatic PyArmor unpacking: when `-p`/`--extract-pyinstaller` flags any
  extracted entry as PyArmor-protected, watson decrypts and decompiles it
  with `pyarmor-1shot` and records a manifest in the report. No flag of its
  own; `watson setup` fetches the tool on Linux x86_64, Windows x86_64, and
  macOS arm64.
- A deterministic Overview section: matched capa capabilities grouped by
  ATT&CK tactic, at the top of the text report and under a new `overview`
  key in the case JSON.

### Fixed
- `-u`/`--unpack` selected from the interactive "which analyses do you
  want to run?" prompt was silently discarded, and an explicit
  `--unpack` on the command line didn't skip that prompt either, unlike
  every other capability flag.

### Docs
- Documented the `-u`/`--unpack` flag in the README (it was already
  implemented, just missing its own bullet).

## [0.6.0] - 2026-07-31

### Added
- PyInstaller extraction (`-p`/`--extract-pyinstaller`): when Detect It
  Easy identifies PyInstaller framing, extracts the sample's bundled
  contents with `pyinstxtractor-ng` and records a manifest (file list,
  sizes, PyArmor-protected entries flagged) in the report.

## [0.5.0] - 2026-07-31

### Added
- GoReSym integration (`-g`/`--goresym`): recovers Go build info (module
  path, dependencies with versions, own-package function names) from Go
  binaries and renders it in the report.

## [0.4.0] - 2026-07-30

### Added
- UPX auto-unpack (`-u`/`--unpack`): detects UPX packing via Detect It
  Easy, unpacks with UPX, and automatically re-analyzes the unpacked
  binary as a second case.

### Fixed
- A round of hardening across install.sh (Python version selection,
  pyenv interpreter completeness checks), YARA scanning (noisy/malformed
  match filtering, internal match-cap warning suppression), and IOC
  string flagging (deduping, TLD casing, Go import paths misclassified
  as domains, long ranked-string truncation).

## [0.3.0] - 2026-07-24

### Added
- ELF support: magic-byte format detection and ELF metadata parsing
  (sections, needed libraries, dynamic symbols, interpreter,
  PIE/stripped flags, packed heuristic), dispatched alongside PE.
- Batch/directory analysis mode, recursing into a directory of samples.
- StringSifter relevance ranking of extracted strings
  (`-r`/`--rank-strings`).
- `install.sh` for a one-command local install.
- Packed/unsigned risk tier bump in classification, and an output
  filename suffix reflecting which capability flags were selected.

## [0.2.0] - 2026-07-10

### Added
- Heuristic malware type and risk classification.
- Detect It Easy packer/compiler/linker detection (`-d`/`--diec`).
- Defender-style detection naming, capa match evidence detail (`-v`),
  and the readable text report saved alongside the JSON case file.

## [0.1.0] - 2026-07-09

### Added
- Initial static engine: file hashing, PE metadata extraction, YARA
  rule scanning, capa capability/ATT&CK/MBC detection, FLOSS string
  extraction with IOC-pattern flagging, JSON and text report builders,
  and the `watson analyze` CLI entry point.
