from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# Dots are replaced so a filename like "rb.exe" can't turn into
# "rb.exe.json" (reads like a double extension); the rest of the set is
# the standard Windows-reserved filename characters, replaced defensively
# since the name ultimately comes from a scanned sample's own filename.
_UNSAFE_FILENAME_CHARS = re.compile(r'[.\\/:*?"<>|]')


def _sanitize_filename_component(name: str) -> str:
    return _UNSAFE_FILENAME_CHARS.sub("-", name)


@dataclass
class Identity:
    sha256: str
    sha1: str
    md5: str
    imphash: Optional[str]
    file_name: str


@dataclass
class PEMetadata:
    machine: str
    compile_timestamp: Optional[str]
    sections: list
    imports: dict
    has_digital_signature: bool
    machine_name: str = ""
    likely_packed: bool = False


@dataclass
class ELFMetadata:
    machine: str
    machine_name: str
    entry_point: str
    interpreter: Optional[str]
    is_pie: bool
    is_stripped: bool
    sections: list
    needed_libraries: list
    dynamic_symbols: list
    likely_packed: bool = False
    has_digital_signature: bool = False


@dataclass
class UnpackingResult:
    tool: str
    success: bool
    reason: Optional[str] = None
    output_path: Optional[str] = None
    unpacked_sha256: Optional[str] = None


@dataclass
class SignatureVerification:
    tool: str
    status: str
    verification_result: str
    signer_subject: Optional[str] = None
    signer_issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    error: Optional[str] = None


@dataclass
class PyInstallerExtractionResult:
    tool: str
    success: bool
    reason: Optional[str] = None
    output_dir: Optional[str] = None
    entries: list = field(default_factory=list)


@dataclass
class PyArmorUnpackResult:
    tool: str
    success: bool
    reason: Optional[str] = None
    output_dir: Optional[str] = None
    entries: list = field(default_factory=list)


@dataclass
class StaticSection:
    pe_metadata: Optional[PEMetadata] = None
    elf_metadata: Optional[ELFMetadata] = None
    yara_matches: list = field(default_factory=list)
    tools: dict = field(default_factory=dict)
    capabilities: list = field(default_factory=list)
    interesting_strings: list = field(default_factory=list)
    classification: Optional[dict] = None
    die_detections: list = field(default_factory=list)
    ranked_strings: list = field(default_factory=list)
    unpacking: Optional[UnpackingResult] = None
    go_build_info: dict = field(default_factory=dict)
    pyinstaller_extraction: Optional[PyInstallerExtractionResult] = None
    pyarmor_unpacking: Optional[PyArmorUnpackResult] = None
    signature_verification: Optional[SignatureVerification] = None


@dataclass
class Case:
    identity: Identity
    static: StaticSection

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        identity = Identity(**data["identity"])
        static_data = data["static"]
        pe_metadata_data = static_data.get("pe_metadata")
        pe_metadata = PEMetadata(**pe_metadata_data) if pe_metadata_data else None
        elf_metadata_data = static_data.get("elf_metadata")
        elf_metadata = ELFMetadata(**elf_metadata_data) if elf_metadata_data else None
        unpacking_data = static_data.get("unpacking")
        unpacking = UnpackingResult(**unpacking_data) if unpacking_data else None
        pyinstaller_extraction_data = static_data.get("pyinstaller_extraction")
        pyinstaller_extraction = (
            PyInstallerExtractionResult(**pyinstaller_extraction_data) if pyinstaller_extraction_data else None
        )
        pyarmor_unpacking_data = static_data.get("pyarmor_unpacking")
        pyarmor_unpacking = PyArmorUnpackResult(**pyarmor_unpacking_data) if pyarmor_unpacking_data else None
        signature_verification_data = static_data.get("signature_verification")
        signature_verification = (
            SignatureVerification(**signature_verification_data) if signature_verification_data else None
        )
        static = StaticSection(
            pe_metadata=pe_metadata,
            elf_metadata=elf_metadata,
            yara_matches=static_data.get("yara_matches", []),
            tools=static_data.get("tools", {}),
            capabilities=static_data.get("capabilities", []),
            interesting_strings=static_data.get("interesting_strings", []),
            classification=static_data.get("classification"),
            die_detections=static_data.get("die_detections", []),
            ranked_strings=static_data.get("ranked_strings", []),
            unpacking=unpacking,
            go_build_info=static_data.get("go_build_info", {}),
            pyinstaller_extraction=pyinstaller_extraction,
            pyarmor_unpacking=pyarmor_unpacking,
            signature_verification=signature_verification,
        )
        return cls(identity=identity, static=static)

    def output_basename(self, now: Optional[datetime] = None, flags: str = "") -> str:
        now = now or datetime.now()
        timestamp = now.strftime("%H-%M-%S-%d-%m-%Y")
        safe_name = _sanitize_filename_component(self.identity.file_name)
        suffix = f"-{flags}" if flags else ""
        return f"{timestamp}-{safe_name}-{self.identity.md5}{suffix}"

    def save(
        self,
        directory: Path,
        now: Optional[datetime] = None,
        data: Optional[dict] = None,
        text_report: Optional[str] = None,
        flags: str = "",
    ) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        basename = self.output_basename(now, flags)
        out_path = directory / f"{basename}.json"
        payload = data if data is not None else self.to_dict()
        out_path.write_text(json.dumps(payload, indent=2))
        if text_report is not None:
            (directory / f"{basename}.txt").write_text(text_report)
        return out_path

    @classmethod
    def load(cls, path: Path) -> "Case":
        data = json.loads(Path(path).read_text())
        return cls.from_dict(data)
