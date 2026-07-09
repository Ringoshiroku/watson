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
class StaticSection:
    pe_metadata: PEMetadata
    yara_matches: list = field(default_factory=list)
    tools: dict = field(default_factory=dict)
    capabilities: list = field(default_factory=list)
    interesting_strings: list = field(default_factory=list)
    classification: Optional[dict] = None


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
        pe_metadata = PEMetadata(**static_data["pe_metadata"])
        static = StaticSection(
            pe_metadata=pe_metadata,
            yara_matches=static_data.get("yara_matches", []),
            tools=static_data.get("tools", {}),
            capabilities=static_data.get("capabilities", []),
            interesting_strings=static_data.get("interesting_strings", []),
            classification=static_data.get("classification"),
        )
        return cls(identity=identity, static=static)

    def output_basename(self, now: Optional[datetime] = None) -> str:
        now = now or datetime.now()
        timestamp = now.strftime("%H-%M-%S-%d-%m-%Y")
        safe_name = _sanitize_filename_component(self.identity.file_name)
        return f"{timestamp}-{safe_name}-{self.identity.md5}"

    def save(self, directory: Path, now: Optional[datetime] = None, data: Optional[dict] = None) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        out_path = directory / f"{self.output_basename(now)}.json"
        payload = data if data is not None else self.to_dict()
        out_path.write_text(json.dumps(payload, indent=2))
        return out_path

    @classmethod
    def load(cls, path: Path) -> "Case":
        data = json.loads(Path(path).read_text())
        return cls.from_dict(data)
