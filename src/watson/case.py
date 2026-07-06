from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


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


@dataclass
class StaticSection:
    pe_metadata: PEMetadata


@dataclass
class Case:
    identity: Identity
    static: StaticSection

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        identity = Identity(**data["identity"])
        pe_metadata = PEMetadata(**data["static"]["pe_metadata"])
        return cls(identity=identity, static=StaticSection(pe_metadata=pe_metadata))

    def save(self, directory: Path) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        out_path = directory / f"{self.identity.sha256}.json"
        out_path.write_text(json.dumps(self.to_dict(), indent=2))
        return out_path

    @classmethod
    def load(cls, path: Path) -> "Case":
        data = json.loads(Path(path).read_text())
        return cls.from_dict(data)
