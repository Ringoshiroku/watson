# src/watson/capa_scan.py
from __future__ import annotations

import contextlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


class CapaScanError(Exception):
    """Raised when capa fails to analyze a file."""


_MAX_EVIDENCE_PER_RULE = 5
_MAX_ADDRESSES_PER_FEATURE = 5


@contextlib.contextmanager
def _resolve_signatures_dir(signatures_dir: Optional[Path]):
    if signatures_dir is not None:
        yield signatures_dir
        return
    with tempfile.TemporaryDirectory() as tmp:
        yield tmp


def _feature_leaves(node) -> list:
    if not isinstance(node, dict) or not node.get("success"):
        return []

    node_info = node.get("node")
    if isinstance(node_info, dict) and node_info.get("type") == "feature":
        feature = node_info.get("feature")
        if not isinstance(feature, dict):
            return []
        ftype = feature.get("type")
        if ftype is None:
            return []
        addresses = [
            loc["value"]
            for loc in node.get("locations") or []
            if isinstance(loc, dict) and "value" in loc
        ]
        return [{"feature": ftype, "value": feature.get(ftype), "addresses": addresses}]

    children = node.get("children")
    if not isinstance(children, list):
        return []
    leaves = []
    for child in children:
        leaves.extend(_feature_leaves(child))
    return leaves


def _extract_evidence(matches: list) -> list:
    evidence = []
    for match in matches:
        if not isinstance(match, (list, tuple)) or len(match) != 2:
            continue
        tree = match[1]
        if not isinstance(tree, dict):
            continue
        for leaf in _feature_leaves(tree):
            total = len(leaf["addresses"])
            leaf["addresses"] = leaf["addresses"][:_MAX_ADDRESSES_PER_FEATURE]
            leaf["more_addresses"] = max(0, total - len(leaf["addresses"]))
            evidence.append(leaf)
            if len(evidence) >= _MAX_EVIDENCE_PER_RULE:
                return evidence
    return evidence


def scan_file(
    file_path: Path,
    rules_dir: Path,
    capa_binary: str = "capa",
    signatures_dir: Optional[Path] = None,
    timeout: int = 120,
) -> list:
    with _resolve_signatures_dir(signatures_dir) as sigs_dir:
        try:
            result = subprocess.run(
                [capa_binary, "-j", "-r", str(rules_dir), "-s", str(sigs_dir), str(file_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise CapaScanError(f"capa timed out after {timeout}s") from exc

    if result.returncode != 0:
        raise CapaScanError(result.stderr.strip() or f"capa exited with code {result.returncode}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CapaScanError(f"capa produced invalid JSON: {exc}") from exc

    return [
        {
            "rule": name,
            "namespace": entry["meta"].get("namespace"),
            "attack": entry["meta"].get("attack", []),
            "mbc": entry["meta"].get("mbc", []),
            "evidence": _extract_evidence(entry.get("matches") or []),
        }
        for name, entry in data.get("rules", {}).items()
    ]
