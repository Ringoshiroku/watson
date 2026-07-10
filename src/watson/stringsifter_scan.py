from __future__ import annotations

import json
import subprocess
from pathlib import Path


class StringSifterError(Exception):
    """Raised when StringSifter fails to rank a list of strings."""


def _prepare_input(strings: list) -> tuple:
    source_by_text = {}
    rankable_texts = []
    for entry in strings:
        text = entry["string"]
        source_by_text[text] = entry["source"]
        if "\n" in text or "\r" in text:
            continue
        rankable_texts.append(text)
    return "\n".join(rankable_texts), source_by_text


def _parse_ranked_output(stdout: str, source_by_text: dict) -> list:
    ranked = []
    for line in stdout.splitlines():
        if not line:
            continue
        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        score_text, text = parts
        try:
            score = float(score_text)
        except ValueError:
            continue
        ranked.append({"string": text, "source": source_by_text.get(text, "unknown"), "score": score})
    ranked.sort(key=lambda entry: entry["score"], reverse=True)
    return ranked


def rank_strings(strings: list, binary: str = "rank_strings", timeout: int = 60) -> list:
    stdin_text, source_by_text = _prepare_input(strings)
    if not stdin_text:
        return []

    try:
        result = subprocess.run(
            [binary, "--scores"],
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise StringSifterError(f"rank_strings timed out after {timeout}s") from exc
    except OSError as exc:
        raise StringSifterError(f"failed to run rank_strings: {exc}") from exc

    if result.returncode != 0:
        raise StringSifterError(
            result.stderr.strip() or f"rank_strings exited with code {result.returncode}"
        )

    return _parse_ranked_output(result.stdout, source_by_text)


def save_ranked_strings(ranked: list, out_dir: Path, base_name: str) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{base_name}_ranked_strings.json"
    out_path.write_text(json.dumps(ranked, indent=2))
    return out_path
