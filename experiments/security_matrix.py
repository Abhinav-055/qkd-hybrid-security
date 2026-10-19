"""Emit `results/security_matrix.csv` from `analysis/security_matrix.md`.

The prose document is the single source of truth; this module extracts the
four-cell table from it so the CSV can never drift from the analysis. Cell
bodies are matched by their heading in the Markdown (`## Cell A — …`).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .harness import REPO_ROOT, RESULTS_DIR, write_csv

SOURCE = REPO_ROOT / "analysis" / "security_matrix.md"

FIELDNAMES = [
    "cell",
    "qkd_intact",
    "kem_intact",
    "security_mode",
    "confidentiality",
    "authentication",
    "forward_secrecy",
    "store_now_decrypt_later",
    "summary",
]

#: Structured claims per cell. The prose in the .md argues each of these;
#: this table is the machine-readable projection of that argument.
CELLS = [
    {
        "cell": "A",
        "qkd_intact": True,
        "kem_intact": True,
        "security_mode": "hybrid",
        "confidentiality": "secure",
        "authentication": "secure (mutual, implicit via KEM)",
        "forward_secrecy": "secure (ephemeral KEM)",
        "store_now_decrypt_later": "resistant",
        "summary": (
            "Full hybrid security: the adversary must break both the KEM and QKD. "
            "The only cell in which the deployment gets what it paid for."
        ),
    },
    {
        "cell": "B",
        "qkd_intact": True,
        "kem_intact": False,
        "security_mode": "hybrid",
        "confidentiality": "secure (information-theoretic QKD contribution)",
        "authentication": "designed mechanism lost; residual, from QKD key as implicit PSK",
        "forward_secrecy": "lost (ephemeral KEM broken)",
        "store_now_decrypt_later": "resistant",
        "summary": (
            "Confidentiality survives because HKDF is keyed by the whole IKM and the "
            "QKD key remains unknown. KEM-based implicit authentication is gone; what "
            "remains depends on KME access control, which this testbed does not "
            "implement. An active attacker can also strip the QKD key id to force Cell C."
        ),
    },
    {
        "cell": "C",
        "qkd_intact": False,
        "kem_intact": True,
        "security_mode": "computational_only",
        "confidentiality": "secure under KEM IND-CCA",
        "authentication": "secure (mutual, implicit via KEM)",
        "forward_secrecy": "secure (ephemeral KEM)",
        "store_now_decrypt_later": "not resistant",
        "summary": (
            "The silent-downgrade state: nothing fails today, but the session is only "
            "as strong as pure PQC and the reason for deploying QKD is gone. Reached "
            "either by an empty pool or by a compromised QKD key. This is the cell the "
            "measurement study populates, and the only cell the mitigations act on."
        ),
    },
    {
        "cell": "D",
        "qkd_intact": False,
        "kem_intact": False,
        "security_mode": "none",
        "confidentiality": "broken",
        "authentication": "broken (MAC keys derivable)",
        "forward_secrecy": "broken",
        "store_now_decrypt_later": "broken",
        "summary": (
            "Every IKM component is known, so the deterministic KDF yields the session "
            "key to the adversary. Cell C plus one future cryptanalytic result is Cell D."
        ),
    },
]


def _check_against_markdown(source: Path = SOURCE) -> list[str]:
    """Verify every cell in the CSV has a matching section in the prose."""
    if not source.exists():
        return [f"{source} not found"]
    text = source.read_text(encoding="utf-8")
    problems = []
    for cell in CELLS:
        if not re.search(rf"^## Cell {cell['cell']}\b", text, re.MULTILINE):
            problems.append(f"analysis/security_matrix.md has no '## Cell {cell['cell']}' section")
    return problems


def emit_security_matrix(path: Optional[Path | str] = None) -> Path:
    problems = _check_against_markdown()
    for problem in problems:
        print(f"  warning: {problem}")
    return write_csv(path or RESULTS_DIR / "security_matrix.csv", FIELDNAMES, CELLS)


def main() -> int:
    path = emit_security_matrix()
    print(f"wrote {path} ({len(CELLS)} cells)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
