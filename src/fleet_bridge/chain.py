"""Per-robot evidence-chain verification.

A robot directory is admissible into a fleet report only if its whole chain
holds:

    log.mcap  ==sha256==  <robot>.seal.json (veriseal, capture-time seal)
    log.mcap  ==sha256==  report/exposure_report.json provenance block
    exposure_report.json  ==Ed25519==  exposure_report.sig.json

Any break in that chain quarantines the robot: its telemetry still appears
in the report's quarantine section (with the exact reason), but none of its
numbers are counted in fleet exposure totals. An underwriter should never be
rating on telemetry nobody can vouch for.

veriseal is invoked as an external CLI (documented exit codes: 0 INTACT,
1 TAMPERED, 2 error) rather than imported, on the family principle that each
tool stands alone and speaks through its published interface.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

STATUS_VERIFIED = "VERIFIED"
STATUS_QUARANTINED = "QUARANTINED"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class RobotVerification:
    robot_id: str
    status: str = STATUS_QUARANTINED
    reasons: list[str] = field(default_factory=list)
    mcap_path: Path | None = None
    seal_path: Path | None = None
    report_path: Path | None = None
    sig_path: Path | None = None
    actual_source_sha256: str | None = None
    seal_source_sha256: str | None = None
    report_source_sha256: str | None = None
    report_sha256: str | None = None
    report: dict | None = None
    veriseal_verdict: str | None = None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def discover_robot_dirs(fleet_dir: Path) -> list[Path]:
    """Every immediate subdirectory of the fleet dir is one robot."""
    return sorted(p for p in fleet_dir.iterdir() if p.is_dir())


def _find_one(robot_dir: Path, pattern: str) -> Path | None:
    matches = sorted(robot_dir.glob(pattern))
    return matches[0] if len(matches) == 1 else (matches[0] if matches else None)


def _veriseal_cmd() -> list[str] | None:
    import sys

    exe = shutil.which("veriseal")
    if exe:
        return [exe]
    # Same environment as this interpreter, even if its Scripts/bin dir is not on PATH.
    sibling = shutil.which("veriseal", path=str(Path(sys.executable).parent))
    return [sibling] if sibling else None


def _run_veriseal_verify(
    mcap_path: Path, seal_path: Path, pubkey: Path | None
) -> tuple[int, str]:
    cmd = _veriseal_cmd()
    if cmd is None:
        return -1, "veriseal CLI not found on PATH (pip install veriseal into this environment)"
    argv = cmd + ["verify", str(mcap_path), str(seal_path)]
    if pubkey is not None:
        argv += ["--pubkey", str(pubkey)]
    env = dict(os.environ, NO_COLOR="1", TERM="dumb")
    proc = subprocess.run(argv, capture_output=True, text=True, env=env)
    out = _ANSI_RE.sub("", (proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode, out


def verify_robot(robot_dir: Path, pubkey: Path | None = None) -> RobotVerification:
    """Run the full evidence-chain check for one robot directory."""
    from fleet_bridge.canonical import canonical_bytes
    from fleet_bridge.signing import verify as ed25519_verify

    rv = RobotVerification(robot_id=robot_dir.name)

    rv.mcap_path = _find_one(robot_dir, "*.mcap")
    rv.seal_path = _find_one(robot_dir, "*.seal.json")
    rv.report_path = robot_dir / "report" / "exposure_report.json"
    rv.sig_path = robot_dir / "report" / "exposure_report.sig.json"

    if rv.mcap_path is None:
        rv.reasons.append("no .mcap telemetry file found")
    if rv.seal_path is None:
        rv.reasons.append("no .seal.json capture-time seal found (unsealed telemetry)")
    if not rv.report_path.exists():
        rv.reasons.append("no report/exposure_report.json found (unanalyzed telemetry)")
        rv.report_path = None
    if rv.sig_path is not None and not rv.sig_path.exists():
        rv.reasons.append("no report/exposure_report.sig.json found (unsigned report)")
        rv.sig_path = None
    if rv.reasons:
        return rv

    # 1. Raw bytes vs the capture-time seal.
    rv.actual_source_sha256 = sha256_file(rv.mcap_path)
    try:
        seal_doc = json.loads(rv.seal_path.read_bytes())
        rv.seal_source_sha256 = seal_doc.get("source", {}).get("sha256")
    except (json.JSONDecodeError, AttributeError):
        rv.reasons.append("seal manifest is not valid JSON")
        return rv

    if rv.seal_source_sha256 != rv.actual_source_sha256:
        rv.reasons.append(
            "telemetry bytes do not match the capture-time seal "
            f"(sealed {str(rv.seal_source_sha256)[:16]}..., "
            f"actual {rv.actual_source_sha256[:16]}...)"
        )

    # 2. Full veriseal verification (message-level Merkle check + signature).
    code, detail = _run_veriseal_verify(rv.mcap_path, rv.seal_path, pubkey)
    if code == 0:
        rv.veriseal_verdict = "INTACT"
    elif code == -1:
        rv.veriseal_verdict = "UNAVAILABLE"
        rv.reasons.append(detail)
    else:
        rv.veriseal_verdict = "TAMPERED"
        first_lines = " | ".join(line.strip() for line in detail.splitlines()[:4])
        rv.reasons.append(f"veriseal verify failed (exit {code}): {first_lines}")

    # 3. Exposure report signature (same convention as rating-bridge verify).
    try:
        report_obj = json.loads(rv.report_path.read_bytes())
        sig_doc = json.loads(rv.sig_path.read_bytes())
    except json.JSONDecodeError as exc:
        rv.reasons.append(f"report or signature is not valid JSON: {exc}")
        return rv

    recomputed = hashlib.sha256(canonical_bytes(report_obj)).hexdigest()
    rv.report_sha256 = recomputed
    hash_ok = recomputed == sig_doc.get("report_sha256")
    sig_ok = False
    if hash_ok:
        try:
            sig_ok = ed25519_verify(
                sig_doc["public_key"],
                bytes.fromhex(sig_doc["report_sha256"]),
                bytes.fromhex(sig_doc["signature"]),
            )
        except Exception:
            sig_ok = False
    if not (hash_ok and sig_ok):
        rv.reasons.append("exposure report signature does not verify (report or sig altered)")

    # 4. The chain link: the report must be about the same bytes the seal sealed.
    rv.report_source_sha256 = report_obj.get("provenance", {}).get("source_sha256")
    if rv.report_source_sha256 != rv.actual_source_sha256:
        rv.reasons.append(
            "exposure report was computed over different bytes than the telemetry on disk "
            f"(report {str(rv.report_source_sha256)[:16]}..., "
            f"actual {rv.actual_source_sha256[:16]}...)"
        )

    if not rv.reasons:
        rv.status = STATUS_VERIFIED
        rv.report = report_obj
    return rv
