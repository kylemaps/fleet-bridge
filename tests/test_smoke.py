"""End-to-end smoke test: build a 2-rover fleet, seal, analyze, aggregate,
tamper one rover, re-aggregate. Requires veriseal and rating-bridge installed
in the same environment (they are dev dependencies of the demo)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("veriseal")
pytest.importorskip("rating_bridge")
pytest.importorskip("mcap")

DEMO_DIR = Path(__file__).parent.parent / "demo"
sys.path.insert(0, str(DEMO_DIR))


@pytest.fixture(scope="module")
def fleet(tmp_path_factory) -> Path:
    from make_fleet import make_rover

    from fleet_bridge.chain import _veriseal_cmd

    root = tmp_path_factory.mktemp("fleet")
    fleet_dir = root / "fleet"
    keys_dir = root / "keys"
    keys_dir.mkdir()

    make_rover(fleet_dir / "rover-a" / "log.mcap", "circle")
    make_rover(fleet_dir / "rover-b" / "log.mcap", "hardstop")

    veriseal = _veriseal_cmd()
    assert veriseal, "veriseal CLI not found"
    capture_key = keys_dir / "capture_key.pem"
    subprocess.run(veriseal + ["keygen", "--out", str(capture_key)], check=True, capture_output=True)
    for robot in ("rover-a", "rover-b"):
        subprocess.run(
            veriseal + ["seal", str(fleet_dir / robot / "log.mcap"), "--no-anchor",
                        "--key", str(capture_key),
                        "--out", str(fleet_dir / robot / "log.seal.json")],
            check=True, capture_output=True,
        )
        subprocess.run(
            [sys.executable, "-m", "rating_bridge", "analyze",
             str(fleet_dir / robot / "log.mcap"),
             "--out-dir", str(fleet_dir / robot / "report"),
             "--sign", "--key", str(keys_dir / "analysis_key.pem")],
            check=True, capture_output=True,
        )
    return fleet_dir


def _aggregate(fleet_dir: Path, out_dir: Path) -> dict:
    from fleet_bridge.cli import main

    assert main(["aggregate", str(fleet_dir), "--out-dir", str(out_dir)]) == 0
    return json.loads((out_dir / "fleet_report.json").read_bytes())


def test_all_verified(fleet: Path, tmp_path: Path):
    report = _aggregate(fleet, tmp_path / "out")
    assert report["fleet"]["robots_verified"] == 2
    assert report["fleet"]["robots_quarantined"] == 0
    assert report["exposure"]["hard_decel_event_count_total"] > 0
    assert report["exposure"]["incident_stub_count"] > 0
    assert report["session"]["message_count_total"] > 0


def test_tamper_quarantines(fleet: Path, tmp_path: Path):
    mcap_path = fleet / "rover-b" / "log.mcap"
    data = bytearray(mcap_path.read_bytes())
    data[len(data) // 2] ^= 0xFF  # corrupt raw bytes: sha256 mismatch vs seal
    mcap_path.write_bytes(bytes(data))

    report = _aggregate(fleet, tmp_path / "out2")
    rows = {r["robot_id"]: r for r in report["per_robot"]}
    assert rows["rover-b"]["status"] == "QUARANTINED"
    assert rows["rover-a"]["status"] == "VERIFIED"
    assert report["fleet"]["robots_quarantined"] == 1
    # Quarantined exposure must not leak into totals.
    assert report["exposure"]["hard_decel_event_count_total"] == 0


def test_clock_warning_flags_implausible_time():
    from fleet_bridge.aggregate import _clock_warning

    assert _clock_warning("r", "not_present_in_source", "not_present_in_source") is None
    assert _clock_warning("r", "2026-07-01T00:00:00Z", "2026-07-01T00:02:00Z") is None
    # Monotonic/steady_clock recorder near epoch:
    assert "predates 2015" in _clock_warning("r", "1970-01-01T00:00:05Z", "1970-01-01T00:02:00Z")
    # Undisciplined future clock:
    assert "future" in _clock_warning("r", "2999-01-01T00:00:00Z", "2999-01-01T00:02:00Z")


def test_signed_report_verifies(fleet: Path, tmp_path: Path):
    from fleet_bridge.cli import main

    out = tmp_path / "signed"
    key = tmp_path / "fleet_key.pem"
    assert main(["aggregate", str(fleet), "--out-dir", str(out),
                 "--sign", "--key", str(key)]) == 0
    assert main(["verify", str(out)]) == 0

    # Any edit to the report flips the verdict.
    report_path = out / "fleet_report.json"
    obj = json.loads(report_path.read_bytes())
    obj["fleet"]["robots_total"] = 999
    report_path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    assert main(["verify", str(out)]) == 1
