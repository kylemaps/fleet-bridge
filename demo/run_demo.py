"""End-to-end fleet-bridge demo.

    1. Generate a 4-rover synthetic exploration fleet (make_fleet.py)
    2. Seal every rover's log at "capture" with veriseal (pinned key, offline)
    3. Analyze every log into a signed exposure report with rating-bridge
    4. Aggregate into one signed Fleet Exposure Report (fleet-bridge)
    5. Tamper one byte inside rover-03's pose stream, post-seal
    6. Re-aggregate: rover-03 is QUARANTINED and excluded from fleet totals

Requires veriseal, rating-bridge, and fleet-bridge installed in the same
environment (see README). Fully offline: sealing uses --no-anchor.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

DEMO_DIR = Path(__file__).parent
FLEET_DIR = DEMO_DIR / "fleet"
KEYS_DIR = DEMO_DIR / "keys"
REPORT_BEFORE = DEMO_DIR / "fleet_report"
REPORT_AFTER = DEMO_DIR / "fleet_report_after_tamper"

ENV = dict(os.environ, NO_COLOR="1")


def run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"\n$ {' '.join(str(a) for a in argv)}")
    proc = subprocess.run([str(a) for a in argv], env=ENV, **kw)
    return proc


def banner(text: str) -> None:
    print(f"\n{'=' * 72}\n{text}\n{'=' * 72}")


def make_capture_key() -> tuple[Path, Path]:
    """One pinned Ed25519 'capture' key shared by the fleet's data recorders."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    priv_path = KEYS_DIR / "capture_key.pem"
    pub_path = KEYS_DIR / "capture_key.pub.pem"
    if not priv_path.exists():
        key = Ed25519PrivateKey.generate()
        priv_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub_path.write_bytes(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return priv_path, pub_path


def tamper_rover(mcap_path: Path) -> None:
    """Flip one byte inside a /pose message payload, post-seal.

    MCAP messages are chunk-compressed, so the tamper decodes and rewrites
    the file with a single flipped payload byte (same approach as
    veriseal's demo/tamper.py).
    """
    from mcap.reader import make_reader
    from mcap.writer import Writer

    with open(mcap_path, "rb") as f:
        reader = make_reader(f)
        rows = list(reader.iter_messages())
        summary = reader.get_summary()
        schemas = {s.id: s for s in summary.schemas.values()}
        channels = {c.id: c for c in summary.channels.values()}

    flipped = False
    new_schema_ids: dict[int, int] = {}
    new_channel_ids: dict[int, int] = {}
    with open(mcap_path, "wb") as f:
        w = Writer(f)
        w.start()
        for _schema, ch, m in rows:
            if ch.schema_id not in new_schema_ids:
                if ch.schema_id == 0:
                    new_schema_ids[ch.schema_id] = 0
                else:
                    s = schemas[ch.schema_id]
                    new_schema_ids[ch.schema_id] = w.register_schema(
                        name=s.name, encoding=s.encoding, data=s.data
                    )
            if ch.id not in new_channel_ids:
                new_channel_ids[ch.id] = w.register_channel(
                    topic=ch.topic,
                    message_encoding=ch.message_encoding,
                    schema_id=new_schema_ids[ch.schema_id],
                    metadata=ch.metadata,
                )
            data = m.data
            if ch.topic == "/pose" and not flipped:
                # Flip a byte inside the pose position (offset past the header)
                idx = len(data) - 8
                data = data[:idx] + bytes([data[idx] ^ 0xFF]) + data[idx + 1:]
                flipped = True
            w.add_message(
                channel_id=new_channel_ids[ch.id],
                log_time=m.log_time,
                data=data,
                publish_time=m.publish_time,
                sequence=m.sequence,
            )
        w.finish()
    assert flipped, "no /pose message found to tamper"


def main() -> int:
    veriseal = shutil.which("veriseal")
    if veriseal is None:
        print("ERROR: veriseal not on PATH. pip install git+https://github.com/kylemaps/veriseal")
        return 2

    for stale in (FLEET_DIR, REPORT_BEFORE, REPORT_AFTER):
        if stale.exists():
            shutil.rmtree(stale)

    banner("STEP 1: generate synthetic 4-rover exploration fleet")
    sys.path.insert(0, str(DEMO_DIR))
    from make_fleet import make_fleet

    make_fleet(FLEET_DIR)
    priv_key, pub_key = make_capture_key()

    banner("STEP 2: seal every rover's log at 'capture' (veriseal, pinned key, offline)")
    for robot_dir in sorted(FLEET_DIR.iterdir()):
        log = robot_dir / "log.mcap"
        run([veriseal, "seal", log, "--no-anchor", "--key", priv_key,
             "--out", robot_dir / "log.seal.json"], check=True)

    banner("STEP 3: per-rover signed exposure reports (rating-bridge)")
    for robot_dir in sorted(FLEET_DIR.iterdir()):
        run([sys.executable, "-m", "rating_bridge", "analyze", robot_dir / "log.mcap",
             "--out-dir", robot_dir / "report", "--sign",
             "--key", KEYS_DIR / "analysis_key.pem"], check=True)

    banner("STEP 4: aggregate into one signed Fleet Exposure Report (fleet-bridge)")
    run([sys.executable, "-m", "fleet_bridge", "aggregate", FLEET_DIR,
         "--out-dir", REPORT_BEFORE, "--sign",
         "--key", KEYS_DIR / "fleet_key.pem", "--pubkey", pub_key], check=True)
    run([sys.executable, "-m", "fleet_bridge", "verify", REPORT_BEFORE], check=True)

    banner("STEP 5: adversary edits rover-03's pose stream AFTER sealing")
    tamper_rover(FLEET_DIR / "rover-03" / "log.mcap")
    print("Flipped one byte inside a /pose message payload of rover-03/log.mcap")

    banner("STEP 6: re-aggregate: rover-03 is QUARANTINED, totals shrink")
    run([sys.executable, "-m", "fleet_bridge", "aggregate", FLEET_DIR,
         "--out-dir", REPORT_AFTER, "--sign",
         "--key", KEYS_DIR / "fleet_key.pem", "--pubkey", pub_key], check=True)

    banner("DONE")
    print(f"Before tamper: {REPORT_BEFORE / 'fleet_report.md'}")
    print(f"After tamper:  {REPORT_AFTER / 'fleet_report.md'}")
    print("Read the 'Quarantined telemetry' section of the after-report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
