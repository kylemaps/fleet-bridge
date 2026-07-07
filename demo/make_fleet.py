"""Generate a synthetic exploration-rover fleet for the fleet-bridge demo.

Four rovers, 120 s each at 10 Hz, modelled on a mineral-exploration traverse:

    rover-01  clean circular survey loop, steady 2 m/s
    rover-02  line traverse with a 4 s full telemetry blackout at t=60 s
              (continuity gap -> draft ALR incident stub)
    rover-03  line traverse with a hard stop at t=80 s (4.0 -> 0.4 m/s,
              ~-3.6 m/s^2 -> hard-deceleration incident stubs)
    rover-04  slow grid sweep, clean

/pose is a real ROS1-serialised geometry_msgs/PoseStamped so rating-bridge's
motion detector computes distance/speed/decel from it. /vehicle/speed,
/autonomy/mode, and /lidar/scan are JSON payloads (autonomy detection is
name-based in rating-bridge v0.1, so /autonomy/mode is flagged for review).

Deterministic: fixed base time (2026-07-01T00:00:00Z), no randomness.
"""

from __future__ import annotations

import json
import math
import struct
from pathlib import Path

from mcap.writer import Writer

BASE_NS = 1_782_864_000_000_000_000  # 2026-07-01T00:00:00Z
STEP_NS = 100_000_000  # 10 Hz
DURATION_S = 120
N_STEPS = DURATION_S * 10

POSESTAMPED_SCHEMA = "geometry_msgs/PoseStamped"
POSESTAMPED_DEF = """std_msgs/Header header
geometry_msgs/Pose pose

================================================================================
MSG: std_msgs/Header
uint32 seq
time stamp
string frame_id

================================================================================
MSG: geometry_msgs/Pose
geometry_msgs/Point position
geometry_msgs/Quaternion orientation

================================================================================
MSG: geometry_msgs/Point
float64 x
float64 y
float64 z

================================================================================
MSG: geometry_msgs/Quaternion
float64 x
float64 y
float64 z
float64 w
"""


def _pose_stamped(seq: int, t_ns: int, x: float, y: float) -> bytes:
    """Hand-packed ROS1 serialisation of geometry_msgs/PoseStamped."""
    secs, nsecs = divmod(t_ns, 1_000_000_000)
    frame = b"map"
    return (
        struct.pack("<3I", seq, secs, nsecs)
        + struct.pack("<I", len(frame))
        + frame
        + struct.pack("<7d", x, y, 0.0, 0.0, 0.0, 0.0, 1.0)
    )


def _speed_at(profile: str, t_s: float) -> float:
    """Ground-truth speed profile per rover (m/s)."""
    if profile == "circle":
        return 2.0
    if profile == "blackout":
        return 3.0
    if profile == "hardstop":
        if t_s < 80.0:
            return 4.0
        if t_s < 81.0:
            # 4.0 -> 0.4 over one second: ~-3.6 m/s^2, over the 3.0 threshold
            return 4.0 - 3.6 * (t_s - 80.0)
        return 0.4
    if profile == "grid":
        return 1.2
    raise ValueError(profile)


def _in_blackout(profile: str, t_s: float) -> bool:
    return profile == "blackout" and 60.0 <= t_s < 64.0


def make_rover(out_path: Path, profile: str) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "wb") as f:
        writer = Writer(f)
        writer.start()

        pose_schema = writer.register_schema(
            name=POSESTAMPED_SCHEMA, encoding="ros1msg", data=POSESTAMPED_DEF.encode()
        )
        json_schema = writer.register_schema(
            name="json_payload", encoding="jsonschema", data=b'{"type":"object"}'
        )
        ch_pose = writer.register_channel(
            topic="/pose", message_encoding="ros1", schema_id=pose_schema
        )
        ch_speed = writer.register_channel(
            topic="/vehicle/speed", message_encoding="json", schema_id=json_schema
        )
        ch_mode = writer.register_channel(
            topic="/autonomy/mode", message_encoding="json", schema_id=json_schema
        )
        ch_lidar = writer.register_channel(
            topic="/lidar/scan", message_encoding="json", schema_id=json_schema
        )

        x = y = 0.0
        heading = 0.0 if profile != "grid" else math.pi / 2
        seq = 0
        for i in range(N_STEPS):
            t_s = i * 0.1
            t_ns = BASE_NS + i * STEP_NS
            if _in_blackout(profile, t_s):
                continue

            speed = _speed_at(profile, t_s)
            if profile == "circle":
                heading += (speed / 20.0) * 0.1  # 20 m radius loop
            elif profile == "grid" and i % 200 == 199:
                heading += math.pi / 2  # turn a grid corner every 20 s
            x += speed * 0.1 * math.cos(heading)
            y += speed * 0.1 * math.sin(heading)

            writer.add_message(
                channel_id=ch_pose,
                log_time=t_ns,
                data=_pose_stamped(seq, t_ns, round(x, 4), round(y, 4)),
                publish_time=t_ns,
            )
            writer.add_message(
                channel_id=ch_speed,
                log_time=t_ns,
                data=json.dumps({"speed_mps": round(speed, 3)}).encode(),
                publish_time=t_ns,
            )
            if i % 10 == 0:  # 1 Hz autonomy mode heartbeat
                writer.add_message(
                    channel_id=ch_mode,
                    log_time=t_ns,
                    data=json.dumps({"mode": "AUTONOMOUS", "estop": False}).encode(),
                    publish_time=t_ns,
                )
            if i % 5 == 0:  # 2 Hz lidar summary
                ranges = [round(8.0 + 3.0 * math.sin(j * 0.4 + i * 0.06), 2) for j in range(16)]
                writer.add_message(
                    channel_id=ch_lidar,
                    log_time=t_ns,
                    data=json.dumps({"ranges": ranges}).encode(),
                    publish_time=t_ns,
                )
            seq += 1

        writer.finish()


ROVERS = {
    "rover-01": "circle",
    "rover-02": "blackout",
    "rover-03": "hardstop",
    "rover-04": "grid",
}


def make_fleet(fleet_dir: Path) -> list[Path]:
    paths = []
    for robot_id, profile in ROVERS.items():
        path = fleet_dir / robot_id / "log.mcap"
        make_rover(path, profile)
        paths.append(path)
        print(f"  {robot_id}: {profile:<9} -> {path}  ({path.stat().st_size / 1024:.0f} KB)")
    return paths


if __name__ == "__main__":
    import sys

    fleet_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "fleet"
    print(f"Generating synthetic fleet in {fleet_dir}")
    make_fleet(fleet_dir)
