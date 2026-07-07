"""Fleet-level aggregation over per-robot verification results.

Only VERIFIED robots contribute numbers to fleet exposure totals. Quarantined
robots appear in the report with their reasons, and the fleet totals say how
much telemetry was refused. Every float is rounded here, before canonical
encoding, so the same fleet directory always reproduces the same metric bytes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import fleet_bridge
from fleet_bridge.chain import STATUS_VERIFIED, RobotVerification

NOT_PRESENT = "not_present_in_source"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _num(value) -> float | None:
    return value if isinstance(value, (int, float)) else None


def build_fleet_report(
    fleet_dir: Path,
    results: list[RobotVerification],
    pubkey_pinned: bool,
    reproduce_command: str,
) -> dict:
    verified = [r for r in results if r.status == STATUS_VERIFIED]
    quarantined = [r for r in results if r.status != STATUS_VERIFIED]

    per_robot = []
    starts: list[str] = []
    ends: list[str] = []
    total_time_s = 0.0
    total_messages = 0
    total_gaps = 0
    longest_gap_s = 0.0
    longest_gap_robot = None
    total_distance_m = 0.0
    distance_robot_count = 0
    total_hard_decel = 0
    incidents: list[dict] = []

    for r in verified:
        rep = r.report
        session = rep["session"]
        continuity = rep["continuity"]
        motion = rep["motion"]
        autonomy = rep["autonomy"]

        if isinstance(session.get("start_utc"), str) and session["start_utc"] != NOT_PRESENT:
            starts.append(session["start_utc"])
        if isinstance(session.get("end_utc"), str) and session["end_utc"] != NOT_PRESENT:
            ends.append(session["end_utc"])
        total_time_s += session.get("duration_s", 0.0)
        total_messages += session.get("message_count", 0)
        total_gaps += continuity.get("gap_count", 0)
        if continuity.get("longest_gap_s", 0.0) > longest_gap_s:
            longest_gap_s = continuity["longest_gap_s"]
            longest_gap_robot = r.robot_id

        distance = _num(motion.get("distance_m"))
        if distance is not None:
            total_distance_m += distance
            distance_robot_count += 1
        hard_decel = _num(motion.get("hard_decel_event_count"))
        if hard_decel is not None:
            total_hard_decel += int(hard_decel)

        for stub in rep.get("incidents", []):
            incidents.append({"robot_id": r.robot_id, **stub})

        autonomy_signal = (
            "flagged_for_review" if autonomy.get("matched_topics") else NOT_PRESENT
        )

        per_robot.append(
            {
                "robot_id": r.robot_id,
                "status": r.status,
                "reasons": [],
                "source_sha256": r.actual_source_sha256,
                "report_sha256": r.report_sha256,
                "veriseal_verdict": r.veriseal_verdict,
                "duration_s": round(session.get("duration_s", 0.0), 6),
                "message_count": session.get("message_count", 0),
                "gap_count": continuity.get("gap_count", 0),
                "distance_m": (
                    round(distance, 3) if distance is not None else NOT_PRESENT
                ),
                "hard_decel_event_count": (
                    int(hard_decel) if hard_decel is not None else NOT_PRESENT
                ),
                "incident_count": len(rep.get("incidents", [])),
                "autonomy_signal": autonomy_signal,
            }
        )

    for r in quarantined:
        per_robot.append(
            {
                "robot_id": r.robot_id,
                "status": r.status,
                "reasons": r.reasons,
                "source_sha256": r.actual_source_sha256,
                "report_sha256": r.report_sha256,
                "veriseal_verdict": r.veriseal_verdict,
                "duration_s": NOT_PRESENT,
                "message_count": NOT_PRESENT,
                "gap_count": NOT_PRESENT,
                "distance_m": NOT_PRESENT,
                "hard_decel_event_count": NOT_PRESENT,
                "incident_count": NOT_PRESENT,
                "autonomy_signal": NOT_PRESENT,
            }
        )

    per_robot.sort(key=lambda row: row["robot_id"])

    robot_hours = total_time_s / 3600.0
    # Rates over tiny exposure are not credible: a 2-minute demo yielding
    # "80 incidents per robot-hour" is an artifact of the denominator, not a
    # fleet property. State the rate but flag it below a floor so no one rates
    # on it. One robot-hour is a deliberately conservative floor for a demo;
    # a real credibility standard is set per program with the underwriter.
    CREDIBILITY_FLOOR_ROBOT_HOURS = 1.0
    incidents_per_robot_hour = (
        round(len(incidents) / robot_hours, 4) if robot_hours > 0 else NOT_PRESENT
    )
    rate_is_credible = robot_hours >= CREDIBILITY_FLOOR_ROBOT_HOURS
    rate_caveat = (
        None if rate_is_credible
        else (
            f"NOT CREDIBLE: only {round(robot_hours, 4)} robot-hours of exposure "
            f"(floor {CREDIBILITY_FLOOR_ROBOT_HOURS}). Rate shown for completeness; "
            "do not price on it."
        )
    )

    return {
        "schema_version": "fleet-bridge-fleet-report-v1",
        "generated_utc": _now_iso(),
        "tool_version": fleet_bridge.__version__,
        "fleet": {
            "fleet_dir": fleet_dir.name,
            "robots_total": len(results),
            "robots_verified": len(verified),
            "robots_quarantined": len(quarantined),
        },
        "verification_policy": {
            "admission_rule": (
                "A robot's numbers count toward fleet exposure only if: telemetry bytes "
                "match its capture-time veriseal seal; veriseal verify reports INTACT; "
                "the exposure report's Ed25519 signature verifies; and the report's "
                "provenance.source_sha256 matches the telemetry bytes on disk."
            ),
            "capture_pubkey_pinned": pubkey_pinned,
            "quarantine_effect": (
                "Quarantined robots are listed with reasons and excluded from every "
                "fleet total. Exposure below is exposure someone can vouch for."
            ),
        },
        "session": {
            "earliest_start_utc": min(starts) if starts else NOT_PRESENT,
            "latest_end_utc": max(ends) if ends else NOT_PRESENT,
            "combined_robot_time_s": round(total_time_s, 6),
            "combined_robot_hours": round(robot_hours, 4),
            "message_count_total": total_messages,
        },
        "exposure": {
            "distance_m_total": round(total_distance_m, 3),
            "distance_robot_count": distance_robot_count,
            "gap_count_total": total_gaps,
            "longest_gap_s": round(longest_gap_s, 6),
            "longest_gap_robot": longest_gap_robot,
            "hard_decel_event_count_total": total_hard_decel,
            "incident_stub_count": len(incidents),
            "incidents_per_robot_hour": incidents_per_robot_hour,
            "rate_is_credible": rate_is_credible,
            "rate_credibility_caveat": rate_caveat,
        },
        "per_robot": per_robot,
        "incidents": incidents,
        "provenance": {
            "command_to_reproduce": reproduce_command,
            "verified_with": "veriseal CLI (exit 0 = INTACT) + Ed25519 report signatures",
            "determinism_note": (
                "Re-running against the same fleet directory reproduces every metric "
                "field byte-for-byte; generated_utc and the signature timestamp are "
                "the only fields that change between runs."
            ),
        },
        "notes": {
            "proves": (
                "Integrity and derivation, per robot and in aggregate: every number in "
                "the fleet totals traces to a telemetry file whose bytes match a "
                "capture-time seal and whose per-robot exposure report signature "
                "verifies. Quarantine reasons are stated verbatim."
            ),
            "does_not_prove": (
                "Veracity at capture. A seal cannot un-fabricate data captured falsely, "
                "and a fleet report inherits every per-robot caveat (draft incident "
                "stubs are threshold triggers, not adjudicated losses; motion and "
                "autonomy carry rating-bridge v0.1 limitations). Demo signing keys are "
                "local PEM files, not HSM-backed identities."
            ),
        },
    }
