"""Ledger-style Markdown rendering of a fleet report, for a non-engineer."""

from __future__ import annotations

NOT_PRESENT = "not_present_in_source"


def _fmt(value, suffix: str = "") -> str:
    if value == NOT_PRESENT or value is None:
        return "n/a"
    return f"{value}{suffix}"


def _short(hex_str: str | None) -> str:
    return f"`{hex_str[:16]}...`" if hex_str else "n/a"


def render_markdown(report: dict) -> str:
    lines: list[str] = []
    ap = lines.append

    fleet = report["fleet"]
    session = report["session"]
    exposure = report["exposure"]

    ap("# Fleet Exposure Report")
    ap("")
    ap(f"- Generated: {report['generated_utc']}  (fleet-bridge v{report['tool_version']})")
    ap(f"- Fleet directory: `{fleet['fleet_dir']}`")
    ap(
        f"- Robots: **{fleet['robots_total']}** total, "
        f"**{fleet['robots_verified']}** verified, "
        f"**{fleet['robots_quarantined']}** quarantined"
    )
    ap("")

    ap("## Fleet exposure (verified robots only)")
    ap("")
    ap("| Metric | Value |")
    ap("|---|---|")
    ap(f"| Combined robot time | {_fmt(session['combined_robot_time_s'], ' s')} "
       f"({_fmt(session['combined_robot_hours'], ' robot-hours')}) |")
    ap(f"| Session window | {_fmt(session['earliest_start_utc'])} to "
       f"{_fmt(session['latest_end_utc'])} |")
    ap(f"| Messages | {_fmt(session['message_count_total'])} |")
    ap(f"| Distance (robots with motion signal: {exposure['distance_robot_count']}) "
       f"| {_fmt(exposure['distance_m_total'], ' m')} |")
    ap(f"| Telemetry gaps > threshold | {_fmt(exposure['gap_count_total'])} "
       f"(longest {_fmt(exposure['longest_gap_s'], ' s')}"
       + (f", {exposure['longest_gap_robot']}" if exposure["longest_gap_robot"] else "")
       + ") |")
    ap(f"| Hard-deceleration events | {_fmt(exposure['hard_decel_event_count_total'])} |")
    ap(f"| Draft incident stubs (ALR-shaped) | {_fmt(exposure['incident_stub_count'])} |")
    ap(f"| Incident stubs per robot-hour | {_fmt(exposure['incidents_per_robot_hour'])} |")
    ap("")
    if exposure.get("rate_credibility_caveat"):
        ap(f"> {exposure['rate_credibility_caveat']}")
        ap("")

    ap("## Per-robot ledger")
    ap("")
    ap("| Robot | Status | Duration | Msgs | Gaps | Distance | Hard decel | Incidents | Telemetry sha256 |")
    ap("|---|---|---|---|---|---|---|---|---|")
    for row in report["per_robot"]:
        ap(
            f"| {row['robot_id']} "
            f"| {row['status']} "
            f"| {_fmt(row['duration_s'], ' s')} "
            f"| {_fmt(row['message_count'])} "
            f"| {_fmt(row['gap_count'])} "
            f"| {_fmt(row['distance_m'], ' m')} "
            f"| {_fmt(row['hard_decel_event_count'])} "
            f"| {_fmt(row['incident_count'])} "
            f"| {_short(row['source_sha256'])} |"
        )
    ap("")

    quarantined = [r for r in report["per_robot"] if r["status"] != "VERIFIED"]
    if quarantined:
        ap("## Quarantined telemetry (excluded from every total above)")
        ap("")
        for row in quarantined:
            ap(f"- **{row['robot_id']}**")
            for reason in row["reasons"]:
                ap(f"  - {reason}")
        ap("")

    if report["incidents"]:
        ap("## Draft incident stubs")
        ap("")
        ap("All stubs are threshold-triggered DRAFTS (`loss_confidence: modeled`), "
           "not adjudicated losses.")
        ap("")
        for stub in report["incidents"]:
            ap(
                f"- `{stub.get('event_id', '?')}` on **{stub['robot_id']}**: "
                f"{stub.get('failure_mode', '?')} at {stub.get('occurred_at', '?')} "
                f"({stub.get('trigger', '')})"
            )
        ap("")

    ap("## Verification policy")
    ap("")
    ap(report["verification_policy"]["admission_rule"])
    ap("")
    ap(f"Capture key pinned: {report['verification_policy']['capture_pubkey_pinned']}.")
    ap("")

    ap("## What this proves / does not prove")
    ap("")
    ap(f"**Proves:** {report['notes']['proves']}")
    ap("")
    ap(f"**Does not prove:** {report['notes']['does_not_prove']}")
    ap("")

    ap("## Provenance")
    ap("")
    ap(f"- Reproduce: `{report['provenance']['command_to_reproduce']}`")
    ap(f"- Verified with: {report['provenance']['verified_with']}")
    ap(f"- {report['provenance']['determinism_note']}")
    ap("")

    return "\n".join(lines)
