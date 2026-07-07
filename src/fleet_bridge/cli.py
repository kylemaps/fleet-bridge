"""fleet-bridge CLI: aggregate / verify.

    python -m fleet_bridge aggregate FLEET_DIR [--out-dir fleet_report] [--sign] [--pubkey capture.pub.pem]
    python -m fleet_bridge verify fleet_report
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import fleet_bridge
from fleet_bridge.aggregate import build_fleet_report
from fleet_bridge.canonical import canonical_bytes
from fleet_bridge.chain import STATUS_VERIFIED, discover_robot_dirs, verify_robot
from fleet_bridge.report import render_markdown
from fleet_bridge.signing import (
    generate_key,
    load_private_pem,
    public_pem,
    save_private_pem,
)
from fleet_bridge.signing import sign as ed25519_sign
from fleet_bridge.signing import verify as ed25519_verify

DEFAULT_KEY_PATH = Path("keys") / "fleet_bridge_signing_key.pem"

_ANSI = {"green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m", "cyan": "\033[36m"}
_RESET = "\033[0m"


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"{_ANSI[code]}{text}{_RESET}" if _color_enabled() else text


def _truncate(hex_id: str) -> str:
    return f"{hex_id[:16]}..."


def _print_header(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def _do_aggregate(args: argparse.Namespace) -> int:
    fleet_dir = Path(args.fleet_dir)
    if not fleet_dir.is_dir():
        print(_c(f"ERROR: fleet directory not found: {fleet_dir}", "red"), file=sys.stderr)
        return 2

    robot_dirs = discover_robot_dirs(fleet_dir)
    if not robot_dirs:
        print(_c(f"ERROR: no robot subdirectories in {fleet_dir}", "red"), file=sys.stderr)
        return 2

    pubkey = Path(args.pubkey) if args.pubkey else None
    results = [verify_robot(rd, pubkey=pubkey) for rd in robot_dirs]

    reproduce = f"python -m fleet_bridge aggregate {fleet_dir.as_posix()}" + (
        f" --pubkey {pubkey.as_posix()}" if pubkey else ""
    ) + (" --sign" if args.sign else "")

    fleet_report = build_fleet_report(
        fleet_dir, results, pubkey_pinned=pubkey is not None, reproduce_command=reproduce
    )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "fleet_report.json"
    md_path = out_dir / "fleet_report.md"
    json_path.write_text(
        json.dumps(fleet_report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    md_path.write_text(render_markdown(fleet_report), encoding="utf-8", newline="\n")

    _print_header("Aggregate complete")
    fleet = fleet_report["fleet"]
    exposure = fleet_report["exposure"]
    verified_str = f"{fleet['robots_verified']}/{fleet['robots_total']} verified"
    print(f"Fleet:         {_c(str(fleet_dir), 'cyan')}  ({_c(verified_str, 'cyan')})")
    for r in results:
        mark = "ok " if r.status == STATUS_VERIFIED else "QUARANTINED"
        color = "green" if r.status == STATUS_VERIFIED else "red"
        print(f"  {r.robot_id:<12} {_c(mark, color)}"
              + (f"  {r.reasons[0]}" if r.reasons else ""))
    print(f"Robot time:    {_c(str(fleet_report['session']['combined_robot_time_s']), 'cyan')} s")
    print(f"Gaps:          {_c(str(exposure['gap_count_total']), 'cyan')}")
    print(f"Hard decel:    {_c(str(exposure['hard_decel_event_count_total']), 'cyan')}")
    print(f"Incidents:     {_c(str(exposure['incident_stub_count']), 'cyan')} draft stub(s)")
    print(f"JSON report:   {json_path}")
    print(f"Markdown:      {md_path}")

    if args.sign:
        return _sign(out_dir, Path(args.key) if args.key else DEFAULT_KEY_PATH)
    return 0


def _sign(out_dir: Path, key_path: Path) -> int:
    json_path = out_dir / "fleet_report.json"
    sig_path = out_dir / "fleet_report.sig.json"
    if not json_path.exists():
        print(_c(f"ERROR: {json_path} not found. Run `aggregate` first.", "red"), file=sys.stderr)
        return 2

    if key_path.exists():
        key = load_private_pem(key_path)
    else:
        key = generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        save_private_pem(key, key_path)
        print(_c(
            f"WARNING: generated new signing key -> {key_path}\n"
            "         This is a local demo key, not an HSM-backed production key.",
            "yellow",
        ))

    report_obj = json.loads(json_path.read_bytes())
    report_sha256 = hashlib.sha256(canonical_bytes(report_obj)).hexdigest()
    signature = ed25519_sign(key, bytes.fromhex(report_sha256))

    sig_doc = {
        "report_sha256": report_sha256,
        "signature": signature.hex(),
        "public_key": public_pem(key),
        "signed_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_version": fleet_bridge.__version__,
    }
    sig_path.write_text(
        json.dumps(sig_doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    _print_header("Sign complete")
    print(f"Report SHA-256: {_c(_truncate(report_sha256), 'cyan')}")
    print(f"Signature:      {sig_path}")
    print(f"Signing key:    {key_path}")
    return 0


def _do_verify(args: argparse.Namespace) -> int:
    out_dir = Path(args.report_dir)
    json_path = out_dir / "fleet_report.json"
    sig_path = out_dir / "fleet_report.sig.json"
    if not json_path.exists() or not sig_path.exists():
        print(
            _c(f"ERROR: expected both {json_path} and {sig_path} to exist.", "red"),
            file=sys.stderr,
        )
        return 2

    try:
        report_obj = json.loads(json_path.read_bytes())
        sig_doc = json.loads(sig_path.read_bytes())
    except json.JSONDecodeError as exc:
        print(_c(f"TAMPERED: invalid JSON: {exc}", "red"))
        return 1

    recomputed = hashlib.sha256(canonical_bytes(report_obj)).hexdigest()
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

    if hash_ok and sig_ok:
        print(_c(f"INTACT: signature valid, report SHA-256 {_truncate(recomputed)}", "green"))
        return 0
    print(_c("TAMPERED: fleet report does not match its signature", "red"))
    if not hash_ok:
        print(f"  expected {sig_doc.get('report_sha256', '?')[:16]}...")
        print(f"  actual   {recomputed[:16]}...")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fleet-bridge",
        description="N sealed robot logs -> one signed Fleet Exposure Report.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_agg = sub.add_parser("aggregate", help="Verify every robot's evidence chain and aggregate.")
    p_agg.add_argument("fleet_dir", help="Directory with one subdirectory per robot.")
    p_agg.add_argument("--out-dir", default="fleet_report")
    p_agg.add_argument("--sign", action="store_true", help="Sign the fleet report.")
    p_agg.add_argument("--key", default=None, help="Ed25519 private key PEM for signing.")
    p_agg.add_argument(
        "--pubkey", default=None,
        help="Pinned capture public key PEM, passed through to veriseal verify.",
    )
    p_agg.set_defaults(func=_do_aggregate)

    p_ver = sub.add_parser("verify", help="Verify a signed fleet report.")
    p_ver.add_argument("report_dir", help="Directory containing fleet_report.json + .sig.json")
    p_ver.set_defaults(func=_do_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
