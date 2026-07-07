# Fleet Bridge

For underwriters, fleet operators, and safety teams who need exposure numbers for a whole robot fleet, counted only from telemetry someone can actually vouch for.

Fleet Bridge turns N robots' sealed logs and signed per-robot exposure reports into **one signed Fleet Exposure Report**. It is the fleet layer of a four-part pipeline: [veriseal](https://github.com/kylemaps/veriseal) seals each robot's raw telemetry (MCAP) at capture; [rating-bridge](https://github.com/kylemaps/rating-bridge) turns each sealed log into a signed, re-runnable exposure report; Fleet Bridge verifies every robot's evidence chain end to end and aggregates only the robots that pass; the [Agent Loss Record](https://github.com/kylemaps/agent-loss-record) standard is the shape the rolled-up incident stubs arrive in.

The core rule: **a robot's numbers count toward fleet exposure only if its whole chain verifies**. Telemetry bytes must match the capture-time seal, `veriseal verify` must report INTACT, the exposure report's Ed25519 signature must verify, and the report must have been computed over the same bytes the seal sealed. Anything else is quarantined: listed in the report with the exact reason, excluded from every total.

> Status: early v0.1, solo project. Aggregate/sign/verify work end-to-end against a synthetic fleet. Adversarial feedback welcome: open an issue.

---

## Quickstart

```bash
git clone https://github.com/kylemaps/fleet-bridge.git
cd fleet-bridge
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[demo]" \
    git+https://github.com/kylemaps/veriseal \
    git+https://github.com/kylemaps/rating-bridge

# Full demo: generate 4 synthetic exploration rovers, seal, analyze,
# aggregate, tamper one post-seal, re-aggregate.
.venv/Scripts/python demo/run_demo.py
```

The demo's before/after pair is the whole product in two files:

- `demo/fleet_report/fleet_report.md`: 4/4 rovers verified; one rover contributes a 4.1 s telemetry blackout, another ten hard-deceleration stubs.
- `demo/fleet_report_after_tamper/fleet_report.md`: one byte inside rover-03's pose stream was flipped after sealing. rover-03 is QUARANTINED with the reason stated, and every fleet total is recomputed without it.

Aggregate an existing fleet directory (one subdirectory per robot, each holding a `.mcap`, its `.seal.json`, and a `report/` from rating-bridge):

```bash
fleet-bridge aggregate FLEET_DIR --sign --pubkey capture_key.pub.pem
fleet-bridge verify fleet_report
```

---

## Architecture

```
per robot (upstream, separate tools)
  robot MCAP --> veriseal seal (capture time) --> log.seal.json
  robot MCAP --> rating-bridge analyze --sign --> report/exposure_report{.json,.sig.json}

fleet-bridge aggregate FLEET_DIR
  for each robot subdirectory:
    sha256(mcap)  ==  seal.source.sha256            (bytes match the seal)
    veriseal verify --pubkey                         (Merkle + signature, INTACT)
    Ed25519 check of exposure_report.sig.json        (report untampered)
    report.provenance.source_sha256 == sha256(mcap)  (report is about these bytes)
  VERIFIED robots  -> fleet totals (time, distance, gaps, hard decels, ALR stubs)
  anything else    -> QUARANTINED (listed with reasons, counted in no total)
        |
        v
  fleet_report.json / .md      canonical JSON, SHA-256 hashed
        |
        v
  fleet-bridge --sign / verify  Ed25519, same conventions as the rest of the family
```

Verification policy, thresholds, and the exact reproduce command are embedded in every report.

---

## What it does NOT prove

- **Integrity and derivation, not veracity.** A verified chain proves nobody altered the telemetry after sealing and that every number derives deterministically from those bytes. It proves nothing about whether sensors recorded reality truthfully at capture.
- **A quarantine is not an accusation.** Bytes that fail verification may be corruption, a bad copy, or an operational mistake rather than fraud. The report states the observed mismatch, nothing more.
- **Fleet totals inherit every per-robot caveat**: rating-bridge draft incident stubs are threshold triggers, not adjudicated losses; motion and autonomy metrics carry rating-bridge v0.1 limitations.
- **Demo keys are local PEM files**, not HSM-backed identities. Key management and signer identity are deployment concerns this tool does not solve.

---

## Part of a pipeline

veriseal seals telemetry; rating-bridge rates one robot; **Fleet Bridge rates the fleet**; Agent Loss Record is the open standard the incidents land in. Each stands alone; together they are the path from "here is a swarm of robots" to "here is what the fleet's risk exposure is, and here is the proof."

## Roadmap

- v0.1: aggregate / sign / verify over veriseal + rating-bridge artifacts
- v0.2: multi-session robots (many logs per robot over time); exposure trends between reports; coalesced incident events
- v0.3: continuous mode (watch a fleet directory, re-aggregate on arrival); HTML report

---

## License

Apache-2.0 (c) Kyle Mapue
