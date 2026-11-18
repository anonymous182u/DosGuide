#!/usr/bin/env python3
"""
Runs one DoSGuide campaign run: builds a synthesis workspace as its analysis/launch.json says, then runs the
target's guidance through the campaign launcher (tools/launch), which decides failures as for every engine.

The JVM options, per-execution timeout and input size limit come from the subject's oracle.json; the
"jvm_args" of launch.json (the synthesis agent's choice) are not used. The synthesized javaagent, if any, is
attached, and the subject class path is on the system class path after the launcher, as in the validation
(scripts/guidance_launch.py). The result is <out>/result.json.

Usage:
    python3 scripts/run_guided.py --run-dir <workspace copy> --target V1 --oracle benchmarks/<s>/oracle.json \
        --launcher tools/launch/target/campaign-launcher.jar --budget-sec 900 --out <run-dir>/out/launch
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guidance_launch  # noqa: E402
import oracle_config  # noqa: E402


BUILD_TIMEOUT_SEC = 3600


def fail(out: Path, message: str) -> int:
    out.mkdir(parents=True, exist_ok=True)
    (out / "result.json").write_text(json.dumps({"engine": "guidance", "outcome": "error", "error": message},
                                                indent=2), encoding="utf-8")
    print(f"RESULT outcome=error ({message[:200]})")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--target", required=True, help="target id of the synthesis register (launch.json targets)")
    ap.add_argument("--oracle", required=True, help="the subject's oracle.json")
    ap.add_argument("--launcher", required=True, help="campaign-launcher.jar")
    ap.add_argument("--budget-sec", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    out = Path(args.out).resolve()
    try:
        launch = json.loads((run_dir / "analysis" / "launch.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return fail(out, f"cannot read analysis/launch.json: {e}")
    target = (launch.get("targets") or {}).get(args.target)
    if not isinstance(target, dict) or not target.get("test_class") or not target.get("method"):
        return fail(out, f"analysis/launch.json has no target {args.target} with test_class and method")

    build = guidance_launch.run_build(run_dir, launch, BUILD_TIMEOUT_SEC)
    if not build["ok"]:
        return fail(out, f"build command failed: {build['command']}: {build['output'][-1500:]}")
    cp, failure = guidance_launch.class_path(run_dir, launch, BUILD_TIMEOUT_SEC)
    if failure:
        return fail(out, f"classpath_command failed: {failure['output'][-1500:]}")

    cfg = oracle_config.load(args.oracle)
    cmd = ["java", *cfg["jvm_args"], *guidance_launch.javaagent_args(run_dir, launch),
           *guidance_launch.system_class_path(Path(args.launcher).resolve(), cp),
           "dosguide.campaign.Launch", "--engine", "guidance",
            "--factory", str(launch.get("guidance_factory")), "--target", args.target,
            "--cp", cp, "--test-class", target["test_class"], "--method", target["method"], "--out", str(out),
            "--budget-sec", str(args.budget_sec), "--timeout-ms", str(cfg["timeout_ms"]),
            "--max-input-bytes", str(cfg["max_input_bytes"]), *oracle_config.fixed_args(cfg)]
    print("[run_guided] " + " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=run_dir)


if __name__ == "__main__":
    raise SystemExit(main())
