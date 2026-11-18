#!/usr/bin/env python3
"""
Python front end for CheckPath, the path-grounding check run after Block 1.

CheckPath (Java, JavaParser + symbol solver) resolves every hop of each target's
`entrypoint` chain in the project source, checks that consecutive hops are connected
by a call, a field data flow or a call sequence, and checks that the path reaches the
target's `source_path`. This module builds the jar on first use, runs it, adds the checks
of the register's `resource`, `failure_mode`, `scale` and `input_bytes` fields (check_fields), and
turns a failing report into a repair message for the analysis agent.

Usage as a library (see dosguide.py):
    report = check_fields(run_checkpath(source_root, entries=target_entries), target_entries)
    if report.get("ok") is False:
        prompt = repair_prompt(report)

Usage from the command line:
    python3 tools/checkpath/checkpath.py --source-root projects/<id> \
        --register workspaces/<id>/<run>/analysis/target_register.json
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
POM = HERE / "pom.xml"
JAR = HERE / "target" / "checkpath.jar"


def ensure_jar(verbose: bool = True) -> Path | None:
    """Return the CheckPath jar, building it with Maven if it is missing or stale."""
    sources = list((HERE / "src").rglob("*.java")) + [POM]
    newest = max((p.stat().st_mtime for p in sources), default=0.0)
    if JAR.exists() and JAR.stat().st_mtime >= newest:
        return JAR
    mvn = shutil.which("mvn")
    if mvn is None:
        if verbose:
            print("[CheckPath] mvn not found; cannot build checkpath.jar", file=sys.stderr)
        return JAR if JAR.exists() else None
    if verbose:
        print("[CheckPath] building checkpath.jar ...", file=sys.stderr)
    proc = subprocess.run([mvn, "-q", "-B", "-f", str(POM), "package", "-DskipTests"],
                          capture_output=True, text=True)
    if proc.returncode != 0 or not JAR.exists():
        if verbose:
            print("[CheckPath] build failed:\n" + (proc.stdout + proc.stderr)[-2000:], file=sys.stderr)
        return JAR if JAR.exists() else None
    return JAR


def run_checkpath(
    source_root: str | Path,
    *,
    entries: list[dict[str, Any]] | None = None,
    register_path: str | Path | None = None,
    max_gap: int = 2,
    sink_depth: int = 6,
    require_sink: bool = False,
    plan: dict[str, Any] | None = None,
    harness: list[str | Path] | None = None,
    timeout: int = 1800,
    previous_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run CheckPath on a target register (given as entries or as a file).

    With `harness` (directories holding the fuzz harness, e.g. benchmarks/<subject>/src), every path must
    start at one of the harness's @Fuzz methods, and each passing target's report gives it as "harness_entry".

    Returns the JSON report. Its "ok" key is True if every target passes and False if
    any fails. With `plan` (a guidance plan, see PLAN_SPEC) the report also has "plan_ok"
    and "plans". With `previous_plan` (the plan a revision replaces), a revision that moves a target's retention
    signals from the sink to hops before it fails (check_signals_before_sink). If CheckPath could not run, the
    report is {"ok": None, "error": "..."}.
    """
    jar = ensure_jar()
    if jar is None:
        return {"ok": None, "error": "checkpath.jar is unavailable (needs Java 17+ and Maven)"}
    java = shutil.which("java")
    if java is None:
        return {"ok": None, "error": "java not found on PATH"}

    with tempfile.TemporaryDirectory(prefix="checkpath-") as tmp:
        if entries is not None:
            register_path = Path(tmp) / "target_register.json"
            register_path.write_text(json.dumps({"ordered_targets": entries}, ensure_ascii=False),
                                     encoding="utf-8")
        if register_path is None:
            return {"ok": None, "error": "no target register given"}
        out = Path(tmp) / "report.json"
        cmd = [java, "-jar", str(jar), "--source-root", str(source_root), "--register", str(register_path),
               "--max-gap", str(max_gap), "--sink-depth", str(sink_depth), "--out", str(out)]
        if require_sink:
            cmd.append("--require-sink")
        for h in harness or []:
            cmd += ["--harness", str(h)]
        if plan is not None:
            plan_path = Path(tmp) / "guidance_plan.json"
            plan_path.write_text(json.dumps(plan, ensure_ascii=False), encoding="utf-8")
            cmd += ["--plan", str(plan_path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"ok": None, "error": f"CheckPath timed out after {timeout}s"}
        if proc.returncode == 2 or not out.exists():
            return {"ok": None, "error": (proc.stderr or proc.stdout).strip()[-2000:] or "CheckPath failed"}
        report = json.loads(out.read_text(encoding="utf-8"))
    if plan is not None and report.get("plans"):
        if entries is None:
            entries = json.loads(Path(register_path).read_text(encoding="utf-8")).get("ordered_targets", [])
        check_signals_before_sink(report, entries, plan, previous_plan)
    return report


def _class_and_method(ref: str) -> tuple[str, str] | None:
    """(simple class name, method name) of `pkg.Outer$Inner#m(T)`, `Outer.Inner#m` or `Class#m`; None otherwise."""
    if "#" not in (ref or ""):
        return None
    cls, name = ref.split("#", 1)
    cls = re.split(r"[.$]", cls.strip())[-1]
    name = re.sub(r"\(.*", "", name).strip()
    return (cls, name) if cls and name else None


def _measured_before_sink(entry: dict[str, Any], sig: dict[str, Any]) -> bool | None:
    """True if every location of the signal is a hop of the entry's attack path that comes before its sink, False if
    some location is at or after the sink, off the path or in a library, None if the path has no in-tree sink."""
    sink = _class_and_method(str(entry.get("sink") or ""))
    hops = [_class_and_method(h.get("method", "")) for h in entry.get("normalized_path") or [] if h.get("kind") == "hop"]
    if not sink or sink not in hops:
        return None
    sink_at = hops.index(sink)
    at = []
    for loc in sig.get("locations") or []:
        written = loc.get("written", "") if isinstance(loc, dict) else str(loc)
        idx = [i for i, h in enumerate(hops) if h == _class_and_method(written)]
        at.append(max(idx) if idx else None)
    return bool(at) and all(i is not None and i < sink_at for i in at)


def _retention(plan_entry: dict[str, Any]) -> list[dict[str, Any]]:
    names = set(plan_entry.get("retention_signals") or [])
    sigs = plan_entry.get("signals") or []
    return [s for s in sigs if s.get("name") in names] or sigs


def check_signals_before_sink(report: dict[str, Any], entries: list[dict[str, Any]], plan: dict[str, Any],
                              previous_plan: dict[str, Any] | None = None) -> dict[str, Any]:
    """Retention signals measured only at hops of the attack path that come before the sink.

    A signal moved from the sink to a hop before it (for example from the decompressed bytes at the sink to the input
    length at the decoder's entry) no longer measures the resource, and the guidance loses its feedback. A location
    before the sink is not wrong in itself (a decoder's read() can return what the sink produced), and the plan does
    not say whether a method is measured at entry or exit. So such a signal is a warning, and a revision is rejected
    only when it moves a target whose retention was measured at or after the sink (or off the path) to locations that
    are all before it. Adds warnings/diagnostics to report["plans"] and fails a rejected revision (report["plan_ok"])."""
    by_id = {e.get("id"): e for e in entries}
    previous = {p.get("target"): p for p in (previous_plan or {}).get("plans", [])}
    planned = {p.get("target"): p for p in (plan or {}).get("plans", [])}
    for p in report.get("plans", []):
        tid = p.get("target")
        entry, now = by_id.get(tid) or {}, planned.get(tid)
        if not entry or not now:
            continue
        before = {s.get("name"): _measured_before_sink(entry, s) for s in _retention(now)}
        for name, b in before.items():
            if b:
                p.setdefault("warnings", []).append(
                    f"Target {tid}, signal `{name}`: every location is on the attack path before the sink "
                    f"{entry.get('sink')}; it observes the sink's resource only if it is measured after the sink ran "
                    "(e.g. a returned length), not at method entry.")
        old = previous.get(tid)
        if old is None or not before or not all(before.values()):
            continue
        if any(_measured_before_sink(entry, s) is False for s in _retention(old)):
            p.setdefault("diagnostics", []).append(
                f"Target {tid}: the revised plan moves the retention signals ({', '.join(before)}) to locations that "
                f"are all on the attack path before the sink {entry.get('sink')}, where the previous plan measured at "
                "or after it. A measurement before the sink cannot observe the resource the sink consumes. Keep "
                "measuring where the resource is consumed; if no input reaches that code, change how the guidance "
                "generates inputs, not where it measures.")
            p["status"] = "FAIL"
            report["plan_ok"] = False
    return report


# The failure observed when a target's resource is exhausted (the register's `failure_mode`). The campaign
# counts exactly these: an execution longer than the subject's time limit, StackOverflowError, OutOfMemoryError.
FAILURE_MODES = ("timeout", "stack_overflow", "out_of_memory")


def field_problems(entry: dict[str, Any], max_input_bytes: int | None = None) -> list[str]:
    """Problems with a register entry's `resource`, `failure_mode`, `scale` and `input_bytes`, which CheckPath
    itself does not read. With `max_input_bytes` (the evaluation's input size limit), `input_bytes` must fit."""
    problems = []
    if not str(entry.get("resource") or "").strip():
        problems.append("`resource` is missing: name the exhausted resource (stack depth, heap memory or CPU time) "
                        "and the quantity that grows with the input.")
    if entry.get("failure_mode") not in FAILURE_MODES:
        problems.append(f"`failure_mode` is {json.dumps(entry.get('failure_mode'))}; it must be exactly one of "
                        f"{', '.join(FAILURE_MODES)}.")
    if not str(entry.get("scale") or "").strip():
        problems.append("`scale` is missing: give the value the growing quantity must reach for the failure under "
                        "the fixed evaluation limits, and the input length this takes, estimated from the source.")
    size = entry.get("input_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        problems.append(f"`input_bytes` is {json.dumps(size)}; it must be a positive integer, the estimated input "
                        "length in bytes that `scale` takes.")
    elif max_input_bytes and size > max_input_bytes:
        problems.append(f"`input_bytes` is {size}, more than the input size limit of this evaluation "
                        f"({max_input_bytes} bytes; longer inputs are cut), so the failure could not occur. Check the "
                        "estimate against the source; if it holds, the target cannot fail in this evaluation.")
    return problems


def check_fields(report: dict[str, Any], entries: list[dict[str, Any]],
                 max_input_bytes: int | None = None) -> dict[str, Any]:
    """Add the field problems of the register entries to a CheckPath report, as "field_problems" (target ->
    problems); any problem makes the report fail. A report of a CheckPath that could not run is left as is."""
    if report.get("ok") is None:
        return report
    problems = {e.get("id"): p for e in entries if (p := field_problems(e, max_input_bytes))}
    if problems:
        report["field_problems"] = problems
        report["ok"] = False
    return report


def failing_targets(report: dict[str, Any]) -> list[str]:
    """Targets whose path or fields failed."""
    failing = {t["target"] for t in report.get("targets", []) if t.get("status") != "PASS"}
    return sorted(failing | set(report.get("field_problems", {})))


def summarize(report: dict[str, Any]) -> str:
    """One line per target, for logs."""
    if report.get("ok") is None:
        return f"[CheckPath] not run: {report.get('error')}"
    lines = []
    for t in report.get("targets", []):
        lines.append(f"[CheckPath] {t['target']}: {t['status']}"
                     + (f" ({len(t['diagnostics'])} problem(s))" if t["status"] != "PASS" else ""))
    for tid, problems in sorted(report.get("field_problems", {}).items()):
        lines.append(f"[CheckPath] {tid}: register fields: {len(problems)} problem(s)")
    return "\n".join(lines)


def repair_prompt(report: dict[str, Any], collapsed: dict[str, str] | None = None) -> str:
    """Message asking the analysis agent to fix the paths that CheckPath rejected and the fields that
    check_fields rejected.

    `collapsed` maps targets whose revised path became identical to another target's (but was
    distinct originally) to that other target; they are asked to describe their own route.
    """
    failing = [t for t in report.get("targets", []) if t.get("status") != "PASS"]
    collapsed = collapsed or {}
    parts = [
        "CHECKPATH: your target register was checked (its attack paths against the source code, and its "
        "`resource`, `failure_mode`, `scale` and `input_bytes` fields), and some entries need to be fixed.",
        "",
    ]
    # With a harness (--harness), paths start at its @Fuzz methods rather than at any public method.
    start = ("at the fuzz harness's @Fuzz method that drives the target (where the fuzzer's input enters)"
             if (report.get("index") or {}).get("harness_fuzz_methods") else "at the public entry point")
    if failing or collapsed:
        parts += [
            "Each `entrypoint` must be an ordered chain of hops `Class.method(ParamType, ...) → ...` that starts "
            f"{start} and ends at the vulnerable location in `source_path`. Consecutive hops "
            "must be connected: the first calls the second (possibly through a few omitted helper calls), or both "
            "are consecutive calls on the same object (e.g. a factory call followed by a call on the object it "
            "returns). Use the exact method and class names declared in the source.",
            "",
            "If a target's risk lies in a library the project uses (a package-level risk), start "
            f"{start} as for any target, follow the project code to the method that calls into the library, "
            "and then continue with the library's methods up to where the resource is consumed. CheckPath does "
            "not analyze library code and accepts those hops as calls outside the source tree. Do not reuse "
            "another target's path for it.",
            "",
            "A target may also give `sink`: the method where the resource is actually consumed (`Class#method`; "
            "for a library risk, the library method). The path must then pass through that method.",
            "",
        ]
    for t in failing:
        parts.append(f"Target {t['target']}: `{t['entrypoint']}` (source_path: {t['source_path']})")
        for d in t.get("diagnostics", []):
            parts.append(f"  - {d}")
        parts.append("")
    for tid, other in sorted(collapsed.items()):
        entry = next((t for t in report.get("targets", []) if t.get("target") == tid), {})
        parts.append(f"Target {tid}: `{entry.get('entrypoint', '')}`")
        parts.append(f"  - Its path is now identical to target {other}'s, although it was a separate risk. "
                     f"Describe the route specific to {tid} (for a library risk, continue into the library's "
                     f"methods as explained above) instead of reusing {other}'s path.")
        parts.append("")
    fields = report.get("field_problems", {})
    if fields:
        parts += [
            "Each target must give `resource`, the exhausted resource (stack depth, heap memory or CPU time) "
            "and the quantity that grows with the input, and `failure_mode`, the failure observed when that "
            "resource is exhausted: exactly one of `timeout` (one execution runs longer than the per-execution "
            "time limit), `stack_overflow` (StackOverflowError) or `out_of_memory` (OutOfMemoryError). "
            "`failure_mode` is not a detection rule: no threshold, ratio or count. `scale` is the value the growing "
            "quantity must reach for that failure under the fixed evaluation limits and the input length this "
            "takes, and `input_bytes` that length in bytes, as an integer.",
            "",
        ]
        for tid, problems in sorted(fields.items()):
            parts.append(f"Target {tid}:")
            parts += [f"  - {p}" for p in problems]
            parts.append("")
    parts += [
        "Re-read the relevant source files, fix these entries (keep the targets that passed unchanged, and keep "
        "the same target IDs, mechanisms, resources, failure modes and scales unless the source shows they are wrong), "
        "and output the complete corrected target register in the same format as before, between "
        "BEGIN_TARGET_REGISTER_JSON and END_TARGET_REGISTER_JSON. Do not write any other files.",
    ]
    return "\n".join(parts)


# ----------------------------------------------------------------------
# Guidance plan (Block 2)
# ----------------------------------------------------------------------

PLAN_BEGIN = "BEGIN_GUIDANCE_PLAN_JSON"
PLAN_END = "END_GUIDANCE_PLAN_JSON"

PLAN_SPEC = """{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "maxDepth",
          "quantity": "what is measured, e.g. recursion depth of node composition",
          "aggregation": "count | sum | max | ratio | weighted",
          "locations": ["Class#method where the cost is incurred", "..."],
          "technique": "bytecode | wrapper",
          "storage": "where the value is kept, e.g. ThreadLocal<long[]> in DepthCounters",
          "reset": "where it is reset before each execution",
          "read": "where it is read after each execution, e.g. V1Guidance.handleResult()"
        }
      ],
      "retention": "which inputs are kept and how they are prioritized",
      "retention_signals": ["maxDepth"],
      "mutation": ["mutation operators the guidance implements: byte-level ones and structure-aware ones (repetition, dictionary tokens from the source, an encoder for formats that reject random bytes)"]
    }
  ]
}"""


def plan_prompt() -> str:
    """The Block 2 request for the structured guidance plan."""
    return "\n".join([
        "=== Structured guidance plan (MANDATORY) ===",
        "End this block's reply with the measurement plan for every target in the register, as JSON between "
        f"{PLAN_BEGIN} and {PLAN_END}:",
        PLAN_SPEC,
        "Rules: one entry per target. `name` is the key the target's Guidance will return from `lastSignals()`. "
        "`locations` are the methods where the cost is incurred, as `Class#method` with the exact names declared "
        "in the source (for a risk inside a library, the library method). `technique` is \"bytecode\" when the "
        "javaagent instruments those methods and \"wrapper\" when the value is measured around the target "
        "invocation. Every signal must be measured during the execution, not computed from the input. "
        "`retention_signals` lists the signals the retention policy uses. The mutation operators must be able to "
        "build the input shape the target's mechanism needs and grow inputs to the target's `input_bytes` (the "
        "register's estimate of the input length the failure takes) within the first minute of fuzzing, and the "
        "retention must keep making progress while the signal is flat (see [R45]-[R47] where the rules have them). "
        "Block 3 implements this plan, and "
        "DoSGuide checks the locations against the source and the implementation against the plan.",
    ])


def extract_plan(text: str) -> dict[str, Any] | None:
    """The guidance plan between the plan markers in a reply, or None."""
    # The JSON may be in a ```json fence.
    m = re.search(PLAN_BEGIN + r"\s*(?:```(?:json)?\s*)?(\{.*?\})\s*(?:```\s*)?" + PLAN_END, text or "", flags=re.S)
    if not m:
        return None
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", m.group(1).strip())
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return plan if isinstance(plan, dict) and isinstance(plan.get("plans"), list) else None


def plan_summarize(report: dict[str, Any]) -> str:
    if report.get("ok") is None:
        return f"[PlanCheck] not run: {report.get('error')}"
    return "\n".join(f"[PlanCheck] {p['target']}: {p['status']}"
                     + (f" ({len(p['diagnostics'])} problem(s))" if p["status"] != "PASS" else "")
                     for p in report.get("plans", []))


def plan_repair_prompt(report: dict[str, Any] | None, missing: bool = False) -> str:
    """Message asking the agent to fix its guidance plan."""
    parts = ["PLANCHECK: your guidance plan was checked against the source code."]
    if missing or report is None:
        parts += ["", f"Your reply has no complete plan between {PLAN_BEGIN} and {PLAN_END}."]
    else:
        parts.append("Some entries need to be fixed:")
        parts.append("")
        for p in report.get("plans", []):
            if p.get("status") == "PASS":
                continue
            parts.append(f"Target {p['target']}:")
            parts += [f"  - {d}" for d in p.get("diagnostics", [])]
            parts += [f"  - (warning) {w}" for w in p.get("warnings", [])]
            parts.append("")
    parts += [
        "",
        "Re-read the relevant source files and output the complete corrected plan for every target, in the same "
        f"format, between {PLAN_BEGIN} and {PLAN_END}:",
        PLAN_SPEC,
        "Keep plans that passed unchanged. Do not write any files.",
    ]
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1] if __doc__ else None)
    ap.add_argument("--source-root", required=True)
    ap.add_argument("--register", required=True, help="target_register.json")
    ap.add_argument("--max-gap", type=int, default=2)
    ap.add_argument("--sink-depth", type=int, default=6)
    ap.add_argument("--harness", action="append", default=[],
                    help="directory holding the fuzz harness (benchmarks/<subject>/src); paths must start at its @Fuzz methods")
    ap.add_argument("--json", action="store_true", help="print the full JSON report")
    ap.add_argument("--repair-prompt", action="store_true", help="print the repair message for failing targets")
    ap.add_argument("--check-fields", action="store_true",
                    help="also check `resource`, `failure_mode`, `scale` and `input_bytes` "
                         "(registers written before these fields lack them)")
    ap.add_argument("--max-input-bytes", type=int,
                    help="the evaluation's input size limit, which `input_bytes` must not exceed")
    args = ap.parse_args()

    report = run_checkpath(args.source_root, register_path=args.register,
                           max_gap=args.max_gap, sink_depth=args.sink_depth, harness=args.harness)
    if args.check_fields:
        register = json.loads(Path(args.register).read_text(encoding="utf-8"))
        check_fields(report, register.get("ordered_targets", []), args.max_input_bytes)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(summarize(report))
        for t in report.get("targets", []):
            for d in t.get("diagnostics", []):
                print(f"    {t['target']}: {d}")
        for tid, problems in sorted(report.get("field_problems", {}).items()):
            for d in problems:
                print(f"    {tid}: {d}")
    if args.repair_prompt and report.get("ok") is False:
        print("\n" + repair_prompt(report))
    if report.get("ok") is None:
        return 2
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
