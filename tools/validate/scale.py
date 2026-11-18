#!/usr/bin/env python3
"""
Scale probe: measures how a target's resource use grows on small inputs, so that the Block 1 agent can check its
`scale` and `input_bytes` estimates before the register is frozen. An estimate made from the code alone can be wrong
by more than the guidance can make up: the nesting depth a stack overflow needs in a fresh JVM, or a regex
backtracking that the JDK memoizes away, so that the vulnerability shows only in another form.

The agent writes, in Block 1, a series of small inputs for each target (analysis/scale/<id>/series.json and the input
files): the shape its mechanism needs, at increasing sizes. DoSGuide builds the frozen fixture, runs each input once
through the target's @Fuzz method in a fresh JVM without any agent or guidance (dosguide.validate.ScaleProbe), and
reports CPU and wall time, allocated bytes, peak heap, and whether the input fits in the probe's thread stack. The
agent extrapolates and revises `scale` and `input_bytes`.

The probe never tells the agent whether an input fails under the evaluation's limits: inputs may be at most a quarter
of the input size limit, the JVM gets a quarter of the heap, the stack search stops at a quarter of the thread stack
size, and an execution is stopped at a tenth of the per-execution time limit. Reaching a cap is reported as such.
The stack is reported as fitting the cap or not, without a search for the smallest stack that fits: the JVM rounds a
thread's stack size up to a platform minimum (about 136 KB on Linux) and JIT compilation changes frame sizes, so such a
search gives inconsistent numbers. A series whose parameter doubles shows where a cap is
crossed, e.g. 500 levels fit in 256 KB and 1,000 do not.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SERIES_ROOT = Path("analysis/scale")
MIN_INPUTS, MAX_INPUTS = 3, 8
REVISION_BEGIN, REVISION_END = "BEGIN_SCALE_REVISION_JSON", "END_SCALE_REVISION_JSON"

_UNITS = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}


def _size(value: str) -> int | None:
    m = re.fullmatch(r"(\d+)([kKmMgG]?)", value)
    return int(m.group(1)) * _UNITS.get(m.group(2).lower(), 1) if m else None


def _jvm_size(jvm_args: list[str], flag: str) -> int | None:
    for a in jvm_args:
        if a.startswith(flag):
            return _size(a[len(flag):])
    return None


def caps(limits: dict[str, Any]) -> dict[str, int]:
    """The probe's caps: a quarter of the input size limit, heap and thread stack, a tenth of the time limit."""
    jvm = [str(a) for a in limits.get("jvm_args", [])]
    heap = _jvm_size(jvm, "-Xmx") or 1024 ** 3
    stack = _jvm_size(jvm, "-Xss") or 1024 ** 2
    return {"input_bytes": int(limits["max_input_bytes"]) // 4, "heap_bytes": heap // 4,
            "stack_bytes": stack // 4, "time_ms": int(limits["timeout_ms"]) // 10}


def probe_jvm_args(limits: dict[str, Any]) -> list[str]:
    """The fixed JVM options with the heap cut to the probe's cap."""
    cap = caps(limits)["heap_bytes"]
    args = [str(a) for a in limits.get("jvm_args", []) if not str(a).startswith("-Xmx")]
    return [f"-Xmx{cap // (1024 * 1024)}m", *args]


def series_instructions(limits: dict[str, Any]) -> str:
    """The Block 1 request for the size series (written after the register's fields are estimated)."""
    c = caps(limits)
    return "\n".join([
        "=== Scale measurement (MANDATORY) ===",
        "DoSGuide measures how each target's resource use grows before the register is frozen, so that `scale` and "
        "`input_bytes` rest on measurements, not only on reading the code. For every target in your register, write "
        f"a size series: {MIN_INPUTS} to {MAX_INPUTS} input files in {SERIES_ROOT}/<target id>/ and "
        f"{SERIES_ROOT}/<target id>/series.json:",
        '  {"parameter": "what grows, e.g. nesting levels", "inputs": [{"file": "n100.bin", "value": 100}, ...]}',
        "Each input is an ordinary input of the shape your mechanism needs, at a small value of the parameter that "
        "doubles from one input to the next (for example 64, 128, 256, 512, 1024 nesting levels), exactly as the fuzz "
        "test will read it (the bytes "
        "the @Fuzz method of the target's path receives). Write the files with the Write tool or a short Python "
        "script; these data files are the only files Block 1 may write. Each input is at most "
        f"{c['input_bytes']} bytes (a quarter of the input size limit); the series is for measuring growth, not for "
        "finding a failing input, and it must not be used later as seed inputs or embedded in the guidance ([R23]).",
        "DoSGuide runs each input once through the fuzz test in a fresh JVM with the fixed JVM options, without any "
        "agent or guidance, and reports per input: CPU and wall time, bytes allocated, peak heap above the level "
        "before the execution, and whether it fits in the probe's thread stack. Measurements stop at caps below the "
        "evaluation's "
        f"limits ({c['time_ms']} ms, {c['stack_bytes'] // 1024} KB of stack, {c['heap_bytes'] // (1024 * 1024)} MB "
        "of heap); an input that reaches a cap is reported as such. You then revise `scale` and `input_bytes` from "
        "the measured growth.",
    ])


def series_problems(run_dir: Path, tid: str, limits: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    """The target's series and what is wrong with it (no series, unreadable, too few/many inputs, too long)."""
    d = Path(run_dir) / SERIES_ROOT / tid
    spec = d / "series.json"
    if not spec.exists():
        return None, [f"{SERIES_ROOT}/{tid}/series.json does not exist"]
    try:
        series = json.loads(spec.read_text(encoding="utf-8"))
        inputs = series["inputs"]
        assert isinstance(inputs, list)
    except Exception as e:  # noqa: BLE001 - report any shape problem to the agent
        return None, [f"{SERIES_ROOT}/{tid}/series.json cannot be read ({type(e).__name__}); use the format shown"]
    problems = []
    if not MIN_INPUTS <= len(inputs) <= MAX_INPUTS:
        problems.append(f"the series has {len(inputs)} inputs; give {MIN_INPUTS} to {MAX_INPUTS}")
    cap = caps(limits)["input_bytes"]
    for item in inputs:
        f = d / str(item.get("file", "")) if isinstance(item, dict) else None
        if f is None or not f.is_file() or not f.resolve().is_relative_to(d.resolve()):
            problems.append(f"input {item!r} does not name a file in {SERIES_ROOT}/{tid}/")
        elif f.stat().st_size > cap:
            problems.append(f"{f.name} is {f.stat().st_size} bytes; the probe takes inputs of at most {cap} bytes")
    return series, problems


def series_prompt(problems: dict[str, list[str]], limits: dict[str, Any]) -> str:
    """Message asking the agent to write or fix the size series of some targets."""
    lines = ["SCALE MEASUREMENT: DoSGuide could not measure these targets because their size series is missing or "
             "invalid:"]
    for tid, ps in problems.items():
        lines += [f"  - {tid}: " + "; ".join(ps)]
    lines += ["", series_instructions(limits), "",
              "Write the missing or corrected series now. Do not change the target register in this reply."]
    return "\n".join(lines)


def build_fixture(fixture_dir: Path, work: Path, timeout: int = 1800) -> tuple[str | None, str | None]:
    """Build a copy of the frozen fixture (benchmarks/<subject>: pom.xml, lib/, src/) as the engines do and return its
    test class path, or (None, error)."""
    dest = work / "fixture"
    shutil.copytree(fixture_dir, dest, ignore=shutil.ignore_patterns("analysis", "target"))
    mvn = shutil.which("mvn")
    if mvn is None:
        return None, "mvn not found on PATH"
    for cmd in ([mvn, "-q", "-B", "-DskipTests", "package", "test-compile"],
                [mvn, "-q", "-B", "-DskipTests", "-DincludeScope=test", "dependency:copy-dependencies",
                 "-DoutputDirectory=target/deps"]):
        try:
            proc = subprocess.run(cmd, cwd=dest, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, f"`{' '.join(cmd[1:])}` timed out after {timeout}s"
        if proc.returncode != 0:
            return None, f"`{' '.join(cmd[1:])}` failed: " + (proc.stdout + proc.stderr)[-1500:]
    jars = sorted((dest / "target" / "deps").glob("*.jar")) + sorted((dest / "lib").glob("*.jar"))
    return ":".join([str(dest / "target" / "test-classes"), str(dest / "target" / "classes"), *map(str, jars)]), None


def _probe_one(java: str, jar: Path, cp: str, limits: dict[str, Any], test_class: str, method: str, inp: Path,
               out: Path, timeout: int) -> dict[str, Any]:
    c = caps(limits)
    cmd = [java, *probe_jvm_args(limits), "-cp", f"{jar}:{cp}", "dosguide.validate.ScaleProbe",
           "--test-class", test_class, "--method", method, "--input", str(inp), "--out", str(out),
           "--time-cap-ms", str(c["time_ms"]), "--stack-cap-bytes", str(c["stack_bytes"])]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        err = proc.stderr
    except subprocess.TimeoutExpired:
        err = f"the probe JVM did not finish within {timeout}s"
    if out.exists():
        return json.loads(out.read_text(encoding="utf-8"))
    causes = [ln.strip() for ln in err.splitlines() if re.search(r"Exception|Error", ln)][:3]
    return {"outcome": "probe_error", "detail": "; ".join(causes) or err[-300:]}


def run_scale_probe(run_dir: Path, entries: list[dict[str, Any]], fixture_dir: Path, limits: dict[str, Any],
                    *, java: str | None = None, per_input_timeout: int = 120) -> dict[str, Any]:
    """Probe every entry that has a valid series. Returns {"caps", "build", "targets": {id: {...}}}."""
    from validate import ensure_jar  # same directory; built with the same pom

    report: dict[str, Any] = {"caps": caps(limits), "targets": {}}
    todo = []
    for e in entries:
        tid = e["id"]
        series, problems = series_problems(run_dir, tid, limits)
        entry_method = str(e.get("harness_entry") or "")
        if "#" not in entry_method:
            problems = problems + ["the target has no harness entry (CheckPath did not ground its first hop)"]
        report["targets"][tid] = {"problems": problems}
        if not problems and series is not None:
            report["targets"][tid]["parameter"] = series.get("parameter")
            todo.append((e, series, entry_method))
    if not todo:
        return report
    jar = ensure_jar(verbose=False)
    java = java or shutil.which("java")
    if jar is None or java is None:
        report["error"] = "validate-artifact.jar or java is unavailable"
        return report
    with tempfile.TemporaryDirectory(prefix="scale-") as tmp:
        cp, error = build_fixture(Path(fixture_dir), Path(tmp))
        report["build"] = {"ok": cp is not None, **({"error": error} if error else {})}
        if cp is None:
            return report
        for e, series, entry_method in todo:
            tid = e["id"]
            test_class, method = entry_method.split("#", 1)
            results = []
            for k, item in enumerate(series["inputs"]):
                inp = Path(run_dir) / SERIES_ROOT / tid / str(item["file"])
                res = _probe_one(java, jar, cp, limits, test_class, method, inp, Path(tmp) / f"{tid}-{k}.json",
                                 per_input_timeout)
                results.append({"file": item["file"], "value": item.get("value"), **res})
            report["targets"][tid]["inputs"] = results
    return report


def _fmt_bytes(n: Any) -> str:
    if not isinstance(n, (int, float)):
        return "-"
    for unit, size in (("MB", 1024 ** 2), ("KB", 1024)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{int(n)} B"


def results_prompt(report: dict[str, Any], entries: list[dict[str, Any]]) -> str:
    """Message with the measurements, asking for revised `scale` and `input_bytes`."""
    c = report["caps"]
    lines = ["SCALE MEASUREMENT: DoSGuide ran each input of your size series once through the target's fuzz test, in "
             "a fresh JVM with the fixed JVM options (heap cut to the probe's cap), without any agent or guidance. "
             f"Caps: {c['time_ms']} ms, {c['stack_bytes'] // 1024} KB of thread stack, "
             f"{c['heap_bytes'] // (1024 * 1024)} MB of heap; they are below the evaluation's limits, so reaching one "
             "does not mean the evaluation would fail. Times, allocation and `peak heap` (the heap in use above the level "
             "when the fuzz test received the input) cover the fuzz test's execution only; an input that completed "
             "fits in the stack cap.", ""]
    for e in entries:
        tid = e["id"]
        t = report["targets"].get(tid) or {}
        lines.append(f"Target {tid} (your estimate: scale = {e.get('scale')!r}; input_bytes = {e.get('input_bytes')}):")
        if t.get("problems"):
            lines.append("  not measured: " + "; ".join(t["problems"]))
        elif report.get("build", {}).get("ok") is False:
            lines.append("  not measured: the fixture did not build (" + str(report["build"].get("error"))[:300] + ")")
        else:
            lines.append(f"  parameter: {t.get('parameter')}")
            lines.append("  value | bytes | outcome | cpu ms | wall ms | allocated | peak heap")
            for r in t.get("inputs", []):
                outcome = {"time_cap": f"reached the time cap ({c['time_ms']} ms)",
                           "stack_cap": f"needs more than the stack cap ({c['stack_bytes'] // 1024} KB)",
                           "heap_cap": f"exceeded the heap cap ({c['heap_bytes'] // (1024 * 1024)} MB)",
                           "completed": "completed" + (f" ({r['detail']})" if r.get("detail") else ""),
                           }.get(r.get("outcome"), f"probe error: {r.get('detail')}")
                lines.append(f"  {r.get('value')} | {r.get('input_bytes', '-')} | {outcome} | "
                             f"{r.get('cpu_ms', '-') if not isinstance(r.get('cpu_ms'), float) else round(r['cpu_ms'], 1)} | "
                             f"{r.get('wall_ms', '-') if not isinstance(r.get('wall_ms'), float) else round(r['wall_ms'], 1)} | "
                             f"{_fmt_bytes(r.get('allocated_bytes'))} | {_fmt_bytes(r.get('peak_heap_bytes'))}")
        lines.append("")
    lines += [
        "Extrapolate the measured growth to the fixed evaluation limits and revise each target's `scale` (state the "
        "measured cost per unit of the parameter and the extrapolation) and `input_bytes` (the input length the "
        "failure takes in the encoding the measurements used; if a denser encoding of the same structure exists, say "
        "so). If a resource does not grow with the parameter as your mechanism says, revise the mechanism in `scale` "
        "and say so. Reply with the revision for every target between "
        f"{REVISION_BEGIN} and {REVISION_END}, as JSON: "
        '{"V1": {"scale": "...", "input_bytes": <integer>}, ...}. Do not re-emit the target register.',
    ]
    return "\n".join(lines)


def extract_revision(text: str) -> dict[str, dict[str, Any]] | None:
    """The {target id: {"scale", "input_bytes"}} revision in a reply, or None."""
    m = re.search(REVISION_BEGIN + r"\s*(?:```(?:json)?\s*)?(\{.*?\})\s*(?:```\s*)?" + REVISION_END, text or "",
                  flags=re.S)
    if not m:
        return None
    try:
        rev = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    return {str(k): v for k, v in rev.items() if isinstance(v, dict)} if isinstance(rev, dict) else None
