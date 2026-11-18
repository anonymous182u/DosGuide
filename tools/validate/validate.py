#!/usr/bin/env python3
"""
Python front end for ValidateArtifact, the execution check run after Block 3.

The run directory declares how to build and launch its fuzzing artifacts in analysis/launch.json
(see README.md). For every target this module builds the project, runs the target's fuzz test
under JQF with the synthesized guidance on a short series of generated, repeated and random
inputs, and checks that the guidance's signal varies, is reset between executions, is measured
during the execution, and that the instrumentation agent rewrote classes. With the subject's fixed
evaluation limits (`limits`), the run uses their JVM options, time limit and input size limit, and a
second short run checks that the guidance takes its maximum input length from the System property
jqf.ei.MAX_INPUT_SIZE (the input-limit probe), a third that it grows its inputs to the register's `input_bytes`
(the growth probe), and a fourth that its signal on its own long inputs keeps up with the agent's own size series
from Block 1 at the same length (the progress probe). A failing report is
turned into a repair message for the synthesis agent. Whether an input makes the test fail is not
part of the verdict and is not reported to the agent.

Usage as a library (see dosguide.py):
    report = run_validation(run_dir, entries)
    if report.get("ok") is False:
        prompt = repair_prompt(report)

Usage from the command line:
    python3 tools/validate/validate.py --run-dir workspaces/<id>/<run>
"""
from __future__ import annotations

import argparse
from collections import Counter
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "scripts"))
import guidance_launch  # noqa: E402  (shared with the campaign's scripts/run_guided.py)

POM = HERE / "pom.xml"
JAR = HERE / "target" / "validate-artifact.jar"
CONTRACT = HERE / "contract" / "SignalSource.java"
CONTRACT_DEST = Path("src/test/java/dosguide/validate/SignalSource.java")

LAUNCH_SPEC = """analysis/launch.json:
{
  "build": ["<shell command run in the run directory>", "..."],
  "classpath": "<class path for running the fuzz tests, entries relative to the run directory>",
  "javaagent": {"jar": "<agent jar, relative path>", "args": "<agent args or empty>"},
  "jvm_args": [],
  "guidance_factory": "<fully.qualified.FuzzRunner>#createGuidance",
  "targets": {"V1": {"test_class": "<fully.qualified.FuzzTest>", "method": "<fuzz method>"}}
}
Use "classpath_command" (a shell command printing the class path) instead of "classpath" if that is
easier, and "javaagent": null when no target uses bytecode instrumentation. "jvm_args" is ignored when the
evaluation fixes the JVM options (see [R41])."""

# The input size limit of the input-limit probe: small enough that a guidance which keeps a limit of its own
# instead of reading jqf.ei.MAX_INPUT_SIZE generates a longer input within a few executions.
PROBE_INPUT_LIMIT = 16
PROBE_OWN = 20

# The growth probe: within GROWTH_BUDGET_MS of the guidance's own inputs, some input must reach the
# length the target register says the vulnerability needs (`input_bytes`, at most the input size limit).
GROWTH_BUDGET_MS = 60_000

# The progress probe: after PROGRESS_BUDGET_MS of the guidance's own inputs, its signal on its long inputs must reach
# PROGRESS_RATIO of what the agent's own size series (Block 1, analysis/scale/<id>) gives at the same length, both
# measured with the guidance's instrumentation. A guidance can reach the input size limit within seconds without ever
# generating the structure its series has, and then finds no failure. The series' growth is extended beyond its
# longest input with the exponent of its upper half, at most PROGRESS_MAX_EXPONENT.
PROGRESS_BUDGET_MS = 120_000
PROGRESS_RATIO = 0.5
PROGRESS_MAX_EXPONENT = 3.0

# Ordinary well-formed example inputs the agent may provide. The validation runs them, but the checks do not count
# them (a signal can vary only on the examples while the guidance's own inputs never reach the sink).
# Never used by the campaign.
EXAMPLES_DIR = Path("analysis/validation_inputs")


def needed_input_bytes(entry: dict[str, Any], limits: dict[str, Any] | None) -> int | None:
    """The input length the growth probe asks for: the target's `input_bytes`, at most the input size limit."""
    try:
        need = int(entry.get("input_bytes"))
    except (TypeError, ValueError):
        return None
    if need <= 0:
        return None
    return min(need, int(limits["max_input_bytes"])) if limits else need


def progress_series(run_dir: str | Path, tid: str) -> list[Path]:
    """The input files of the target's size series (analysis/scale/<id>/series.json), in its order; [] if none."""
    from scale import SERIES_ROOT  # same directory; scale.py imports this module the same way

    d = Path(run_dir) / SERIES_ROOT / tid
    if not (d / "series.json").exists():
        # A Phase 2 retry (--phase2-from) has no Block 1 of its own: its series is in the run it starts from.
        try:
            src = json.loads((Path(run_dir) / "analysis" / "phase2_from.json").read_text(encoding="utf-8"))["source_run"]
            d = Path(src) / SERIES_ROOT / tid
        except (OSError, ValueError, KeyError, TypeError):
            return []
    try:
        items = json.loads((d / "series.json").read_text(encoding="utf-8"))["inputs"]
    except (OSError, ValueError, KeyError, TypeError):
        return []
    files = [d / str(i.get("file", "")) for i in items if isinstance(i, dict)]
    return [f for f in files if f.is_file() and f.resolve().is_relative_to(d.resolve())]


def _series_curve(points: list[tuple[float, float]]) -> tuple[Any, float, tuple[float, float]] | None:
    """How one signal grows along the series: (f, exponent, (bytes, value) of the longest input), where f(bytes)
    interpolates the measured values on a log-log scale and extends them beyond the longest input with the exponent
    fitted on the upper half of the series (at most PROGRESS_MAX_EXPONENT); None if the signal does not grow."""
    import math

    by_len: dict[float, float] = {}
    for b, v in points:
        if b > 0 and v > 0:
            by_len[b] = max(v, by_len.get(b, 0.0))
    pts = sorted(by_len.items())
    if len(pts) < 2 or pts[-1][1] < 1.5 * pts[0][1]:
        return None
    upper = pts[-max(2, (len(pts) + 1) // 2):]
    xs, ys = [math.log(b) for b, _ in upper], [math.log(v) for _, v in upper]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    var = sum((x - mx) ** 2 for x in xs)
    exponent = min(PROGRESS_MAX_EXPONENT, sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var) if var else 0.0
    if exponent < 0.3:
        return None

    def f(n: float) -> float:
        if n >= pts[-1][0]:
            return pts[-1][1] * (n / pts[-1][0]) ** exponent
        if n <= pts[0][0]:
            return pts[0][1] * (n / pts[0][0]) ** exponent
        for (b0, v0), (b1, v1) in zip(pts, pts[1:]):
            if b0 <= n <= b1:
                t = math.log(n / b0) / math.log(b1 / b0)
                return math.exp(math.log(v0) + t * (math.log(v1) - math.log(v0)))
        return pts[-1][1]

    return f, exponent, pts[-1]


def primary_signal(plan: dict[str, Any] | None, tid: str) -> str | None:
    """The signal the target's search maximizes: the first of the plan's `retention_signals`, else its first signal."""
    entry = next((p for p in (plan or {}).get("plans", []) if isinstance(p, dict) and p.get("target") == tid), None)
    if entry is None:
        return None
    names = [str(s) for s in entry.get("retention_signals") or [] if s] or [
        str(s["name"]) for s in entry.get("signals") or [] if isinstance(s, dict) and s.get("name")]
    return names[0] if names else None


def progress_check(probe: dict[str, Any], tid: str, primary: str | None = None,
                   need: int | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """The verdict of the progress probe (ValidateArtifact --probe-progress): (check, comparison).

    For every signal that grows along the series, the guidance's own inputs at least as long as the series' longest
    input (or, if it generated none, at least half as long as its longest input) are compared with the series' value
    at the same length, but at most at `need` bytes (the register's `input_bytes`: the agent's own estimate of the
    length at which the series' structure fails, so a longer input need not reach more; without it a dense cubic
    series carried to 10 KB inputs asks for 1e12 regex steps). The verdict uses the `primary` signal (the one the search maximizes) if it grows along the
    series, else the best of the signals: the check fails if it is below PROGRESS_RATIO. (Judging on any signal would
    let signals that only count the input's units pass.) It is not decided
    ("skip") if the series did not run, no signal grows along it, or an execution of the guidance's own inputs reached
    the time limit.
    """
    from scale import SERIES_ROOT

    p = probe.get("progress") or {}
    checks = {c.get("name"): c for c in probe.get("checks", [])}
    if checks.get("progress", {}).get("status") == "fail":
        return checks["progress"], {}
    if "progress" not in probe:
        detail = probe.get("error") or next((c["detail"] for c in probe.get("checks", []) if c.get("status") == "fail"),
                                            "unknown error")
        return {"name": "progress", "status": "fail", "detail": f"the progress probe produced no verdict: {detail}"}, {}
    if probe.get("stopped_early") and p.get("phase") == "own":
        return {"name": "progress", "status": "skip",
                "detail": "not compared: an execution of the guidance's own inputs ran as long as the time limit"}, {}
    series = [s for s in p.get("series", []) if isinstance(s, dict)]
    own = p.get("own_best") or {}
    comparison: dict[str, Any] = {}
    # A series input still running when the probe stopped (it ran as long as the time limit): the inputs before it
    # are a lower bound for the series, so if no curve can be fitted, the primary signal is compared with the value
    # of the longest completed input, carried flat.
    unfinished = p.get("series_unfinished_bytes") is not None
    for k in sorted({k for s in series for k in (s.get("signals") or {})}):
        points = [(float(s["bytes"]), float(s["signals"][k])) for s in series if k in (s.get("signals") or {})]
        curve = _series_curve(points)
        if curve is None and unfinished and k == primary and any(b > 0 and v > 0 for b, v in points):
            top = max((b, v) for b, v in points if b > 0 and v > 0)
            curve = ((lambda n, v=top[1]: v), 0.0, top)
        if curve is None:
            continue
        f, exponent, (top_bytes, top_value) = curve
        pts = [(float(b), float(v), int(ms)) for b, v, ms in own.get(k, []) if b > 0]
        longest = max((b for b, _, _ in pts), default=0.0)
        eligible = [q for q in pts if q[0] >= top_bytes] or [q for q in pts if q[0] >= longest / 2]
        if not eligible:
            continue
        at = (lambda n: min(n, float(need))) if need else (lambda n: n)
        b, v, ms = max(eligible, key=lambda q: q[1] / f(at(q[0])))
        comparison[k] = {"exponent": round(exponent, 2), "series_longest": [int(top_bytes), top_value],
                         "best": [int(b), v, ms], "compared_at": int(at(b)), "series_at_best": f(at(b)),
                         "ratio": v / f(at(b))}
    if not comparison:
        why = "the series did not run" if not series else "no signal grows along the series"
        return {"name": "progress", "status": "skip", "detail": f"not compared: {why}"}, {}
    ranked = sorted(comparison.items(), key=lambda kv: (kv[0] != primary, -kv[1]["ratio"]))
    if ranked[0][1]["ratio"] >= PROGRESS_RATIO:
        k, c = ranked[0]
        return {"name": "progress", "status": "pass", "ratio": c["ratio"],
                "detail": f"`{k}` reached {c['ratio']:.0%} of the series at {c['best'][0]} bytes"}, comparison
    secs = round(int(p.get("own_ms") or p.get("budget_ms") or 0) / 1000)

    def num(x: float) -> str:
        return f"{x:,.0f}" if abs(x) >= 100 else f"{x:.3g}"

    lead = (f"`{primary}`, the signal your guidance's search maximizes," if ranked[0][0] == primary
            else f"your guidance's best signal, `{ranked[0][0]}`,")
    parts = [f"in {secs} s ({p.get('executions')} executions) {lead} reached on its own long inputs only "
             f"{ranked[0][1]['ratio']:.0%} of what your own size series ({SERIES_ROOT}/{tid}/, run once with your "
             "guidance's instrumentation after the fuzzing) gives at the same input length:"]
    for k, c in ranked[:3]:
        capped = c["compared_at"] < c["best"][0]
        if c["exponent"] == 0.0:
            # The lower-bound comparison; it does not say why the longer series inputs are not used.
            parts.append(f"`{k}` reaches {num(c['series_longest'][1])} on your series' input of "
                         f"{c['series_longest'][0]} bytes (the comparison uses only your series' inputs up to that "
                         f"length); your guidance's best input of {c['best'][0]} bytes reached {num(c['best'][1])} "
                         f"({c['ratio']:.0%}).")
            continue
        parts.append(f"`{k}` reaches {num(c['series_longest'][1])} on your series' longest input "
                     f"({c['series_longest'][0]} bytes) and grows there about as bytes^{c['exponent']:.1f}, which gives "
                     f"about {num(c['series_at_best'])} at {c['compared_at']} bytes"
                     + (" (your register's `input_bytes`)" if capped else "")
                     + f"; your guidance's best input of {c['best'][0]} bytes reached {num(c['best'][1])} "
                     f"({c['ratio']:.0%}).")
    parts.append(f"The inputs your guidance generates do not have the structure your series has. Compare them (its "
                 "corpus) with your series and change the mutation operators or generators so that the search itself "
                 "can build that structure and scale it to the input size limit, for example from the units your series "
                 "repeats, in its order and at its density. If that structure is a complete syntactic construct of the "
                 "input format, single-token dictionary insertions cannot assemble it when no partial construct changes "
                 "the signal: generate whole well-formed constructs of the format (all combinations of their parts, not "
                 "only the one in your series), or measure a signal that rises as an input gets closer to the "
                 "construct. Do not use the series inputs as seeds and do not embed them "
                 "or any complete failure-inducing input ([R23]); DoSGuide rejects guidance sources that contain "
                 "fragments of them. This check is advisory: DoSGuide keeps your change "
                 f"only if it raises `{ranked[0][0]}` on your guidance's own inputs relative to the series, and "
                 "otherwise restores your previous guidance; it never removes a target.")
    return {"name": "progress", "status": "fail", "advisory": True, "ratio": ranked[0][1]["ratio"],
            "detail": " ".join(parts)}, comparison


# The series-embedding check: the guidance's sources (not the fuzz tests) may not contain a fragment of
# EMBED_WINDOW characters of the repeated structure of a series input (a fragment that occurs at least twice in it,
# with at least EMBED_DISTINCT distinct characters), after Java comments and backslashes are removed. The progress
# message points the agent at its series, which must not become seeds or literals. (A fragment that occurs once, such
# as a document header every input of a series starts with, is ordinary syntax its guidance may share.)
EMBED_WINDOW = 20
EMBED_DISTINCT = 6
SERIES_ROOT_TEXT = "analysis/scale"  # scale.SERIES_ROOT


def series_embedded(run_dir: str | Path, tid: str) -> list[str]:
    """Fragments of the target's size series found in the workspace's Java sources other than the fuzz tests."""
    files = snapshot(run_dir)
    fuzz = set(fuzz_tests(files))
    text = {}
    for p, t in files.items():
        if p.endswith(".java") and p not in fuzz:
            t = re.sub(r"/\*.*?\*/", " ", t, flags=re.S)
            t = re.sub(r"(?m)^\s*//.*$|\s//[^\"\n]*$", " ", t)
            text[p] = t.replace("\\", "")
    windows: dict[str, str] = {}
    for p, t in text.items():
        for i in range(len(t) - EMBED_WINDOW + 1):
            windows.setdefault(t[i:i + EMBED_WINDOW], p)
    found = []
    for f in progress_series(run_dir, tid):
        s = f.read_bytes()[:65536].decode("latin-1")
        counts = Counter(s[i:i + EMBED_WINDOW] for i in range(len(s) - EMBED_WINDOW + 1))
        for i in range(len(s) - EMBED_WINDOW + 1):
            w = s[i:i + EMBED_WINDOW]
            if counts[w] >= 2 and len(set(w)) >= EMBED_DISTINCT and w in windows:
                found.append(f"{windows[w]} contains {w!r} from your size series input {f.name}")
                break
    return found


def progress_ratios(report: dict[str, Any]) -> dict[str, float]:
    """{target: ratio} of the targets whose only failing check is the advisory progress check."""
    out = {}
    for t in report.get("targets", []):
        failing = [c for c in t.get("checks", []) if c.get("status") == "fail"]
        if failing and all(c.get("advisory") for c in failing):
            out[t["target"]] = float(next(c.get("ratio", 0.0) for c in failing if c.get("name") == "progress"))
    return out


def contract_prompt(plan: bool = False, limits: bool = False) -> str:
    """The Block 3 requirements that make the artifacts checkable by ValidateArtifact. `limits`: the run has fixed
    evaluation limits, so the input size rule and the input-limit probe apply."""
    implement_plan = [
        "- Implement your guidance plan from Block 2 (analysis/guidance_plan.json): each Guidance's `lastSignals()` "
        "returns exactly the plan's signal names, and the javaagent instruments the planned locations of every "
        "`bytecode` signal.",
    ] if plan else []
    return "\n".join([
        "Part D — Validation contract (DoSGuide checks Parts A–C by execution after this block):",
        *implement_plan,
        f"- Every Guidance class implements `dosguide.validate.SignalSource` (already present at {CONTRACT_DEST}; "
        "do not modify it). `lastSignals()` returns the signal values measured during the most recent execution, "
        "read after handleResult: the value of that execution only, not a running total or a best-so-far value.",
        "- FuzzRunner has `public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, "
        "PrintStream log)` returning the target's Guidance, and uses it itself.",
        *(["- Every Guidance takes its maximum input length from the System property `jqf.ei.MAX_INPUT_SIZE`, read "
           "when it is created (the evaluation sets it to the input size limit), never generates a longer input, and "
           "imposes no smaller maximum of its own."] if limits else []),
        f"- Optionally, put up to 10 ordinary well-formed example inputs (valid instances of the input format, not "
        f"failure-inducing) in {EXAMPLES_DIR}/. The validation runs them and reports their signal values, but the "
        "checks use only the inputs your guidance generates and the validator's variants of them; the campaign never "
        "uses the examples.",
        "- Write analysis/launch.json describing how to build and run your artifacts:",
        LAUNCH_SPEC,
        "After this block DoSGuide runs the build commands and then each target's fuzz test with your guidance on a "
        "short series of generated, repeated and random inputs. It checks that the javaagent rewrites classes, that "
        "the signal varies across inputs, that it is reset before each execution, and that it stays near zero when "
        "the target is not executed."
        + (f" A second short run sets `jqf.ei.MAX_INPUT_SIZE` to {PROBE_INPUT_LIMIT} and checks that no generated "
           "input is longer. A third run of at most "
           f"{GROWTH_BUDGET_MS // 1000} s checks that the guidance generates an input as long as the target register's "
           "`input_bytes` (at most the input size limit). A fourth run fuzzes for "
           f"{PROGRESS_BUDGET_MS // 1000} s and then runs the inputs of your Block 1 size series once, and checks "
           "that on its own long inputs your guidance's signal reaches at least "
           f"{PROGRESS_RATIO:.0%} of what the series gives at the same input length (the series' measured growth "
           "carried to that length): the search must be able to build the structure your series has." if limits else "")
        + " Failed checks are sent back to you to fix.",
    ])


def ensure_jar(verbose: bool = True) -> Path | None:
    """Return the ValidateArtifact jar, building it with Maven if it is missing or stale."""
    sources = list((HERE / "src").rglob("*.java")) + [POM]
    newest = max((p.stat().st_mtime for p in sources), default=0.0)
    if JAR.exists() and JAR.stat().st_mtime >= newest:
        return JAR
    mvn = shutil.which("mvn")
    if mvn is None:
        if verbose:
            print("[Validate] mvn not found; cannot build validate-artifact.jar", file=sys.stderr)
        return JAR if JAR.exists() else None
    if verbose:
        print("[Validate] building validate-artifact.jar ...", file=sys.stderr)
    proc = subprocess.run([mvn, "-q", "-B", "-f", str(POM), "package", "-DskipTests"],
                          capture_output=True, text=True)
    if proc.returncode != 0 or not JAR.exists():
        if verbose:
            print("[Validate] build failed:\n" + (proc.stdout + proc.stderr)[-2000:], file=sys.stderr)
        return JAR if JAR.exists() else None
    return JAR


def install_contract(run_dir: str | Path) -> Path:
    """Copy the SignalSource interface into the run directory's test sources."""
    dest = Path(run_dir) / CONTRACT_DEST
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CONTRACT, dest)
    return dest


def _tail(text: str, n: int = 1500) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else "..." + text[-n:]


def load_launch(run_dir: Path) -> tuple[dict[str, Any] | None, list[str]]:
    """Read and check analysis/launch.json; returns (spec, problems)."""
    path = run_dir / "analysis" / "launch.json"
    if not path.exists():
        return None, ["analysis/launch.json is missing"]
    try:
        spec = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return None, [f"analysis/launch.json is not valid JSON: {e}"]
    problems = []
    if not isinstance(spec.get("build"), list):
        problems.append('"build" must be a list of shell commands')
    if not spec.get("classpath") and not spec.get("classpath_command"):
        problems.append('give "classpath" or "classpath_command"')
    for key in ("classpath", "classpath_command"):
        if spec.get(key) is not None and not isinstance(spec[key], str):
            problems.append(f'"{key}" must be one string (for "classpath": the entries separated by ":"), '
                            f'not a {type(spec[key]).__name__}')
    if "#" not in str(spec.get("guidance_factory", "")):
        problems.append('"guidance_factory" must look like "pkg.FuzzRunner#createGuidance"')
    if not isinstance(spec.get("targets"), dict) or not spec["targets"]:
        problems.append('"targets" must map each target id to {"test_class", "method"}')
    agent = spec.get("javaagent")
    if agent is not None and not (isinstance(agent, dict) and agent.get("jar")):
        problems.append('"javaagent" must be null or {"jar": ..., "args": ...}')
    return spec, problems


# Directories of a run directory that hold build outputs, fuzzing outputs or DoSGuide's own reports.
SNAPSHOT_SKIP_DIRS = {"target", "out", "build-tmp", "analysis", "node_modules"}
SNAPSHOT_MAX_BYTES = 1 << 20


def snapshot(run_dir: str | Path) -> dict[str, str]:
    """The workspace files a repair round may change, as {relative path: text}: sources, build files and
    analysis/launch.json. Hidden entries, binary files and files over 1 MiB are skipped."""
    run_dir = Path(run_dir)
    files: dict[str, str] = {}
    for root, dirs, names in os.walk(run_dir):
        rel_root = Path(root).relative_to(run_dir)
        dirs[:] = sorted(d for d in dirs if not d.startswith(".")
                         and not (rel_root == Path(".") and d in SNAPSHOT_SKIP_DIRS))
        for name in sorted(names):
            p = Path(root) / name
            if name.startswith(".") or p.is_symlink() or p.stat().st_size > SNAPSHOT_MAX_BYTES:
                continue
            try:
                files[(rel_root / name).as_posix()] = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
    launch = run_dir / "analysis" / "launch.json"
    if launch.is_file():
        files["analysis/launch.json"] = launch.read_text(encoding="utf-8", errors="replace")
    return files


def fuzz_tests(files: dict[str, str]) -> dict[str, str]:
    """The fuzz tests among snapshot files: Java sources with a JQF @Fuzz method. They hold the oracles."""
    return {p: text for p, text in files.items() if p.endswith(".java") and re.search(r"@Fuzz\b", text)}


def declared_classes(files: dict[str, str]) -> set[str]:
    """Fully qualified names of the top-level classes of Java source files."""
    out = set()
    for p, text in files.items():
        m = re.search(r"^\s*package\s+([\w.]+)\s*;", text, flags=re.M)
        out.add((m.group(1) + "." if m else "") + Path(p).stem)
    return out


def restore(run_dir: str | Path, original: dict[str, str], current: dict[str, str]) -> list[str]:
    """Write back every file of `original` that `current` changed or deleted; returns their paths."""
    restored = []
    for p, text in original.items():
        if current.get(p) != text:
            dest = Path(run_dir) / p
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
            restored.append(p)
    return restored


def revert(run_dir: str | Path, before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
    """Undo a repair between two snapshots: write back the files it changed or deleted, remove the ones it added."""
    restored = restore(run_dir, before, after)
    removed = []
    for p in sorted(set(after) - set(before)):
        try:
            (Path(run_dir) / p).unlink()
            removed.append(p)
        except OSError:
            pass
    return {"restored": restored, "removed": removed}


def changes(before: dict[str, str], after: dict[str, str], max_diff: int = 200_000) -> dict[str, Any]:
    """Files added, deleted and modified between two snapshots, with a unified diff."""
    added = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(p for p in set(before) & set(after) if before[p] != after[p])
    diff = "".join("".join(difflib.unified_diff(before.get(p, "").splitlines(True), after.get(p, "").splitlines(True),
                                                f"a/{p}", f"b/{p}"))
                   for p in modified + added + deleted)
    if len(diff) > max_diff:
        diff = diff[:max_diff] + f"\n... ({len(diff) - max_diff} more characters)\n"
    return {"added": added, "deleted": deleted, "modified": modified, "diff": diff}


def _intended_classes(entry: dict[str, Any]) -> list[str]:
    """Classes the instrumentation should reach: the sink's class and the source_path file's class."""
    out = []
    sink = str(entry.get("sink") or "")
    if "#" in sink:
        out.append(sink.split("#")[0].strip())
    sp = str(entry.get("source_path") or "")
    if sp.endswith(".java"):
        out.append(Path(sp).stem)
    return [c for i, c in enumerate(out) if c and c not in out[:i]]


def _entry_mismatch(entry: dict[str, Any], launch_target: dict[str, Any]) -> str | None:
    """The register's `harness_entry` (Class#method, the @Fuzz method CheckPath found at the start of the target's
    path) if launch.json runs the target with a different method; None if they agree or there is none."""
    want = str(entry.get("harness_entry") or "")
    if "#" not in want:
        return None
    cls, method = want.rsplit("#", 1)
    test_class = str(launch_target.get("test_class") or "")
    same_class = test_class == cls or (("." not in test_class or "." not in cls)
                                       and test_class.rsplit(".", 1)[-1] == cls.rsplit(".", 1)[-1])
    return None if same_class and launch_target.get("method") == method else want


def _planned(plan: dict[str, Any] | None, tid: str) -> tuple[list[str], list[str]]:
    """The target's planned signal names, and the classes its `bytecode` signals instrument."""
    entry = next((p for p in (plan or {}).get("plans", []) if isinstance(p, dict) and p.get("target") == tid), None)
    if entry is None:
        return [], []
    signals = [s for s in entry.get("signals") or [] if isinstance(s, dict)]
    names = [str(s["name"]) for s in signals if s.get("name")]
    classes: list[str] = []
    for s in signals:
        if str(s.get("technique", "")).lower() != "bytecode":
            continue
        locations = s.get("locations") or ([s["location"]] if s.get("location") else [])
        for loc in locations:
            cls = str(loc).split("#")[0].strip()
            if cls and cls not in classes:
                classes.append(cls)
    return names, classes


def run_validation(
    run_dir: str | Path,
    entries: list[dict[str, Any]],
    *,
    own: int = 40,
    random: int = 40,
    build_timeout: int = 1200,
    target_timeout: int = 600,
    exec_timeout_ms: int = 20000,
    plan: dict[str, Any] | None = None,
    fuzz_classes: set[str] | None = None,
    limits: dict[str, Any] | None = None,
    progress: bool = True,
    progress_only: bool = False,
) -> dict[str, Any]:
    """Build the run directory and validate every target in `entries`.

    With `limits` (the subject's fixed evaluation limits: "jvm_args", "timeout_ms", "max_input_bytes"), every
    target runs with those JVM options, time limit and input size limit instead of launch.json's "jvm_args", and
    the input-limit probe adds the check `input_limit` to each target whose run completed, the growth probe the check
    `input_growth`, and, if that passes and the target has a size series, the progress probe the check `progress`
    (`progress=False` leaves it out; `progress_only=True` runs only the progress probe, for measuring it).

    With a guidance plan (see tools/checkpath PLAN_SPEC), each target is also checked against its plan:
    `lastSignals()` must return the planned signals, and the classes of `bytecode` signals must be rewritten.
    With `fuzz_classes`, a target's test class must be one of them (the fuzz tests written before repair).
    Returns {"ok": True|False, "launch": [...], "build": {...}, "targets": [...]}, or
    {"ok": None, "error": ...} if the validator itself could not run.
    """
    run_dir = Path(run_dir).resolve()
    jar = ensure_jar()
    if jar is None:
        return {"ok": None, "error": "validate-artifact.jar is unavailable (needs Java 17+ and Maven)"}
    java = shutil.which("java")
    if java is None:
        return {"ok": None, "error": "java not found on PATH"}
    launcher = guidance_launch.ensure_launcher_jar()
    if launcher is None:
        return {"ok": None, "error": "campaign-launcher.jar is unavailable (mvn -f tools/launch/pom.xml package)"}

    report: dict[str, Any] = {"ok": False, "launch": [], "build": {}, "targets": []}
    if limits:
        exec_timeout_ms = int(limits["timeout_ms"])
        report["limits"] = limits
    spec, problems = load_launch(run_dir)
    report["launch"] = problems
    if problems:
        return report

    # The campaign builds a copy of the run directory without its build outputs (see README.md), so the
    # validation does the same: an artifact that works only with outputs left from the agent's own builds (e.g. a
    # dependency directory it filled by hand) fails here instead of in the campaign. Repairs edit the run directory.
    with tempfile.TemporaryDirectory(prefix="validate-") as tmp:
        build_dir = guidance_launch.copy_for_build(run_dir, Path(tmp) / "run")
        build = guidance_launch.run_build(build_dir, spec, build_timeout)
        if not build["ok"]:
            report["build"] = {**build, "output": _tail(build["output"])}
            return report
        report["build"] = {"ok": True}

        classpath, failure = guidance_launch.class_path(build_dir, spec, build_timeout)
        if failure:
            report["build"] = {**failure, "output": _tail(failure["output"])}
            return report
        agent = spec.get("javaagent")
        if agent and not (build_dir / agent["jar"]).exists():
            report["build"] = {"ok": False, "command": "(after build)",
                               "output": f"the javaagent jar {agent['jar']} does not exist after the build commands"}
            return report

        for entry in entries:
            tid = entry["id"]
            t = spec["targets"].get(tid)
            if not isinstance(t, dict) or not t.get("test_class") or not t.get("method"):
                report["targets"].append({"target": tid, "ok": False, "checks": [{
                    "name": "contract", "status": "fail",
                    "detail": f'analysis/launch.json has no "targets"["{tid}"] with "test_class" and "method"'}]})
                continue
            entry_method = _entry_mismatch(entry, t)
            if entry_method:
                report["targets"].append({"target": tid, "ok": False, "checks": [{
                    "name": "contract", "status": "fail",
                    "detail": f'analysis/launch.json runs target {tid} with {t["test_class"]}#{t["method"]}, but its '
                              f'attack path (target register) starts at the harness method {entry_method}; '
                              f'run the target with that method'}]})
                continue
            if fuzz_classes and t["test_class"] not in fuzz_classes:
                report["targets"].append({"target": tid, "ok": False, "checks": [{
                    "name": "contract", "status": "fail",
                    "detail": f'"test_class" {t["test_class"]} is not one of the fuzz tests written in Block 3 '
                              f'({", ".join(sorted(fuzz_classes))}); the fuzz tests cannot be replaced during repair'}]})
                continue
            out = Path(tmp) / f"{tid}.json"
            planned_signals, planned_classes = _planned(plan, tid)
            # The JVM as in the campaign (scripts/guidance_launch.py): the agent, then the launcher and the subject
            # class path on the system class path; ValidateArtifact (observer agent and main class) comes last.
            jvm_args = limits["jvm_args"] if limits else spec.get("jvm_args") or []
            base = [java, *[str(a) for a in jvm_args], *guidance_launch.javaagent_args(build_dir, spec),
                    f"-javaagent:{jar}", *guidance_launch.system_class_path(launcher, classpath, str(jar)),
                    "dosguide.validate.ValidateArtifact",
                     "--factory", spec["guidance_factory"], "--target", tid,
                     "--test-class", t["test_class"], "--method", t["method"],
                     "--exec-timeout-ms", str(exec_timeout_ms)]
            if agent:
                base.append("--agent")
            cmd = base + ["--intended", ",".join(planned_classes or _intended_classes(entry)),
                          "--planned-signals", ",".join(planned_signals),
                          "--planned-classes", ",".join(planned_classes),
                          "--own", str(own), "--random", str(random),
                          "--out", str(out), "--work", str(Path(tmp) / f"work-{tid}")]
            if limits:
                cmd += ["--max-input-bytes", str(limits["max_input_bytes"])]
            if (build_dir / EXAMPLES_DIR).is_dir():
                cmd += ["--examples", str(build_dir / EXAMPLES_DIR)]
            growth_ok = progress_only
            if progress_only:
                result: dict[str, Any] = {"ok": True, "checks": []}
            else:
                result = _run_validator(cmd, build_dir, out, target_timeout)
            # The input-limit probe, in a JVM of its own: the guidance reads the property when it is created.
            if not progress_only and limits and any(c.get("name") == "runs" and c.get("status") == "pass"
                                                    for c in result.get("checks", [])):
                probe_out = Path(tmp) / f"{tid}.input-limit.json"
                probe = _run_validator(base + ["--own", str(PROBE_OWN), "--probe-input-limit", str(PROBE_INPUT_LIMIT),
                                               "--out", str(probe_out), "--work", str(Path(tmp) / f"probe-{tid}")],
                                       build_dir, probe_out, target_timeout)
                check = next((c for c in probe.get("checks", []) if c.get("name") == "input_limit"), None) or {
                    "name": "input_limit", "status": "fail",
                    "detail": "the input-limit probe produced no verdict: " + str(
                        probe.get("error") or next((c["detail"] for c in probe.get("checks", [])
                                                    if c.get("status") == "fail"), "unknown error"))}
                result.setdefault("checks", []).append(check)
                result["input_limit_probe"] = {k: probe.get(k) for k in ("max_input_bytes", "longest_input",
                                                                         "executions", "error") if k in probe}
                if check.get("status") == "fail":
                    result["ok"] = False
                # The growth probe, also in a JVM of its own (a fresh guidance, as at the start of a campaign run).
                need = needed_input_bytes(entry, limits)
                if need:
                    growth_out = Path(tmp) / f"{tid}.growth.json"
                    growth = _run_validator(base + ["--max-input-bytes", str(limits["max_input_bytes"]),
                                                    "--probe-growth", str(need), "--budget-ms", str(GROWTH_BUDGET_MS),
                                                    "--out", str(growth_out), "--work", str(Path(tmp) / f"growth-{tid}")],
                                            build_dir, growth_out, target_timeout)
                    check = next((c for c in growth.get("checks", []) if c.get("name") == "input_growth"), None) or {
                        "name": "input_growth", "status": "fail",
                        "detail": "the growth probe produced no verdict: " + str(
                            growth.get("error") or next((c["detail"] for c in growth.get("checks", [])
                                                         if c.get("status") == "fail"), "unknown error"))}
                    result.setdefault("checks", []).append(check)
                    result["growth_probe"] = {k: growth.get(k) for k in ("needed_input_bytes", "longest_input",
                                                                         "executions", "growth", "error") if k in growth}
                    if check.get("status") == "fail":
                        result["ok"] = False
                growth_ok = check.get("status") != "fail"
            embedded = series_embedded(run_dir, tid) if progress or progress_only else []
            if embedded:
                result.setdefault("checks", []).append({
                    "name": "series_embedded", "status": "fail",
                    "detail": "; ".join(embedded) + f" ({SERIES_ROOT_TEXT}/{tid}/). The size series is for measuring "
                              "growth only ([R23]): remove it from the guidance and let the search build such inputs"})
                result["ok"] = False
            # The progress probe, in a JVM of its own as well: the guidance's own inputs first, then the series. Its
            # check is advisory: `hard_ok` is the verdict without it (the runner drops targets by `hard_ok`).
            result["hard_ok"] = bool(result.get("ok"))
            series = progress_series(run_dir, tid) if (progress or progress_only) and limits and growth_ok else []
            if series:
                listing = Path(tmp) / f"{tid}.series.txt"
                listing.write_text("".join(f"{f.resolve()}\n" for f in series), encoding="utf-8")
                progress_out = Path(tmp) / f"{tid}.progress.json"
                probe = _run_validator(base + ["--max-input-bytes", str(limits["max_input_bytes"]),
                                               "--probe-progress", str(listing), "--budget-ms", str(PROGRESS_BUDGET_MS),
                                               "--out", str(progress_out), "--work", str(Path(tmp) / f"progress-{tid}")],
                                       build_dir, progress_out, target_timeout)
                check, comparison = progress_check(probe, tid, primary_signal(plan, tid),
                                                   needed_input_bytes(entry, limits))
                result.setdefault("checks", []).append(check)
                result["progress_probe"] = {**{k: (probe.get("progress") or {}).get(k)
                                               for k in ("own_ms", "executions", "longest_input", "phase")},
                                            "series_inputs": len(series), "comparison": comparison,
                                            "measurements": probe.get("progress"),
                                            **({"error": probe["error"]} if probe.get("error") else {})}
                if check.get("status") == "fail":
                    result["ok"] = False
            result["target"] = tid
            report["targets"].append(result)
    report["ok"] = bool(report["targets"]) and all(t.get("ok") for t in report["targets"])
    report["hard_ok"] = bool(report["targets"]) and all(t.get("hard_ok", t.get("ok")) for t in report["targets"])
    return report


def _run_validator(cmd: list[str], run_dir: Path, out: Path, timeout: int) -> dict[str, Any]:
    """Run one ValidateArtifact JVM and return its report (a failing `runs` check if it wrote none)."""
    try:
        proc = subprocess.run(cmd, cwd=run_dir, capture_output=True, text=True, timeout=timeout)
        stderr = proc.stderr
    except subprocess.TimeoutExpired:
        stderr = f"timed out after {timeout}s"
    if out.exists():
        return json.loads(out.read_text(encoding="utf-8"))
    # The causes, e.g. "Caused by: java.lang.NoClassDefFoundError: ...", rather than the end of a stack trace.
    causes = list(dict.fromkeys(line.strip() for line in stderr.splitlines()
                                if re.search(r"Caused by:|Error:|Exception in thread|FATAL ERROR", line)))
    detail = "; ".join(causes)[:800] if causes else _tail(stderr, 800)
    return {"ok": False, "checks": [{"name": "runs", "status": "fail",
                                     "detail": "the validation JVM produced no report: " + detail}]}


def summarize(report: dict[str, Any]) -> str:
    """One line per target, for logs."""
    if report.get("ok") is None:
        return f"[Validate] not run: {report.get('error')}"
    if report.get("launch"):
        return "[Validate] launch.json: " + "; ".join(report["launch"])
    if report.get("build", {}).get("ok") is False:
        return f"[Validate] build failed: {report['build'].get('command')}"
    lines = []
    for t in report.get("targets", []):
        bad = [c["name"] for c in t.get("checks", []) if c.get("status") == "fail" and not c.get("advisory")]
        advisory = [c["name"] for c in t.get("checks", []) if c.get("status") == "fail" and c.get("advisory")]
        lines.append(f"[Validate] {t['target']}: {'PASS' if t.get('hard_ok', t.get('ok')) else 'FAIL'}"
                     + (f" ({', '.join(bad)})" if bad else "")
                     + (f" (advisory: {', '.join(advisory)})" if advisory else ""))
    return "\n".join(lines)


def repair_prompt(report: dict[str, Any], plan: bool = False, notes: list[str] | None = None,
                  fuzz_tests_fixed: bool = True, plan_spec: str = "") -> str:
    """Message asking the synthesis agent to fix what the validation rejected.

    `plan`: the artifacts are checked against a guidance plan, which the agent may revise in its reply.
    `plan_spec`: the plan's format (tools/checkpath PLAN_SPEC), shown so that a revision can be read.
    `notes`: what happened to the previous repair (reverted fuzz tests, a rejected plan revision).
    `fuzz_tests_fixed`: the build has succeeded once, so the fuzz tests may no longer change.
    """
    limits = report.get("limits")
    parts = [
        "VALIDATION: DoSGuide built your workspace and ran each target's fuzz test with your guidance on a short "
        "series of inputs (inputs your guidance generated, repeats of them, and random inputs), reading "
        "`lastSignals()` after every execution. The checks are: the build succeeds; the javaagent rewrites the "
        "classes it is meant to instrument; the signal varies across inputs; re-running an input gives the same "
        "value (counters are reset before each execution); and the signal stays near zero when the target is not "
        "executed (it is measured during the execution, not computed from the input)."
        + (" With the fixed evaluation limits, the runs use their JVM options and input size limit, a second "
           f"short run with `jqf.ei.MAX_INPUT_SIZE` set to {PROBE_INPUT_LIMIT} checks that the guidance generates "
           f"no longer input (`input_limit`), a third run of at most {GROWTH_BUDGET_MS // 1000} s checks that it "
           "generates an input as long as the target register's `input_bytes` (`input_growth`), and a fourth run "
           f"of {PROGRESS_BUDGET_MS // 1000} s compares the signal on its own long inputs with your Block 1 size "
           "series at the same length (`progress`)." if limits else "")
        + (" With your guidance plan, `lastSignals()` must also return the planned signal names, and the javaagent "
           "must rewrite the classes of the plan's `bytecode` signals." if plan else "")
        + " Some checks failed:",
        "",
    ]
    if notes:
        parts += ["About your previous repair:", *[f"  - {n}" for n in notes], ""]
    if report.get("launch"):
        parts.append("analysis/launch.json:")
        parts += [f"  - {p}" for p in report["launch"]]
        parts += ["", "Expected format:", LAUNCH_SPEC, ""]
    elif report.get("build", {}).get("ok") is False:
        b = report["build"]
        parts += [f"The build failed at `{b.get('command')}`:", "```", b.get("output", ""), "```", ""]
    else:
        for t in report.get("targets", []):
            if t.get("ok"):
                continue
            parts.append(f"Target {t['target']}:")
            if t.get("error"):
                parts.append(f"  - the validator stopped with {t['error']}")
            for c in t.get("checks", []):
                if c.get("status") == "fail":
                    parts.append(f"  - {c['name']}: {c['detail']}")
            for c in t.get("checks", []):
                if c.get("status") == "warn":
                    parts.append(f"  - (warning) {c['name']}: {c['detail']}")
            sig = t.get("signals")
            if sig:
                parts.append("  - observed signal values: " + ", ".join(
                    f"`{k}` {v['min']}..{v['max']} ({v['distinct']} distinct)" for k, v in sig.items()))
            parts.append("")
    fuzz_test_rule = (
        "Do not change the fuzz tests (the classes with @Fuzz methods), which hold the oracles, or the frozen "
        "harness if there is one: DoSGuide restores them if they change."
        if fuzz_tests_fixed else
        "You may edit the fuzz tests (the classes with @Fuzz methods) only as far as needed to make them compile; do "
        "not change what they check, since they hold the oracles. Once the build succeeds they are fixed, and "
        "DoSGuide restores them if they change later. A frozen harness cannot be changed.")
    parts += [
        "Fix the guidance, the javaagent, the runner or analysis/launch.json so that these checks pass. Keep the "
        f"target IDs. {fuzz_test_rule} Do not add seed inputs, dictionaries or generators that encode a specific "
        "failure-inducing input (seed inputs may be ordinary well-formed examples of the input format).",
    ]
    if plan:
        parts += [
            "If a check fails because the guidance plan itself is wrong, for example because it names a class or "
            "method where the cost is not incurred, also revise the plan: include the complete corrected plan for "
            "every target in your reply, in the Block 2 format, between BEGIN_GUIDANCE_PLAN_JSON and "
            "END_GUIDANCE_PLAN_JSON. DoSGuide checks a revised plan with PlanCheck and, if it passes, validates "
            "against it. Do not include a plan if it does not need to change."
            + (" A plan in any other shape cannot be read and is ignored. The format:" if plan_spec else ""),
        ]
        if plan_spec:
            parts.append(plan_spec)
    parts += ["When you are done, reply with a short summary of what you changed; DoSGuide will run the validation "
              "again."]
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate synthesized guidance in a run directory by execution.")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--register", help="target_register.json (default: <run-dir>/analysis/target_register.json)")
    ap.add_argument("--plan", help="guidance_plan.json (default: <run-dir>/analysis/guidance_plan.json if present)")
    ap.add_argument("--own", type=int, default=40)
    ap.add_argument("--random", type=int, default=40)
    ap.add_argument("--oracle", help="the subject's oracle.json: run with its fixed evaluation limits")
    ap.add_argument("--no-progress", action="store_true", help="leave out the progress probe")
    ap.add_argument("--progress-only", action="store_true", help="run only the progress probe (needs --oracle)")
    ap.add_argument("--json", action="store_true", help="print the full JSON report")
    ap.add_argument("--repair-prompt", action="store_true", help="print the repair message if validation fails")
    args = ap.parse_args()

    run_dir = Path(args.run_dir)
    reg = Path(args.register) if args.register else run_dir / "analysis" / "target_register.json"
    entries = json.loads(reg.read_text(encoding="utf-8"))["ordered_targets"]
    plan_path = Path(args.plan) if args.plan else run_dir / "analysis" / "guidance_plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.exists() else None
    limits = None
    if args.oracle:
        sys.path.insert(0, str(HERE.parent.parent / "scripts"))
        import oracle_config  # noqa: E402
        cfg = oracle_config.load(args.oracle)
        limits = {"jvm_args": list(cfg["jvm_args"]), "timeout_ms": int(cfg["timeout_ms"]),
                  "max_input_bytes": int(cfg["max_input_bytes"])}
    report = run_validation(run_dir, entries, own=args.own, random=args.random, plan=plan, limits=limits,
                            progress=not args.no_progress, progress_only=args.progress_only)
    print(json.dumps(report, indent=2, ensure_ascii=False) if args.json else summarize(report))
    if args.repair_prompt and report.get("ok") is False:
        print("\n" + repair_prompt(report))
    if report.get("ok") is None:
        return 2
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
