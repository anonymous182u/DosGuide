#!/usr/bin/env python3
"""
How a synthesized guidance is built and started from its run directory's analysis/launch.json. The validation
(tools/validate/validate.py) and the campaign (scripts/run_guided.py) both use this module, so that they run the
guidance the same way: the same build commands and class path, the javaagent, and the same system class path,
campaign-launcher.jar followed by the subject class path.

The subject class path must be on the system class path because a javaagent is loaded by the system class loader:
there it finds the classes it uses (ASM, its counters, the guidance). With the subject class path only in a child
class loader of the launcher, whose own ASM is relocated, such an agent could not link. The launcher loads the fuzz
test through a child class loader on the same class path; it delegates to the system class loader, so JQF, JUnit
and junit-quickcheck come from the launcher in every engine.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
LAUNCHER_POM = REPO / "tools" / "launch" / "pom.xml"
LAUNCHER_JAR = REPO / "tools" / "launch" / "target" / "campaign-launcher.jar"


# Build outputs that the campaign's copy of a run directory leaves out (see README.md), and with it the
# validation's: both build from the run directory's sources only. Names match at any depth (shutil.ignore_patterns).
BUILD_OUTPUTS = ("target", "out", "build-tmp", ".m2", "node_modules")


def copy_for_build(run_dir: Path, dest: Path) -> Path:
    """Copy a run directory without its build outputs, as the campaign does; returns dest."""
    shutil.copytree(run_dir, dest, symlinks=True, dirs_exist_ok=True, ignore=shutil.ignore_patterns(*BUILD_OUTPUTS))
    return dest


def ensure_launcher_jar() -> Path | None:
    """The campaign launcher jar, built with Maven if it is missing; None if it cannot be built."""
    if LAUNCHER_JAR.exists():
        return LAUNCHER_JAR
    mvn = shutil.which("mvn")
    if mvn is None:
        return None
    subprocess.run([mvn, "-q", "-B", "-f", str(LAUNCHER_POM), "package", "-DskipTests"], capture_output=True, text=True)
    return LAUNCHER_JAR if LAUNCHER_JAR.exists() else None


def run_build(run_dir: Path, spec: dict[str, Any], timeout: int) -> dict[str, Any]:
    """Run launch.json's build commands in the run directory, in order. Returns {"ok": True}, or {"ok": False,
    "command": ..., "output": ...} for the first command that fails or times out."""
    for cmd in spec.get("build") or []:
        try:
            proc = subprocess.run(cmd, shell=True, cwd=run_dir, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"ok": False, "command": cmd, "output": f"timed out after {timeout}s"}
        if proc.returncode != 0:
            return {"ok": False, "command": cmd, "output": proc.stdout + proc.stderr}
    return {"ok": True}


def class_path(run_dir: Path, spec: dict[str, Any], timeout: int) -> tuple[str | None, dict[str, Any] | None]:
    """The fuzz tests' class path: launch.json's "classpath", or the last line "classpath_command" prints, with
    entries relative to the run directory made absolute. Returns (class path, None), or (None, failure) in the
    shape of run_build's result."""
    if spec.get("classpath_command"):
        cmd = spec["classpath_command"]
        try:
            proc = subprocess.run(cmd, shell=True, cwd=run_dir, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, {"ok": False, "command": cmd, "output": f"timed out after {timeout}s"}
        if proc.returncode != 0 or not proc.stdout.strip():
            return None, {"ok": False, "command": cmd,
                          "output": (proc.stdout + proc.stderr) or "the command printed no class path"}
        cp = proc.stdout.strip().splitlines()[-1]
    else:
        cp = str(spec.get("classpath") or "")
    return ":".join(e if not e or Path(e).is_absolute() else str(run_dir / e) for e in cp.split(":")), None


def javaagent_args(run_dir: Path, spec: dict[str, Any]) -> list[str]:
    """The -javaagent option for launch.json's "javaagent", or nothing."""
    agent = spec.get("javaagent")
    if not agent:
        return []
    return [f"-javaagent:{run_dir / agent['jar']}" + (f"={agent['args']}" if agent.get("args") else "")]


def system_class_path(launcher: Path, cp: str, *extra: str) -> list[str]:
    """The -cp option: the launcher first, then the subject class path (and any extra entries)."""
    return ["-cp", ":".join([str(launcher), cp, *extra])]
