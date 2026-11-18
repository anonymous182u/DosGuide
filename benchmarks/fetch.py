#!/usr/bin/env python3
"""Fetches the parts of the benchmark fixtures that are not in this folder: the library under test, built from the
subject's vulnerable commit, and the fixed release for the fixed-version check.

Each subject folder holds the fixture's own files: `oracle.json` (evaluation limits and the fixed version), the fuzz
harness (`src/`) and `pom.xml`. Its `build.json` says how to obtain the rest:

  clone_url, commit   the project's repository and the vulnerable commit
  jdk                 the JDK major version the build uses (8, 17 or 21); a recipe that also needs another one uses
                      $JDK8/$JDK17/$JDK21 and names it in `tools`
  linux_only          true if the build needs Linux x86_64 (native code), with `system_packages` to install first;
                      the native library is rebuilt from the commit too, but only the .class entries are compared
  commands            shell commands of the project's own build, run with bash in a work directory whose `src/` is the
                      checkout at `commit`; environment: JAVA_HOME (the JDK above, first on PATH), JDK8/JDK17/JDK21
                      (each one given), LIB (the subject's lib/ directory), SUBJECT
  artifacts           the jars of the build: `built` (path in the work directory), `lib` (path in the subject folder),
                      `sha256` (the fixture's jar) and `classes_sha256` (digest of its .class entries); optional
                      `classes_exclude`: .class entries left out of the digest (a class that embeds the build time)
  sources             (instead of a build, for a fixture whose pom compiles project files itself) files copied from
                      the checkout: `from` (path in the work directory), `to` (path in the subject folder), `sha256`
  fixed               the fixed release: the coordinates of its jars (group:artifact:version[:classifier], from Maven
                      Central unless the jar names another `repo`), their sha256, and the file-name regex of the class
                      path entries they replace (`drop`); `oracle.json` refers to them as fixed/lib/*

A rebuilt jar is not byte-identical to the evaluation's (manifests and timestamps differ), so the check compares its
.class entries: `classes_sha256` is the sha256 of the sorted lines "<entry name> <sha256 of the entry>" of all .class
entries except those in `classes_exclude`. The fixed jars are downloaded from Maven Central and must match their sha256 exactly.

Usage:
  python3 benchmarks/fetch.py --all --jdk8 <home> --jdk17 <home> [--jdk21 <home>]
  python3 benchmarks/fetch.py snappy-java_GHSA-55g7-9cwv-5qfv --jdk17 <home>
Options: --work DIR (checkouts and build trees, default benchmarks/.work), --out DIR (write lib/ and fixed/ under
DIR/<subject>/ instead of the subject folder), --skip-lib / --skip-fixed, --keep-going.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CENTRAL = "https://repo1.maven.org/maven2"


def classes_digest(jar: Path, exclude: list[str] | tuple[str, ...] = ()) -> tuple[str, int]:
    """sha256 of the sorted "<name> <sha256>" lines of the jar's .class entries not in `exclude`, and their number."""
    lines = []
    with zipfile.ZipFile(jar) as z:
        for info in z.infolist():
            if info.filename.endswith(".class") and not info.is_dir() and info.filename not in exclude:
                lines.append(f"{info.filename} {hashlib.sha256(z.read(info)).hexdigest()}")
    lines.sort()
    return hashlib.sha256("\n".join(lines).encode()).hexdigest(), len(lines)


def class_entries(jar: Path) -> dict[str, str]:
    with zipfile.ZipFile(jar) as z:
        return {i.filename: hashlib.sha256(z.read(i)).hexdigest() for i in z.infolist()
                if i.filename.endswith(".class") and not i.is_dir()}


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str] | str, cwd: Path, env: dict[str, str] | None = None, shell: bool = False) -> None:
    print(f"  $ {cmd if shell else ' '.join(cmd)}", flush=True)
    subprocess.run(["bash", "-euo", "pipefail", "-c", cmd] if shell else cmd, cwd=cwd, env=env, check=True)


def checkout(spec: dict, work: Path) -> None:
    src = work / "src"
    if not (src / ".git").exists():
        work.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--filter=blob:none", "--no-checkout", "--quiet", spec["clone_url"], "src"], work)
    run(["git", "-C", "src", "fetch", "--quiet", "--tags", "origin"], work)
    run(["git", "-C", "src", "checkout", "--quiet", "--force", spec["commit"]], work)
    head = subprocess.run(["git", "-C", "src", "rev-parse", "HEAD"], cwd=work, capture_output=True, text=True,
                          check=True).stdout.strip()
    if head != spec["commit"]:
        raise SystemExit(f"checkout is at {head}, not {spec['commit']}")


def build_lib(subject: str, spec: dict, work: Path, out: Path, jdks: dict[int, str]) -> bool:
    if spec.get("linux_only") and (platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64")):
        print(f"  needs Linux x86_64 (native code); system packages: {', '.join(spec.get('system_packages', []))}")
        return False
    jdk = jdks.get(int(spec["jdk"]))
    if not jdk:
        print(f"  needs JDK {spec['jdk']} (--jdk{spec['jdk']})")
        return False
    checkout(spec, work)
    ok = True
    for f in spec.get("sources", []):  # project source files the fixture's own build compiles
        dest = out / f["to"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(work / f["from"], dest)
        same = sha256(dest) == f["sha256"]
        ok &= same
        print(f"  {f['to']}: {'identical to' if same else 'differs from'} the evaluation's copy")
    lib = out / "lib"
    lib.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, JAVA_HOME=jdk, PATH=f"{jdk}/bin:{os.environ['PATH']}", LIB=str(lib), SUBJECT=subject)
    env.update({f"JDK{k}": v for k, v in jdks.items()})
    for c in spec.get("commands", []):
        run(c, work, env=env, shell=True)
    for a in spec.get("artifacts", []):
        built, dest = work / a["built"], out / a["lib"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, dest)
        exclude = a.get("classes_exclude", [])
        digest, n = classes_digest(dest, exclude)
        if digest == a["classes_sha256"]:
            skipped = f" ({len(exclude)} excluded: {', '.join(exclude)})" if exclude else ""
            print(f"  {a['lib']}: {n} classes identical to the evaluation's jar{skipped}")
        else:
            ok = False
            print(f"  {a['lib']}: .class entries differ from the evaluation's jar (digest {digest[:16]}, {n} classes; "
                  f"expected {a['classes_sha256'][:16]})")
    return ok


def fetch_fixed(spec: dict, out: Path) -> bool:
    fixed = spec.get("fixed")
    if not fixed:
        print("  no fixed version")
        return True
    d = out / "fixed" / "lib"
    d.mkdir(parents=True, exist_ok=True)
    ok = True
    for j in fixed["jars"]:
        parts = j["coords"].split(":")  # group:artifact:version[:classifier]
        g, a, v = parts[:3]
        name = f"{a}-{v}-{parts[3]}.jar" if len(parts) > 3 else f"{a}-{v}.jar"
        dest = d / name
        if not dest.exists() or sha256(dest) != j["sha256"]:
            url = f"{j.get('repo', CENTRAL)}/{g.replace('.', '/')}/{a}/{v}/{name}"
            print(f"  downloading {url}", flush=True)
            with urllib.request.urlopen(url, timeout=120) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f)
        if sha256(dest) != j["sha256"]:
            ok = False
            print(f"  fixed/lib/{name}: sha256 differs from the evaluation's")
        else:
            print(f"  fixed/lib/{name}: identical")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch the library under test and the fixed release of the fixtures.")
    ap.add_argument("subjects", nargs="*")
    ap.add_argument("--all", action="store_true")
    for k in (8, 17, 21):
        ap.add_argument(f"--jdk{k}", help=f"JAVA_HOME of a JDK {k}")
    ap.add_argument("--work", type=Path, default=HERE / ".work")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--skip-lib", action="store_true")
    ap.add_argument("--skip-fixed", action="store_true")
    ap.add_argument("--keep-going", action="store_true")
    args = ap.parse_args()
    subjects = sorted(p.parent.name for p in HERE.glob("*/build.json")) if args.all else args.subjects
    if not subjects:
        ap.error("name subjects or give --all")
    jdks = {k: getattr(args, f"jdk{k}") for k in (8, 17, 21) if getattr(args, f"jdk{k}")}
    status = {}
    for s in subjects:
        spec = json.loads((HERE / s / "build.json").read_text(encoding="utf-8"))
        out = (args.out.resolve() / s) if args.out else HERE / s
        print(f"== {s}", flush=True)
        try:
            lib_ok = True if args.skip_lib else build_lib(s, spec, args.work.resolve() / s, out, jdks)
            fixed_ok = True if args.skip_fixed else fetch_fixed(spec, out)
            status[s] = "ok" if lib_ok and fixed_ok else "check"
        except (subprocess.CalledProcessError, OSError, KeyError) as e:
            status[s] = f"error: {e}"
            print(f"  {status[s]}")
            if not args.keep_going:
                break
    print("\n" + "\n".join(f"{s}: {v}" for s, v in status.items()))
    return 0 if all(v == "ok" for v in status.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
