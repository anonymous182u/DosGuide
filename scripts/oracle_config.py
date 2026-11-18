#!/usr/bin/env python3
"""
The per-subject oracle settings that every engine uses (benchmarks/<subject>/oracle.json).

Missing fields take the evaluation defaults: a 20 s per-execution timeout, -Xmx1g -Xss1m, and at most 10,240
input bytes per execution (JQF's default for Zest). See README.md for how the launcher applies them.

The optional "fixed" entry names the fixed version of the library under test: {"lib": class path of its jars,
relative to the oracle.json's directory (e.g. "fixed/lib/*"), "drop": regex of the file names of the fuzz test's
class path entries those jars replace}. With it the launcher counts a failure only if the fixed version does not
fail on the same input (--fixed-lib, --fixed-drop). load() returns "lib" as an absolute class path.

Usage from a shell script:
    eval "$(python3 scripts/oracle_config.py benchmarks/<subject>/oracle.json --shell)"
    # defines ORACLE_TIMEOUT_MS, ORACLE_JVM_ARGS (space separated), ORACLE_MAX_INPUT_BYTES,
    # and ORACLE_FIXED_LIB, ORACLE_FIXED_DROP (empty without "fixed"); pass them to the launcher as
    # ${ORACLE_FIXED_LIB:+--fixed-lib "$ORACLE_FIXED_LIB" --fixed-drop "$ORACLE_FIXED_DROP"}
"""
from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {"timeout_ms": 20000, "jvm_args": ["-Xmx1g", "-Xss1m"], "max_input_bytes": 10240,
                             "fixed": None}


def load(path: str | Path) -> dict[str, Any]:
    """The settings in `path`, with defaults for missing fields (all defaults if the file does not exist)."""
    cfg = dict(DEFAULTS)
    p = Path(path)
    if p.is_file():
        cfg.update({k: v for k, v in json.loads(p.read_text(encoding="utf-8")).items() if k in DEFAULTS})
    fixed = cfg.get("fixed")
    if fixed:
        lib = ":".join(_absolute(e, p.parent) for e in str(fixed["lib"]).split(":") if e)
        cfg["fixed"] = {"lib": lib, "drop": str(fixed["drop"])}
    return cfg


def _absolute(entry: str, base: Path) -> str:
    """A class path entry relative to `base` made absolute; a trailing `dir/*` stays a wildcard."""
    path = Path(entry)
    if path.is_absolute():
        return entry
    if path.name == "*":
        return str((base / path.parent).resolve() / "*")
    return str((base / path).resolve())


def fixed_args(cfg: dict[str, Any]) -> list[str]:
    """The launcher options for the fixed version, or nothing."""
    f = cfg.get("fixed")
    return ["--fixed-lib", f["lib"], "--fixed-drop", f["drop"]] if f else []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    ap.add_argument("oracle_json")
    ap.add_argument("--shell", action="store_true", help="print shell variable assignments instead of JSON")
    args = ap.parse_args()
    cfg = load(args.oracle_json)
    if args.shell:
        print(f"ORACLE_TIMEOUT_MS={int(cfg['timeout_ms'])}")
        print(f"ORACLE_JVM_ARGS={shlex.quote(' '.join(cfg['jvm_args']))}")
        print(f"ORACLE_MAX_INPUT_BYTES={int(cfg['max_input_bytes'])}")
        print(f"ORACLE_FIXED_LIB={shlex.quote((cfg['fixed'] or {}).get('lib', ''))}")
        print(f"ORACLE_FIXED_DROP={shlex.quote((cfg['fixed'] or {}).get('drop', ''))}")
    else:
        print(json.dumps(cfg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
