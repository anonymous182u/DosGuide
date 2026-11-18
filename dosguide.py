"""
dosguide.py
===========
DoSGuide: synthesizes a JQF guidance for one vulnerability advisory.

A model works through the three blocks of prompt/prompt.txt in one continuous session (ClaudeSDKClient, or
oss_backend.OpenAIAgentSession with --backend openai), so every block can refer to the files read, the analysis
and the decisions of the earlier blocks. After each block DoSGuide checks the output (CheckPath and the scale
probe after Block 1, PlanCheck after Block 2, ValidateArtifact after Block 3) and sends failed checks back for
repair. --no-session runs each block as an independent query() with a truncated summary of the earlier blocks
(sessionless mode).

The environment is set up by install_dependencies.sh (see README.md).
"""

import argparse
import asyncio
import hashlib
import itertools
import json
import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


from prompt_parser import parse_prompt_into_three_parts

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
import oracle_config  # noqa: E402


# ====================================================================
# Workspace write-guard (enforces source_root read-only)
# ====================================================================

def _resolve_tool_path(raw_path: str, cwd: str) -> Path:
    """Resolve a file path from tool input to an absolute Path."""
    p = Path(raw_path)
    if not p.is_absolute():
        p = Path(cwd) / p
    try:
        return p.resolve()
    except (OSError, ValueError):
        return p


def _is_inside(path: Path, root: Path) -> bool:
    """Check if path is inside root directory."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


# Bash patterns that indicate writes outside controlled paths
_BASH_WRITE_PATTERNS = [
    # redirects:  > /some/path   >> /some/path
    r"(?:>{1,2})\s*(\S+)",
    # tee to file
    r"\btee\s+(?:-a\s+)?(\S+)",
    # cp/mv destination (last arg)
    r"\b(?:cp|mv)\b.*\s(\S+)\s*$",
    # install to dir
    r"\binstall\b.*\s(\S+)\s*$",
]


def make_pre_tool_hook(workspace_dir: str, source_root: str, *, allow_execution: bool = True,
                       frozen_files: list[str] | None = None):
    """Create a PreToolUse hook callback that blocks writes outside workspace.

    Hook signature: (input_data, tool_use_id, context) -> dict
    Runs BEFORE the permission system — cannot be bypassed by allowed_tools.

    frozen_files: absolute paths of injected benchmark-fixture files (harness/oracle/
    pom) that must stay immutable so the comparison against Zest/PerfFuzz stays valid.
    """
    ws = Path(workspace_dir).resolve()
    src = Path(source_root).resolve()
    _allow_execution = allow_execution
    _PROJECTS_DIR = Path("projects").resolve()
    _FROZEN = {Path(f).resolve() for f in (frozen_files or [])}

    _BLOCKED_TOOLS = frozenset({
        "WebSearch", "WebFetch", "web_search", "web_fetch",
        "WebBrowse", "web_browse", "Browse", "browse",
        "WebTool", "web_tool", "BrowserTool", "browser_tool",
    })

    def _deny(reason: str) -> dict:
        print(f"  [GUARD] {reason}", file=sys.stderr)
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }

    def _is_in_projects(p: Path) -> bool:
        try:
            p.relative_to(_PROJECTS_DIR)
            return True
        except ValueError:
            return False

    def _check_projects_path_str(raw: str) -> bool:
        normalized = raw.replace("\\", "/").strip("'\"")
        if normalized == "projects" or normalized.startswith("projects/") or normalized.startswith("./projects/"):
            return True
        try:
            return _is_inside(_resolve_tool_path(normalized, workspace_dir), _PROJECTS_DIR)
        except Exception:
            return False

    async def hook(input_data: dict, tool_use_id: str | None, context) -> dict:
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})

        # --- Block ALL web tools ---
        if tool_name in _BLOCKED_TOOLS:
            return _deny(f"BLOCKED: {tool_name} is not permitted. Web access is disabled.")

        # --- Write/Edit/MultiEdit: block projects/ and outside workspace ---
        if tool_name in ("Write", "Edit", "MultiEdit"):
            file_path_raw = tool_input.get("file_path", "")
            if file_path_raw:
                resolved = _resolve_tool_path(file_path_raw, workspace_dir)
                if resolved in _FROZEN:
                    return _deny(
                        f"BLOCKED: {tool_name} targets frozen benchmark fixture "
                        f"'{file_path_raw}'. The harness and oracle are immutable "
                        f"(shared with Zest/PerfFuzz). Synthesize the Guidance (+ measurement "
                        f"agent) only; do not modify the fixture. (pom.xml is editable.)"
                    )
                if _is_inside(resolved, _PROJECTS_DIR):
                    return _deny(
                        f"BLOCKED: {tool_name} targets '{file_path_raw}' inside "
                        f"projects/ directory. Project sources are read-only."
                    )
                if not _is_inside(resolved, ws):
                    return _deny(
                        f"BLOCKED: {tool_name} targets '{file_path_raw}' which resolves "
                        f"outside workspace ({ws}). Source tree is read-only."
                    )

        # --- Bash checks ---
        if tool_name == "Bash":
            command = tool_input.get("command", "")

            # Block web access
            if re.search(r"\b(curl|wget)\b", command) or re.search(r"https?://", command):
                return _deny("BLOCKED: Bash command attempts web access. Web access is disabled.")

            # Block git
            if re.search(r"\bgit\b", command):
                return _deny("BLOCKED: git is not permitted (prevents patch mining).")

            # Block writes to projects/ and outside workspace
            for pattern in _BASH_WRITE_PATTERNS:
                for m in re.finditer(pattern, command):
                    target_raw = m.group(1).strip("'\"").rstrip(";")
                    
                    if target_raw == "/dev/null":
                        continue
            
                    if _check_projects_path_str(target_raw):
                        return _deny(
                            f"BLOCKED: Bash command writes to '{target_raw}' "
                            f"inside projects/ directory. Project sources are read-only."
                        )
                    if target_raw.startswith("/") or target_raw.startswith("~"):
                        resolved = _resolve_tool_path(target_raw, workspace_dir)
                        if not _is_inside(resolved, ws) and not _is_inside(resolved, src):
                            return _deny(
                                f"BLOCKED: Bash command writes to '{target_raw}' "
                                f"which is outside workspace ({ws})."
                            )

            # Block destructive commands targeting protected dirs
            _DESTRUCTIVE_CMDS = ("rm ", "mv ", "> ", ">> ", "tee ", "chmod ", "chown ", "sed -i", "patch ")
            for protected_dir in (str(_PROJECTS_DIR), str(src)):
                if protected_dir in command:
                    for write_cmd in _DESTRUCTIVE_CMDS:
                        if write_cmd in command and protected_dir in command.split(write_cmd, 1)[-1]:
                            return _deny(
                                f"BLOCKED: Bash command appears to modify protected directory "
                                f"({protected_dir}). Project sources are read-only."
                            )

            # Block destructive Bash targeting a frozen benchmark fixture file.
            for frozen in _FROZEN:
                if str(frozen) in command:
                    for write_cmd in _DESTRUCTIVE_CMDS:
                        if write_cmd in command:
                            return _deny(
                                f"BLOCKED: Bash command appears to modify frozen fixture "
                                f"'{frozen.name}'. The harness/oracle are immutable."
                            )

            # Block test/fuzzer execution if disallowed
            if not _allow_execution:
                if re.search(r"(?<!\w)java(?!c|doc)(\s|$)", command):
                    return _deny("BLOCKED: Java execution is disabled — compile only.")
                if re.search(r"(?<!\w)mvn(\s|$)", command) and re.search(r"\b(test|verify|exec(?::|\b)|surefire|failsafe)\b", command):
                    return _deny("BLOCKED: Maven test/exec is disabled — compile only.")
                if re.search(r"(?<!\w)gradle(\s|$)", command) and re.search(r"\b(test|run)\b", command):
                    return _deny("BLOCKED: Gradle test/run is disabled — compile only.")
                _READ_CMDS = ("grep", "find", "cat", "head", "tail", "wc", "awk", "sed", "less", "more")
                is_read_cmd = any(command.strip().startswith(rc) for rc in _READ_CMDS)
                if not is_read_cmd and re.search(r"\bFuzzRunner\b", command):
                    return _deny("BLOCKED: FuzzRunner execution is disabled — compile only.")

        # Allow — return empty dict
        return {}

    return hook


def audit_workspace_boundary(
    workspace_dir: Path,
    source_root: Path,
    block_label: str,
) -> bool:
    """Post-block check: verify source_root was not modified.

    Returns True if clean, False if violation detected.
    Checks modification times aren't newer than run start.
    """
    violations: list[str] = []

    # Quick scan: check if any files in source_root have mtime after workspace creation
    ws_mtime = workspace_dir.stat().st_mtime

    # We only check 1 level deep for new files (git tracks the rest)
    try:
        for item in source_root.rglob("*"):
            if not item.is_file():
                continue
            try:
                if item.stat().st_mtime > ws_mtime + 1:  # 1s tolerance
                    # Could be a legitimate build artifact — check if inside common build dirs
                    rel = item.relative_to(source_root).as_posix()
                    # Skip known build output directories
                    if any(rel.startswith(d) for d in ("target/", "build/", ".gradle/", "out/", "node_modules/")):
                        continue
                    violations.append(rel)
            except (OSError, ValueError):
                continue
    except (OSError, PermissionError):
        pass  # source_root might not be traversable — skip audit

    if violations:
        print(
            f"  [AUDIT WARNING] After {block_label}, these source_root files were "
            f"modified (possible write violation):",
            file=sys.stderr,
        )
        for v in violations[:10]:
            print(f"    - {v}", file=sys.stderr)
        if len(violations) > 10:
            print(f"    ... and {len(violations) - 10} more", file=sys.stderr)
        return False

    return True


# ====================================================================
# Project Maven coordinate extraction & dependency audit
# ====================================================================

def extract_project_maven_coords(source_root: Path) -> list[tuple[str, str]]:
    """Extract (groupId, artifactId) pairs from the project's own pom.xml files.

    Searches source_root for pom.xml files and extracts the project's own
    coordinates. These are used to prevent the agent from adding the fuzzed
    project as a Maven dependency (which would pull the latest, fixed version
    from Maven Central instead of using the local vulnerable copy).

    Returns a list of (groupId, artifactId) tuples found.
    """
    import xml.etree.ElementTree as ET

    coords: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # Check root pom.xml and immediate child pom.xml files (multi-module)
    pom_candidates = [source_root / "pom.xml"]
    pom_candidates.extend(source_root.glob("*/pom.xml"))

    ns = {"m": "http://maven.apache.org/POM/4.0.0"}

    for pom_path in pom_candidates:
        if not pom_path.is_file():
            continue
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()

            # Try with namespace first, then without
            for prefix in [ns, {}]:
                ns_prefix = "m:" if prefix else ""
                group_el = root.find(f"{ns_prefix}groupId", prefix)
                art_el = root.find(f"{ns_prefix}artifactId", prefix)

                # If groupId is missing, check parent
                if group_el is None:
                    parent = root.find(f"{ns_prefix}parent", prefix)
                    if parent is not None:
                        group_el = parent.find(f"{ns_prefix}groupId", prefix)

                if group_el is not None and art_el is not None:
                    gid = (group_el.text or "").strip()
                    aid = (art_el.text or "").strip()
                    if gid and aid and (gid, aid) not in seen:
                        seen.add((gid, aid))
                        coords.append((gid, aid))
                    break  # found with this namespace variant
        except Exception:
            continue

    return coords


def audit_pom_no_self_dependency(
    workspace_dir: Path,
    project_coords: list[tuple[str, str]],
    block_label: str,
) -> bool:
    """Post-block audit: check that workspace pom.xml does not depend on the fuzzed project.

    The agent must compile against local source via the classpath, not pull a
    (potentially fixed) release from Maven Central.

    Returns True if clean, False if violation detected.
    """
    if not project_coords:
        return True

    import xml.etree.ElementTree as ET

    pom_path = workspace_dir / "pom.xml"
    if not pom_path.is_file():
        return True

    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    violations: list[str] = []

    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()

        for prefix in [ns, {}]:
            ns_prefix = "m:" if prefix else ""
            deps_el = root.find(f".//{ns_prefix}dependencies", prefix)
            if deps_el is None:
                continue

            for dep in deps_el.findall(f"{ns_prefix}dependency", prefix):
                dep_gid_el = dep.find(f"{ns_prefix}groupId", prefix)
                dep_aid_el = dep.find(f"{ns_prefix}artifactId", prefix)
                if dep_gid_el is None or dep_aid_el is None:
                    continue
                dep_gid = (dep_gid_el.text or "").strip()
                dep_aid = (dep_aid_el.text or "").strip()

                for proj_gid, proj_aid in project_coords:
                    # Match groupId exactly; artifactId may be a submodule
                    if dep_gid == proj_gid and dep_aid == proj_aid:
                        dep_ver_el = dep.find(f"{ns_prefix}version", prefix)
                        dep_ver = (dep_ver_el.text or "???").strip() if dep_ver_el is not None else "???"
                        violations.append(f"{dep_gid}:{dep_aid}:{dep_ver}")

            if violations:
                break  # found with this namespace variant
    except Exception:
        pass

    if violations:
        print(
            f"\n  [AUDIT WARNING] After {block_label}, workspace pom.xml depends on the "
            f"fuzzed project itself from Maven Central — this will pull the LATEST "
            f"(likely FIXED) version instead of the local vulnerable source!\n"
            f"  Violating dependencies:",
            file=sys.stderr,
        )
        for v in violations:
            print(f"    - {v}", file=sys.stderr)
        print(
            f"  The fuzz harness MUST compile against local source via <systemPath>, "
            f"source overlay, or classpath — NOT via Maven Central coordinates.",
            file=sys.stderr,
        )
        return False

    return True


# ====================================================================
# Run directory
# ====================================================================

def make_timestamp_run_dir(workspaces_root: Path, project_id: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    pid = os.getpid()
    run_name = f"run-{ts}-{pid}"
    run_dir = (workspaces_root / project_id / run_name).resolve()
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


# ====================================================================
# File manifest tracking
# ====================================================================

@dataclass
class EmittedFile:
    path: str
    role: str
    block: str
    target: str | None = None


_EMITTED_FILES: list[EmittedFile] = []
_CURRENT_BLOCK: str = ""
_CURRENT_BLOCK_IDX: int = 0
_USAGE: list[dict[str, Any]] = []  # one entry per agent query: block, turns used, turn limit reached
# Turn limit of each agent query, by block (--max-turns-block1, --max-turns). The session runs with the largest (the CLI's --max-turns is fixed
# per session); a query of a block with a lower limit that used more turns counts as stopped at its limit, which gives
# the same verdict as a cap: the agent is not told the limit either way.
_TURN_LIMITS: dict[int, int] = {}
# Targets dropped because they still failed a check after its repair rounds (target id -> check). A subject's
# synthesis fails only when no target is left; the remaining blocks work on the others.
_DROPPED: dict[str, str] = {}
_ANALYSIS_DIR: Path | None = None  # the run's analysis/ directory, once known

# Claude Code's replies when the subscription's limit is reached ("You've hit your session limit"; also usage/weekly
# limits) and the API's rate-limit and overload errors. Only these phrases count: an analysis may well talk about
# rate limits.
_SERVICE_LIMIT = re.compile(
    r"Claude AI usage limit|usage limit reached|limit will reset|You.ve hit your [\w ]*limit|"
    r"rate_limit_error|overloaded_error|API Error: (429|529)", re.I)


def _infer_role_from_block(block_name: str, rel_path: str) -> str:
    b = (block_name or "").upper()
    p = rel_path.replace("\\", "/")
    pl = p.lower()

    # 3-block layout:
    #   Block 1: Analysis + Target Selection  (no files expected)
    #   Block 2: Strategy + Project Setup     (pom.xml, meta)
    #   Block 3: Agent + Guidance + Tests + Runner + Replay

    if "BLOCK 2" in b:
        return "pom" if p.endswith("pom.xml") else "meta"
    if "BLOCK 3" in b:
        if "agent" in pl or "javaagent" in pl or "transformer" in pl or "classvisitor" in pl:
            return "agent"
        if "guidance" in pl:
            return "guidance"
        if "readme" in pl:
            return "readme"
        if "audit" in pl or "checklist" in pl:
            return "audit"
        if "replay" in pl:
            return "replay"
        if "runner" in pl:
            return "runner"
        return "tests"

    if p.endswith("pom.xml"):
        return "pom"
    return "unknown"


def _infer_target_from_block(block_name: str) -> str | None:
    m = re.search(r"\b(V\d{1,2}|PKGRISK-?\d{1,2})\b", block_name, flags=re.IGNORECASE)
    return None if not m else m.group(1).upper().replace("PKGRISK", "PkgRisk")


def _infer_target_from_path(rel_path: str) -> str | None:
    p = rel_path.replace("\\", "/")

    # Check each path component (directories + filename) for target IDs.
    # Case-SENSITIVE for V — target IDs use uppercase V1, V2, ...
    # This avoids false positives from lowercase software version numbers
    # in package paths.
    _V_RE = re.compile(r"V(\d{1,2})(?!\d)")
    _PKG_RE = re.compile(r"(?<![A-Za-z0-9])PKGRISK[-_]?(\d{1,2})(?!\d)", re.IGNORECASE)

    for component in p.split("/"):
        m = _V_RE.search(component)
        if m:
            return f"V{m.group(1)}"
        m = _PKG_RE.search(component)
        if m:
            return f"PkgRisk{m.group(1)}"
    return None


def scan_emitted_files(run_root: Path, since: set[str]) -> list[EmittedFile]:
    # Prefixes/suffixes to exclude from emitted file tracking.
    # These are build artifacts or internal metadata, not fuzz harness source.
    _SKIP_PREFIXES = ("analysis/", "target/", "lib/", ".mvn/", "out/")
    _SKIP_SUFFIXES = (".jar", ".class", ".war")
    _SKIP_EXACT = ("run_manifest.json",)

    current_paths: set[str] = set()
    for p in run_root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.resolve().relative_to(run_root).as_posix()
        if any(rel.startswith(pfx) for pfx in _SKIP_PREFIXES):
            continue
        if any(rel.endswith(sfx) for sfx in _SKIP_SUFFIXES):
            continue
        if rel in _SKIP_EXACT:
            continue
        current_paths.add(rel)

    new_paths = sorted(current_paths - since)
    emitted: list[EmittedFile] = []
    for rel_path in new_paths:
        target = _infer_target_from_block(_CURRENT_BLOCK)
        if target is None:
            target = _infer_target_from_path(rel_path)
        emitted.append(
            EmittedFile(
                path=rel_path,
                role=_infer_role_from_block(_CURRENT_BLOCK, rel_path),
                block=_CURRENT_BLOCK,
                target=target,
            )
        )
    return emitted


def _write_run_manifest(out_dir: Path, main_class: str, project_id: str | None,
                        commit: str | None, cwd: str):
    payload: dict[str, Any] = {
        "project_id": project_id,
        "commit": commit,
        "main_class": main_class,
        "cwd": cwd,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": [asdict(f) for f in _EMITTED_FILES],
    }
    (out_dir / "run_manifest.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ====================================================================
# Prompt slicing utils
# ====================================================================

def extract_step1_only(procedure_text: str) -> str:
    m = re.search(r"^\s*Step\s*2\b.*$", procedure_text, flags=re.IGNORECASE | re.MULTILINE)
    if not m:
        return procedure_text.strip()
    return procedure_text[: m.start()].strip()


def extract_between_steps(procedure_text: str, start_step: int, end_step: int | None) -> str:
    start_pat = rf"^\s*Step\s*{start_step}\b.*$"
    m_start = re.search(start_pat, procedure_text, flags=re.IGNORECASE | re.MULTILINE)
    if not m_start:
        return ""
    if end_step is None:
        return procedure_text[m_start.start():].strip()
    end_pat = rf"^\s*Step\s*{end_step}\b.*$"
    m_end = re.search(end_pat, procedure_text, flags=re.IGNORECASE | re.MULTILINE)
    if not m_end:
        return procedure_text[m_start.start():].strip()
    return procedure_text[m_start.start():m_end.start()].strip()


def resolve_main_file(main_class_arg: str, code_paths: list[Path]) -> Path:
    p = Path(main_class_arg)
    if p.exists():
        return p
    rel = Path(*main_class_arg.split("."))
    candidates = []
    for suffix in (".java", ".kt", ".scala"):
        wanted_tail = str(rel) + suffix
        for cp in code_paths:
            if str(cp).endswith(wanted_tail):
                candidates.append(cp)
    if not candidates:
        raise SystemExit(f"[ERROR] --main-class '{main_class_arg}' not found")
    if len(candidates) > 1:
        for c in candidates:
            if "/src/main/" in str(c).replace("\\", "/"):
                return c
        return candidates[0]
    return candidates[0]


def read_file_as_xml_block(path: Path) -> str:
    content = path.read_text(encoding="utf-8", errors="replace")
    return f'<file name="{path.name}" path="{path.as_posix()}">\n{content}\n</file>'


# ====================================================================
# Target register extraction + validation
# ====================================================================

def _normalize_target_id(raw: str | None) -> str | None:
    if not raw:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # Cap at 1-2 digits to avoid matching version strings (e.g. V20221201)
    m = re.search(r"(?i)\bV(\d{1,2})\b", s)
    if m:
        return f"V{int(m.group(1))}"
    m = re.search(r"(?i)\bPKGRISK[-_ ]?(\d{1,2})\b", s)
    if m:
        return f"PkgRisk{int(m.group(1))}"
    return None


def _extract_target_ids(text: str) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    # Cap at 1-2 digits to avoid matching version strings (e.g. V20221201)
    for raw in re.findall(r"(?i)\bV\d{1,2}\b|\bPKGRISK[-_ ]?\d{1,2}\b", text or ""):
        norm = _normalize_target_id(raw)
        if norm and norm not in seen:
            seen.add(norm)
            ids.append(norm)
    return ids


def _as_int(value: Any) -> Any:
    """An integer register value given as a number or a plain digit string (e.g. "4096", "4,096"); anything
    else is kept as it is, for the field check to report."""
    if isinstance(value, str) and re.fullmatch(r"\s*\d[\d,_]*\s*", value):
        return int(re.sub(r"[\s,_]", "", value))
    return value


def _hop_text(hop: Any) -> str:
    """A hop as CheckPath reads it, `Class.method(T1, T2)`, from a string or from an object with `class`, `method`
    and `params` (or `parameters`)."""
    if not isinstance(hop, dict):
        return str(hop).strip()
    cls, method = str(hop.get("class") or "").strip(), str(hop.get("method") or "").strip()
    params = hop.get("params", hop.get("parameters"))
    sig = f"({', '.join(str(x) for x in params)})" if isinstance(params, list) else ""
    return f"{cls}.{method}{sig}" if cls and method else json.dumps(hop, ensure_ascii=False)


def _entrypoint_text(value: Any) -> str:
    """The `entrypoint` chain as one string. A list of hops (strings or objects) is joined with arrows, so that
    CheckPath can read it."""
    if isinstance(value, list):
        return " → ".join(t for t in (_hop_text(h) for h in value) if t)
    return _hop_text(value) if isinstance(value, dict) else str(value or "").strip()


def _sink_text(value: Any) -> str:
    """The `sink` as `Class#method`, also from an object with `class` and `method`, or with only `method` written as
    `Class.method(...)`."""
    if isinstance(value, dict):
        method = re.sub(r"\(.*", "", str(value.get("method") or "")).strip()
        if value.get("class") and method:
            return f"{str(value['class']).strip()}#{method}"
        if "." in method:
            cls, _, name = method.rpartition(".")
            return f"{cls}#{name}"
        return json.dumps(value, ensure_ascii=False)
    return str(value or "").strip()


def _normalize_register_entries(entries: list[dict[str, Any]], max_targets: int = 5) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in entries:
        tid = _normalize_target_id(item.get("id") or item.get("target_id"))
        if not tid or tid in seen:
            continue
        seen.add(tid)
        normalized.append(
            {
                "slot": len(normalized) + 1,
                "id": tid,
                "name": str(item.get("name", "")).strip(),
                "entrypoint": _entrypoint_text(item.get("entrypoint", "")),
                "source_path": str(item.get("source_path", item.get("path", ""))).strip(),
                "sink": _sink_text(item.get("sink", "")),
                "mechanism": str(item.get("mechanism", "")).strip(),
                "resource": str(item.get("resource", "")).strip(),
                "failure_mode": str(item.get("failure_mode", "")).strip().lower(),
                "scale": str(item.get("scale", "")).strip(),
                "input_bytes": _as_int(item.get("input_bytes")),
                "cwe": str(item.get("cwe", "")).strip(),
            }
        )
        if len(normalized) >= max_targets:
            break
    return normalized


def extract_target_register(block2_text: str, *, fallback_text: str = "", max_targets: int = 5) -> list[dict[str, Any]]:
    if block2_text:
        # The JSON may be in a ```json fence; a fenced register must not read as "no complete register".
        m = re.search(
            r"BEGIN_TARGET_REGISTER_JSON\s*(?:```(?:json)?\s*)?(\{.*?\}|\[.*?\])\s*(?:```\s*)?END_TARGET_REGISTER_JSON",
            block2_text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if m:
            try:
                parsed = json.loads(m.group(1))
                if isinstance(parsed, dict):
                    raw_entries = parsed.get("ordered_targets") or parsed.get("targets") or []
                elif isinstance(parsed, list):
                    raw_entries = parsed
                else:
                    raw_entries = []
                if isinstance(raw_entries, list):
                    entries = _normalize_register_entries(raw_entries, max_targets=max_targets)
                    if entries:
                        return entries
            except Exception:
                pass

    ids = _extract_target_ids(block2_text)
    if not ids and fallback_text:
        ids = _extract_target_ids(fallback_text)
    if not ids:
        return []
    raw_entries = [{"id": tid} for tid in ids[:max_targets]]
    return _normalize_register_entries(raw_entries, max_targets=max_targets)


def render_target_register_section(entries: list[dict[str, Any]]) -> str:
    payload = {"ordered_targets": entries}
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _cleanup_failed_block_files(cwd: str, new_files: list[EmittedFile]) -> None:
    run_root = Path(cwd).resolve()
    for ef in new_files:
        try:
            p = (run_root / ef.path).resolve()
            p.relative_to(run_root)
            if p.exists() and p.is_file():
                p.unlink()
        except Exception:
            continue


def validate_target_alignment(
    response_text: str,
    new_files: list[EmittedFile],
    *,
    allowed_targets: set[str],
) -> tuple[bool, str]:
    """Validate that emitted FILES only target allowed targets.

    Text mentions of other targets (e.g. in checklists, justifications,
    audit trails) are allowed — the model legitimately references excluded
    targets to explain *why* they were excluded or subsumed.  Only actual
    file emissions for disallowed targets trigger a hard failure.
    """
    # Hard check: files emitted for disallowed targets
    file_targets = {_normalize_target_id(ef.target) for ef in new_files if ef.target}
    file_targets.discard(None)
    disallowed_files = sorted(t for t in file_targets if t not in allowed_targets)
    if disallowed_files:
        return False, (
            f"Files emitted for disallowed targets: {', '.join(disallowed_files)}. "
            f"Allowed: {', '.join(sorted(allowed_targets))}"
        )

    # Soft check: warn about text mentions but don't fail
    mentioned = {_normalize_target_id(t) for t in _extract_target_ids(response_text)}
    mentioned.discard(None)
    extra_mentions = sorted(t for t in mentioned if t not in allowed_targets)
    if extra_mentions:
        print(
            f"  [Validation] INFO: Text references to non-selected targets "
            f"(OK — prose/audit context): {', '.join(extra_mentions)}",
            file=sys.stderr,
        )

    return True, "ok"


# ====================================================================
# CheckPath: ground the Block 1 attack paths in the source code
# ====================================================================

def _load_checkpath():
    """Import tools/checkpath/checkpath.py, or return None if it is unavailable."""
    cp_dir = Path(__file__).resolve().parent / "tools" / "checkpath"
    if not (cp_dir / "checkpath.py").exists():
        return None
    if str(cp_dir) not in sys.path:
        sys.path.insert(0, str(cp_dir))
    try:
        import checkpath  # type: ignore
        return checkpath
    except Exception as e:  # pragma: no cover - environment-dependent
        print(f"[CheckPath] unavailable: {e}", file=sys.stderr)
        return None


async def _ask_in_session(client: Any, prompt: str, backend: str) -> tuple[str, str, float | None]:
    """Send one more user turn to an open session; returns (full, text-only, cost)."""
    if backend == "openai":
        full, text, _sid, cost = await client.query_block(prompt)
        return full, text, cost
    await client.query(prompt)
    collected: list[Any] = []
    await _collect_response(client.receive_response(), collected)
    _record_usage("repair", collected)
    return _extract_full_response(collected), _extract_text_only(collected), _extract_cost_from_result(collected)


def _register_path(normalized_path: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A CheckPath `normalized_path` as stored in the register. The agent's text of each hop is already in
    `entrypoint`, and a call's evidence restates its two hops and its site, so both are left out here;
    the full report in analysis/checkpath.round<N>.json keeps them."""
    out = []
    for el in normalized_path:
        el = dict(el)
        if el.get("kind") == "hop" and "method" in el:
            el.pop("written", None)
            if el.get("provenance") == "agent":
                el.pop("provenance")
        elif el.get("kind") == "connection" and el.get("type") == "CALL" and el.get("site"):
            el.pop("evidence", None)
        out.append(el)
    return out


def _save_register(analysis_dir: Path, entries: list[dict[str, Any]]) -> None:
    (analysis_dir / "target_register.json").write_text(
        json.dumps({"ordered_targets": entries}, indent=2, ensure_ascii=False), encoding="utf-8")
    (analysis_dir / "target_register.md").write_text(render_target_register_section(entries) + "\n",
                                                     encoding="utf-8")


def _fixed_limits(args: argparse.Namespace) -> dict[str, Any] | None:
    """The subject's fixed evaluation limits (JVM options, per-execution time limit, input size limit) from the
    frozen fixture's oracle.json, the values every engine runs with; None without a frozen fixture. Only these
    values are read: the file's justifications, which describe the vulnerability, stay out of the synthesis."""
    if not getattr(args, "freeze_harness", False):
        return None
    cfg = oracle_config.load(Path(args.benchmarks_root) / args.project_id / "oracle.json")
    return {"jvm_args": list(cfg["jvm_args"]), "timeout_ms": int(cfg["timeout_ms"]),
            "max_input_bytes": int(cfg["max_input_bytes"])}


def render_limits_section(limits: dict[str, Any] | None) -> str:
    """The prompt section with the fixed evaluation limits ([R41])."""
    if not limits:
        return ""
    return ("=== Fixed evaluation limits (this subject; the same for every fuzzer, see [R41]) ===\n"
            f"- JVM options: {' '.join(limits['jvm_args'])}\n"
            f"- Per-execution time limit: {limits['timeout_ms']} ms; an execution that runs longer is a timeout "
            "failure.\n"
            f"- Input size limit: {limits['max_input_bytes']} bytes per execution. Longer inputs are cut to this "
            "length, and the System property jqf.ei.MAX_INPUT_SIZE is set to it.\n\n")


def _harness_dirs(args: argparse.Namespace) -> list[Path]:
    """The frozen fixture's sources, for CheckPath: paths must start at the harness's @Fuzz methods. The
    fixture in benchmarks/ is used rather than its copy in the workspace, where Block 3 adds the agent's code."""
    if not getattr(args, "freeze_harness", False):
        return []
    src = Path(args.benchmarks_root) / args.project_id / "src"
    return [src] if src.is_dir() else []


async def checkpath_gate(
    client: Any,
    args: argparse.Namespace,
    target_entries: list[dict[str, Any]],
    source_root: Path,
    analysis_dir: Path,
) -> tuple[list[dict[str, Any]], float]:
    """Check the Block 1 attack paths with CheckPath, and each target's `resource` and `failure_mode`.

    If a path cannot be grounded or a field is invalid and a session is open, the diagnostics are sent back
    to the agent, which re-reads the source and re-emits the register; this repeats for up to
    --checkpath-rounds rounds. Reports go to analysis/checkpath.round<N>.json and a summary
    to analysis/checkpath.json. Returns the (possibly revised) entries and the extra cost.
    """
    cp = _load_checkpath()
    if cp is None:
        (analysis_dir / "checkpath.json").write_text(
            json.dumps({"final_ok": None, "error": "tools/checkpath is unavailable"}, indent=2), encoding="utf-8")
        if args.checkpath_strict:
            _fail_synthesis(analysis_dir, "checkpath", "CheckPath could not run: tools/checkpath is unavailable")
        return target_entries, 0.0

    extra_cost = 0.0
    history: list[dict[str, Any]] = []
    original_dups: dict[str, Any] | None = None
    format_note = ""  # set when the previous reply had no readable register; sent with the next repair message
    for rnd in range(args.checkpath_rounds + 1):
        report = await asyncio.to_thread(
            cp.run_checkpath, source_root, entries=target_entries, max_gap=args.checkpath_max_gap,
            require_sink=getattr(args, "checkpath_require_sink", False), harness=_harness_dirs(args))
        cp.check_fields(report, target_entries, (getattr(args, "fixed_limits", None) or {}).get("max_input_bytes"))
        (analysis_dir / f"checkpath.round{rnd}.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(cp.summarize(report))
        # A target whose path became a copy of another target's during repair (e.g. a library-level
        # risk rewritten as V1's path) is sent back too, even though CheckPath accepts the path.
        dups = {t["target"]: t.get("duplicate_of") for t in report.get("targets", [])}
        if original_dups is None:
            original_dups = dups
        collapsed = {t: d for t, d in dups.items() if d and not original_dups.get(t)}
        history.append({
            "round": rnd,
            "ok": report.get("ok"),
            "error": report.get("error"),
            "failing": cp.failing_targets(report),
            "collapsed": sorted(collapsed),
        })
        needs_repair = report.get("ok") is False or (report.get("ok") is True and bool(collapsed))
        if not needs_repair or client is None or rnd == args.checkpath_rounds:
            break

        print(f"[CheckPath] returning diagnostics to the agent (repair round {rnd + 1}/{args.checkpath_rounds})"
              + (f"; collapsed targets: {sorted(collapsed)}" if collapsed else ""))
        full, text, cost = await _ask_in_session(
            client, (format_note + "\n\n" if format_note else "") + cp.repair_prompt(report, collapsed), args.backend)
        if cost:
            extra_cost += cost
        (analysis_dir / f".block1.checkpath{rnd + 1}.md").write_text(full, encoding="utf-8")
        revised = extract_target_register(text, max_targets=5) if re.search(
            r"BEGIN_TARGET_REGISTER_JSON", text or "", flags=re.IGNORECASE) else []
        if not revised or not all(e.get("entrypoint") for e in revised):
            # An unreadable reply counts as a round, and the next message asks for the register again.
            print("[CheckPath] the reply has no complete target register; keeping the previous one and asking again")
            format_note = ("Your previous reply had no complete target register that DoSGuide could read, so the "
                           "previous register was checked again. Emit the complete register for every target between "
                           "BEGIN_TARGET_REGISTER_JSON and END_TARGET_REGISTER_JSON, as a JSON list in the same format "
                           "as your Block 1 register: every field, with `entrypoint` as one string of hops joined by "
                           "\" → \".")
            continue
        format_note = ""
        target_entries = revised

    # The last report is for the final entries. Attach each target's resolved path to its entry, so the
    # frozen register and the later blocks that receive it carry every hop's declaration and the
    # connection between consecutive hops, not only the agent's one-line `entrypoint`.
    resolved = {t.get("target"): t for t in report.get("targets", [])}
    for entry in target_entries:
        t = resolved.get(entry.get("id"))
        if t and t.get("normalized_path"):
            entry["checkpath_status"] = t.get("status")
            entry["normalized_path"] = _register_path(t["normalized_path"])
        if t and t.get("harness_entry"):
            entry["harness_entry"] = t["harness_entry"]  # the @Fuzz method the path starts at

    summary = {"final_ok": history[-1]["ok"], "collapsed_final": history[-1].get("collapsed", []),
               "repair_rounds": len(history) - 1, "rounds": history}
    (analysis_dir / "checkpath.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    # Strict, per target: a target whose path or fields still fail is dropped; the subject fails if none is left
    # or if CheckPath could not run (final_ok None).
    if summary["final_ok"] is not True and args.checkpath_strict:
        failing = history[-1].get("failing") or []
        if summary["final_ok"] is None or not failing:
            _save_register(analysis_dir, target_entries)
            _fail_synthesis(analysis_dir, "checkpath",
                            "CheckPath: the target register still fails after the repair rounds"
                            if summary["final_ok"] is False else f"CheckPath could not run: {history[-1].get('error')}",
                            failing)
        _save_register(analysis_dir, target_entries)
        _drop_targets(analysis_dir, "checkpath", target_entries, failing)
    return target_entries, extra_cost


# ====================================================================
# Scale probe: measure how each target's resource use grows (Block 1)
# ====================================================================

def _load_scale():
    """Import tools/validate/scale.py, or return None if it is unavailable."""
    if _load_validate() is None:
        return None
    try:
        import scale  # type: ignore  (tools/validate is on sys.path after _load_validate)
        return scale
    except Exception as e:  # pragma: no cover - environment-dependent
        print(f"[Scale] unavailable: {e}", file=sys.stderr)
        return None


def _scale_enabled(args: argparse.Namespace) -> bool:
    """The scale probe needs the frozen fixture and its fixed limits; --no-scale-probe turns it off."""
    return (not getattr(args, "no_scale_probe", False) and getattr(args, "freeze_harness", False)
            and getattr(args, "fixed_limits", None) is not None and _load_scale() is not None)


async def scale_gate(
    client: Any,
    args: argparse.Namespace,
    target_entries: list[dict[str, Any]],
    run_dir: Path,
    analysis_dir: Path,
) -> tuple[list[dict[str, Any]], float]:
    """Measure the resource growth of every kept target on the agent's size series and let the agent revise `scale`
    and `input_bytes` (tools/validate/scale.py). The agent never learns whether an input fails under the
    evaluation's limits: the probe's caps are below them.

    One message asks for missing or invalid series; the measurements then go back to the agent, which replies with a
    revision (up to --scale-rounds messages until the revised fields pass the field check). A target whose revised
    `input_bytes` still exceeds the input size limit is dropped, as CheckPath's field check would. Outputs:
    analysis/scale_probe.json (measurements), analysis/scale.json (rounds and revisions), .block1.scale*.md."""
    sc, cp = _load_scale(), _load_checkpath()
    limits = args.fixed_limits
    kept = _kept(target_entries)
    extra_cost = 0.0
    summary: dict[str, Any] = {"series_request": None, "rounds": []}

    problems = {e["id"]: ps for e in kept if (ps := sc.series_problems(run_dir, e["id"], limits)[1])}
    if problems and client is not None:
        print(f"[Scale] asking for the size series of {', '.join(problems)}")
        full, _text, cost = await _ask_in_session(client, sc.series_prompt(problems, limits), args.backend)
        extra_cost += cost or 0.0
        (analysis_dir / ".block1.scale_series.md").write_text(full, encoding="utf-8")
        summary["series_request"] = sorted(problems)

    fixture = Path(args.benchmarks_root) / args.project_id
    report = await asyncio.to_thread(sc.run_scale_probe, run_dir, kept, fixture, limits)
    (analysis_dir / "scale_probe.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    measured = [tid for tid, t in report.get("targets", {}).items() if t.get("inputs")]
    print(f"[Scale] measured {', '.join(measured) or 'no target'}"
          + (f"; build: {report['build']}" if report.get("build", {}).get("ok") is False else ""))
    if client is None or not measured:
        (analysis_dir / "scale.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return target_entries, extra_cost

    by_id = {e["id"]: e for e in target_entries}
    prompt = sc.results_prompt(report, kept)
    failing: list[str] = []
    for rnd in range(max(1, getattr(args, "scale_rounds", 2))):
        full, text, cost = await _ask_in_session(client, prompt, args.backend)
        extra_cost += cost or 0.0
        (analysis_dir / f".block1.scale{rnd + 1}.md").write_text(full, encoding="utf-8")
        revision = sc.extract_revision(text)
        if revision is None:
            summary["rounds"].append({"round": rnd + 1, "revision": None})
            prompt = (f"Your reply has no revision between {sc.REVISION_BEGIN} and {sc.REVISION_END}. Reply with the "
                      'revision for every measured target, as JSON: {"V1": {"scale": "...", "input_bytes": <integer>}}.')
            continue
        for tid, fields in revision.items():
            e = by_id.get(tid)
            if e is None or tid in _DROPPED:
                continue
            if str(fields.get("scale") or "").strip():
                e["scale"] = str(fields["scale"]).strip()
            if "input_bytes" in fields:
                e["input_bytes"] = _as_int(fields["input_bytes"])
        field = {e["id"]: ps for e in _kept(target_entries)
                 if (ps := cp.field_problems(e, limits["max_input_bytes"]))} if cp else {}
        summary["rounds"].append({"round": rnd + 1, "revision": revision, "field_problems": field})
        failing = sorted(field)
        if not field:
            break
        prompt = ("The revised fields have problems:\n" + "\n".join(f"  - {t}: {'; '.join(p)}" for t, p in field.items())
                  + f"\nReply with a corrected revision between {sc.REVISION_BEGIN} and {sc.REVISION_END}.")
    for tid, t in report.get("targets", {}).items():
        if tid in by_id and t.get("inputs"):
            by_id[tid]["scale_measurement"] = [
                {k: r.get(k) for k in ("value", "input_bytes", "outcome", "cpu_ms", "allocated_bytes",
                                       "peak_heap_bytes") if r.get(k) is not None} for r in t["inputs"]]
    (analysis_dir / "scale.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    if failing:
        _save_register(analysis_dir, target_entries)
        _drop_targets(analysis_dir, "scale", target_entries, failing)
    return target_entries, extra_cost


# ====================================================================
# PlanCheck: ground the Block 2 guidance plan in the source code
# ====================================================================

async def plan_gate(
    client: Any,
    args: argparse.Namespace,
    plan: dict[str, Any] | None,
    target_entries: list[dict[str, Any]],
    source_root: Path,
    analysis_dir: Path,
) -> tuple[dict[str, Any] | None, float]:
    """Check the Block 2 guidance plan with CheckPath (--plan).

    Every target needs a complete plan whose signal locations resolve to methods in the source tree
    (or to library methods). A missing or failing plan is sent back to the agent with the
    diagnostics, for up to --plan-rounds rounds. Reports go to analysis/plancheck.round<N>.json, a
    summary to analysis/plancheck.json, and the final plan to analysis/guidance_plan.json. Returns
    the (possibly revised) plan and the extra cost.
    """
    cp = _load_checkpath()
    if cp is None:
        (analysis_dir / "plancheck.json").write_text(
            json.dumps({"final_ok": None, "error": "tools/checkpath is unavailable"}, indent=2), encoding="utf-8")
        if args.plan_strict:
            _fail_synthesis(analysis_dir, "plancheck", "PlanCheck could not run: tools/checkpath is unavailable")
        return plan, 0.0

    extra_cost = 0.0
    history: list[dict[str, Any]] = []
    format_note = ""  # set when the previous reply had no readable plan; sent with the next repair message
    for rnd in range(args.plan_rounds + 1):
        report = None
        if plan is None:
            ok: bool | None = False
            print(f"[PlanCheck] the reply has no plan between {cp.PLAN_BEGIN} and {cp.PLAN_END}")
            history.append({"round": rnd, "ok": False, "missing": True})
        else:
            report = await asyncio.to_thread(
                cp.run_checkpath, source_root, entries=target_entries, max_gap=args.checkpath_max_gap, plan=plan,
                harness=_harness_dirs(args))
            (analysis_dir / f"plancheck.round{rnd}.json").write_text(
                json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(cp.plan_summarize(report))
            ok = report.get("plan_ok") if report.get("ok") is not None else None
            history.append({
                "round": rnd,
                "ok": ok,
                "error": report.get("error"),
                "failing": [p["target"] for p in report.get("plans", []) if p.get("status") != "PASS"],
            })
        if ok is not False or client is None or rnd == args.plan_rounds:
            break

        print(f"[PlanCheck] returning diagnostics to the agent (repair round {rnd + 1}/{args.plan_rounds})")
        full, text, cost = await _ask_in_session(
            client, (format_note + "\n\n" if format_note else "") + cp.plan_repair_prompt(report, missing=plan is None),
            args.backend)
        if cost:
            extra_cost += cost
        (analysis_dir / f".block2.plan{rnd + 1}.md").write_text(full, encoding="utf-8")
        revised = cp.extract_plan(text)
        format_note = ""
        if revised is not None:
            plan = revised
        elif plan is not None:
            # An unreadable reply counts as a round, and the next message asks again.
            print("[PlanCheck] the reply has no complete plan; keeping the previous one and asking again")
            format_note = (f"Your previous reply had no complete plan that DoSGuide could read between {cp.PLAN_BEGIN} "
                           f"and {cp.PLAN_END}, so the previous plan was checked again. Include the complete plan for "
                           "every target, in the format below.")

    summary = {"final_ok": history[-1]["ok"], "repair_rounds": len(history) - 1, "rounds": history}
    (analysis_dir / "plancheck.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    # Strict, per target: a target whose plan still fails is dropped; the subject fails if none is left, if there
    # is no plan at all, or if PlanCheck could not run.
    if summary["final_ok"] is not True and args.plan_strict:
        failing = history[-1].get("failing") or []
        if summary["final_ok"] is None or not failing or plan is None:
            if plan is not None:
                (analysis_dir / "guidance_plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False),
                                                                  encoding="utf-8")
            _fail_synthesis(analysis_dir, "plancheck",
                            "PlanCheck: the guidance plan still fails after the repair rounds"
                            if summary["final_ok"] is False else f"PlanCheck could not run: {history[-1].get('error')}",
                            failing)
        _drop_targets(analysis_dir, "plancheck", target_entries, failing)
    if plan is not None:
        plan = {**plan, "plans": [p for p in plan.get("plans", []) if p.get("target") not in _DROPPED]}
        (analysis_dir / "guidance_plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False),
                                                          encoding="utf-8")
    return plan, extra_cost


# ====================================================================
# ValidateArtifact: check the Block 3 artifacts by execution
# ====================================================================

def _load_validate():
    """Import tools/validate/validate.py, or return None if it is unavailable."""
    vd_dir = Path(__file__).resolve().parent / "tools" / "validate"
    if not (vd_dir / "validate.py").exists():
        return None
    if str(vd_dir) not in sys.path:
        sys.path.insert(0, str(vd_dir))
    try:
        import validate  # type: ignore
        return validate
    except Exception as e:  # pragma: no cover - environment-dependent
        print(f"[Validate] unavailable: {e}", file=sys.stderr)
        return None


async def validate_gate(
    client: Any,
    args: argparse.Namespace,
    run_dir: Path,
    target_entries: list[dict[str, Any]],
    analysis_dir: Path,
    plan: dict[str, Any] | None = None,
    source_root: Path | None = None,
) -> float:
    """Validate the Block 3 artifacts by execution with ValidateArtifact.

    The validator (not the agent) builds the workspace and runs each target's fuzz test with the
    synthesized guidance on generated, repeated and random inputs; with the guidance plan it also
    checks that the implementation returns the planned signals and instruments the planned classes.
    If a check fails and a session is open, the diagnostics are sent back to the agent, which fixes
    the code; this repeats for up to --validate-rounds rounds. Whether an input makes the test fail
    is neither part of the verdict nor sent to the agent.

    The fuzz tests (the classes with @Fuzz methods, which hold the oracles) are fixed in the first round
    whose build succeeds: a repair before that may edit them to make them compile; after it, changes to
    them are restored and launch.json may only name those fuzz tests. The agent may revise the
    guidance plan in its reply; a revision that passes PlanCheck (needs `source_root`) replaces the plan
    for the following rounds. Reports go to analysis/validate.round<N>.json, the files each repair
    changed to analysis/validate.repair<N>.json, and a summary to analysis/validate.json. Returns the
    extra cost.
    """
    vd = _load_validate()
    if vd is None:
        (analysis_dir / "validate.json").write_text(
            json.dumps({"final_ok": None, "error": "tools/validate is unavailable"}, indent=2), encoding="utf-8")
        if args.validate_strict:
            _fail_synthesis(analysis_dir, "validate", "ValidateArtifact could not run: tools/validate is unavailable")
        return 0.0

    # The fuzz tests hold the oracles. They are fixed as they are in the first round whose build succeeds; until
    # then a repair may still edit them to make them compile (no input has been executed yet).
    fuzz_tests: dict[str, str] | None = None
    fuzz_classes: set[str] | None = None
    fixed_at: int | None = None
    cp = _load_checkpath() if plan is not None and source_root is not None else None

    extra_cost = 0.0
    history: list[dict[str, Any]] = []
    notes: list[str] = []
    passed: set[str] = set()                       # targets that passed in the state kept so far
    before: dict[str, str] | None = None           # the workspace before the last repair, and its plan
    plan_before = plan
    # The progress check is advisory (tools/validate/validate.py): it never drops a target, and a repair that only it
    # asked for is kept only if it raised the progress of a target it was asked about; otherwise it is undone and no
    # further progress repair is asked for. These are the ratios before such a repair.
    progress_before: dict[str, float] | None = None
    progress_done = False

    def hard_ok(t: dict[str, Any]) -> bool:
        return bool(t.get("hard_ok", t.get("ok")))

    for rnd in range(args.validate_rounds + 1):
        report = await asyncio.to_thread(
            vd.run_validation, run_dir, target_entries, own=args.validate_own, random=args.validate_random,
            plan=plan, fuzz_classes=fuzz_classes, limits=getattr(args, "fixed_limits", None),
            progress=not getattr(args, "no_progress_probe", False))
        (analysis_dir / f"validate.round{rnd}.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(vd.summarize(report))
        if fuzz_tests is None and report.get("build", {}).get("ok") is True:
            fuzz_tests = vd.fuzz_tests(vd.snapshot(run_dir))
            fuzz_classes = vd.declared_classes(fuzz_tests) or None
            fixed_at = rnd
        entry: dict[str, Any] = {
            "round": rnd,
            "ok": report.get("hard_ok", report.get("ok")) if report.get("ok") is not None else None,
            "error": report.get("error"),
            "launch": report.get("launch"),
            "build_ok": report.get("build", {}).get("ok"),
            "failing": [t["target"] for t in report.get("targets", []) if not hard_ok(t)],
            "progress_advisory": vd.progress_ratios(report),
        }
        # A repair must not break a target that passed: if it did, the files and the plan go back to their state
        # before it, which is validated again (so the build outputs match), and the agent is told.
        regressed = sorted(passed - {t["target"] for t in report.get("targets", []) if hard_ok(t)})
        # A repair asked for only by the progress check is undone the same way if no target it was about improved.
        # (A check that is not decided any more, e.g. because an execution now reaches the time limit, counts as raised.)
        now = {t["target"]: c.get("ratio", 1.0) if c.get("status") != "skip" else float("inf")
               for t in report.get("targets", []) for c in t.get("checks", []) if c.get("name") == "progress"}
        unimproved = (progress_before is not None and not regressed and report.get("ok") is not None
                      and not any(now.get(t, 0.0) > r for t, r in progress_before.items()))
        if unimproved and before is not None:
            undone = vd.revert(run_dir, before, vd.snapshot(run_dir))
            plan = plan_before
            if plan is not None:
                (analysis_dir / "guidance_plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False),
                                                                  encoding="utf-8")
            print(f"[Validate] the progress repair did not raise {', '.join(progress_before)}; reverted it")
            report = await asyncio.to_thread(
                vd.run_validation, run_dir, target_entries, own=args.validate_own, random=args.validate_random,
                plan=plan, fuzz_classes=fuzz_classes, limits=getattr(args, "fixed_limits", None),
                progress=not getattr(args, "no_progress_probe", False))
            (analysis_dir / f"validate.round{rnd}.reverted.json").write_text(
                json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(vd.summarize(report))
            entry.update({"progress_unimproved": dict(progress_before), "reverted": undone,
                          "ok": report.get("hard_ok", report.get("ok")) if report.get("ok") is not None else None,
                          "failing": [t["target"] for t in report.get("targets", []) if not hard_ok(t)],
                          "progress_advisory": vd.progress_ratios(report)})
            progress_done = True
        elif regressed and before is not None and report.get("ok") is not None:
            undone = vd.revert(run_dir, before, vd.snapshot(run_dir))
            plan = plan_before
            if plan is not None:
                (analysis_dir / "guidance_plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False),
                                                                  encoding="utf-8")
            print(f"[Validate] the repair made {', '.join(regressed)} fail, which had passed; reverted it")
            report = await asyncio.to_thread(
                vd.run_validation, run_dir, target_entries, own=args.validate_own, random=args.validate_random,
                plan=plan, fuzz_classes=fuzz_classes, limits=getattr(args, "fixed_limits", None),
                progress=not getattr(args, "no_progress_probe", False))
            (analysis_dir / f"validate.round{rnd}.reverted.json").write_text(
                json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(vd.summarize(report))
            entry.update({"regressed": regressed, "reverted": undone,
                          "ok": report.get("hard_ok", report.get("ok")) if report.get("ok") is not None else None,
                          "failing": [t["target"] for t in report.get("targets", []) if not hard_ok(t)]})
            notes = [f"Your previous repair made {', '.join(regressed)} fail, which had passed before it, so it was "
                     "undone: the files and the guidance plan are as they were before that repair. Fix the failing "
                     "targets without breaking the ones that pass."]
        passed = {t["target"] for t in report.get("targets", []) if hard_ok(t)}
        history.append(entry)
        if report.get("ok") is not False or client is None or rnd == args.validate_rounds:
            break
        # Only the advisory progress check failed: ask for one more repair unless one was already undone.
        progress_only = report.get("hard_ok") is True
        if progress_only and progress_done:
            break
        progress_before = vd.progress_ratios(report) if progress_only else None

        print(f"[Validate] returning diagnostics to the agent (repair round {rnd + 1}/{args.validate_rounds})")
        before = vd.snapshot(run_dir)
        plan_before = plan
        full, text, cost = await _ask_in_session(
            client, vd.repair_prompt(report, plan=cp is not None, notes=notes,
                                     fuzz_tests_fixed=fuzz_tests is not None,
                                     plan_spec=cp.PLAN_SPEC if cp is not None else ""), args.backend)
        if cost:
            extra_cost += cost
        (analysis_dir / f".block3.validate{rnd + 1}.md").write_text(full, encoding="utf-8")

        notes = []
        restored = vd.restore(run_dir, fuzz_tests, vd.snapshot(run_dir)) if fuzz_tests is not None else []
        if restored:
            print(f"[Validate] restored fuzz tests changed by the repair: {', '.join(restored)}")
            notes.append(f"Your changes to {', '.join(restored)} were reverted: the fuzz tests and their oracles "
                         "cannot be changed during repair.")
        repair: dict[str, Any] = {"round": rnd + 1, "restored_fuzz_tests": restored,
                                  **vd.changes(before, vd.snapshot(run_dir))}

        revised = cp.extract_plan(text) if cp is not None else None
        if revised is not None:
            # previous_plan: a revision may not move a target's retention signals from the sink to hops before it
            # (e.g. from the decompressed bytes at the sink to the input length at the decoder's entry).
            pc = await asyncio.to_thread(cp.run_checkpath, source_root, entries=target_entries,
                                         max_gap=getattr(args, "checkpath_max_gap", 2), plan=revised,
                                         harness=_harness_dirs(args), previous_plan=plan)
            (analysis_dir / f"plancheck.validate{rnd + 1}.json").write_text(
                json.dumps(pc, indent=2, ensure_ascii=False), encoding="utf-8")
            print(cp.plan_summarize(pc))
            repair["plan_revised"] = pc.get("plan_ok") is True
            if repair["plan_revised"]:
                plan = revised
                for name in ("guidance_plan.json", f"guidance_plan.validate{rnd + 1}.json"):
                    (analysis_dir / name).write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                problems = [f"{p['target']}: {d}" for p in pc.get("plans", []) if p.get("status") != "PASS"
                            for d in p.get("diagnostics", [])] or [str(pc.get("error"))]
                notes.append("Your revised guidance plan did not pass PlanCheck, so the previous plan is still "
                             "used: " + "; ".join(problems))
        elif cp is not None and re.search(cp.PLAN_BEGIN, text or ""):
            # A plan the parser cannot read (e.g. targets keyed by id instead of a `plans` list) is not applied.
            repair["plan_revised"] = False
            repair["plan_unreadable"] = True
            notes.append(f"Your reply has text between {cp.PLAN_BEGIN} and {cp.PLAN_END}, but it is not a guidance "
                         "plan in the format shown below (a JSON object whose `plans` list has one entry per target), "
                         "so the previous plan is still used.")
        (analysis_dir / f"validate.repair{rnd + 1}.json").write_text(
            json.dumps(repair, indent=2, ensure_ascii=False), encoding="utf-8")
        brief = {k: repair[k] for k in ("added", "deleted", "modified", "restored_fuzz_tests") if repair[k]}
        if "plan_revised" in repair:
            brief["plan_revised"] = repair["plan_revised"]
        history[-1]["repair"] = brief

    summary = {"final_ok": history[-1]["ok"], "repair_rounds": len(history) - 1,
               "fuzz_tests_fixed_at_round": fixed_at, "rounds": history}
    (analysis_dir / "validate.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    # Strict, per target: a target whose checks still fail is dropped; the subject fails if none is left, or if
    # the build, launch.json or the validator itself failed (no target was validated).
    if summary["final_ok"] is not True and args.validate_strict:
        failing = history[-1].get("failing") or []
        if summary["final_ok"] is None or not failing:
            _fail_synthesis(analysis_dir, "validate",
                            "ValidateArtifact: checks still fail after the repair rounds"
                            if summary["final_ok"] is False else f"ValidateArtifact could not run: {history[-1].get('error')}",
                            failing)
        _drop_targets(analysis_dir, "validate", target_entries, failing)
    return extra_cost


# ====================================================================
# Controlled cross-block memory (only used with --no-session)
# ====================================================================

BLOCK2_MEMORY_MAX_CHARS = 12000
GENERIC_MEMORY_MAX_CHARS = 4000


def _truncate_for_prompt(text: str, max_chars: int) -> str:
    s = (text or "").strip()
    if not s or len(s) <= max_chars:
        return s
    head = int(max_chars * 0.7)
    tail = max_chars - head
    return s[:head] + "\n\n...[TRUNCATED FOR CONTEXT BUDGET]...\n\n" + s[-tail:]


def build_controlled_memory(block_idx: int, responses: list[str]) -> str:
    """Build manual cross-block memory from prior text responses.

    Only used in --no-session mode. When using ClaudeSDKClient,
    the SDK carries full conversation history automatically.
    """
    if not responses:
        return ""

    if block_idx == 2:
        prior = _truncate_for_prompt(responses[0], BLOCK2_MEMORY_MAX_CHARS)
        if not prior:
            return ""
        return (
            "=== CONTROLLED MEMORY: BLOCK 1 OUTPUT (SOURCE OF TRUTH) ===\n"
            + prior
            + "\n=== END CONTROLLED MEMORY ===\n"
        )

    prior = _truncate_for_prompt(responses[-1], GENERIC_MEMORY_MAX_CHARS)
    if not prior:
        return ""
    return (
        "=== CONTROLLED MEMORY: PREVIOUS BLOCK OUTPUT ===\n"
        + prior
        + "\n=== END CONTROLLED MEMORY ===\n"
    )


# ====================================================================
# Message extraction helpers
# ====================================================================

def _lazy_import_types() -> tuple:
    """Import SDK message types; returns (ok, AssistantMessage, ResultMessage,
    TextBlock, ToolUseBlock, ToolResultBlock) or (False, ...) on ImportError."""
    try:
        
        from claude_agent_sdk import (  # type: ignore
            AssistantMessage,
            ResultMessage,
            TextBlock,
            ToolUseBlock,
            ToolResultBlock,
            HookMatcher,
        )
        return True, AssistantMessage, ResultMessage, TextBlock, ToolUseBlock, ToolResultBlock
    except ImportError:
        return False, None, None, None, None, None


def _extract_full_response(messages: list[Any]) -> str:
    """Extract ALL content from SDK messages — text, tool use, and results."""
    ok, AssistantMessage, ResultMessage, TextBlock, ToolUseBlock, ToolResultBlock = _lazy_import_types()
    if ok:
        return _extract_full_response_typed(
            messages, AssistantMessage, ResultMessage, TextBlock, ToolUseBlock, ToolResultBlock
        )
    return _extract_full_response_duck(messages)


def _extract_full_response_typed(
    messages: list[Any],
    AssistantMessage: type,
    ResultMessage: type,
    TextBlock: type,
    ToolUseBlock: type,
    ToolResultBlock: type,
) -> str:
    chunks: list[str] = []
    for msg in messages:
        if isinstance(msg, AssistantMessage):
            for block in msg.content:
                if isinstance(block, TextBlock):
                    chunks.append(block.text)
                elif isinstance(block, ToolUseBlock):
                    tool_input = getattr(block, "input", None) or {}
                    if isinstance(tool_input, dict):
                        summary_parts = [f"[TOOL_USE: {block.name}]"]
                        for key in ("file_path", "path", "command", "pattern", "glob"):
                            if key in tool_input:
                                summary_parts.append(f"  {key}: {tool_input[key]}")
                        chunks.append("\n".join(summary_parts))
                    else:
                        chunks.append(f"[TOOL_USE: {block.name}]")
        elif isinstance(msg, ResultMessage):
            if msg.result:
                chunks.append(msg.result)
        elif isinstance(msg, ToolResultBlock):
            content = getattr(msg, "content", None)
            if isinstance(content, str) and content:
                if len(content) <= 2000:
                    chunks.append(f"[TOOL_RESULT]\n{content}")
                else:
                    chunks.append(f"[TOOL_RESULT] ({len(content)} chars, truncated)\n{content[:1000]}...")
    return "\n".join(chunks).strip()


def _extract_full_response_duck(messages: list[Any]) -> str:
    """Duck-typed fallback for older or unknown SDK versions."""
    chunks: list[str] = []
    for msg in messages:
        result = getattr(msg, "result", None)
        if isinstance(result, str) and result:
            chunks.append(result)
            continue

        content = getattr(msg, "content", None)
        if isinstance(content, str) and content:
            chunks.append(content)
            continue
        if isinstance(content, list):
            for block in content:
                text = getattr(block, "text", None)
                if isinstance(text, str) and text:
                    chunks.append(text)
                    continue
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    chunks.append(block["text"])
                    continue
                name = getattr(block, "name", None)
                if isinstance(name, str):
                    tool_input = getattr(block, "input", None) or {}
                    summary_parts = [f"[TOOL_USE: {name}]"]
                    if isinstance(tool_input, dict):
                        for key in ("file_path", "path", "command", "pattern", "glob"):
                            if key in tool_input:
                                summary_parts.append(f"  {key}: {tool_input[key]}")
                    chunks.append("\n".join(summary_parts))

        tool_use_id = getattr(msg, "tool_use_id", None)
        if tool_use_id and not getattr(msg, "name", None):
            tc = getattr(msg, "content", None)
            if isinstance(tc, str) and tc:
                if len(tc) <= 2000:
                    chunks.append(f"[TOOL_RESULT]\n{tc}")
                else:
                    chunks.append(f"[TOOL_RESULT] ({len(tc)} chars, truncated)\n{tc[:1000]}...")

        text = getattr(msg, "text", None)
        if isinstance(text, str) and text and text not in chunks:
            chunks.append(text)

    return "\n".join(chunks).strip()


def _extract_text_only(messages: list[Any]) -> str:
    """Extract ONLY text blocks — used for clean cross-block memory and target extraction."""
    ok, AssistantMessage, ResultMessage, TextBlock, _, _ = _lazy_import_types()
    if ok:
        chunks: list[str] = []
        for msg in messages:
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        chunks.append(block.text)
            elif isinstance(msg, ResultMessage) and msg.result:
                chunks.append(msg.result)
        return "\n".join(chunks).strip()

    # Duck-type fallback
    chunks: list[str] = []
    for msg in messages:
        result = getattr(msg, "result", None)
        if isinstance(result, str) and result:
            chunks.append(result)
            continue
        content = getattr(msg, "content", None)
        if isinstance(content, list):
            for block in content:
                text = getattr(block, "text", None)
                name = getattr(block, "name", None)
                if isinstance(text, str) and text and name is None:
                    chunks.append(text)
    return "\n".join(chunks).strip()


def _extract_session_id_from_result(messages: list[Any]) -> str | None:
    """Extract session_id from the ResultMessage."""
    for msg in messages:
        sid = getattr(msg, "session_id", None)
        if isinstance(sid, str) and sid:
            return sid
    return None


def _extract_cost_from_result(messages: list[Any]) -> float | None:
    """Extract total_cost_usd from the ResultMessage."""
    for msg in messages:
        cost = getattr(msg, "total_cost_usd", None)
        if cost is not None:
            return float(cost)
    return None


def _record_usage(kind: str, messages: list[Any]) -> None:
    """Record from the ResultMessage how many turns one agent query used and whether it hit its block's turn limit."""
    for msg in messages:
        if getattr(msg, "num_turns", None) is not None:
            subtype = getattr(msg, "subtype", None)
            limit = _TURN_LIMITS.get(_CURRENT_BLOCK_IDX)
            _USAGE.append({
                "block": _CURRENT_BLOCK_IDX,
                "kind": kind,
                "num_turns": msg.num_turns,
                "turn_limit": limit,
                "subtype": subtype,
                "hit_turn_limit": subtype == "error_max_turns" or (limit is not None and msg.num_turns > limit),
                "cost_usd": getattr(msg, "total_cost_usd", None),
            })
            return


def _session_max_turns(args: argparse.Namespace) -> int:
    """The CLI's --max-turns for the session: the largest per-block limit."""
    return max(args.max_turns, args.max_turns_block1)


def _write_usage(analysis_dir: Path) -> None:
    (analysis_dir / "usage.json").write_text(json.dumps(_USAGE, indent=2), encoding="utf-8")


def _fail_synthesis(analysis_dir: Path, stage: str, message: str, targets: list[str] | None = None,
                    status: str = "failure") -> None:
    """Stop the run because synthesis of this subject failed, recording why in analysis/outcome.json.
    status "interrupted" marks a run stopped by the service (stage "rate_limit"), not by a check."""
    outcome = {"status": status, "stage": stage, "message": message, "failing_targets": targets or []}
    (analysis_dir / "outcome.json").write_text(json.dumps(outcome, indent=2), encoding="utf-8")
    _write_usage(analysis_dir)
    raise SystemExit(f"[ERROR] {message}")


def _drop_targets(analysis_dir: Path, stage: str, entries: list[dict[str, Any]], failing: list[str]) -> None:
    """Drop the targets that still fail `stage` after its repair rounds (recorded in _DROPPED); the subject fails
    only if no target is left."""
    left = [e["id"] for e in entries if e["id"] not in failing and e["id"] not in _DROPPED]
    if not left:
        _fail_synthesis(analysis_dir, stage, f"{stage}: no target passes after the repair rounds", sorted(failing))
    for t in failing:
        _DROPPED.setdefault(t, stage)
    print(f"[{stage}] dropping {', '.join(sorted(failing))} (still failing after the repair rounds); "
          f"continuing with {', '.join(left)}")


def _kept(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in entries if e["id"] not in _DROPPED]


def _dropped_note() -> str:
    """Prepended to the prompts of the blocks after a target was dropped."""
    if not _DROPPED:
        return ""
    return ("NOTE: " + ", ".join(f"target {t} failed {stage}" for t, stage in sorted(_DROPPED.items()))
            + " after the repair rounds and was dropped. Work only on the targets in the frozen register; do not "
            "write code for dropped targets.\n\n")


# Present only in the Block 2 prompt (frozen-harness override); marks where Phase 2 begins in a session transcript.
_BLOCK2_MARKER = "This block: produce the MEASUREMENT STRATEGY only."


def _phase2_session(src_analysis: Path, run_dir: Path) -> tuple[str, dict[str, Any]]:
    """Copy the source run's Claude Code session up to the Block 2 prompt into a new session that `run_dir` resumes,
    so that Phase 2 starts with exactly the context the source run had after Block 1 and its CheckPath repairs."""
    import uuid
    projects = Path.home() / ".claude" / "projects"

    def text(d: dict[str, Any]) -> str:
        c = (d.get("message") or {}).get("content")
        return c if isinstance(c, str) else "".join(x.get("text", "") for x in (c or []) if isinstance(x, dict))

    # The source run's session: from session_id.txt, else the session in the source workspace's session directory
    # that contains the Block 2 prompt (for a run without session_id.txt).
    sid_file = src_analysis / "session_id.txt"
    if sid_file.exists():
        sid = sid_file.read_text(encoding="utf-8").strip()
        found = sorted(projects.glob(f"*/{sid}.jsonl"))
    else:
        src_dir = projects / re.sub(r"[^A-Za-z0-9]", "-", str(src_analysis.parent.resolve()))
        found = [f for f in sorted(src_dir.glob("*.jsonl")) if _BLOCK2_MARKER in f.read_text(encoding="utf-8")]
        sid = found[0].stem if len(found) == 1 else "?"
    if len(found) != 1:
        raise SystemExit(f"[ERROR] --phase2-from: found {len(found)} Claude Code sessions for {src_analysis.parent}")
    lines = found[0].read_text(encoding="utf-8").splitlines()

    cut = next((i for i, line in enumerate(lines)
                if (d := json.loads(line)).get("type") == "user" and _BLOCK2_MARKER in text(d)), None)
    if cut is None:
        # A Phase 1 probe (--stop-after-block 1, outcome "probe") ended after Block 1 and its checks, before the
        # Block 2 prompt: its whole session is the context Phase 2 starts from.
        outcome = src_analysis / "outcome.json"
        if outcome.exists() and json.loads(outcome.read_text(encoding="utf-8")).get("status") == "probe":
            cut = len(lines)
        else:
            raise SystemExit(f"[ERROR] --phase2-from: the Block 2 prompt is not in session {sid}")
    while cut > 0 and (d := json.loads(lines[cut - 1])).get("type") == "queue-operation" \
            and _BLOCK2_MARKER in str(d.get("content") or ""):
        cut -= 1  # the queued copy of the Block 2 prompt
    new = str(uuid.uuid4())
    kept = []
    for line in lines[:cut]:
        d = json.loads(line)
        if "sessionId" in d:
            d["sessionId"] = new
        kept.append(json.dumps(d, ensure_ascii=False))
    dest = projects / re.sub(r"[^A-Za-z0-9]", "-", str(run_dir.resolve()))  # Claude Code's directory for that cwd
    dest.mkdir(parents=True, exist_ok=True)
    (dest / f"{new}.jsonl").write_text("\n".join(kept) + "\n", encoding="utf-8")
    return new, {"source_session": sid, "source_transcript": str(found[0]), "lines_kept": cut, "lines_total": len(lines)}


def _check_turn_limit(args: argparse.Namespace, analysis_dir: Path, block: int) -> None:
    """Under the strict setting of the check that follows a block, a block whose agent query (or repair
    reply) stopped at --max-turns fails the subject."""
    strict = {1: args.checkpath_strict, 2: args.plan_strict, 3: args.validate_strict}[block]
    if strict and any(u["hit_turn_limit"] for u in _USAGE if u["block"] == block):
        limit = args.max_turns_block1 if block == 1 else args.max_turns
        _fail_synthesis(analysis_dir, f"block{block}", f"Block {block} stopped at its turn limit ({limit} turns)")


def _live_print_message(message: Any) -> None:
    """Live-print a single streamed message to stdout."""
    ok, AssistantMessage, _, TextBlock, ToolUseBlock, _ = _lazy_import_types()

    if ok:
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(block.text, end="", flush=True)
                elif isinstance(block, ToolUseBlock):
                    tool_input = getattr(block, "input", None) or {}
                    path_hint = ""
                    if isinstance(tool_input, dict):
                        path_hint = (
                            tool_input.get("file_path")
                            or tool_input.get("path")
                            or tool_input.get("command", "")
                        )
                    print(f"\n  >> [TOOL: {block.name}] {path_hint}", flush=True)
        return

    # Duck-type fallback
    content = getattr(message, "content", None)
    if isinstance(content, list):
        for block in content:
            text = getattr(block, "text", None)
            name = getattr(block, "name", None)
            if isinstance(text, str) and name is None:
                print(text, end="", flush=True)
            elif isinstance(name, str):
                tool_input = getattr(block, "input", None) or {}
                path_hint = ""
                if isinstance(tool_input, dict):
                    path_hint = (
                        tool_input.get("file_path")
                        or tool_input.get("path")
                        or tool_input.get("command", "")
                    )
                print(f"\n  >> [TOOL: {name}] {path_hint}", flush=True)
    elif isinstance(content, str):
        print(content, end="", flush=True)

    result = getattr(message, "result", None)
    if isinstance(result, str):
        print(result, end="", flush=True)


# ====================================================================
# Core execution: ClaudeSDKClient (default) and query() fallback
# ====================================================================

def _stop_if_service_limit(text: str) -> None:
    """End the run as interrupted if `text` is Claude Code's report of a usage or rate limit."""
    if _ANALYSIS_DIR is not None and _SERVICE_LIMIT.search(text or ""):
        _fail_synthesis(_ANALYSIS_DIR, "rate_limit",
                        f"the session stopped at a usage or rate limit; re-run this subject: {text.strip()[:300]}",
                        status="interrupted")


async def _collect_response(response_iter, collected: list[Any]) -> None:
    """Iterate over response messages, live-print them, and collect. A turn that a usage or rate limit ended
    stops the run (outcome "interrupted"), so that it is re-run rather than counted as a failed synthesis."""
    try:
        async for message in response_iter:
            collected.append(message)
            _live_print_message(message)
    except Exception as e:  # the SDK raises when the CLI exits, e.g. at a usage limit
        _stop_if_service_limit(str(e))
        raise
    print()  # newline after streaming
    for message in collected:
        if getattr(message, "num_turns", None) is not None:  # the ResultMessage
            _stop_if_service_limit(str(getattr(message, "result", "") or ""))


async def run_blocks_with_client(
    *,
    block_prompts: list[tuple[int, str, str]],  # [(block_idx, block_label, prompt_text), ...]
    model: str,
    system_prompt: str,
    max_turns: int,
    cwd: str,
    source_root: str,
    allow_execution: bool = True,
) -> list[tuple[str, str, str | None, float | None]]:
    """Run all blocks in a single ClaudeSDKClient session.

    The client maintains full conversation history across blocks.
    Each subsequent block benefits from prompt caching of prior turns.

    Args:
        block_prompts: list of (block_index, label, prompt_text) tuples
        model, system_prompt, max_turns, cwd: SDK config
        source_root: read-only source tree (agent cannot write here)

    Returns:
        list of (full_response, text_only_response, session_id, cost_usd)
        per block, in order.
    """
    try:
        from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, HookMatcher  # type: ignore
    except ImportError as e:
        raise SystemExit(
            "[ERROR] claude_agent_sdk import failed. Install with:\n"
            "  pip install claude-agent-sdk --break-system-packages"
        ) from e

    hook = make_pre_tool_hook(str(run_dir), str(source_root), allow_execution=not args.no_exec)

    options = ClaudeAgentOptions(
        model=args.model,
        system_prompt=system_prompt,
        cwd=str(run_dir),
        max_turns=args.max_turns,
        allowed_tools=["Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "LS", "Bash"],
        disallowed_tools=["WebSearch", "WebFetch", "WebBrowse", "Browse", "Task"],
        permission_mode="acceptEdits",
        hooks={
            "PreToolUse": [
                HookMatcher(hooks=[hook]),  # no matcher = fires for ALL tools
            ],
        },
        add_dirs=[str(source_root)],
        max_buffer_size=10 * 1024 * 1024,
    )


    results: list[tuple[str, str, str | None, float | None]] = []

    async with ClaudeSDKClient(options=options) as client:
        for block_idx, block_label, prompt_text in block_prompts:
            print(f"  [Client] Sending block {block_idx} ({block_label})...")

            await client.query(prompt_text)

            collected: list[Any] = []
            await _collect_response(client.receive_response(), collected)

            full_response = _extract_full_response(collected)
            text_only = _extract_text_only(collected)
            session_id = _extract_session_id_from_result(collected)
            cost_usd = _extract_cost_from_result(collected)

            if cost_usd is not None:
                print(f"  [Cost] Block {block_idx}: ${cost_usd:.4f}")

            results.append((full_response, text_only, session_id, cost_usd))

    return results


async def run_single_block_query(
    *,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_turns: int,
    cwd: str,
    source_root: str,
    allow_execution: bool = True,
) -> tuple[str, str]:
    """Run a single block via standalone query() — for --no-session mode.

    Each call creates a fresh session with no memory of prior blocks.
    Cross-block memory is injected manually via truncated text in the prompt.

    Returns:
        (full_response, text_only_response)
    """
    try:
        from claude_agent_sdk import query, ClaudeAgentOptions, HookMatcher  # type: ignore
    except ImportError as e:
        raise SystemExit(
            "[ERROR] claude_agent_sdk import failed. Install with:\n"
            "  pip install claude-agent-sdk --break-system-packages"
        ) from e

    hook = make_pre_tool_hook(str(run_dir), str(source_root), allow_execution=not args.no_exec)

    options = ClaudeAgentOptions(
        model=args.model,
        system_prompt=system_prompt,
        cwd=str(run_dir),
        max_turns=args.max_turns,
        allowed_tools=["Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "LS", "Bash"],
        disallowed_tools=["WebSearch", "WebFetch", "WebBrowse", "Browse", "Task"],
        permission_mode="acceptEdits",
        hooks={
            "PreToolUse": [
                HookMatcher(hooks=[hook]),
            ],
        },
        add_dirs=[source_root],
        max_buffer_size=10 * 1024 * 1024,
    )

    collected: list[Any] = []

    try:
        async for message in query(prompt=user_prompt, options=options):
            collected.append(message)
            _live_print_message(message)
    finally:
        # A query that stops at --max-turns yields its ResultMessage and then raises ResultError.
        _record_usage("block", collected)

    print()  # newline after streaming

    full_response = _extract_full_response(collected)
    text_only = _extract_text_only(collected)
    return full_response, text_only


# ====================================================================
# Prompt builder
# ====================================================================

class PromptBuilder:
    """Encapsulates all prompt construction logic."""

    def __init__(
        self,
        *,
        parts: Any,  # PromptParts from parse_prompt_into_three_parts
        main_label: str,
        main_path_display: str,
        step1_only: str,
        step2_3_only: str,
        step4_plus: str,
        selection_text: str,
        source_discovery: str,
        local_dep_warning: str = "",
        focus_paths: list[str] | None = None,
        frozen_harness: bool = False,
        validation_contract: str = "",
        plan_request: str = "",
        limits: dict[str, Any] | None = None,
        scale_request: str = "",
    ):
        self.parts = parts
        self.main_label = main_label
        self.main_path_display = main_path_display
        self.step1_only = step1_only
        self.step2_3_only = step2_3_only
        self.step4_plus = step4_plus
        self.selection_text = selection_text
        self.source_discovery = source_discovery
        self.local_dep_warning = local_dep_warning
        self.focus_paths = focus_paths or []
        self.frozen_harness = frozen_harness
        self.validation_contract = validation_contract
        self.plan_request = plan_request
        self.limits_section = render_limits_section(limits)
        self.jvm_options = " ".join((limits or oracle_config.DEFAULTS)["jvm_args"])
        self.scale_request = scale_request

    @staticmethod
    def _frozen_override(block_idx: int) -> str:
        """Override text injected when the benchmark harness is frozen/read-only.

        Scopes synthesis to guidance-only: the agent must reuse the GIVEN harness
        (entry point and oracle) and must not regenerate the fixture (pom/FuzzTest).
        """
        common = (
            "=== FROZEN BENCHMARK FIXTURE ===\n"
            "The fuzz harness (*FuzzTest.java) is ALREADY PRESENT in the workspace and is\n"
            "READ-ONLY / IMMUTABLE. It defines the SHARED entry point and the SHARED oracle used\n"
            "by every approach (Zest, PerfFuzz, LLM one-shot, and this pipeline): an execution\n"
            "fails only if the harness method throws a throwable it does not declare (e.g.\n"
            "StackOverflowError, OutOfMemoryError) or runs longer than the per-execution time\n"
            "limit. You MUST NOT create, edit, overwrite, or delete it -- such tool calls are\n"
            "blocked by policy.\n"
            "pom.xml is also provided as the canonical build. Do NOT rewrite it; you MAY adjust\n"
            "ONLY the local vulnerable-jar <systemPath> if `mvn` cannot locate the jar in this\n"
            "environment. Do NOT change dependencies, plugins, or the fuzzed-artifact identity.\n"
        )
        if block_idx == 1:
            return common + (
                "This block: READ the provided FuzzTest to learn the exact entry point and how\n"
                "it decodes its input, then perform analysis + emit the target register.\n"
                "Each target's `entrypoint` path starts at the FuzzTest's @Fuzz method through\n"
                "which that target's input enters (`FuzzTestClass.method(ParamType)`), followed by\n"
                "the method it calls, and continues to the sink. CheckPath checks this.\n\n"
            )
        if block_idx == 2:
            return common + (
                "This block: produce the MEASUREMENT STRATEGY only. The pom.xml is provided --\n"
                "do not rewrite it (fix only the vulnerable-jar systemPath if the build fails).\n"
                "Do NOT copy or re-implement the harness. Plan the cost signal and\n"
                "instrumentation your Guidance will use against the GIVEN harness.\n\n"
            )
        if block_idx == 3:
            return common + (
                "This block: emit ONLY the Guidance class(es), and (if needed) the measurement\n"
                "Java agent + counters, and a FuzzRunner that loads them. Wire everything to the\n"
                "GIVEN FuzzTest entry point. Do NOT modify the FuzzTest (immutable); do not\n"
                "rewrite pom.xml.\n\n"
            )
        return common

    @staticmethod
    def _render_focus_paths_section(focus_paths: list[str]) -> str:
        if not focus_paths:
            return ""
        # Render as a short, explicit instruction. These are READ-ONLY hints
        # to steer analysis away from facade entrypoints.
        lines = ["=== Focus Files (READ FIRST; high-signal for vulnerability mechanics) ==="]
        for p in focus_paths[:50]:
            lines.append(f"- {p}")
        if len(focus_paths) > 50:
            lines.append(f"... and {len(focus_paths) - 50} more")
        lines.append(
            "Rules:\n"
            "- These files are provided as guidance for where the real work happens.\n"
            "- Treat them as READ-ONLY; do not modify SOURCE_ROOT.\n"
            "- If a focus file doesn't exist under SOURCE_ROOT, say so and continue.\n"
        )
        return "\n".join(lines) + "\n"

    @staticmethod
    def frozen_register_section(entries: list[dict[str, Any]]) -> str:
        path_note = ""
        if any(e.get("normalized_path") for e in entries):
            path_note = (
                "`normalized_path` is the attack path as CheckPath resolved it in the source: each hop's method "
                "and declaration line (hops with provenance `checkpath (omitted call)` lie between hops written in "
                "`entrypoint`), and the connection between consecutive hops (CALL with its call site; DATAFLOW, "
                "INDIRECT, DISPATCH, SEQUENCE, UNCHECKED or MISSING with its evidence). `checkpath_status` is FAIL if the "
                "path could not be grounded. Use these locations when choosing where to measure.\n"
            )
        return (
            "=== FROZEN TARGET REGISTER (AUTHORITATIVE) ===\n"
            + render_target_register_section(entries)
            + "\n"
            + path_note
            + "Rules: Do NOT add/remove/rename/reorder targets in later blocks.\n"
            + "If a block cannot be completed with this register, output exactly TARGET_REGISTER_CONFLICT.\n"
        )

    def build(self, block_idx: int, entries: list[dict[str, Any]], memory: str = "") -> str:
        """Build prompt for the given block index (1-3).

        Block mapping (3-block layout):
          Block 1: Analysis + Target Selection
          Block 2: Strategy + Project Setup
          Block 3: Agent + Guidance + Tests + Runner + Replay
        """
        frozen = self.frozen_register_section(entries) if entries else ""
        memory_section = (memory.strip() + "\n\n") if memory and memory.strip() else ""
        focus_section = self._render_focus_paths_section(self.focus_paths)
        fh = self._frozen_override(block_idx) if self.frozen_harness else ""
        
        # ==============================================================
        # BLOCK 1: Analysis + Target Selection
        # ==============================================================
        if block_idx == 1:
            no_files = ("Do NOT generate pom.xml, Java code, or any files other than the scale-measurement data files "
                        "described below." if self.scale_request else "Do NOT generate pom.xml, Java code, or any files.")
            return fh + f"""BLOCK 1 — Step 1 (Analysis) + Target Selection. HARD STOP after target register.
{no_files}
Do NOT proceed to Steps 2-3 or any implementation.

PHASE A — Analysis:
Read and analyze the source code to identify DoS vulnerabilities.

{memory_section}=== Main ===
{self.main_label}
{self.main_path_display}

=== Global Rules ===
{self.parts.global_rules}
{self.limits_section}
=== Step 1 ===
{self.step1_only}

{focus_section}
{self.source_discovery}

PHASE B — Target Selection:
After completing analysis, apply the selection controls below and emit the target register.

{self.selection_text}

- For each target, identify the most specific applicable CWE (e.g. CWE-400 Uncontrolled Resource Consumption, CWE-770 Allocation of Resources Without Limits, CWE-1333 Regex DoS). Include the CWE ID in the target register.
- `entrypoint`: the call path from the public entry point to the vulnerable code, one method per hop in call order, written as `Class.method(ParamType, ...) → Class.method(...) → ...`.
- `sink`: the method where the resource is actually consumed (`Class#method`); for a risk inside a library the project uses, that library method. The entrypoint path must pass through it. It is the code location responsible for the growth.
- `mechanism`: how the input makes the resource consumption grow (e.g. recursive descent on nested elements).
- `resource`: the exhausted resource (stack depth, heap memory or CPU time) and the quantity that grows with the input, e.g. "stack depth: one parser frame per nesting level".
- `failure_mode`: the failure observed when the resource is exhausted, exactly one of `timeout` (one execution runs longer than the per-execution time limit), `stack_overflow` (StackOverflowError) or `out_of_memory` (OutOfMemoryError under the fixed heap size). It is not a detection rule: do not give a threshold, ratio or count here. The fuzz harness and the time limit decide failures; what to measure belongs in `resource`.
- `scale`: the value the growing quantity must reach for that failure under the fixed evaluation limits, and the input length this takes, estimated from the source, e.g. "about 4,000 nesting levels overflow the 1 MB stack; one byte per level, so about 4 KB".
- `input_bytes`: that input length in bytes, as an integer. If it exceeds the input size limit, the failure cannot occur in this evaluation.
{self.scale_request}

MANDATORY OUTPUT at the very end (authoritative for all later blocks):
BEGIN_TARGET_REGISTER_JSON
{{
  "ordered_targets": [
    {{
      "slot": 1,
      "id": "V1",
      "name": "...",
      "entrypoint": "...",
      "source_path": "...",
      "sink": "...",
      "mechanism": "...",
      "resource": "...",
      "failure_mode": "timeout | stack_overflow | out_of_memory",
      "scale": "...",
      "input_bytes": <integer>,
      "cwe": "..."
    }}
  ]
}}
END_TARGET_REGISTER_JSON

Rules:
- Use ONLY targets found in Phase A analysis.
- Include ONLY DoS targets.
- Order by implementation priority.
- Max 3 targets.
- ids must be exact Vn or PkgRiskN from analysis.
- Do NOT add new targets not found in analysis.
"""

        # ==============================================================
        # BLOCK 2: Strategy + Project Setup
        # ==============================================================
        if block_idx == 2:
            return fh + f"""BLOCK 2 — Steps 2-3 (Strategy/Measurement) + Step 4a (pom.xml + directory tree). HARD STOP.
No agent code, no Guidance code, no test code.
Write pom.xml via tools. Do not print pom.xml in plain chat.

CRITICAL — VULNERABLE ARTIFACT ONLY (NO SOURCE COPYING):
You MUST fuzz the REAL vulnerable implementation from SOURCE_ROOT (preferred) or from a jar found under projects/.

ABSOLUTE FORBIDDEN:
- Copying / extracting / re-implementing “minimal vulnerable code” into workspace src/main/java.
- Creating a local clone of Spring classes in the workspace and fuzzing target/classes.
These break benchmark validity.

REQUIRED APPROACH:
1) Build the vulnerable jar(s) from SOURCE_ROOT (preferred):
   - Run: (cd SOURCE_ROOT && mvn -q -DskipTests package)
   - Identify the module jar that contains the target classes (e.g., spring-web/target/*.jar).
2) If (1) is impractical, locate an existing jar under projects/ (read-only) that corresponds to the vulnerable commit.

pom.xml requirement:
- Add the vulnerable project jar as a SYSTEM dependency:
  <scope>system</scope> + <systemPath> pointing to the absolute jar path.
- Add ONLY third-party deps normally.
- Do NOT add the fuzzed project itself via Maven Central coordinates.

MANDATORY PROOF:
In Block 3, include a “Class Origin Check” step that prints the CodeSource location
for the target class (e.g., ETagHeaderParser / HttpHeaders) to prove it is loaded from:
- SOURCE_ROOT/.../target/*.jar  OR  projects/.../*.jar
and NOT from workspace target/classes.
{self.local_dep_warning}
{memory_section}=== Main ===
{self.main_label}
{self.main_path_display}

=== Global Rules ===
{self.parts.global_rules}
{self.limits_section}
{frozen}

=== Steps 2-3 (Strategy & Measurement Plans) ===
{self.step2_3_only}

=== Step 4a (Project Setup) ===
{self.step4_plus}

{focus_section}
{self.source_discovery}
{self.plan_request}
"""

        # ==============================================================
        # BLOCK 3: Agent + Guidance + Tests + Runner + Replay
        # ==============================================================
        if block_idx == 3:
            return fh + f"""BLOCK 3 — Emit ALL implementation files. HARD STOP.

Part A — Java Agent:
Emit javaagent files if required by selected targets.
If no selected target requires Tier-1/javaagent instrumentation, skip Part A.

Part B — Guidance:
Emit exactly one Guidance class per selected target, in slot order.

Part C — Fuzz Tests + Runner + Replay:
Emit fuzz tests, CLI runner, replay harness, README, audits, and checklist.
Use byte[]/InputStream only. No generators.
Also emit a run.sh shell script that:
1. Compiles the workspace with: mvn compile -q 2>&1 | tail -30
2. Runs FuzzRunner for each selected target with the full runtime classpath.
   Use the fixed JVM options ({self.jvm_options}).
   Example invocation per target: java {self.jvm_options} -cp target/classes:<jar_deps> FuzzRunner V1 60 2>&1 | tail -50
Make run.sh executable (chmod +x run.sh in a Bash call after writing it).

{self.validation_contract}

{memory_section}=== SELECTED TARGETS (IN ORDER) ===
{render_target_register_section(entries)}

=== Main ===
{self.main_label}
{self.main_path_display}

=== Global Rules ===
{self.parts.global_rules}
{self.limits_section}
{frozen}
{self.step4_plus}

{self.source_discovery}
"""

        raise ValueError(f"unsupported block index: {block_idx}")


# ====================================================================
# Frozen benchmark harness injection (for controlled model ablation)
# ====================================================================
def inject_frozen_harness(run_dir: Path, project_id: str, benchmarks_root: str) -> list[str]:
    """Inject the benchmark fixture into the workspace; freeze the harness source.

    Copies the benchmarks/<project_id>/ tree into the workspace, except the directories and
    files left out below. Then:
      * pom.xml is made WRITABLE so the agent can fix the local vulnerable-jar <systemPath>
        for this environment;
      * every .java under src/ is chmod 444 and returned, so the pre-tool hook blocks edits.

    File NAMES are not assumed: whatever .java the fixture ships under src/ is frozen -- the
    harness FuzzTest, any Oracle/Exception (some subjects have none), and any vendored
    vulnerable classes (some fixtures inline the vulnerable source). All are part of the
    SHARED fixture that Zest/PerfFuzz also run against, so freezing them keeps the comparison
    valid. The agent ADDS its Guidance (+ measurement agent + runner) as NEW files (allowed).

    Returns absolute paths of the frozen (immutable) files for the pre-tool hook.
    """
    import shutil

    src = Path(benchmarks_root) / project_id
    if not src.exists():
        raise SystemExit(
            f"[ERROR] --freeze-harness: no benchmark fixture at {src}. "
            f"Expected at least pom.xml + a *FuzzTest.java under src/."
        )

    # analysis/ holds the earlier synthesis of this fixture (register, transcripts), oracle.json's
    # justifications describe the vulnerability and its fix, and fixed/ holds the fixed version of the library (the
    # campaign reads oracle.json and fixed/ from benchmarks/): leaving them out keeps a new synthesis from reading
    # earlier results or comparing against the fix.
    shutil.copytree(src, run_dir, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("build-temp", "target", ".git", "analysis", "oracle.json", "fixed"))

    # pom.xml: writable (agent may adjust the vulnerable-jar systemPath).
    pom = run_dir / "pom.xml"
    if pom.is_file():
        try:
            os.chmod(pom, 0o644)
        except OSError:
            pass

    # Freeze every .java under src/ (harness + any oracle/exception + vendored vulnerable
    # code), whatever they are named.
    frozen: list[str] = []
    src_dir = run_dir / "src"
    if src_dir.is_dir():
        for jp in sorted(src_dir.rglob("*.java")):
            frozen.append(str(jp.resolve()))

    if not frozen:
        print(f"[FreezeHarness] WARNING: no .java found under {src_dir} — fixture may be incomplete.")

    seen: set[str] = set()
    uniq = [f for f in frozen if not (f in seen or seen.add(f))]
    for f in uniq:
        try:
            os.chmod(f, 0o444)
        except OSError:
            pass
    return uniq


# ====================================================================
# Main orchestration (async)
# ====================================================================

async def async_main(args: argparse.Namespace) -> None:
    use_sessions = not args.no_session

    if args.backend == "openai" and not use_sessions:
        raise SystemExit("[ERROR] --backend openai supports session mode only; drop --no-session.")

    raw_prompt = Path(args.prompt).read_text(encoding="utf-8")
    parts = parse_prompt_into_three_parts(raw_prompt)

    # ---- Focus paths (optional): repeatable and/or comma-separated ----
    # Accept patterns like:
    #   --focus-paths a/b/C.java --focus-paths x/y/Z.java
    #   --focus-paths "a/b/C.java,x/y/Z.java"
    focus_paths: list[str] = []
    if getattr(args, "focus_paths", None):
        raw_items: list[str] = []
        if isinstance(args.focus_paths, list):
            raw_items = [str(x) for x in args.focus_paths]
        else:
            raw_items = [str(args.focus_paths)]
        for item in raw_items:
            for part in str(item).split(","):
                p = part.strip()
                if p:
                    # Normalize slashes; keep relative paths relative to SOURCE_ROOT.
                    focus_paths.append(p.replace("\\", "/"))
    # De-dup preserve order
    seen_fp: set[str] = set()
    focus_paths = [p for p in focus_paths if not (p in seen_fp or seen_fp.add(p))]

    step1_only = extract_step1_only(parts.procedure)
    step2_3_only = extract_between_steps(parts.procedure, 2, 4)
    step4_plus = extract_between_steps(parts.procedure, 4, None)

    source_root = Path(args.source_root).resolve()
    if not source_root.exists() or not source_root.is_dir():
        raise SystemExit(f"[ERROR] --source-root is not a directory: {source_root}")

    code_paths = [Path(p) for p in args.input_code]
    for p in code_paths:
        if not p.exists():
            raise SystemExit(f"[ERROR] Missing --input-code file: {p}")

    main_path: Path | None = None
    if code_paths:
        main_path = resolve_main_file(args.main_class, code_paths)
    else:
        p = Path(args.main_class)
        if p.exists():
            main_path = p.resolve()
        elif not p.is_absolute():
            maybe = (source_root / p).resolve()
            if maybe.exists():
                main_path = maybe

    main_path_display = main_path.as_posix() if main_path else "(discover with tools)"
    seed_input_code = ""
    if args.attach_input_code and code_paths:
        seed_input_code = "\n\n".join(read_file_as_xml_block(p) for p in code_paths)
    main_label = args.main_class

    workspaces_root = Path(args.workspaces_root)
    if args.run_dir:
        run_dir = Path(args.run_dir).resolve()
        run_dir.mkdir(parents=True, exist_ok=True)
    else:
        run_dir = make_timestamp_run_dir(workspaces_root, args.project_id)

    print(f"[Run dir] {run_dir}")
    print(f"[Model]    {args.model}")
    print(f"[Source]   {source_root}")
    print(f"[Mode]     {'ClaudeSDKClient (continuous session)' if use_sessions else 'query() per block (no session)'}")
    print(f"[Guard]    Workspace write-guard active: writes blocked outside {run_dir}")
    print(f"[ReadOnly] Source root: {source_root}")
    print(f"[NoWeb]    Web access BLOCKED (web search, curl, wget, URLs in bash)")
    if args.no_exec:
        print(f"[NoExec]   Test/fuzzer execution BLOCKED (compile-only mode)")

    # Extract project's own Maven coordinates to prevent self-dependency
    project_coords = extract_project_maven_coords(source_root)
    if project_coords:
        coord_strs = [f"{g}:{a}" for g, a in project_coords]
        print(f"[MavenGuard] Project coordinates (blocked as dependencies): {', '.join(coord_strs)}")
    else:
        print(f"[MavenGuard] No pom.xml found in source root — Maven self-dependency guard inactive")

    system_prompt = (
        "You are an expert security researcher specializing in fuzz testing.\n"
        "Follow the block instruction exactly and obey HARD STOP boundaries.\n"
        "\n"
        "WORKSPACE RULES (ENFORCED — violations will be blocked):\n"
        f"- WORKSPACE (read-write): {run_dir}  — ALL generated files MUST go here.\n"
        f"- SOURCE_ROOT (READ-ONLY): {source_root.as_posix()}  — You may READ files here but NEVER write, edit, or delete.\n"
        "- Use tools to read project files under source root.\n"
        "- Write ALL generated artifacts (pom.xml, Java files, scripts, etc.) under the workspace directory.\n"
        "- Do NOT write files to source root or any directory outside the workspace.\n"
        "\n"
        "Never ask for permission. If a block asks to emit files, write them in the workspace.\n"
        "Do not defer work to a later message.\n"
        "\n"
        "WEB ACCESS RULES (ENFORCED — violations will be blocked):\n"
        "- Do NOT use web search, web fetch, web browse, or any internet access tools.\n"
        "- Do NOT use curl, wget, or any HTTP/HTTPS requests in Bash commands.\n"
        "- Do NOT access any URLs or download anything from the internet.\n"
        "- All information must come from local source files only.\n"
        "- Maven dependency resolution via `mvn` is allowed (it uses the local repo and Maven Central\n"
        "  for declared dependencies), but you must NOT manually fetch files from the web.\n"
        "\n"
        "COMMAND OUTPUT RULES (ENFORCED — buffer overflow will crash the session):\n"
        "- ALWAYS pipe long-running commands through `tail -n 50` or `head -n 50`.\n"
        "- ALWAYS use `2>&1 | tail -50` for Java/Maven builds and test runs.\n"
        "- NEVER run a fuzzer or test without output limiting (e.g. `| tail -50`).\n"
        "- For compilation: `mvn compile 2>&1 | tail -30`\n"
        "- For test runs:   `java ... FuzzRunner V1 5 2>&1 | tail -50`\n"
        "- If you need BOTH start and end: `cmd 2>&1 | (head -20; echo '...'; tail -30)`\n"
        "- Raw unbounded output WILL crash the session with a buffer overflow error.\n"
    )

    if args.no_exec:
        system_prompt += (
            "\n"
            "EXECUTION RULES (ENFORCED — violations will be blocked):\n"
            "- Do NOT run java, mvn test, mvn verify, mvn exec, or any test/fuzzer.\n"
            "- You MAY run: mvn compile, mvn package -DskipTests, javac, jar.\n"
            "- Compile to verify correctness, but do NOT execute the compiled tests.\n"
        )

    # Build local-source dependency rules (NO SOURCE COPYING; USE REAL JAR)
    local_dep_rules = (
        "\n"
        "LOCAL SOURCE DEPENDENCY RULES (CRITICAL — MUST USE VULNERABLE ARTIFACT):\n"
        "You are fuzzing a SPECIFIC VULNERABLE VERSION checked out in SOURCE_ROOT.\n"
        "\n"
        "ABSOLUTE RULE: DO NOT COPY/RE-IMPLEMENT/EXTRACT 'minimal versions' of project classes into the workspace.\n"
        "That changes the target and can accidentally fuzz a different (often fixed) implementation.\n"
        "\n"
        "You MUST compile and execute the fuzz harness against the REAL vulnerable build output from SOURCE_ROOT\n"
        "(preferred), or an existing jar under the read-only projects/ directory.\n"
        "\n"
        "Allowed ways to get the vulnerable classes on the classpath (choose in this order):\n"
        "  (1) Build from SOURCE_ROOT: run `mvn -q -DskipTests package` (or the project's build) in SOURCE_ROOT,\n"
        "      then reference the resulting jar(s) from SOURCE_ROOT/<module>/target/*.jar.\n"
        "  (2) If (1) is too heavy, locate a prebuilt jar in projects/ (read-only) that matches the vulnerable commit,\n"
        "      and reference that jar directly.\n"
        "\n"
        "How to wire the jar(s) into the workspace build:\n"
        "- In workspace pom.xml, use <dependency> with <scope>system</scope> and <systemPath> pointing to the\n"
        "  locally-built jar path (absolute path). This is allowed and ensures we are using the vulnerable artifact.\n"
        "- DO NOT add the fuzzed project itself as a normal Maven dependency via groupId:artifactId from Maven Central.\n"
        "  That will pull the latest (likely fixed) version.\n"
        "\n"
        "Transitive dependencies:\n"
        "- You MAY declare third-party dependencies normally from Maven Central (junit, jqf, asm, etc.).\n"
        "- For multi-module projects (e.g., Spring), if the target classes live in a module (e.g., spring-web), you MUST\n"
        "  use the jar from that module, not a workspace-copied class.\n"
        "\n"
        "Verification requirement (MANDATORY):\n"
        "- In Block 2 or Block 3, you MUST prove which artifact is used by printing:\n"
        "    `java -cp <runtime_cp> <small helper> to print Class.getProtectionDomain().getCodeSource()`\n"
        "  or an equivalent check that shows the class is loaded from SOURCE_ROOT/target/*.jar (or projects/*.jar),\n"
        "  NOT from target/classes.\n"
    )
    if project_coords:
        coord_list = ", ".join(f"{g}:{a}" for g, a in project_coords)
        local_dep_rules += (
            f"- SPECIFICALLY FORBIDDEN Maven coordinates: {coord_list}\n"
            f"  These are the fuzzed project's own coordinates — DO NOT add them as normal <dependency>.\n"
        )
    local_dep_rules += (
        "- If you cannot build a jar from SOURCE_ROOT and cannot find a jar under projects/, you MUST output:\n"
        "  UNKNOWN_VULNERABLE_ARTIFACT and stop (do not fall back to copying minimal code).\n"
    )
    system_prompt += local_dep_rules

    selection_text = ""
    if args.selection:
        selection_text = Path(args.selection).read_text(encoding="utf-8")
    else:
        selection_text = (getattr(parts, "selection_controls", "") or "").strip()
        if not selection_text:
            selection_text = (
                "My selection for this run (DoS-only):\n"
                "- Execute V*: ONLY DoS-related items inferred from analyzed code.\n"
                "- Execute PkgRisk-*: ONLY DoS-related dependency risks.\n"
                "- Everything else: EXCLUDED."
            )

    preferred_discovery_root = main_path.parent.as_posix() if main_path else source_root.as_posix()
    source_discovery = f"""=== Source Discovery (READ-ONLY) ===
Use tools to READ source files under SOURCE_ROOT: {source_root.as_posix()}.
Start discovery from: {preferred_discovery_root}.
Expand outside that subtree only if required by the frozen target register.
Do not assume file contents you have not read.
IMPORTANT: SOURCE_ROOT is READ-ONLY. All generated files go in the workspace (cwd).
"""
    if focus_paths:
        source_discovery = PromptBuilder._render_focus_paths_section(focus_paths) + "\n" + source_discovery
    if seed_input_code:
        source_discovery += f"""
=== Seed Input Code (Optional) ===
{seed_input_code}
"""

    # Build per-block reinforcement for local source dependency
    local_dep_warning = ""
    if project_coords:
        forbidden = "\n".join(f"  - {g}:{a}" for g, a in project_coords)
        local_dep_warning = (
            f"FORBIDDEN Maven coordinates (these are the fuzzed project itself):\n"
            f"{forbidden}\n"
            f"Do NOT add these as <dependency> — use local source instead.\n"
        )
        

    validator = None if args.no_validate else _load_validate()
    planner = None if args.no_plan_check else _load_checkpath()
    args.fixed_limits = _fixed_limits(args)
    pb = PromptBuilder(
        parts=parts,
        main_label=main_label,
        main_path_display=main_path_display,
        step1_only=step1_only,
        step2_3_only=step2_3_only,
        step4_plus=step4_plus,
        selection_text=selection_text,
        source_discovery=source_discovery,
        local_dep_warning=local_dep_warning,
        focus_paths=focus_paths,
        frozen_harness=args.freeze_harness,
        validation_contract=validator.contract_prompt(plan=planner is not None,
                                                      limits=args.fixed_limits is not None) if validator else "",
        plan_request=planner.plan_prompt() if planner else "",
        limits=args.fixed_limits,
        scale_request=_load_scale().series_instructions(args.fixed_limits) if _scale_enabled(args) else "",
    )

    global _ANALYSIS_DIR
    analysis_dir = run_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    _ANALYSIS_DIR = analysis_dir
    _TURN_LIMITS.update({1: args.max_turns_block1, 2: args.max_turns, 3: args.max_turns})
    # The settings this run actually used (turn limit, repair rounds, strictness, ...), for reporting.
    run_config = {k: v for k, v in sorted(vars(args).items()) if k != "openai_api_key"}
    run_config["prompt_sha256"] = hashlib.sha256(raw_prompt.encode("utf-8")).hexdigest()
    (analysis_dir / "run_config.json").write_text(json.dumps(run_config, indent=2, default=str), encoding="utf-8")

    frozen_files: list[str] = []
    if args.freeze_harness:
        frozen_files = inject_frozen_harness(run_dir, args.project_id, args.benchmarks_root)
        print(f"[FreezeHarness] Injected {len(frozen_files)} read-only fixture file(s) from "
              f"{args.benchmarks_root}/{args.project_id}; synthesis constrained to guidance-only.")
    if validator:
        print(f"[Validate] Installed {validator.install_contract(run_dir)}")

    responses: list[str] = []          # text-only responses
    guidance_plan: dict[str, Any] | None = None  # Block 2 plan, after PlanCheck
    target_entries: list[dict[str, Any]] = []
    total_cost = 0.0

    # Phase 2 again from an earlier run's Phase 1 (its target register, CheckPath results and session up to Block 2).
    start_block, resume_session = 1, None
    if args.phase2_register and not args.phase2_from:
        raise SystemExit("[ERROR] --phase2-register needs --phase2-from (the run whose Block 1 context Phase 2 resumes)")
    if args.phase2_from:
        if not (use_sessions and args.backend != "openai" and args.freeze_harness):
            raise SystemExit("[ERROR] --phase2-from needs a Claude session (no --no-session, no openai backend) "
                             "and --freeze-harness")
        src_analysis = Path(args.phase2_from).resolve() / "analysis"
        for f in sorted(src_analysis.iterdir()):
            if f.name.startswith(".block1"):
                shutil.copy2(f, analysis_dir / f.name)
            elif not args.phase2_register and (f.name.startswith("checkpath")
                                               or f.name in ("target_register.json", "target_register.md")):
                shutil.copy2(f, analysis_dir / f.name)
        if args.phase2_register:
            # A target register written outside the pipeline replaces the source run's (an ablation: Phase 2 from a
            # given analysis). It is grounded with CheckPath, without repair, which also records each harness_entry.
            target_entries = json.loads(Path(args.phase2_register).read_text(encoding="utf-8"))["ordered_targets"]
            if not args.no_checkpath:
                target_entries, _ = await checkpath_gate(None, args, target_entries, source_root, analysis_dir)
            _save_register(analysis_dir, target_entries)
        else:
            target_entries = json.loads((src_analysis / "target_register.json").read_text(encoding="utf-8"))["ordered_targets"]
        if args.checkpath_strict:  # targets CheckPath dropped (in the source run) stay dropped
            _DROPPED.update({e["id"]: "checkpath" for e in target_entries if e.get("checkpath_status") == "FAIL"})
        target_entries = _kept(target_entries)
        src_usage = src_analysis / "usage.json"
        if src_usage.exists():
            _USAGE.extend({**u, "inherited": True} for u in json.loads(src_usage.read_text(encoding="utf-8"))
                          if u.get("block") == 1)
        resume_session, info = _phase2_session(src_analysis, run_dir)
        (analysis_dir / "phase2_from.json").write_text(json.dumps(
            {"source_run": str(src_analysis.parent), "new_session": resume_session, **info,
             **({"register": str(Path(args.phase2_register).resolve())} if args.phase2_register else {})},
            indent=2), encoding="utf-8")
        print(f"[Phase2] Phase 1 from {src_analysis.parent}; resuming its session up to Block 2 as {resume_session}")
        start_block = 2

    global _CURRENT_BLOCK, _CURRENT_BLOCK_IDX

    # ----------------------------------------------------------------
    # ClaudeSDKClient mode: continuous session across all blocks
    # ----------------------------------------------------------------
    if use_sessions:
        hook = make_pre_tool_hook(str(run_dir), str(source_root), allow_execution=not args.no_exec,
                                  frozen_files=frozen_files)

        if args.backend == "openai":
            from oss_backend import OpenAIAgentSession
            client_cm = OpenAIAgentSession(
                base_url=args.openai_base_url,
                api_key=args.openai_api_key,
                model=args.model,
                system_prompt=system_prompt,
                cwd=str(run_dir),
                source_root=str(source_root),
                hook=hook,
                max_turns=_session_max_turns(args),
                usage_dir=analysis_dir,
                context_tokens=args.openai_context_tokens,
            )
        else:
            try:
                from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, HookMatcher  # type: ignore
            except ImportError as e:
                raise SystemExit(
                    "[ERROR] claude_agent_sdk import failed. Install with:\n"
                    "  pip install claude-agent-sdk --break-system-packages"
                ) from e
            options = ClaudeAgentOptions(
                model=args.model,
                system_prompt=system_prompt,
                cwd=str(run_dir),
                max_turns=_session_max_turns(args),
                allowed_tools=["Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "LS", "Bash"],
                disallowed_tools=["WebSearch", "WebFetch", "WebBrowse", "Browse", "Task"],
                permission_mode="acceptEdits",
                hooks={
                    "PreToolUse": [
                        HookMatcher(hooks=[hook]),
                    ],
                },
                add_dirs=[source_root],
                max_buffer_size=10 * 1024 * 1024,
                resume=resume_session,
            )
            client_cm = ClaudeSDKClient(options=options)
        
        session_id: str | None = None

        async with client_cm as client:
            for i in range(start_block, 4):  # 3 blocks (from Block 2 with --phase2-from)
                # In session mode, no controlled memory needed — client has full history.
                prompt = _dropped_note() + pb.build(i, target_entries, memory="")
                if i == 2 and args.phase2_register:
                    prompt = ("NOTE: After Block 1, the target register you emitted was replaced by the reviewed one in "
                              "the FROZEN TARGET REGISTER below. Use that register for the following blocks; the "
                              "register from your Block 1 reply no longer applies.\n\n") + prompt

                first_line = (prompt.splitlines()[0] if prompt else "").strip()
                _CURRENT_BLOCK = first_line or f"Block {i}"
                _CURRENT_BLOCK_IDX = i

                print(f"\n{'='*60}")
                print(f"  {_CURRENT_BLOCK}")
                print(f"{'='*60}\n")

                allowed_targets = {e["id"] for e in target_entries} | set(_DROPPED)  # files for dropped targets are ignored
                emitted_before = {ef.path for ef in _EMITTED_FILES}

                # Get this block's response from the active backend.
                if args.backend == "openai":
                    response_full, response_text_only, sid, cost = await client.query_block(prompt)
                else:
                    await client.query(prompt)
                    collected: list[Any] = []
                    await _collect_response(client.receive_response(), collected)
                    response_full = _extract_full_response(collected)
                    response_text_only = _extract_text_only(collected)
                    sid = _extract_session_id_from_result(collected)
                    cost = _extract_cost_from_result(collected)
                    _record_usage("block", collected)

                # Track session ID.
                if sid:
                    if session_id is None:
                        print(f"  [Session] ID: {sid[:30]}...")
                        # Written now, not only at the end, so that a run that fails a check keeps it (--phase2-from).
                        (analysis_dir / "session_id.txt").write_text(sid + "\n", encoding="utf-8")
                    session_id = sid
                if cost is not None:
                    total_cost += cost
                    print(f"  [Cost] Block {i}: ${cost:.4f}  (cumulative: ${total_cost:.4f})")
                _check_turn_limit(args, analysis_dir, i)

                # Scan for new files and validate.
                new_files = scan_emitted_files(run_dir, emitted_before)

                if allowed_targets and i >= 2:
                    ok, why = validate_target_alignment(
                        response_full, new_files, allowed_targets=allowed_targets,
                    )
                    if not ok:
                        print(f"[Validation] FAILED on block {i}: {why}")
                        _cleanup_failed_block_files(str(run_dir), new_files)
                        _fail_synthesis(analysis_dir, f"block{i}",
                                        f"Target register validation failed for block {i}: {why}")

                _EMITTED_FILES.extend(new_files)
                responses.append(response_text_only)

                # Post-block audit: verify source_root wasn't modified
                audit_workspace_boundary(run_dir, source_root, _CURRENT_BLOCK)

                # After block 2 (pom.xml emission): check for self-dependency
                if i == 2 and project_coords:
                    audit_pom_no_self_dependency(run_dir, project_coords, _CURRENT_BLOCK)

                # Save audit files.
                out_path = analysis_dir / f".block{i}.md"
                out_path.write_text(response_full, encoding="utf-8")
                print(f"[Saved {_CURRENT_BLOCK} -> {out_path}]")

                tool_lines = [
                    line for line in response_full.splitlines()
                    if line.strip().startswith("[TOOL_USE:") or line.strip().startswith(">> [TOOL:")
                    or line.strip().startswith("file_path:") or line.strip().startswith("path:")
                    or line.strip().startswith("command:")
                ]
                if tool_lines:
                    tool_log_path = analysis_dir / f".block{i}.tools.log"
                    tool_log_path.write_text("\n".join(tool_lines) + "\n", encoding="utf-8")
                    print(f"[Tool log ({len(tool_lines)} ops) -> {tool_log_path}]")

                # Block 1 includes analysis + target selection
                if i == 1:
                    target_entries = extract_target_register(
                        response_text_only,
                        max_targets=5,
                    )
                    if not target_entries:
                        _fail_synthesis(analysis_dir, "block1", "Could not extract target register from Block 1 output")
                    if not args.no_checkpath:
                        target_entries, cp_cost = await checkpath_gate(
                            client, args, target_entries, source_root, analysis_dir)
                        if cp_cost:
                            total_cost += cp_cost
                            print(f"  [Cost] CheckPath repair: ${cp_cost:.4f}  (cumulative: ${total_cost:.4f})")
                    if _scale_enabled(args):
                        target_entries, s_cost = await scale_gate(client, args, target_entries, run_dir, analysis_dir)
                        if s_cost:
                            total_cost += s_cost
                            print(f"  [Cost] Scale measurement: ${s_cost:.4f}  (cumulative: ${total_cost:.4f})")
                    _save_register(analysis_dir, target_entries)
                    print(f"[Saved frozen target register -> {analysis_dir / 'target_register.json'}]")
                    target_entries = _kept(target_entries)

                if i == 2 and planner:
                    guidance_plan, p_cost = await plan_gate(
                        client, args, planner.extract_plan(response_text_only), target_entries, source_root,
                        analysis_dir)
                    if p_cost:
                        total_cost += p_cost
                        print(f"  [Cost] PlanCheck repair: ${p_cost:.4f}  (cumulative: ${total_cost:.4f})")
                    target_entries = _kept(target_entries)

                if i == 3 and validator:
                    v_cost = await validate_gate(client, args, run_dir, target_entries, analysis_dir, guidance_plan,
                                                 source_root)
                    if v_cost:
                        total_cost += v_cost
                        print(f"  [Cost] Validation repair: ${v_cost:.4f}  (cumulative: ${total_cost:.4f})")
                    target_entries = _kept(target_entries)

                _check_turn_limit(args, analysis_dir, i)  # repair replies of this block's check
                if args.stop_after_block and i >= args.stop_after_block:
                    print(f"[Probe] stopping after Block {i} (--stop-after-block)")
                    break

        # Save session ID for manual resumption later.
        if session_id:
            (analysis_dir / "session_id.txt").write_text(session_id + "\n", encoding="utf-8")
            print(f"[Session ID saved -> {analysis_dir / 'session_id.txt'}]")

    # ----------------------------------------------------------------
    # Sessionless mode (--no-session): independent query() per block with truncated memory
    # ----------------------------------------------------------------
    else:
        for i in range(1, 4):  # 3 blocks
            controlled_memory = build_controlled_memory(i, responses)
            prompt = _dropped_note() + pb.build(i, target_entries, controlled_memory)

            first_line = (prompt.splitlines()[0] if prompt else "").strip()
            _CURRENT_BLOCK = first_line or f"Block {i}"
            _CURRENT_BLOCK_IDX = i

            print(f"\n{'='*60}")
            print(f"  {_CURRENT_BLOCK}")
            print(f"{'='*60}\n")

            allowed_targets = {e["id"] for e in target_entries} | set(_DROPPED)  # files for dropped targets are ignored
            emitted_before = {ef.path for ef in _EMITTED_FILES}

            try:
                response_full, response_text_only = await run_single_block_query(
                    model=args.model,
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                    max_turns=args.max_turns_block1 if i == 1 else args.max_turns,
                    cwd=str(run_dir),
                    source_root=str(source_root),
                    allow_execution=not args.no_exec,
                )
            except Exception:
                _check_turn_limit(args, analysis_dir, i)  # stopped at the turn limit: a recorded failure
                raise
            _check_turn_limit(args, analysis_dir, i)

            new_files = scan_emitted_files(run_dir, emitted_before)

            if allowed_targets and i >= 2:
                ok, why = validate_target_alignment(
                    response_full, new_files, allowed_targets=allowed_targets,
                )
                if not ok:
                    print(f"[Validation] FAILED on block {i}: {why}")
                    _cleanup_failed_block_files(str(run_dir), new_files)
                    _fail_synthesis(analysis_dir, f"block{i}",
                                    f"Target register validation failed for block {i}: {why}")

            _EMITTED_FILES.extend(new_files)
            responses.append(response_text_only)

            # Post-block audit: verify source_root wasn't modified
            audit_workspace_boundary(run_dir, source_root, _CURRENT_BLOCK)

            # After block 2 (pom.xml emission): check for self-dependency
            if i == 2 and project_coords:
                audit_pom_no_self_dependency(run_dir, project_coords, _CURRENT_BLOCK)

            out_path = analysis_dir / f".block{i}.md"
            out_path.write_text(response_full, encoding="utf-8")
            print(f"[Saved {_CURRENT_BLOCK} -> {out_path}]")

            tool_lines = [
                line for line in response_full.splitlines()
                if line.strip().startswith("[TOOL_USE:") or line.strip().startswith(">> [TOOL:")
                or line.strip().startswith("file_path:") or line.strip().startswith("path:")
                or line.strip().startswith("command:")
            ]
            if tool_lines:
                tool_log_path = analysis_dir / f".block{i}.tools.log"
                tool_log_path.write_text("\n".join(tool_lines) + "\n", encoding="utf-8")
                print(f"[Tool log ({len(tool_lines)} ops) -> {tool_log_path}]")

            # Block 1 includes analysis + target selection
            if i == 1:
                target_entries = extract_target_register(
                    response_text_only,
                    max_targets=5,
                )
                if not target_entries:
                    _fail_synthesis(analysis_dir, "block1", "Could not extract target register from Block 1 output")
                if not args.no_checkpath:
                    # No open session in sessionless mode: record the check, but do not repair.
                    target_entries, _ = await checkpath_gate(
                        None, args, target_entries, source_root, analysis_dir)
                _save_register(analysis_dir, target_entries)
                print(f"[Saved frozen target register -> {analysis_dir / 'target_register.json'}]")
                target_entries = _kept(target_entries)

            # No open session in sessionless mode: record the plan check and the validation, but do not repair.
            if i == 2 and planner:
                guidance_plan, _ = await plan_gate(
                    None, args, planner.extract_plan(response_text_only), target_entries, source_root, analysis_dir)
                target_entries = _kept(target_entries)
            if i == 3 and validator:
                await validate_gate(None, args, run_dir, target_entries, analysis_dir, guidance_plan, source_root)
                target_entries = _kept(target_entries)

    # ----------------------------------------------------------------
    # Finalize
    # ----------------------------------------------------------------
    _write_run_manifest(
        out_dir=run_dir,
        main_class=str(main_label),
        project_id=args.project_id,
        commit=None,
        cwd=str(run_dir),
    )
    (analysis_dir / "outcome.json").write_text(
        json.dumps({"status": "probe" if args.stop_after_block and args.stop_after_block < 3 else "ok",
                    "targets": [e["id"] for e in _kept(target_entries)],
                    "dropped_targets": _DROPPED,
                    **({"phase2_from": str(Path(args.phase2_from).resolve())} if args.phase2_from else {})},
                   indent=2), encoding="utf-8")
    _write_usage(analysis_dir)

    # In a continuous session, every ResultMessage's total_cost_usd is the session's running total, so the sum
    # total_cost counts earlier queries again. The session's cost is the largest value recorded.
    session_cost = max((u.get("cost_usd") or 0.0 for u in _USAGE), default=0.0)
    if use_sessions and session_cost > 0:
        total_cost = session_cost
    if total_cost > 0:
        (analysis_dir / "cost.txt").write_text(f"${total_cost:.4f}\n", encoding="utf-8")

    print(f"\n[Wrote run manifest -> {run_dir / 'run_manifest.json'}]")
    if total_cost > 0:
        print(f"[Total cost: ${total_cost:.4f}]")
    print(f"\n{'='*60}")
    print("  COMPLETE")
    print(f"{'='*60}\n")


# ====================================================================
# CLI entry point
# ====================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Generate fuzz harnesses using Claude Agent SDK (ClaudeSDKClient for continuous conversation)"
    )
    ap.add_argument("--prompt", required=True, help="Path to prompt file")
    ap.add_argument("--model", default="claude-opus-4-6", help="Model ID. For --backend claude: a Claude model. For --backend openai: the served model name, e.g. Qwen/Qwen3.6-27B.")
    ap.add_argument("--backend", choices=["claude", "openai"], default="claude",
                    help="Model backend: 'claude' (Claude Agent SDK) or 'openai' (vLLM/OpenAI-compatible open model).")
    ap.add_argument("--openai-base-url", default=os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1"),
                    help="OpenAI-compatible base URL (vLLM). Used when --backend openai.")
    ap.add_argument("--openai-api-key", default=os.environ.get("OPENAI_API_KEY", "EMPTY"),
                    help="API key for the OpenAI-compatible endpoint (vLLM ignores it).")
    ap.add_argument("--openai-context-tokens", type=int, default=131072,
                    help="Context window of the served model (vLLM --max-model-len); the session compacts its "
                         "context before a request would pass 75%% of it. Used when --backend openai.")
    ap.add_argument(
        "--input-code",
        nargs="*",
        default=[],
        help="Optional seed source files. Use --attach-input-code to inline them in prompts.",
    )
    ap.add_argument(
        "--attach-input-code",
        action="store_true",
        help="Attach --input-code files inline in prompts.",
    )
    ap.add_argument("--main-class", required=True, help="Main class under test (file path or FQCN)")
    ap.add_argument("--source-root", default=".", help="Source discovery root")
    ap.add_argument("--selection", help="Path to selection-block file")
    ap.add_argument(
        "--focus-paths",
        nargs="*",
        default=[],
        help=(
            "Optional list of high-signal source file paths (relative to SOURCE_ROOT) "
            "to read early. Accepts repeated values and/or comma-separated lists. "
            'Example: --focus-paths "src/main/java/a.java,src/main/java/b.java"'
        ),
    )
    ap.add_argument("--max-turns", type=int, default=80,
                    help="Max turns of each agent query of Blocks 2 and 3 (and of their repair replies)")
    ap.add_argument("--phase2-from", default=None, metavar="RUN_DIR",
                    help="Run Phase 2 again from RUN_DIR's Phase 1: its target register and CheckPath results, and its "
                         "Claude Code session up to the Block 2 prompt (resumed as a new session), in a new workspace")
    ap.add_argument("--phase2-register", default=None, metavar="FILE",
                    help="With --phase2-from: use this target register (JSON with ordered_targets) instead of the source "
                         "run's, e.g. an analysis written by hand (an ablation, not a DoSGuide result)")
    ap.add_argument("--stop-after-block", type=int, default=0,
                    help="Stop after this block and its check (diagnostic runs, e.g. 1 = Phase 1 only); the outcome "
                         "status is then \"probe\", which is neither a success nor a failure of the synthesis")
    ap.add_argument("--max-turns-block1", type=int, default=80,
                    help="Max turns of each agent query of Block 1 (and of its CheckPath repair replies)")
    ap.add_argument("--project-id", required=True, help="Project identifier")
    ap.add_argument("--workspaces-root", default="workspaces", help="Root directory for all runs")
    ap.add_argument("--run-dir", default=None, help="Override auto-generated run directory")
    ap.add_argument(
        "--no-session",
        action="store_true",
        help="Disable ClaudeSDKClient. Each block runs as independent query() with truncated memory.",
    )
    ap.add_argument(
        "--no-exec",
        action="store_true",
        help="Block the agent from running java/tests/fuzzers. Compile only.",
    )
    ap.add_argument(
        "--freeze-harness",
        action="store_true",
        help="Inject the frozen benchmarks/<project-id> fixture (pom.xml + *FuzzTest.java, which "
             "holds the oracle) read-only into the workspace and constrain synthesis to "
             "guidance-only (do not regenerate harness/pom). Use for model-ablation "
             "runs so the harness stays identical and Zest/PerfFuzz need not be re-run.",
    )
    ap.add_argument(
        "--benchmarks-root",
        default="benchmarks",
        help="Root of frozen benchmark fixtures (used by --freeze-harness).",
    )
    ap.add_argument(
        "--no-checkpath",
        action="store_true",
        help="Skip CheckPath, the source-grounding check of the Block 1 attack paths (tools/checkpath).",
    )
    ap.add_argument(
        "--no-scale-probe",
        action="store_true",
        help="Skip the scale probe after CheckPath (tools/validate/scale.py), which measures each target's resource "
             "growth on the agent's size series and lets the agent revise `scale` and `input_bytes`.",
    )
    ap.add_argument(
        "--no-progress-probe",
        action="store_true",
        help="Leave the progress probe out of ValidateArtifact (tools/validate/validate.py), which compares the "
             "guidance's signal on its own long inputs with the agent's Block 1 size series at the same length.",
    )
    ap.add_argument("--scale-rounds", type=int, default=2,
                    help="Messages for the scale revision (until the revised fields pass the field check).")
    ap.add_argument(
        "--checkpath-rounds",
        type=int,
        default=3,
        help="Max repair rounds in which CheckPath diagnostics are returned to the agent (session mode).",
    )
    ap.add_argument(
        "--checkpath-max-gap",
        type=int,
        default=2,
        help="Max omitted intermediate calls CheckPath allows between consecutive hops.",
    )
    ap.add_argument(
        "--checkpath-strict",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Drop the targets whose attack paths or fields still fail CheckPath after the repair rounds; fail the "
             "subject if none is left, if CheckPath cannot run, or if Block 1 stops at the turn limit (default: on).",
    )
    ap.add_argument(
        "--checkpath-require-sink",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Fail targets that do not declare a `sink` method, so the repair rounds ask the agent for one "
             "(default: on).",
    )
    ap.add_argument(
        "--no-plan-check",
        action="store_true",
        help="Do not ask Block 2 for a structured guidance plan and do not check it (PlanCheck, tools/checkpath).",
    )
    ap.add_argument(
        "--plan-rounds",
        type=int,
        default=3,
        help="Max repair rounds in which PlanCheck diagnostics are returned to the agent (session mode).",
    )
    ap.add_argument(
        "--plan-strict",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Drop the targets whose guidance plan still fails PlanCheck after the repair rounds; fail the subject "
             "if none is left, if there is no plan, if PlanCheck cannot run, or if Block 2 stops at the turn limit "
             "(default: on).",
    )
    ap.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip ValidateArtifact, the execution check of the Block 3 artifacts (tools/validate). The check "
             "runs the agent-declared build commands and fuzz tests itself, independently of --no-exec.",
    )
    ap.add_argument(
        "--validate-rounds",
        type=int,
        default=3,
        help="Max repair rounds in which validation diagnostics are returned to the agent (session mode).",
    )
    ap.add_argument(
        "--validate-own",
        type=int,
        default=40,
        help="Executions on inputs generated by the synthesized guidance itself.",
    )
    ap.add_argument(
        "--validate-random",
        type=int,
        default=40,
        help="Executions on random inputs and variants of earlier inputs substituted by the validator.",
    )
    ap.add_argument(
        "--validate-strict",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Drop the targets whose Block 3 artifacts still fail validation after the repair rounds; fail the "
             "subject if none is left, if the build or the validator fails, or if Block 3 stops at the turn limit "
             "(default: on).",
    )
    args = ap.parse_args()

    try:
        asyncio.run(async_main(args))
    except Exception as e:  # e.g. the CLI stopped at a usage limit while a query was being sent
        _stop_if_service_limit(str(e))
        raise


if __name__ == "__main__":
    main()