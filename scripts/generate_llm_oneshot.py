from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

# Backend config (set from CLI in main()). Default preserves Claude behaviour.
_BACKEND = "claude"
_OPENAI_BASE_URL = "http://localhost:8000/v1"
_OPENAI_API_KEY = "EMPTY"


# ============================================================
# Data models
# ============================================================

@dataclass
class TargetRecord:
    slot: int
    id: str
    name: str
    entrypoint: str
    source_path: str
    mechanism: str
    oracle: str


@dataclass
class GenerationContext:
    repo_root: Path
    target_slug: str
    benchmark_dir: Path
    project_dir: Path
    target_register_json: Path
    block1_read_files_file: Optional[Path]
    harness_file: Path
    package_name: str
    harness_class_name: str
    output_class_name: str
    output_filename: str
    selected_target: TargetRecord
    selected_summary: str
    files_used: List[Path]
    additional_context: str


@dataclass
class UsageSummary:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    @classmethod
    def from_api_usage(cls, usage: object | None) -> "UsageSummary":
        if usage is None:
            return cls()
        return cls(
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
            cache_creation_input_tokens=int(getattr(usage, "cache_creation_input_tokens", 0) or 0),
            cache_read_input_tokens=int(getattr(usage, "cache_read_input_tokens", 0) or 0),
        )

    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_creation_input_tokens
            + self.cache_read_input_tokens
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
            "total_tokens": self.total_tokens(),
        }

    @classmethod
    def aggregate(cls, usages: Iterable["UsageSummary"]) -> "UsageSummary":
        total = cls()
        for usage in usages:
            total.input_tokens += usage.input_tokens
            total.output_tokens += usage.output_tokens
            total.cache_creation_input_tokens += usage.cache_creation_input_tokens
            total.cache_read_input_tokens += usage.cache_read_input_tokens
        return total


@dataclass(frozen=True)
class ModelPricing:
    model_family: str
    input_per_million_usd: float
    cache_creation_per_million_usd: float
    cache_read_per_million_usd: float
    output_per_million_usd: float


@dataclass
class ClaudeCallResult:
    raw_response: str
    usage: UsageSummary


@dataclass
class GenerationResult:
    context: GenerationContext
    java_out: Path
    run_script_out: Path
    prompt_out: Path
    raw_out: Path
    usage_out: Path
    target_manifest_out: Path
    usage: UsageSummary
    cost_estimate: dict[str, object]


# ============================================================
# General helpers
# ============================================================

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]
GEN_ID_PATTERN = re.compile(r"gen-(\d+)$")
PRICING_SOURCE_URL = "https://docs.anthropic.com/en/docs/about-claude/pricing"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def find_first_existing(paths: Iterable[Path]) -> Optional[Path]:
    for p in paths:
        if p.exists():
            return p
    return None


def relpath_or_abs(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except Exception:
        return str(path)


def _round_cost(value: float) -> float:
    return round(value, 6)


def resolve_model_pricing(model_name: str) -> Optional[ModelPricing]:
    normalized = model_name.strip().lower().replace("_", "-")

    # Anthropic publishes pricing by model family. Repo-local aliases such as
    # claude-opus-4-6 and claude-sonnet-4-5 are mapped to their public family.
    if normalized.startswith("claude-opus-4"):
        return ModelPricing(
            model_family="claude-opus-4",
            input_per_million_usd=15.0,
            cache_creation_per_million_usd=18.75,
            cache_read_per_million_usd=1.50,
            output_per_million_usd=75.0,
        )
    if normalized.startswith("claude-sonnet-4"):
        return ModelPricing(
            model_family="claude-sonnet-4",
            input_per_million_usd=3.0,
            cache_creation_per_million_usd=3.75,
            cache_read_per_million_usd=0.30,
            output_per_million_usd=15.0,
        )
    if normalized.startswith("claude-sonnet-3-7") or normalized.startswith("claude-sonnet-3.7"):
        return ModelPricing(
            model_family="claude-sonnet-3.7",
            input_per_million_usd=3.0,
            cache_creation_per_million_usd=3.75,
            cache_read_per_million_usd=0.30,
            output_per_million_usd=15.0,
        )
    if normalized.startswith("claude-sonnet-3-5") or normalized.startswith("claude-sonnet-3.5"):
        return ModelPricing(
            model_family="claude-sonnet-3.5",
            input_per_million_usd=3.0,
            cache_creation_per_million_usd=3.75,
            cache_read_per_million_usd=0.30,
            output_per_million_usd=15.0,
        )
    if normalized.startswith("claude-haiku-3-5") or normalized.startswith("claude-haiku-3.5"):
        return ModelPricing(
            model_family="claude-haiku-3.5",
            input_per_million_usd=0.80,
            cache_creation_per_million_usd=1.0,
            cache_read_per_million_usd=0.08,
            output_per_million_usd=4.0,
        )
    if normalized.startswith("claude-opus-3"):
        return ModelPricing(
            model_family="claude-opus-3",
            input_per_million_usd=15.0,
            cache_creation_per_million_usd=18.75,
            cache_read_per_million_usd=1.50,
            output_per_million_usd=75.0,
        )
    if normalized.startswith("claude-haiku-3"):
        return ModelPricing(
            model_family="claude-haiku-3",
            input_per_million_usd=0.25,
            cache_creation_per_million_usd=0.30,
            cache_read_per_million_usd=0.03,
            output_per_million_usd=1.25,
        )

    return None


def estimate_cost_usd(model_name: str, usage: UsageSummary) -> dict[str, object]:
    pricing = resolve_model_pricing(model_name)
    if pricing is None:
        return {
            "estimated": False,
            "model": model_name,
            "model_family": None,
            "pricing_source_url": PRICING_SOURCE_URL,
            "pricing_note": "No pricing mapping is defined for this model name.",
            "input_cost_usd": None,
            "cache_creation_cost_usd": None,
            "cache_read_cost_usd": None,
            "output_cost_usd": None,
            "total_cost_usd": None,
        }

    input_cost = usage.input_tokens * pricing.input_per_million_usd / 1_000_000
    cache_creation_cost = (
        usage.cache_creation_input_tokens * pricing.cache_creation_per_million_usd / 1_000_000
    )
    cache_read_cost = usage.cache_read_input_tokens * pricing.cache_read_per_million_usd / 1_000_000
    output_cost = usage.output_tokens * pricing.output_per_million_usd / 1_000_000
    total_cost = input_cost + cache_creation_cost + cache_read_cost + output_cost

    return {
        "estimated": True,
        "model": model_name,
        "model_family": pricing.model_family,
        "pricing_source_url": PRICING_SOURCE_URL,
        "pricing_note": "Estimated from Anthropic public pricing by model family.",
        "input_cost_usd": _round_cost(input_cost),
        "cache_creation_cost_usd": _round_cost(cache_creation_cost),
        "cache_read_cost_usd": _round_cost(cache_read_cost),
        "output_cost_usd": _round_cost(output_cost),
        "total_cost_usd": _round_cost(total_cost),
    }


def aggregate_cost_estimates(cost_estimates: Iterable[dict[str, object]]) -> dict[str, object]:
    estimates = list(cost_estimates)
    if not estimates:
        return {
            "estimated": False,
            "pricing_source_url": PRICING_SOURCE_URL,
            "pricing_note": "No generations were saved.",
            "input_cost_usd": None,
            "cache_creation_cost_usd": None,
            "cache_read_cost_usd": None,
            "output_cost_usd": None,
            "total_cost_usd": None,
        }

    if any(item.get("estimated") is not True for item in estimates):
        return {
            "estimated": False,
            "pricing_source_url": PRICING_SOURCE_URL,
            "pricing_note": "At least one target used an unmapped model name, so the aggregate cost is unavailable.",
            "input_cost_usd": None,
            "cache_creation_cost_usd": None,
            "cache_read_cost_usd": None,
            "output_cost_usd": None,
            "total_cost_usd": None,
        }

    def summed(key: str) -> float:
        return _round_cost(sum(float(item.get(key) or 0.0) for item in estimates))

    return {
        "estimated": True,
        "pricing_source_url": PRICING_SOURCE_URL,
        "pricing_note": "Summed from per-target cost estimates using Anthropic public pricing by model family.",
        "input_cost_usd": summed("input_cost_usd"),
        "cache_creation_cost_usd": summed("cache_creation_cost_usd"),
        "cache_read_cost_usd": summed("cache_read_cost_usd"),
        "output_cost_usd": summed("output_cost_usd"),
        "total_cost_usd": summed("total_cost_usd"),
    }


def resolve_generation_id(repo_root: Path, target_slug: str, requested_gen_id: Optional[str]) -> str:
    normalized = (requested_gen_id or "auto").strip()
    if normalized and normalized.lower() != "auto":
        return normalized

    max_seen = 0
    generated_root = repo_root / "engines" / "llm_oneshot" / "generated" / target_slug
    if generated_root.exists():
        for child in generated_root.iterdir():
            if not child.is_dir():
                continue
            match = GEN_ID_PATTERN.fullmatch(child.name)
            if match:
                max_seen = max(max_seen, int(match.group(1)))

    manifest_root = repo_root / "engines" / "llm_oneshot" / "manifests" / target_slug
    manifest_pattern = re.compile(r"^gen-(\d+)(?:_.+)?\.json$")
    if manifest_root.exists():
        for child in manifest_root.iterdir():
            if not child.is_file():
                continue
            match = manifest_pattern.fullmatch(child.name)
            if match:
                max_seen = max(max_seen, int(match.group(1)))

    return f"gen-{max_seen + 1:03d}"


def find_target_register_json(benchmark_dir: Path) -> Path:
    candidates = [
        benchmark_dir / "analysis" / "target_register.json",
        benchmark_dir / "docs" / "analysis" / "target_register.json",
    ]
    result = find_first_existing(candidates)
    if not result:
        raise FileNotFoundError(
            f"Could not find target_register.json under benchmark directory: {benchmark_dir}"
        )
    return result


def find_block1_read_files_file(benchmark_dir: Path) -> Optional[Path]:
    candidates = [
        benchmark_dir / "analysis" / ".block1.tools.log",
    ]
    return find_first_existing(candidates)

def resolve_target_slug(repo_root: Path, target_arg: str) -> str:
    """
    Accept either:
      - full target slug: activemq_GHSA-whxr-3p84-rf3c
      - GHSA id only: GHSA-whxr-3p84-rf3c

    Returns the canonical folder slug.
    """
    target_arg = target_arg.strip()

    # If it already looks like a full folder name and exists, use it directly.
    direct_candidates = [
        repo_root / "benchmarks" / target_arg,
        repo_root / "benchmark" / target_arg,
        repo_root / "projects" / target_arg,
    ]
    if any(p.exists() for p in direct_candidates):
        return target_arg

    # If user passed a GHSA id, find matching folder names.
    ghsa_match = re.fullmatch(r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", target_arg)
    if not ghsa_match:
        raise FileNotFoundError(
            f"Could not resolve target '{target_arg}'. "
            "Pass either a full target slug or a GHSA id like GHSA-whxr-3p84-rf3c."
        )

    search_roots = [
        repo_root / "benchmarks",
        repo_root / "benchmark",
        repo_root / "projects",
    ]

    matches = set()
    for root in search_roots:
        if not root.exists():
            continue
        for child in root.iterdir():
            if child.is_dir() and child.name.endswith(f"_{target_arg}"):
                matches.add(child.name)

    matches = sorted(matches)
    if not matches:
        raise FileNotFoundError(f"Could not find any target folder matching GHSA id: {target_arg}")
    if len(matches) > 1:
        raise ValueError(
            f"GHSA id '{target_arg}' matched multiple target folders: {matches}. "
            "Please pass the full target slug."
        )

    return matches[0]

# ============================================================
# Benchmark/layout discovery
# ============================================================

def find_benchmark_dir(repo_root: Path, target_slug: str) -> Path:
    candidates = [
        repo_root / "benchmarks" / target_slug,
        repo_root / "benchmark" / target_slug,
    ]
    result = find_first_existing(candidates)
    if not result:
        raise FileNotFoundError(f"Could not find benchmark directory for target: {target_slug}")
    return result


def find_project_dir(repo_root: Path, target_slug: str) -> Path:
    candidates = [
        repo_root / "projects" / target_slug,
    ]
    result = find_first_existing(candidates)
    if not result:
        raise FileNotFoundError(f"Could not find project directory for target: {target_slug}")
    return result


def find_analysis_file(benchmark_dir: Path) -> Path:
    candidates = [
        benchmark_dir / "analysis" / "full_analysis.md",
        benchmark_dir / "analysis" / "analysis.md",
        benchmark_dir / "docs" / "analysis" / "full_analysis.md",
        benchmark_dir / "docs" / "analysis" / "analysis.md",
        benchmark_dir / "analysis.txt",
    ]
    result = find_first_existing(candidates)
    if not result:
        raise FileNotFoundError(
            f"Could not find analysis file under benchmark directory: {benchmark_dir}"
        )
    return result


def find_tool_trace_file(benchmark_dir: Path) -> Path:
    candidates = [
        benchmark_dir / "analysis" / "tool_trace.txt",
        benchmark_dir / "analysis" / "tool_use_trace.txt",
        benchmark_dir / "docs" / "analysis" / "tool_trace.txt",
        benchmark_dir / "docs" / "analysis" / "tool_use_trace.txt",
        benchmark_dir / "tool_trace.txt",
    ]
    result = find_first_existing(candidates)
    if not result:
        raise FileNotFoundError(
            f"Could not find tool trace file under benchmark directory: {benchmark_dir}"
        )
    return result


def find_harness_file(benchmark_dir: Path) -> Path:
    src_root_candidates = [
        benchmark_dir / "src" / "test" / "java",
        benchmark_dir / "fuzz-target" / "src" / "test" / "java",
    ]

    for src_root in src_root_candidates:
        if src_root.exists():
            fuzz_tests = sorted(src_root.rglob("*FuzzTest.java"))
            if fuzz_tests:
                return fuzz_tests[0]
            any_java = sorted(src_root.rglob("*.java"))
            if any_java:
                return any_java[0]

    raise FileNotFoundError(f"Could not find harness Java file under: {benchmark_dir}")


def parse_target_register_json_file(path: Path) -> List[TargetRecord]:
    payload = json.loads(read_text(path))
    ordered_targets = payload.get("ordered_targets", [])
    if not ordered_targets:
        raise ValueError(f"ordered_targets is empty in {path}")

    records: List[TargetRecord] = []
    for item in ordered_targets:
        records.append(
            TargetRecord(
                slot=int(item["slot"]),
                id=str(item["id"]),
                name=str(item["name"]),
                entrypoint=str(item["entrypoint"]),
                source_path=str(item["source_path"]),
                mechanism=str(item["mechanism"]),
                oracle=str(item["oracle"]),
            )
        )
    return records


def parse_preprocessed_read_paths(path: Path, repo_root: Path) -> List[Path]:
    seen = set()
    out: List[Path] = []

    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        p = Path(line)
        if not p.is_absolute():
            p = (repo_root / p).resolve()
        else:
            p = p.resolve()

        if p.exists():
            key = str(p)
            if key not in seen:
                seen.add(key)
                out.append(p)

    return out


def infer_supporting_files_from_target(project_dir: Path, selected_target: TargetRecord) -> List[Path]:
    candidates: List[Path] = []

    primary = (project_dir / selected_target.source_path).resolve()
    if primary.exists():
        candidates.append(primary)

    likely_names = set(re.findall(r"[A-Z][A-Za-z0-9_]+", selected_target.entrypoint))
    likely_names.update(re.findall(r"[A-Z][A-Za-z0-9_]+", selected_target.mechanism))

    for name in sorted(likely_names):
        matches = list(project_dir.rglob(f"{name}.java"))
        for m in matches[:3]:
            if m.exists():
                candidates.append(m.resolve())

    deduped: List[Path] = []
    seen = set()
    for p in candidates:
        key = str(p)
        if key not in seen:
            seen.add(key)
            deduped.append(p)

    return deduped

# ============================================================
# Java helpers
# ============================================================

def extract_package_name(java_source: str) -> str:
    m = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;", java_source, flags=re.MULTILINE)
    if not m:
        raise ValueError("Could not extract package declaration from harness")
    return m.group(1)


def extract_java_class_name(java_source: str) -> str:
    m = re.search(r"\bpublic\s+class\s+([A-Za-z0-9_]+)\b", java_source)
    if m:
        return m.group(1)
    m = re.search(r"\bclass\s+([A-Za-z0-9_]+)\b", java_source)
    if m:
        return m.group(1)
    raise ValueError("Could not extract class name from harness")


def derive_oneshot_class_name(harness_class_name: str, target_id: str) -> str:
    if harness_class_name.endswith("FuzzTest"):
        base = harness_class_name[:-8]
    elif harness_class_name.endswith("Test"):
        base = harness_class_name[:-4]
    else:
        base = harness_class_name

    return f"{base}{target_id}OneShotTest"


# ============================================================
# Analysis parsing
# ============================================================

TARGET_REGISTER_PATTERN = re.compile(
    r"BEGIN_TARGET_REGISTER_JSON\s*(\{.*?\})\s*END_TARGET_REGISTER_JSON",
    flags=re.DOTALL,
)


def parse_target_register(analysis_text: str) -> List[TargetRecord]:
    m = TARGET_REGISTER_PATTERN.search(analysis_text)
    if not m:
        raise ValueError("Could not find BEGIN_TARGET_REGISTER_JSON / END_TARGET_REGISTER_JSON block")

    payload = json.loads(m.group(1))
    ordered_targets = payload.get("ordered_targets", [])
    if not ordered_targets:
        raise ValueError("ordered_targets is empty in target register JSON")

    records: List[TargetRecord] = []
    for item in ordered_targets:
        records.append(
            TargetRecord(
                slot=int(item["slot"]),
                id=str(item["id"]),
                name=str(item["name"]),
                entrypoint=str(item["entrypoint"]),
                source_path=str(item["source_path"]),
                mechanism=str(item["mechanism"]),
                oracle=str(item["oracle"]),
            )
        )
    return records


def select_target(records: List[TargetRecord], selected_target_id: Optional[str]) -> TargetRecord:
    if selected_target_id is None:
        return sorted(records, key=lambda r: r.slot)[0]

    selected_target_id = selected_target_id.strip()
    for r in records:
        if r.id == selected_target_id:
            return r

    raise ValueError(f"Could not find selected target id: {selected_target_id}")


def extract_target_summary(analysis_text: str, target_id: str) -> str:
    """
    Extract the detailed markdown block under:
    #### V1: ...
    until the next #### heading or next major section.
    """
    pattern = re.compile(
        rf"(^####\s+{re.escape(target_id)}:.*?)(?=^####\s+[A-Za-z0-9_-]+:|^###\s+1\.2|^##\s+PHASE B|^BEGIN_TARGET_REGISTER_JSON|\Z)",
        flags=re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(analysis_text)
    if m:
        return m.group(1).strip()
    return ""


# ============================================================
# Tool trace parsing
# ============================================================

READ_PATH_PATTERN = re.compile(
    r"\[TOOL_USE:\s*Read\]\s*[\r\n]+\s*file_path:\s*(.+)",
    flags=re.MULTILINE,
)


def parse_read_paths(tool_trace_text: str) -> List[Path]:
    seen = set()
    paths: List[Path] = []

    for raw in READ_PATH_PATTERN.findall(tool_trace_text):
        p = Path(raw.strip())
        if p.exists():
            key = str(p.resolve())
            if key not in seen:
                seen.add(key)
                paths.append(p.resolve())

    return paths


# ============================================================
# Candidate ranking
# ============================================================

def tokenize_for_matching(text: str) -> List[str]:
    return re.findall(r"[A-Za-z0-9_.$-]+", text)


def rank_candidate_file(
    path: Path,
    selected_target: TargetRecord,
    harness_text: str,
) -> int:
    score = 0
    lower_name = path.name.lower()
    full_path = str(path)

    # Strong signals from target register
    if selected_target.source_path and selected_target.source_path in full_path:
        score += 100

    entry_tokens = tokenize_for_matching(selected_target.entrypoint)
    mech_tokens = tokenize_for_matching(selected_target.mechanism)
    oracle_tokens = tokenize_for_matching(selected_target.oracle)
    harness_tokens = tokenize_for_matching(harness_text)

    text_blob = f"{path.name} {full_path}"

    for tok in entry_tokens[:30]:
        if tok and tok in text_blob:
            score += 8

    for tok in mech_tokens[:40]:
        if tok and tok in text_blob:
            score += 4

    for tok in oracle_tokens:
        if tok and tok in text_blob:
            score += 3

    for tok in harness_tokens[:80]:
        if tok and tok in text_blob:
            score += 2

    # Strong filename heuristics
    if "marshaller" in lower_name:
        score += 8
    if "openwireformat" in lower_name:
        score += 15
    if "bytesequence" in lower_name:
        score += 10
    if "pom.xml" == lower_name:
        score -= 50
    if "test" in lower_name:
        score -= 10

    return score


def select_relevant_files(
    read_paths: List[Path],
    selected_target: TargetRecord,
    harness_text: str,
    max_files: int,
) -> List[Path]:
    ranked = sorted(
        read_paths,
        key=lambda p: rank_candidate_file(p, selected_target, harness_text),
        reverse=True,
    )

    chosen: List[Path] = []
    seen_names = set()

    for p in ranked:
        if len(chosen) >= max_files:
            break

        # Skip obvious low-value files
        if p.name == "pom.xml":
            continue

        # Avoid too many duplicates by filename
        if p.name in seen_names:
            continue

        try:
            size = p.stat().st_size
        except Exception:
            continue

        if size > 250_000:
            continue

        chosen.append(p)
        seen_names.add(p.name)

    return chosen


# ============================================================
# Snippet preparation
# ============================================================

def maybe_truncate(content: str, max_chars: int) -> str:
    content = content.strip()
    if len(content) <= max_chars:
        return content
    return content[:max_chars] + "\n\n/* ... truncated ... */"


def build_source_sections(repo_root: Path, files: List[Path], max_chars_per_file: int) -> str:
    sections = []
    for p in files:
        try:
            content = read_text(p)
        except Exception:
            continue

        content = maybe_truncate(content, max_chars_per_file)
        sections.append(
            f"### Relevant Source File: {relpath_or_abs(p, repo_root)}\n\n{content}"
        )

    if not sections:
        return "None provided."

    return "\n\n".join(sections)


# ============================================================
# Prompt building
# ============================================================

def build_prompt(ctx: GenerationContext) -> str:
    harness_text = read_text(ctx.harness_file)
    source_sections = build_source_sections(
        repo_root=ctx.repo_root,
        files=ctx.files_used,
        max_chars_per_file=12000,
    )

    return f"""
Role
You are a Java software security expert specializing in denial-of-service vulnerabilities.

Objective
Generate exactly one deterministic Java unit test file whose goal is to exercise the selected target and trigger its selected oracle.
The generated test should prioritize reaching the target mechanism described below and causing the target manifestation associated with that mechanism.
Do not generate a test that merely returns normally after malformed input is rejected.

Important
This repository uses an automated assembly pipeline.
Your generated file will be inserted into an existing Maven/JUnit project.

Strict Constraints
1. Output EXACTLY one Java source file.
2. Do NOT generate pom.xml.
3. Do NOT generate build files.
4. Do NOT generate additional helper classes in separate files.
5. Do NOT generate fuzzing infrastructure.
6. Do NOT generate a fuzzer, guidance class, runner, or instrumentation agent.
7. Do NOT output markdown.
8. Do NOT output explanations.
9. Do NOT silently swallow exceptions.
10. The output must compile in an existing Maven project.
11. The package must be exactly:
   package {ctx.package_name};
12. The Java class name must be exactly:
   {ctx.output_class_name}
13. The output file name must be exactly:
   {ctx.output_filename}
14. Use the same vulnerable entry point as the existing harness unless impossible.
15. Reuse the same API usage style and setup pattern from the harness when appropriate.
16. Generate one deterministic adversarial test, not random fuzzing.
17. Use JUnit 4, not JUnit 5.
18. Import annotations from:
   import org.junit.Test;
19. Do NOT use:
   org.junit.jupiter.*
20. The test method should be annotated with:
   @Test
21. Do NOT use @BeforeEach, @AfterEach, @ParameterizedTest, or other JUnit 5 features.
22. The file must contain exactly one Java test class.
23. The file must contain exactly one method annotated with @Test.
24. Do NOT generate multiple @Test methods.
25. Focus only on the selected target id: {ctx.selected_target.id}
26. Do NOT generate test methods for any other target.
27. You are NOT allowed to modify any existing source files in the project.
28. Do NOT propose patches or edits to project files.
29. The generated test must work with the project exactly as-is.
30. Only the generated test file may contain new code.
31. Do NOT assume changes to method visibility, constructors, or APIs.
32. Do NOT assume the existence of helper classes that are not already in the project.
33. If helper logic is required, implement it directly inside the generated test class.
34. The generated test must be specifically constructed to reach the selected target mechanism using the selected entrypoint.
35. The generated test must prioritize triggering the selected oracle over producing a merely valid-looking input.
36. Do not generate a testcase that succeeds only by exercising generic parsing or validation code without reaching the selected target mechanism.
37. Do not treat malformed-input rejection as success.
38. If the selected oracle is not triggered, the test should not silently mask that outcome.
44. The test MUST use the following result convention: the test method FAILS (throws AssertionError or similar) when the vulnerability IS triggered, and PASSES when it is not.
45. Do NOT use @Test(expected=...) to detect the vulnerability. If a specific exception (e.g. StackOverflowError, OutOfMemoryError) is the oracle, catch it explicitly and call org.junit.Assert.fail() inside the catch block to signal that the vulnerability was confirmed.
46. Do NOT use @Test(timeout=...) to detect the vulnerability. If excessive time/CPU is the oracle, measure elapsed time or resource usage manually inside the test body and call org.junit.Assert.fail() with a descriptive message when the threshold is exceeded.
39. Use the provided source context to infer the concrete input structure required to reach the selected target mechanism.
40. Place attacker-controlled values only where they are semantically relevant to the selected target path.
41. Prefer a payload that is minimal but sufficient to drive execution into the selected target mechanism.
42. The automation layer will generate a shell run script for this test based on the exact package and class name you emit.
43. Do not change the package or class name from the required values.

Target Information
- Target slug: {ctx.target_slug}
- Selected target id: {ctx.selected_target.id}
- Name: {ctx.selected_target.name}
- Entrypoint: {ctx.selected_target.entrypoint}
- Source path: {ctx.selected_target.source_path}
- Mechanism: {ctx.selected_target.mechanism}
- Expected oracle: {ctx.selected_target.oracle}

Selected Vulnerability Summary
{ctx.selected_summary if ctx.selected_summary else ctx.selected_target.mechanism}

Existing Harness
File: {relpath_or_abs(ctx.harness_file, ctx.repo_root)}

{harness_text}

Relevant Source Context
{source_sections}

Additional Context
{ctx.additional_context if ctx.additional_context else "None"}

Task
Generate exactly one Java test class named {ctx.output_class_name}.
The file must be valid Java source and compile in the existing Maven project.
Return ONLY the Java source code.
""".strip()


def build_oneshot_run_script(test_class: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/" && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/prepare_common.sh" ]]; then
  SNAPPY_JAR="$("$ROOT/prepare_common.sh" | tail -n 1)"
  export SNAPPY_JAR
fi

TEST_CLASS="${{TEST_CLASS:-{test_class}}}"

if [[ -z "$TEST_CLASS" ]]; then
  echo "[run_llm_oneshot] Could not determine one-shot test class" >&2
  exit 2
fi

echo "[run_llm_oneshot] Running $TEST_CLASS"
mvn -q -Dsnappy.local.jar="${{SNAPPY_JAR:-}}" -DskipTests=false -Dtest="$TEST_CLASS" -DfailIfNoTests=false test
"""


# ============================================================
# Claude call + extraction
# ============================================================

def call_claude(prompt: str, model: str, max_tokens: int, temperature: float) -> ClaudeCallResult:
    if _BACKEND == "openai":
        return _call_openai(prompt, model, max_tokens, temperature)

    from anthropic import Anthropic

    client = Anthropic()

    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
    )

    parts: List[str] = []
    for block in resp.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)

    return ClaudeCallResult(
        raw_response="\n".join(parts).strip(),
        usage=UsageSummary.from_api_usage(getattr(resp, "usage", None)),
    )


def _call_openai(prompt: str, model: str, max_tokens: int, temperature: float) -> ClaudeCallResult:
    """OpenAI-compatible endpoint path (e.g. vLLM-served open-weight models)."""
    from openai import OpenAI

    client = OpenAI(base_url=_OPENAI_BASE_URL, api_key=_OPENAI_API_KEY)
    resp = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        messages=[{"role": "user", "content": prompt}],
    )

    text = (resp.choices[0].message.content or "").strip()

    usage = None
    try:
        u = getattr(resp, "usage", None)
        if u is not None:
            # Map OpenAI token names onto the Anthropic shape from_api_usage expects.
            shim = type("_U", (), {
                "input_tokens": getattr(u, "prompt_tokens", None),
                "output_tokens": getattr(u, "completion_tokens", None),
            })()
            usage = UsageSummary.from_api_usage(shim)
    except Exception:
        usage = None

    return ClaudeCallResult(raw_response=text, usage=usage)


def extract_java_source(raw_text: str, package_name: str, class_name: str) -> str:
    text = raw_text.strip()

    fence_match = re.search(r"```(?:java)?\s*(.*?)```", text, flags=re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    if f"package {package_name};" not in text:
        raise ValueError(f"Generated output does not contain expected package: {package_name}")

    class_pat = re.compile(rf"\bclass\s+{re.escape(class_name)}\b")
    if not class_pat.search(text):
        raise ValueError(f"Generated output does not contain expected class: {class_name}")

    test_count = len(re.findall(r"@\s*Test\b", text))
    if test_count != 1:
        raise ValueError(f"Expected exactly one @Test method, found {test_count}")

    return text


def generate_for_one_target(
    repo_root: Path,
    target_slug: str,
    selected_target_id: str,
    gen_id: str,
    model: str,
    max_tokens: int,
    temperature: float,
    max_source_files: int,
    additional_context: str,
    dry_run: bool,
) -> Optional[GenerationResult]:
    ctx = build_generation_context(
        repo_root=repo_root,
        target_slug=target_slug,
        selected_target_id=selected_target_id,
        max_source_files=max_source_files,
        additional_context=additional_context,
    )

    prompt = build_prompt(ctx)

    if dry_run:
        print(f"\n===== PROMPT FOR {selected_target_id} =====\n")
        print(prompt)
        return None

    call_result = call_claude(
        prompt=prompt,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
    )

    java_source = extract_java_source(
        raw_text=call_result.raw_response,
        package_name=ctx.package_name,
        class_name=ctx.output_class_name,
    )

    result = save_outputs(
        ctx=ctx,
        gen_id=gen_id,
        prompt=prompt,
        raw_response=call_result.raw_response,
        java_source=java_source,
        model=model,
        usage=call_result.usage,
        cost_estimate=estimate_cost_usd(model, call_result.usage),
    )

    print(f"[{selected_target_id}] Wrote generated Java file: {result.java_out}")
    print(f"[{selected_target_id}] Wrote target manifest: {result.target_manifest_out}")
    if result.cost_estimate.get("total_cost_usd") is not None:
        print(
            f"[{selected_target_id}] Usage: {result.usage.total_tokens()} total tokens "
            f"(input={result.usage.input_tokens}, output={result.usage.output_tokens}); "
            f"estimated cost=${float(result.cost_estimate['total_cost_usd']):.6f}"
        )
    else:
        print(
            f"[{selected_target_id}] Usage: {result.usage.total_tokens()} total tokens "
            f"(input={result.usage.input_tokens}, output={result.usage.output_tokens}); "
            "estimated cost unavailable for this model"
        )
    return result

# ============================================================
# Context construction
# ============================================================

def build_generation_context(
    repo_root: Path,
    target_slug: str,
    selected_target_id: Optional[str],
    max_source_files: int,
    additional_context: str,
) -> GenerationContext:
    benchmark_dir = find_benchmark_dir(repo_root, target_slug)
    project_dir = find_project_dir(repo_root, target_slug)
    target_register_json = find_target_register_json(benchmark_dir)
    block1_read_files_file = find_block1_read_files_file(benchmark_dir)
    harness_file = find_harness_file(benchmark_dir)

    harness_text = read_text(harness_file)

    records = parse_target_register_json_file(target_register_json)
    selected_target = select_target(records, selected_target_id)

    package_name = extract_package_name(harness_text)
    harness_class_name = extract_java_class_name(harness_text)
    output_class_name = derive_oneshot_class_name(harness_class_name, selected_target.id)
    output_filename = output_class_name + ".java"

    selected_summary = f"""
Selected target: {selected_target.id} — {selected_target.name}

Entrypoint:
{selected_target.entrypoint}

Mechanism:
{selected_target.mechanism}

Oracle:
{selected_target.oracle}
""".strip()

    if block1_read_files_file and block1_read_files_file.exists():
        read_paths = parse_preprocessed_read_paths(block1_read_files_file, repo_root)
    else:
        read_paths = infer_supporting_files_from_target(project_dir, selected_target)

    relevant_files = select_relevant_files(
        read_paths=read_paths,
        selected_target=selected_target,
        harness_text=harness_text,
        max_files=max_source_files,
    )

    primary_source_abs = (project_dir / selected_target.source_path).resolve()
    if primary_source_abs.exists() and primary_source_abs not in relevant_files:
        relevant_files = [primary_source_abs] + relevant_files

    deduped: List[Path] = []
    seen = set()
    for p in relevant_files:
        key = str(p.resolve())
        if key not in seen and p.exists():
            deduped.append(p.resolve())
            seen.add(key)

    relevant_files = deduped[:max_source_files]

    return GenerationContext(
        repo_root=repo_root,
        target_slug=target_slug,
        benchmark_dir=benchmark_dir,
        project_dir=project_dir,
        target_register_json=target_register_json,
        block1_read_files_file=block1_read_files_file,
        harness_file=harness_file,
        package_name=package_name,
        harness_class_name=harness_class_name,
        output_class_name=output_class_name,
        output_filename=output_filename,
        selected_target=selected_target,
        selected_summary=selected_summary,
        files_used=relevant_files,
        additional_context=additional_context,
    )

# ============================================================
# Saving outputs
# ============================================================

def save_outputs(
    ctx: GenerationContext,
    gen_id: str,
    prompt: str,
    raw_response: str,
    java_source: str,
    model: str,
    usage: UsageSummary,
    cost_estimate: dict[str, object],
) -> GenerationResult:
    generated_dir = (
        ctx.repo_root
        / "engines"
        / "llm_oneshot"
        / "generated"
        / ctx.target_slug
        / gen_id
        / ctx.selected_target.id
    )
    generated_dir.mkdir(parents=True, exist_ok=True)

    java_out = generated_dir / ctx.output_filename
    run_script_out = generated_dir / "run_llm_oneshot.sh"
    prompt_out = generated_dir / "prompt.txt"
    raw_out = generated_dir / "raw_response.txt"
    usage_out = generated_dir / "usage.json"

    write_text(java_out, java_source)
    write_text(run_script_out, build_oneshot_run_script(f"{ctx.package_name}.{ctx.output_class_name}"))
    run_script_out.chmod(0o755)
    write_text(prompt_out, prompt)
    write_text(raw_out, raw_response)
    write_text(
        usage_out,
        json.dumps(
            {
                "model": model,
                "usage": usage.to_dict(),
                "cost_estimate": cost_estimate,
            },
            indent=2,
        ),
    )

    manifest_dir = ctx.repo_root / "engines" / "llm_oneshot" / "manifests" / ctx.target_slug
    manifest_dir.mkdir(parents=True, exist_ok=True)
    target_manifest_out = manifest_dir / f"{gen_id}_{ctx.selected_target.id}.json"

    target_manifest = {
        "generator": "claude_messages_api",
        "model": model,
        "target_slug": ctx.target_slug,
        "generation_id": gen_id,
        "benchmark_dir": relpath_or_abs(ctx.benchmark_dir, ctx.repo_root),
        "project_dir": relpath_or_abs(ctx.project_dir, ctx.repo_root),
        "target_register_json": relpath_or_abs(ctx.target_register_json, ctx.repo_root),
        "block1_read_files_file": relpath_or_abs(ctx.block1_read_files_file, ctx.repo_root) if ctx.block1_read_files_file else None,
        "harness_file": relpath_or_abs(ctx.harness_file, ctx.repo_root),
        "selected_target": {
            "slot": ctx.selected_target.slot,
            "id": ctx.selected_target.id,
            "name": ctx.selected_target.name,
            "entrypoint": ctx.selected_target.entrypoint,
            "source_path": ctx.selected_target.source_path,
            "mechanism": ctx.selected_target.mechanism,
            "oracle": ctx.selected_target.oracle,
        },
        "output_file": relpath_or_abs(java_out, ctx.repo_root),
        "run_script_file": relpath_or_abs(run_script_out, ctx.repo_root),
        "prompt_file": relpath_or_abs(prompt_out, ctx.repo_root),
        "raw_response_file": relpath_or_abs(raw_out, ctx.repo_root),
        "usage_file": relpath_or_abs(usage_out, ctx.repo_root),
        "package_name": ctx.package_name,
        "class_name": ctx.output_class_name,
        "files_passed_to_llm": [relpath_or_abs(p, ctx.repo_root) for p in ctx.files_used],
        "usage": usage.to_dict(),
        "cost_estimate": cost_estimate,
    }
    write_text(target_manifest_out, json.dumps(target_manifest, indent=2))

    return GenerationResult(
        context=ctx,
        java_out=java_out,
        run_script_out=run_script_out,
        prompt_out=prompt_out,
        raw_out=raw_out,
        usage_out=usage_out,
        target_manifest_out=target_manifest_out,
        usage=usage,
        cost_estimate=cost_estimate,
    )


def save_generation_manifest(
    repo_root: Path,
    target_slug: str,
    gen_id: str,
    model: str,
    requested_gen_id: Optional[str],
    results: List[GenerationResult],
) -> Path:
    manifest_dir = repo_root / "engines" / "llm_oneshot" / "manifests" / target_slug
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_out = manifest_dir / f"{gen_id}.json"

    aggregate_usage = UsageSummary.aggregate(result.usage for result in results)
    aggregate_cost = aggregate_cost_estimates(result.cost_estimate for result in results)

    targets_payload = []
    for result in results:
        ctx = result.context
        targets_payload.append(
            {
                "selected_target": {
                    "slot": ctx.selected_target.slot,
                    "id": ctx.selected_target.id,
                    "name": ctx.selected_target.name,
                    "entrypoint": ctx.selected_target.entrypoint,
                    "source_path": ctx.selected_target.source_path,
                    "mechanism": ctx.selected_target.mechanism,
                    "oracle": ctx.selected_target.oracle,
                },
                "benchmark_dir": relpath_or_abs(ctx.benchmark_dir, repo_root),
                "project_dir": relpath_or_abs(ctx.project_dir, repo_root),
                "target_register_json": relpath_or_abs(ctx.target_register_json, repo_root),
                "block1_read_files_file": relpath_or_abs(ctx.block1_read_files_file, repo_root) if ctx.block1_read_files_file else None,
                "harness_file": relpath_or_abs(ctx.harness_file, repo_root),
                "output_file": relpath_or_abs(result.java_out, repo_root),
                "run_script_file": relpath_or_abs(result.run_script_out, repo_root),
                "prompt_file": relpath_or_abs(result.prompt_out, repo_root),
                "raw_response_file": relpath_or_abs(result.raw_out, repo_root),
                "usage_file": relpath_or_abs(result.usage_out, repo_root),
                "target_manifest_file": relpath_or_abs(result.target_manifest_out, repo_root),
                "package_name": ctx.package_name,
                "class_name": ctx.output_class_name,
                "files_passed_to_llm": [relpath_or_abs(p, repo_root) for p in ctx.files_used],
                "usage": result.usage.to_dict(),
                "cost_estimate": result.cost_estimate,
            }
        )

    manifest = {
        "generator": "claude_messages_api",
        "model": model,
        "target_slug": target_slug,
        "requested_generation_id": requested_gen_id or "auto",
        "generation_id": gen_id,
        "generation_dir": relpath_or_abs(
            repo_root / "engines" / "llm_oneshot" / "generated" / target_slug / gen_id,
            repo_root,
        ),
        "target_count": len(results),
        "targets": targets_payload,
        "usage": aggregate_usage.to_dict(),
        "cost_estimate": aggregate_cost,
    }

    # Preserve the old single-target fields so existing consumers can keep
    # reading the summary manifest without changes.
    if len(results) == 1:
        single = results[0]
        ctx = single.context
        manifest.update(
            {
                "benchmark_dir": relpath_or_abs(ctx.benchmark_dir, repo_root),
                "project_dir": relpath_or_abs(ctx.project_dir, repo_root),
                "target_register_json": relpath_or_abs(ctx.target_register_json, repo_root),
                "block1_read_files_file": relpath_or_abs(ctx.block1_read_files_file, repo_root) if ctx.block1_read_files_file else None,
                "harness_file": relpath_or_abs(ctx.harness_file, repo_root),
                "selected_target": targets_payload[0]["selected_target"],
                "output_file": relpath_or_abs(single.java_out, repo_root),
                "run_script_file": relpath_or_abs(single.run_script_out, repo_root),
                "prompt_file": relpath_or_abs(single.prompt_out, repo_root),
                "raw_response_file": relpath_or_abs(single.raw_out, repo_root),
                "usage_file": relpath_or_abs(single.usage_out, repo_root),
                "package_name": ctx.package_name,
                "class_name": ctx.output_class_name,
                "files_passed_to_llm": [relpath_or_abs(p, repo_root) for p in ctx.files_used],
            }
        )

    write_text(manifest_out, json.dumps(manifest, indent=2))
    return manifest_out


# ============================================================
# Main
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an LLM one-shot Java test from benchmark files + target_register.json."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Full target slug or GHSA id, e.g. activemq_GHSA-whxr-3p84-rf3c or GHSA-whxr-3p84-rf3c",
    )
    parser.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT), help="Repository root")
    parser.add_argument("--selected-target", default=None, help="Selected target id, e.g. V1")
    parser.add_argument("--all-targets", action="store_true", help="Generate one file per target in target_register.json")
    parser.add_argument("--gen-id", default="auto", help="Generation id or 'auto' to choose the next gen-###")
    parser.add_argument("--model", default="claude-opus-4-6", help="Model name. For --backend claude: an Anthropic model ID. For --backend openai: the model name served at the endpoint.")
    parser.add_argument("--backend", choices=["claude", "openai"], default="claude",
                        help="Model backend: 'claude' (Anthropic) or 'openai' (vLLM/OpenAI-compatible open model).")
    parser.add_argument("--openai-base-url", default=os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1"),
                        help="OpenAI-compatible base URL (vLLM). Used when --backend openai.")
    parser.add_argument("--openai-api-key", default=os.environ.get("OPENAI_API_KEY", "EMPTY"),
                        help="API key for the OpenAI-compatible endpoint (vLLM ignores it).")
    parser.add_argument("--max-tokens", type=int, default=20000, help="Max output tokens")
    parser.add_argument("--temperature", type=float, default=0.2, help="Sampling temperature")
    parser.add_argument("--max-source-files", type=int, default=4, help="How many source files to pass to the LLM")
    parser.add_argument("--additional-context", default="", help="Extra plain-text instructions")
    parser.add_argument("--dry-run", action="store_true", help="Print prompt only")
    args = parser.parse_args()

    global _BACKEND, _OPENAI_BASE_URL, _OPENAI_API_KEY
    _BACKEND = args.backend
    _OPENAI_BASE_URL = args.openai_base_url
    _OPENAI_API_KEY = args.openai_api_key

    repo_root = Path(args.repo_root).resolve()
    target_slug = resolve_target_slug(repo_root, args.target)

    benchmark_dir = find_benchmark_dir(repo_root, target_slug)
    target_register_json = find_target_register_json(benchmark_dir)
    records = parse_target_register_json_file(target_register_json)
    gen_id = resolve_generation_id(repo_root, target_slug, args.gen_id)

    saved_results: List[GenerationResult] = []
    if args.all_targets:
        for record in sorted(records, key=lambda r: r.slot):
            result = generate_for_one_target(
                repo_root=repo_root,
                target_slug=target_slug,
                selected_target_id=record.id,
                gen_id=gen_id,
                model=args.model,
                max_tokens=args.max_tokens,
                temperature=args.temperature,
                max_source_files=args.max_source_files,
                additional_context=args.additional_context,
                dry_run=args.dry_run,
            )
            if result is not None:
                saved_results.append(result)
    else:
        selected_target_id = args.selected_target
        if not selected_target_id:
            selected_target_id = sorted(records, key=lambda r: r.slot)[0].id

        result = generate_for_one_target(
            repo_root=repo_root,
            target_slug=target_slug,
            selected_target_id=selected_target_id,
            gen_id=gen_id,
            model=args.model,
            max_tokens=args.max_tokens,
            temperature=args.temperature,
            max_source_files=args.max_source_files,
            additional_context=args.additional_context,
            dry_run=args.dry_run,
        )
        if result is not None:
            saved_results.append(result)

    if args.dry_run or not saved_results:
        return

    summary_manifest_out = save_generation_manifest(
        repo_root=repo_root,
        target_slug=target_slug,
        gen_id=gen_id,
        model=args.model,
        requested_gen_id=args.gen_id,
        results=saved_results,
    )
    aggregate_usage = UsageSummary.aggregate(result.usage for result in saved_results)
    aggregate_cost = aggregate_cost_estimates(result.cost_estimate for result in saved_results)

    print(f"[generation] Resolved generation id: {gen_id}")
    print(f"[generation] Wrote summary manifest: {summary_manifest_out}")
    if aggregate_cost.get("total_cost_usd") is not None:
        print(
            f"[generation] Usage: {aggregate_usage.total_tokens()} total tokens; "
            f"estimated cost=${float(aggregate_cost['total_cost_usd']):.6f}"
        )
    else:
        print(
            f"[generation] Usage: {aggregate_usage.total_tokens()} total tokens; "
            "estimated cost unavailable for this model"
        )


if __name__ == "__main__":
    main()
