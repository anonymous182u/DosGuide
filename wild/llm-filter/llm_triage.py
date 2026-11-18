#!/usr/bin/env python3
"""LLM second-pass triage for CodeQL DoS findings.

Reduces false positives by asking Claude, per finding, whether the flagged sink
is actually reachable/triggerable from REMOTE / untrusted input (and whether an
existing guard already neutralizes it). Emits a verdict per finding and a ranked
report that surfaces the remotely-triggerable ones first.

Inputs : codeql-sarif/*.sarif  +  analysis/snapshot.manifest.json (repo -> src)
Outputs: analysis/llm-triage.jsonl        (one verdict per finding)
         analysis/llm-triage.report.md     (ranked: true-positive -> needs-review)

Auth   : needs ANTHROPIC_API_KEY (or an `ant auth login` profile the SDK reads).
Usage  : python3 llm-filter/llm_triage.py --dry-run            # build 1 prompt, no API call
         python3 llm-filter/llm_triage.py --max 300            # triage up to 300 findings
         python3 llm-filter/llm_triage.py --rules all --model claude-sonnet-5
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SARIF_DIR = os.path.join(ROOT, "codeql-sarif")
MANIFEST = os.path.join(ROOT, "analysis", "snapshot.manifest.json")
OUT_JSONL = os.path.join(ROOT, "analysis", "llm-triage.jsonl")
OUT_REPORT = os.path.join(ROOT, "analysis", "llm-triage.report.md")

# Rule IDs of the 12 DoS queries (queries/codeql-dos-queries.txt), all triaged by default.
DEFAULT_RULES = {
    "unbounded-alloc-from-input", "bignumber-abuse-from-input",
    "regex-recursion-soe", "regex-recursion-soe-shape",
    "xxe", "uncontrolled-file-decompression", "redos", "polynomial-redos",
    "regex-injection", "thread-resource-abuse", "infinite-loop",
    "uncontrolled-recursion",
}
# Skip these test/experiment SARIFs (not real batch outputs).
SKIP_SARIF = (".custom", ".shape", ".recloop", ".recloop2", ".il", ".rectight")

MODEL_DEFAULT = "claude-sonnet-4-6"  # bulk LLM-judge; --model to override (e.g. claude-sonnet-5, claude-opus-4-8)

VERDICT_TOOL = {
    "name": "record_triage",
    "description": "Record the DoS reachability triage verdict for one CodeQL finding.",
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "remote_reachable": {
                "type": "string", "enum": ["yes", "no", "unclear"],
                "description": "Can the flagged sink be reached with attacker-controlled / remote / untrusted input?",
            },
            "verdict": {
                "type": "string",
                "enum": ["true_positive", "needs_review", "false_positive"],
                "description": "true_positive: reachable from untrusted input and no adequate guard. "
                               "false_positive: unreachable from untrusted input, or an existing bound/guard neutralizes it. "
                               "needs_review: cannot decide from the given context.",
            },
            "confidence": {"type": "number", "description": "0.0-1.0 confidence in the verdict."},
            "untrusted_entry": {
                "type": "string",
                "description": "Concrete path by which untrusted input reaches the sink (public API / parser / request handler), or empty if none.",
            },
            "existing_guard": {
                "type": "string",
                "description": "Any size/depth/limit/validation that already bounds the sink, or empty if none.",
            },
            "reason": {"type": "string", "description": "<=2 sentences justifying the verdict."},
        },
        "required": ["remote_reachable", "verdict", "confidence", "untrusted_entry", "existing_guard", "reason"],
    },
}

SYSTEM = (
    "You are a security engineer triaging static-analysis (CodeQL) alerts for DENIAL-OF-SERVICE bugs "
    "in open-source Java libraries. For each alert you are given the rule, the flagged location, the "
    "enclosing source code, and (when available) the CodeQL data-flow path from source to sink.\n\n"
    "Your ONE job: decide whether the flagged sink is actually reachable/triggerable by an attacker who "
    "controls REMOTE or otherwise UNTRUSTED input (network request, parsed document/message, deserialized "
    "data, file uploaded by a user, etc.), and whether any existing bound/guard already neutralizes the DoS.\n\n"
    "Rules of judgment:\n"
    "- A sink is a real DoS risk only if untrusted input can drive it (huge size, deep nesting, pathological "
    "regex input, decompression bomb, etc.) AND there is no adequate upstream limit.\n"
    "- Constant/config/classpath/hardcoded/test-only inputs are NOT untrusted -> false_positive.\n"
    "- NON-PRODUCTION code -> false_positive: the flagged location is in test, example, benchmark, demo, "
    "mock, or generated code (not part of the shipped code), or the repository itself is a tutorial, demo, "
    "or deliberately vulnerable training project (treat all of its code as example code).\n"
    "- If a bound check, length cap, depth counter, or trusted-only caller clearly neutralizes it -> false_positive.\n"
    "- Recursion/loops bounded by finite in-memory structures (not input nesting) are not input-driven -> false_positive.\n"
    "- If you genuinely cannot tell from the provided context, use needs_review (do not guess true_positive).\n"
    "- IMPORTANT: the shown CodeQL data-flow is only ONE example path. If the SINK itself is in production "
    "parser/deserialization/codec code but the traced SOURCE happens to be a test/benchmark caller, do NOT "
    "call it false_positive on that basis alone — judge whether a *production* untrusted path to the same sink "
    "plausibly exists (it usually does for a public parse/read/deserialize method); use true_positive or "
    "needs_review. Only call false_positive when the SINK's own location is non-production or a real guard bounds it.\n"
    "Be conservative about noise, but do not discard a production sink just because the example flow came through test code.\n"
    "Always answer by calling the record_triage tool."
)

_print_lock = threading.Lock()


def load_src_map():
    m = {}
    for r in json.load(open(MANIFEST)):
        if r.get("ok") and r.get("src_path"):
            m[r["full_name"].replace("/", "__")] = r["src_path"]
    return m


def read_lines(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        return None


METHOD_RE = re.compile(
    r"^\s*(public|protected|private|static|final|synchronized|abstract|\s)*[\w\<\>\[\]\.,\s]+\s+\w+\s*\([^;]*\)\s*(\{|throws)"
)


def enclosing_snippet(lines, line_no, max_up=80, max_total=160):
    """Extract the enclosing method (best effort) around a 1-indexed line."""
    if not lines:
        return ""
    i = max(0, line_no - 1)
    start = i
    for j in range(i, max(-1, i - max_up), -1):
        if METHOD_RE.match(lines[j]):
            start = j
            break
    else:
        start = max(0, i - 25)
    end = min(len(lines), start + max_total)
    out = []
    for k in range(start, end):
        mark = "  >>" if k == line_no - 1 else "    "
        out.append(f"{k+1:5d}{mark} {lines[k]}")
    return "\n".join(out)


def flow_steps(result, src_root):
    steps = []
    for cf in result.get("codeFlows", []) or []:
        for tf in cf.get("threadFlows", []) or []:
            for loc in tf.get("locations", []) or []:
                pl = loc.get("location", {}).get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "?")
                ln = pl.get("region", {}).get("startLine", "?")
                snippet = ""
                if isinstance(ln, int):
                    fl = read_lines(os.path.join(src_root, uri))
                    if fl and 0 < ln <= len(fl):
                        snippet = fl[ln - 1].strip()[:120]
                steps.append(f"  {uri}:{ln}  {snippet}")
        break  # first code flow is enough
    return steps


def build_prompt(finding):
    parts = [
        f"Repository: {finding['repo']}",
        f"CodeQL rule: {finding['rule']}",
        f"Alert message: {finding['message']}",
        f"Location: {finding['uri']}:{finding['line']}",
        "",
    ]
    if finding["flow"]:
        parts += ["CodeQL data-flow path (source -> sink):", *finding["flow"], ""]
    parts += ["Enclosing source (>> marks the flagged line):", "```java", finding["snippet"], "```"]
    return "\n".join(parts)


def collect_findings(rules, repo_filter, src_map, allow_repos=None):
    findings = []
    seen_keys = set()
    for f in sorted(glob.glob(os.path.join(SARIF_DIR, "*.sarif"))):
        name = os.path.basename(f)[:-len(".sarif")]
        # rc_<repo>.alloc.sarif : recovered unbounded-alloc from the codec rescan (updated query)
        name_ra = name[3:-6] if (name.startswith("rc_") and name.endswith(".alloc")) else None
        repo_key = name_ra or name
        if name_ra is None and any(name.endswith(s) for s in SKIP_SARIF):
            continue
        if repo_filter and repo_filter not in repo_key:
            continue
        if allow_repos is not None and repo_key not in allow_repos:
            continue
        src_root = src_map.get(repo_key)
        if not src_root:
            continue
        try:
            data = json.load(open(f))
        except Exception:
            continue
        for run in data.get("runs", []):
            for res in run.get("results", []):
                rule = res.get("ruleId", "?").split("/")[-1]
                if rules != "all" and rule not in rules:
                    continue
                loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                uri = loc.get("artifactLocation", {}).get("uri", "?")
                line = loc.get("region", {}).get("startLine", 0)
                dk = (repo_key, uri, line, rule)
                if dk in seen_keys:          # same sink in main SARIF and rc_ rescan -> once
                    continue
                seen_keys.add(dk)
                lines = read_lines(os.path.join(src_root, uri))
                findings.append({
                    "repo": repo_key, "rule": rule,
                    "message": (res.get("message", {}) or {}).get("text", "")[:300],
                    "uri": uri, "line": line,
                    "snippet": enclosing_snippet(lines, line) if line else "",
                    "flow": flow_steps(res, src_root),
                })
    return findings


def triage_one(client, model, finding):
    import anthropic
    prompt = build_prompt(finding)
    for attempt in range(4):
        try:
            resp = client.messages.create(
                model=model, max_tokens=1024, system=SYSTEM,
                tools=[VERDICT_TOOL],
                tool_choice={"type": "tool", "name": "record_triage"},
                messages=[{"role": "user", "content": prompt}],
            )
            for block in resp.content:
                if getattr(block, "type", None) == "tool_use" and block.name == "record_triage":
                    return {**{k: finding[k] for k in ("repo", "rule", "uri", "line", "message")}, **block.input}
            return {**{k: finding[k] for k in ("repo", "rule", "uri", "line", "message")},
                    "verdict": "needs_review", "reason": "no tool output", "confidence": 0.0,
                    "remote_reachable": "unclear", "untrusted_entry": "", "existing_guard": ""}
        except anthropic.RateLimitError:
            import time; time.sleep(5 * (attempt + 1))
        except (anthropic.APIStatusError, anthropic.APIConnectionError) as e:
            if attempt == 3:
                return {**{k: finding[k] for k in ("repo", "rule", "uri", "line", "message")},
                        "verdict": "needs_review", "reason": f"api error: {e}", "confidence": 0.0,
                        "remote_reachable": "unclear", "untrusted_entry": "", "existing_guard": ""}
            import time; time.sleep(3 * (attempt + 1))
    return None


def write_report(verdicts):
    order = {"true_positive": 0, "needs_review": 1, "false_positive": 2}
    verdicts.sort(key=lambda v: (order.get(v.get("verdict"), 3), -float(v.get("confidence") or 0)))
    tp = [v for v in verdicts if v.get("verdict") == "true_positive"]
    nr = [v for v in verdicts if v.get("verdict") == "needs_review"]
    fp = [v for v in verdicts if v.get("verdict") == "false_positive"]
    L = ["# LLM DoS Triage — reachability pre-screen", "",
         f"Total triaged: {len(verdicts)}  |  true_positive: {len(tp)}  needs_review: {len(nr)}  false_positive: {len(fp)}",
         "", "## Remotely triggerable (true_positive)", "",
         "| conf | rule | location | untrusted entry | reason |", "| ---: | --- | --- | --- | --- |"]
    for v in tp:
        L.append(f"| {float(v.get('confidence') or 0):.2f} | {v['rule']} | {v['repo']}/{v['uri']}:{v['line']} | "
                 f"{(v.get('untrusted_entry') or '')[:60]} | {(v.get('reason') or '')[:120]} |")
    L += ["", "## Needs human review", "", "| conf | rule | location | reason |", "| ---: | --- | --- | --- |"]
    for v in nr:
        L.append(f"| {float(v.get('confidence') or 0):.2f} | {v['rule']} | {v['repo']}/{v['uri']}:{v['line']} | {(v.get('reason') or '')[:120]} |")
    L += ["", f"## Filtered out as false_positive: {len(fp)} (see llm-triage.jsonl)", ""]
    open(OUT_REPORT, "w").write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="default", help="'default', 'all', or comma-separated rule ids")
    ap.add_argument("--repo", default="", help="only triage SARIFs whose name contains this")
    ap.add_argument("--max", type=int, default=0, help="cap number of findings (0 = no cap)")
    ap.add_argument("--model", default=MODEL_DEFAULT)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--dry-run", action="store_true", help="build prompts, print one, no API call")
    args = ap.parse_args()

    rules = ("all" if args.rules == "all"
             else DEFAULT_RULES if args.rules == "default"
             else set(s.strip() for s in args.rules.split(",")))

    src_map = load_src_map()
    findings = collect_findings(rules, args.repo, src_map)
    if args.max:
        findings = findings[: args.max]
    print(f"collected {len(findings)} findings (rules={args.rules}, repos matched by src map)")

    if args.dry_run:
        if findings:
            print("\n===== EXAMPLE PROMPT (finding 1) =====\n")
            print(build_prompt(findings[0]))
            print("\n===== verdict tool schema fields:", list(VERDICT_TOOL["input_schema"]["properties"]))
        est_in = len(findings) * 1200  # rough tokens/finding
        print(f"\n[dry-run] would issue {len(findings)} calls to {args.model}; "
              f"~{est_in:,} input tokens (rough). Set ANTHROPIC_API_KEY and drop --dry-run to execute.")
        return 0

    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        print("ERROR: no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN in env (and no `ant` profile). "
              "Set one and re-run; use --dry-run to preview without credentials.", file=sys.stderr)
        return 2

    import anthropic
    client = anthropic.Anthropic()
    verdicts = []
    done = 0
    with open(OUT_JSONL, "w") as jf, ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(triage_one, client, args.model, f): f for f in findings}
        for fut in as_completed(futs):
            v = fut.result()
            if not v:
                continue
            verdicts.append(v)
            jf.write(json.dumps(v, ensure_ascii=False) + "\n"); jf.flush()
            done += 1
            if done % 20 == 0:
                with _print_lock:
                    print(f"  triaged {done}/{len(findings)}", flush=True)
    write_report(verdicts)
    tp = sum(v.get("verdict") == "true_positive" for v in verdicts)
    fp = sum(v.get("verdict") == "false_positive" for v in verdicts)
    print(f"\ndone: {len(verdicts)} triaged -> true_positive={tp} false_positive={fp} "
          f"needs_review={len(verdicts)-tp-fp}")
    print(f"wrote {OUT_JSONL}\nwrote {OUT_REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
