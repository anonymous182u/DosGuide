#!/usr/bin/env python3
"""LLM triage for CodeQL DoS findings — Claude Agent SDK edition (uses the Claude
Code SUBSCRIPTION, no ANTHROPIC_API_KEY).

Same job as llm_triage.py (judge whether each flagged sink is reachable from
remote/untrusted input, to cut false positives), but calls Claude through
`claude_agent_sdk.query()` — which authenticates via the local Claude Code login
(subscription OAuth) instead of an API key. Reuses the SARIF extraction, prompt
builder, and report writer from llm_triage.py.

Usage: python3 llm-filter/llm_triage_agent.py --max 3
       python3 llm-filter/llm_triage_agent.py --repo owner__project --model claude-sonnet-4-6
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys

from claude_agent_sdk import (
    query, ClaudeAgentOptions, AssistantMessage, TextBlock, ResultMessage,
)

# reuse everything except the API-call layer
from llm_triage import (
    collect_findings, build_prompt, load_src_map, write_report,
    DEFAULT_RULES, OUT_JSONL,
)

MODEL_DEFAULT = "claude-sonnet-4-6"
FIELDS = ["remote_reachable", "verdict", "confidence", "untrusted_entry", "existing_guard", "reason"]

AGENT_SYSTEM = (
    "You are a security engineer triaging static-analysis (CodeQL) alerts for DENIAL-OF-SERVICE bugs "
    "in open-source Java libraries. For each alert you get the rule, the flagged location, the enclosing "
    "source code, and (when available) the CodeQL data-flow path from source to sink.\n\n"
    "Decide whether the flagged sink is actually reachable/triggerable by an attacker who controls REMOTE "
    "or UNTRUSTED input (network request, parsed document/message, deserialized data, user-uploaded file), "
    "and whether an existing bound/guard already neutralizes the DoS.\n"
    "- Real risk only if untrusted input can drive the sink (huge size, deep nesting, pathological regex "
    "input, decompression bomb) AND there is no adequate upstream limit.\n"
    "- Constant/config/classpath/hardcoded/test-only inputs are NOT untrusted -> false_positive.\n"
    "- NON-PRODUCTION code -> false_positive: the flagged location is in test, example, benchmark, demo, "
    "mock, or generated code (not part of the shipped code), or the repository itself is a tutorial, demo, "
    "or deliberately vulnerable training project (treat all of its code as example code).\n"
    "- A clear bound/length cap/depth counter/trusted-only caller -> false_positive.\n"
    "- Recursion/loops bounded by finite in-memory structures (not input nesting) -> false_positive.\n"
    "- If you cannot tell from the given context -> needs_review (do not guess true_positive).\n"
    "- The shown CodeQL data-flow is only ONE example path. If the SINK is in production parser/deserialization/"
    "codec code but the traced SOURCE happens to be a test/benchmark caller, do NOT call it false_positive on "
    "that basis — a production untrusted path to the same public parse/read/deserialize sink usually exists; use "
    "true_positive or needs_review. Call false_positive only when the SINK's own location is non-production or a "
    "real guard bounds it.\n"
    "Be conservative about noise, but do not discard a production sink just because the example flow came through test code.\n\n"
    "Respond with ONLY a single JSON object, no prose, no code fence, with EXACTLY these keys:\n"
    '{"remote_reachable":"yes|no|unclear","verdict":"true_positive|needs_review|false_positive",'
    '"confidence":0.0-1.0,"untrusted_entry":"...","existing_guard":"...","reason":"<=2 sentences"}'
)


def parse_verdict(text, finding):
    base = {k: finding[k] for k in ("repo", "rule", "uri", "line", "message")}
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            obj = json.loads(m.group(0))
            return {**base, **{k: obj.get(k, "") for k in FIELDS}}
        except Exception:
            pass
    return {**base, "verdict": "needs_review", "remote_reachable": "unclear",
            "confidence": 0.0, "untrusted_entry": "", "existing_guard": "",
            "reason": "unparseable model output"}


async def judge(finding, model):
    prompt = build_prompt(finding) + "\n\nReturn ONLY the JSON object described in the system prompt."
    opts = ClaudeAgentOptions(
        system_prompt=AGENT_SYSTEM,
        model=model,
        max_turns=1,
        allowed_tools=[],            # pure judgment, no tool use
        permission_mode="bypassPermissions",
        setting_sources=None,        # don't load project/user settings into the sub-run
    )
    text = ""
    try:
        async for msg in query(prompt=prompt, options=opts):
            if isinstance(msg, AssistantMessage):
                for b in msg.content:
                    if isinstance(b, TextBlock):
                        text += b.text
            elif isinstance(msg, ResultMessage):
                if getattr(msg, "result", None):
                    text = msg.result or text
    except Exception as e:
        base = {k: finding[k] for k in ("repo", "rule", "uri", "line", "message")}
        return {**base, "verdict": "needs_review", "remote_reachable": "unclear",
                "confidence": 0.0, "untrusted_entry": "", "existing_guard": "",
                "reason": f"agent error: {type(e).__name__}: {str(e)[:150]}"}
    return parse_verdict(text, finding)


async def run(findings, model, concurrency, jf, timeout):
    sem = asyncio.Semaphore(concurrency)
    verdicts = []
    done = 0

    async def one(f):
        nonlocal done
        async with sem:
            try:
                v = await asyncio.wait_for(judge(f, model), timeout=timeout)
            except asyncio.TimeoutError:
                v = {**{k: f[k] for k in ("repo", "rule", "uri", "line", "message")},
                     "verdict": "needs_review", "remote_reachable": "unclear", "confidence": 0.0,
                     "untrusted_entry": "", "existing_guard": "", "reason": f"timeout >{timeout}s"}
        verdicts.append(v)
        jf.write(json.dumps(v, ensure_ascii=False) + "\n"); jf.flush()   # incremental: survive interruption
        done += 1
        if done % 10 == 0 or v.get("verdict") == "true_positive":
            print(f"  [{done}/{len(findings)}] {v['rule']:<26} {str(v.get('verdict')):<14} {v['repo']}/{v['uri']}:{v['line']}", flush=True)
        return v

    await asyncio.gather(*(one(f) for f in findings))
    return verdicts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="default")
    ap.add_argument("--repo", default="")
    ap.add_argument("--max", type=int, default=0)
    ap.add_argument("--model", default=MODEL_DEFAULT)
    ap.add_argument("--concurrency", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=150, help="per-finding timeout seconds")
    ap.add_argument("--repos-file", default="", help="only triage repo keys listed in this file (one safe_name per line)")
    ap.add_argument("--out", default="", help="override output jsonl path")
    ap.add_argument("--reuse", default="", help="existing verdicts jsonl: reuse them, only re-judge new / errored findings")
    args = ap.parse_args()

    rules = ("all" if args.rules == "all"
             else DEFAULT_RULES if args.rules == "default"
             else set(s.strip() for s in args.rules.split(",")))

    allow = None
    if args.repos_file:
        allow = set(l.strip() for l in open(args.repos_file) if l.strip() and not l.startswith("#"))
    findings = collect_findings(rules, args.repo, load_src_map(), allow_repos=allow)
    if args.max:
        findings = findings[: args.max]

    reused = []
    if args.reuse:
        def needs_rejudge(old):
            reason = old.get("reason", "") or ""
            return any(s in reason for s in ("agent error", "timeout >", "unparseable"))
        prev = {}
        for l in open(args.reuse):
            x = json.loads(l); prev[(x["repo"], x["uri"], x["line"])] = x
        to_judge = []
        for f in findings:
            k = (f["repo"], f["uri"], f["line"])
            if k in prev and not needs_rejudge(prev[k]):
                reused.append(prev[k])
            else:
                to_judge.append(f)
        print(f"collected {len(findings)}: reuse {len(reused)} old verdicts, re-judge {len(to_judge)} "
              f"(new / errored)")
        findings = to_judge

    print(f"judging {len(findings)} via Claude Agent SDK (subscription), model={args.model}")
    if not findings and not reused:
        return 0

    out_path = args.out or OUT_JSONL
    with open(out_path, "w") as jf:
        for v in reused:
            jf.write(json.dumps(v, ensure_ascii=False) + "\n")
        jf.flush()
        verdicts = asyncio.run(run(findings, args.model, args.concurrency, jf, args.timeout)) if findings else []
    verdicts = reused + verdicts
    tp = sum(v.get("verdict") == "true_positive" for v in verdicts)
    fp = sum(v.get("verdict") == "false_positive" for v in verdicts)
    print(f"\ndone: {len(verdicts)} -> true_positive={tp} false_positive={fp} needs_review={len(verdicts)-tp-fp}")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
