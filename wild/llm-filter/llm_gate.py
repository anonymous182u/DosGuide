#!/usr/bin/env python3
"""Second-stage exploitability gate over the true-positive DoS sinks.

Two gates, judged from the sink's code by Claude (subscription, Agent SDK):
  1. resource-bound gate      : is the resource (alloc size / recursion depth / loop
                                count / number magnitude) effectively capped by a
                                validated limit BEFORE it is consumed?
  2. input-controllability gate: does the attacker cheaply control the MAGNITUDE, i.e.
                                is there AMPLIFICATION (small input -> large resource)?
                                e.g. `new byte[declaredLen]` allocated before any check
                                that declaredLen <= bytes actually sent.

exploitable = (controls magnitude) AND (not resource-bounded). Only these are worth a PoC.

Gates every true-positive sink from the first round, ordered by severity_rank harm score
(ordering only; nothing is dropped unless --top / --min-harm is given). Subscription auth,
concurrency 64.
Output: analysis/llm-gate.jsonl  + analysis/llm-gate.shortlist.md
"""
from __future__ import annotations
import argparse, asyncio, json, os, re, sys

from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock, ResultMessage
from llm_triage import collect_findings, build_prompt, load_src_map
import severity_rank as SR

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRIAGE = os.path.join(ROOT, "analysis", "llm-triage.jsonl")
OUT = os.path.join(ROOT, "analysis", "llm-gate.jsonl")
SHORTLIST = os.path.join(ROOT, "analysis", "llm-gate.shortlist.md")
MODEL = "claude-sonnet-4-6"
FIELDS = ["resource_bounded", "attacker_controls_magnitude", "exploitable", "amplification", "reason"]

GATE_SYSTEM = (
    "You are a security engineer deciding whether a Java DoS sink is ACTUALLY EXPLOITABLE, given the sink's "
    "code and (when present) the source->sink data-flow. Assume the sink is already reachable from untrusted "
    "input. Apply exactly two gates:\n\n"
    "GATE 1 - resource bound: Is the consumed resource (array/collection allocation size, recursion depth, "
    "loop iteration count, or numeric magnitude) effectively capped by a VALIDATED limit BEFORE it is consumed? "
    "(a length/size/depth check that throws or clamps; a small fixed cap; a framework limit visible in code). "
    "If yes -> resource_bounded = yes.\n\n"
    "GATE 2 - magnitude controllability / AMPLIFICATION: Does the attacker cheaply control the MAGNITUDE — a "
    "SMALL input causing a LARGE resource use? For allocation: is the size taken from a declared header/length "
    "field and allocated BEFORE any check that the declared size <= bytes actually supplied? (then a few bytes "
    "force a huge allocation = amplification = yes). If the code must actually read/copy N real bytes to reach "
    "size N (so the attacker must transmit N bytes), there is NO amplification -> attacker_controls_magnitude = no. "
    "For recursion/loops: does attacker-controlled nesting depth / count drive it with small input? For BigInteger/"
    "BigDecimal: can a short literal (e.g. \"1e999999\") cause huge CPU/memory?\n\n"
    "exploitable = yes  only if attacker_controls_magnitude = yes AND resource_bounded = no.\n"
    "exploitable = no   if resource_bounded = yes, or there is no amplification (magnitude bounded by real input size).\n"
    "exploitable = maybe if you cannot tell from the code.\n"
    "Be strict: the goal is to keep only sinks a small crafted input can actually blow up.\n\n"
    "Respond with ONLY one JSON object, no prose, keys exactly: "
    '{"resource_bounded":"yes|no|unclear","attacker_controls_magnitude":"yes|no|unclear",'
    '"exploitable":"yes|maybe|no","amplification":"<e.g. 5-byte payload -> 2GB, or none>","reason":"<=2 sentences"}'
)


def parse(text, base):
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            o = json.loads(m.group(0))
            return {**base, **{k: o.get(k, "") for k in FIELDS}}
        except Exception:
            pass
    return {**base, "exploitable": "maybe", "resource_bounded": "unclear",
            "attacker_controls_magnitude": "unclear", "amplification": "", "reason": "unparseable"}


async def judge(f, model):
    prompt = build_prompt(f) + "\n\nReturn ONLY the JSON object from the system prompt."
    opts = ClaudeAgentOptions(system_prompt=GATE_SYSTEM, model=model, max_turns=1,
                              allowed_tools=[], permission_mode="bypassPermissions", setting_sources=None)
    text = ""
    base = {k: f[k] for k in ("repo", "rule", "uri", "line")}
    base["harm"] = f.get("harm")
    try:
        async for msg in query(prompt=prompt, options=opts):
            if isinstance(msg, AssistantMessage):
                for b in msg.content:
                    if isinstance(b, TextBlock):
                        text += b.text
            elif isinstance(msg, ResultMessage) and getattr(msg, "result", None):
                text = msg.result or text
    except Exception as e:
        return {**base, "exploitable": "maybe", "resource_bounded": "unclear",
                "attacker_controls_magnitude": "unclear", "amplification": "",
                "reason": f"agent error: {type(e).__name__}"}
    return parse(text, base)


async def run(findings, model, concurrency, jf):
    sem = asyncio.Semaphore(concurrency)
    out = []
    done = 0

    async def one(f):
        nonlocal done
        async with sem:
            try:
                v = await asyncio.wait_for(judge(f, model), timeout=150)
            except asyncio.TimeoutError:
                v = {k: f[k] for k in ("repo", "rule", "uri", "line")}
                v.update(exploitable="maybe", resource_bounded="unclear",
                         attacker_controls_magnitude="unclear", amplification="", reason="timeout")
        out.append(v)
        jf.write(json.dumps(v, ensure_ascii=False) + "\n"); jf.flush()
        done += 1
        if v.get("exploitable") == "yes" or done % 20 == 0:
            print(f"  [{done}/{len(findings)}] exploitable={v.get('exploitable'):<6} {v['rule']:<24} {v['repo']}/{v['uri'].split('/')[-1]}:{v['line']}", flush=True)
        return v

    await asyncio.gather(*(one(f) for f in findings))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=0, help="only gate the top-N highest-harm TP sinks (default 0 = all)")
    ap.add_argument("--min-harm", type=float, default=0.0)
    ap.add_argument("--concurrency", type=int, default=64)
    args = ap.parse_args()

    meta = SR.load_meta()
    # TP set with snippets (from collect_findings) keyed by (repo,uri,line)
    findings = {(f["repo"], f["uri"], f["line"]): f for f in collect_findings("all", "", load_src_map())}
    tp = {}
    for l in open(TRIAGE):
        x = json.loads(l)
        if x.get("verdict") != "true_positive":
            continue
        k = (x["repo"], x["uri"], x["line"])
        f = findings.get(k)
        if not f:
            continue
        m = meta.get(x["repo"], {"full_name": x["repo"], "stars": 0, "maven": False, "desc": ""})
        f = dict(f)
        f["harm"] = round(SR.score(x, m)[0], 1)
        tp[k] = f
    ranked = sorted(tp.values(), key=lambda f: -f["harm"])
    ranked = [f for f in ranked if f["harm"] >= args.min_harm]
    if args.top:
        ranked = ranked[: args.top]
    print(f"gating {len(ranked)} TP sinks (of {len(tp)}) via subscription, model={MODEL}")

    with open(OUT, "w") as jf:
        res = asyncio.run(run(ranked, MODEL, args.concurrency, jf))

    ex = [r for r in res if r.get("exploitable") == "yes"]
    ex.sort(key=lambda r: -(r.get("harm") or 0))
    L = ["# Exploitable DoS shortlist (passed resource-bound + controllability gates)", "",
         f"{len(res)} gated -> {len(ex)} exploitable, "
         f"{sum(r.get('exploitable')=='maybe' for r in res)} maybe, "
         f"{sum(r.get('exploitable')=='no' for r in res)} bounded/no-amplification.", "",
         "| harm | rule | location | amplification | reason |", "| ---: | --- | --- | --- | --- |"]
    for r in ex:
        L.append(f"| {r.get('harm')} | {r['rule']} | {r['repo']}/{r['uri'].split('/')[-1]}:{r['line']} | "
                 f"{(r.get('amplification') or '')[:40]} | {(r.get('reason') or '')[:110]} |")
    open(SHORTLIST, "w").write("\n".join(L) + "\n")
    print(f"\n-> exploitable={len(ex)}  maybe={sum(r.get('exploitable')=='maybe' for r in res)}  "
          f"no={sum(r.get('exploitable')=='no' for r in res)}")
    print(f"wrote {OUT}\nwrote {SHORTLIST}")


if __name__ == "__main__":
    main()
