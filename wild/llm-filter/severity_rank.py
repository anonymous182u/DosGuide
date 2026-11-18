#!/usr/bin/env python3
"""Static harm/severity ranking of DoS true-positives, from alert metadata only.

No new LLM calls. Combines the LLM triage fields (untrusted_entry, existing_guard,
confidence, rule) with library reach (stars/maven) into a CVSS-like harm score, so
you can prioritise which candidates to PoC first. This is an ESTIMATE — real
severity needs a PoC — but it orders the pile well.

Inputs : analysis/llm-triage.jsonl
Output : analysis/severity-ranked.md  + printed top list
"""
from __future__ import annotations
import json, math, os, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "analysis", "snapshot.manifest.json")
JSONLS = [os.path.join(ROOT, "analysis", "llm-triage.jsonl")]
OUT = os.path.join(ROOT, "analysis", "severity-ranked.md")

REMOTE_KW = ("socket", "tcp", "wire", "protocol", "network", "rpc", "dns",
             "mqtt", "amqp", "deserial", "request body", "http request",
             "http post", "endpoint", "jax-rs", "servlet", "rmi", "frame", "unmarshal")
FILE_KW = ("parse", "document", " file", "xml", "box", "chunk", "config", "resource")
# Formats that are, in practice, attacker-supplied via upload/attachment endpoints
# everywhere (crafted image/office/media/archive). De-facto remote, above plain file read.
UPLOAD_KW = ("image", "pdf", "xlsx", "excel", "word", "docx", "office", "audio", "video",
             "media", "archive", "decompress", "zip", "font", "dicom", "photo", "picture",
             "bmp", "jpeg", "jpg", "png", "gif", "tiff", "svg", "epub", "mp4", "mp3",
             "upload", "attachment", "mov", "wav", "ttf", "otf", "ico", "webp")
IMPACT = {  # DoS impact class -> weight
    "unbounded-alloc-from-input": 3.0, "uncontrolled-file-decompression": 3.0,
    "infinite-loop": 2.8,
    "regex-recursion-soe": 2.3, "regex-recursion-soe-shape": 2.3, "uncontrolled-recursion": 2.2,
    "bignumber-abuse-from-input": 2.0, "redos": 2.0, "polynomial-redos": 2.0, "xxe": 2.6,
    "regex-injection": 1.8, "thread-resource-abuse": 1.8,
}
AMP_KW = ("max_value", "2 gb", "2gb", "immediate", "tiny", "small payload", "5-byte",
          "5 byte", "few bytes", "byte payload", "billion", "unbounded", "no limit",
          "no bound", "without validation", "without any", "directly allocate")


def load_meta():
    m = {}
    for r in json.load(open(MANIFEST)):
        m[r["full_name"].replace("/", "__")] = {
            "full_name": r["full_name"], "stars": r.get("stars", 0) or 0, "maven": bool(r.get("maven")),
            "desc": (r.get("description") or "").lower(),
        }
    return m


def surface_score(entry, remote):
    e = (entry or "").lower()
    if any(k in e for k in REMOTE_KW):
        base = 3.0                                   # network / deserialization: directly remote
    elif any(k in e for k in UPLOAD_KW):
        base = 2.7                                   # crafted image/office/media/archive: de-facto remote via uploads
    elif any(k in e for k in FILE_KW):
        base = 2.0                                   # generic file/config parse
    else:
        base = 1.0
    if remote == "no":
        base = min(base, 1.0)
    elif remote == "unclear":
        base *= 0.85
    return base


def guard_mult(guard):
    g = (guard or "").strip().lower()
    if not g or g.startswith("none") or g.startswith("no ") or g == "n/a":
        return 1.2          # unbounded
    return 0.7              # some guard present


def pop_score(meta):
    stars = meta.get("stars", 0)
    s = 1.0 + math.log10(stars + 10) / 2.0          # 500*->~1.35, 30k->~2.3
    if meta.get("maven"):
        s += 0.2
    return s


def score(v, meta):
    rule = v["rule"]
    impact = IMPACT.get(rule, 1.5)
    surf = surface_score(v.get("untrusted_entry"), v.get("remote_reachable"))
    guard = guard_mult(v.get("existing_guard"))
    conf = float(v.get("confidence") or 0.5)
    reason = (v.get("reason", "") + " " + v.get("untrusted_entry", "")).lower()
    amp = 1.2 if any(k in reason for k in AMP_KW) else 1.0
    pop = pop_score(meta)
    s = surf * impact * guard * conf * amp * pop
    return s, dict(surface=round(surf, 2), impact=impact, guard=round(guard, 2),
                   conf=round(conf, 2), amp=amp, pop=round(pop, 2))


def main():
    meta = load_meta()
    tp = {}
    for jf in JSONLS:
        if not os.path.exists(jf):
            continue
        for l in open(jf):
            x = json.loads(l)
            if x.get("verdict") != "true_positive":
                continue
            k = (x["repo"], x["uri"], x["line"])
            if k not in tp or float(x.get("confidence") or 0) > float(tp[k].get("confidence") or 0):
                tp[k] = x

    scored = []
    for x in tp.values():
        m = meta.get(x["repo"], {"full_name": x["repo"].replace("__", "/"), "stars": 0, "maven": False})
        s, comp = score(x, m)
        scored.append((s, x, m, comp))
    scored.sort(key=lambda t: -t[0])

    # library-level: max score + count
    libagg = collections.defaultdict(lambda: [0.0, 0])
    for s, x, m, _ in scored:
        libagg[m["full_name"]][0] = max(libagg[m["full_name"]][0], s)
        libagg[m["full_name"]][1] += 1

    L = ["# DoS harm ranking (static, from alerts only)", "",
         f"{len(scored)} distinct true-positive sinks scored. Harm = surface x impact x guard x confidence x amplification x reach. "
         "Estimate only — confirm with a PoC.", "",
         "## Top libraries by peak harm", "", "| lib | peak | sinks | ★ |", "| --- | ---: | ---: | ---: |"]
    for fn in sorted(libagg, key=lambda r: -libagg[r][0])[:30]:
        pk, n = libagg[fn]
        st = meta.get(fn.replace("/", "__"), {}).get("stars", 0)
        L.append(f"| {fn} | {pk:.1f} | {n} | {st} |")
    L += ["", "## Top 60 individual sinks", "",
          "| # | harm | rule | location | ★ | surface·impact·guard·conf·amp | entry |",
          "| ---: | ---: | --- | --- | ---: | --- | --- |"]
    for i, (s, x, m, c) in enumerate(scored[:60], 1):
        comp = f"{c['surface']}·{c['impact']}·{c['guard']}·{c['conf']}·{c['amp']}"
        L.append(f"| {i} | {s:.1f} | {x['rule']} | {m['full_name']}/{x['uri'].split('/')[-1]}:{x['line']} | "
                 f"{m['stars']} | {comp} | {(x.get('untrusted_entry') or '')[:70]} |")
    open(OUT, "w").write("\n".join(L) + "\n")

    print(f"scored {len(scored)} true-positive sinks")
    print("\nTop 20 by harm:")
    for i, (s, x, m, c) in enumerate(scored[:20], 1):
        print(f"{i:>2}. {s:5.1f}  {x['rule']:<26} {m['full_name']}/{x['uri'].split('/')[-1]}:{x['line']}  (★{m['stars']})")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
