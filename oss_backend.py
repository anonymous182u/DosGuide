"""
oss_backend.py
==============
OpenAI-compatible (vLLM) agent backend for dosguide.py.

Lets the SAME 3-block DoS-guidance synthesis pipeline run on open-weight models
(Qwen3.6-27B, Devstral-Small-2-24B, ...) served behind an OpenAI-compatible
endpoint, instead of the Claude Agent SDK.

It re-implements what the SDK gives us for free:
  * the 8 tools (Read/Write/Edit/MultiEdit/Glob/Grep/LS/Bash), executed locally;
  * the SAME pre-tool restriction hook (passed in by the runner) that blocks web
    / git access and writes outside the workspace;
  * a continuous conversation across the 3 blocks (mirrors ClaudeSDKClient);
  * context compaction when the conversation nears the model's context window
    (Claude Code compacts automatically; see OpenAIAgentSession._maybe_compact);
  * per-block token-usage logging (recovers the input/output split the Claude
    path never recorded).

Requires:  pip install openai
Serve a model with vLLM, e.g.:
  python -m vllm.entrypoints.openai.api_server \
      --model Qwen/Qwen3.6-27B --tensor-parallel-size 1 \
      --max-model-len 131072 --enable-auto-tool-choice \
      --tool-call-parser hermes        # use the parser that matches your model
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Awaitable, Callable

MAX_TOOL_RESULT_CHARS = 30_000
READ_DEFAULT_LIMIT = 2000
MAX_TOKENS_PER_CALL = 8192

# Context compaction. The conversation of a synthesis (three blocks, their repair rounds and every tool result)
# grows past the context window of most served models, so the session compacts it before a request would not fit:
#   1. tool results older than the newest few (as many as fit in KEPT_SHARE of the budget, 2 to 8), and long
#      arguments of older tool calls (e.g. the content of a Write: the file is on disk), are replaced by a short note;
#   2. if that is not enough, the model summarizes the conversation before its last KEEP_RECENT_GROUPS tool-call
#      groups; the current request (block prompt or repair message) stays verbatim, the summary follows it;
#   3. if still too long, only the last two tool results are kept and long replies in the kept part are shortened.
# User messages (block prompts, check diagnostics) are never elided. A request the server rejects as too long is
# compacted harder and sent again (at most COMPACT_RETRIES times).
CONTEXT_TOKENS = 131_072          # the served model's context window (vLLM --max-model-len)
COMPACT_AT = 0.75                 # compact when the next request would pass this share of the window
KEEP_RECENT_TOOL_RESULTS = 8      # stage 1 keeps at most this many of the newest tool results ...
MIN_KEPT_TOOL_RESULTS = 2         # ... and at least this many,
KEPT_SHARE = 0.4                  # as many as fit in this share of the budget
KEEP_RECENT_GROUPS = 4            # assistant turns (with their tool results) kept verbatim by stage 2
ELIDE_PREVIEW_CHARS = 300
ELIDE_ARG_CHARS = 2000            # tool-call arguments longer than this are elided in older turns
SUMMARY_MAX_TOKENS = 4096
SUMMARY_INPUT_CHARS_PER_MESSAGE = 4000
CHARS_PER_TOKEN = 3.5             # until the server has reported a prompt's size
COMPACT_RETRIES = 2
SUMMARY_MARKER = ("\n\n[Context summary: the earlier part of this conversation was condensed to save context. Files "
                  "you wrote are on disk; read them again if you need their contents.]\n")
SUMMARY_INSTRUCTION = (
    "You are condensing the conversation of a coding agent so that it can continue its task with less context. "
    "Summarize the conversation below for the agent itself. Keep, with exact identifiers, file paths, class and "
    "method names and numbers: the task and its rules as far as they bear on the remaining work; the target "
    "register and measurement plan as decided (they are also on disk under analysis/); every file created or "
    "changed and what it does; every check result and repair message received and what was done about it; what "
    "remains to be done next. Do not add advice. Write plain text.")


# ====================================================================
# Tool schemas (OpenAI function-calling format) -- mirror the SDK tools
# ====================================================================
def _schema(name: str, desc: str, props: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {"type": "object", "properties": props, "required": required},
        },
    }


TOOL_SCHEMAS = [
    _schema("Read", "Read a file from disk. Returns line-numbered content.",
            {"file_path": {"type": "string"},
             "offset": {"type": "integer", "description": "1-based start line"},
             "limit": {"type": "integer"}}, ["file_path"]),
    _schema("Write", "Write (create/overwrite) a file in the workspace.",
            {"file_path": {"type": "string"}, "content": {"type": "string"}},
            ["file_path", "content"]),
    _schema("Edit", "Replace an exact string in a file.",
            {"file_path": {"type": "string"}, "old_string": {"type": "string"},
             "new_string": {"type": "string"}, "replace_all": {"type": "boolean"}},
            ["file_path", "old_string", "new_string"]),
    _schema("MultiEdit", "Apply several Edit operations to one file in order.",
            {"file_path": {"type": "string"},
             "edits": {"type": "array", "items": {
                 "type": "object",
                 "properties": {"old_string": {"type": "string"},
                                "new_string": {"type": "string"},
                                "replace_all": {"type": "boolean"}},
                 "required": ["old_string", "new_string"]}}},
            ["file_path", "edits"]),
    _schema("Glob", "Find files matching a glob pattern.",
            {"pattern": {"type": "string"}, "path": {"type": "string"}}, ["pattern"]),
    _schema("Grep", "Search file contents with ripgrep.",
            {"pattern": {"type": "string"}, "path": {"type": "string"},
             "glob": {"type": "string"}, "-i": {"type": "boolean"},
             "output_mode": {"type": "string",
                             "enum": ["content", "files_with_matches", "count"]}},
            ["pattern"]),
    _schema("LS", "List a directory.", {"path": {"type": "string"}}, []),
    _schema("Bash", "Run a shell command in the workspace.",
            {"command": {"type": "string"}, "timeout": {"type": "integer",
             "description": "milliseconds"}}, ["command"]),
]


# ====================================================================
# Tool executors (run locally; the restriction hook vets calls first)
# ====================================================================
def _resolve(cwd: Path, p: str) -> Path:
    pp = Path(p).expanduser()
    return pp if pp.is_absolute() else (cwd / pp)


def _truncate(s: str) -> str:
    if len(s) <= MAX_TOOL_RESULT_CHARS:
        return s
    head = s[: MAX_TOOL_RESULT_CHARS - 200]
    return head + f"\n... [truncated {len(s) - len(head)} chars]"


def tool_Read(cwd: Path, a: dict) -> str:
    p = _resolve(cwd, a["file_path"])
    if not p.exists():
        return f"ERROR: file not found: {p}"
    if p.is_dir():
        return f"ERROR: is a directory: {p}"
    lines = p.read_text(errors="replace").splitlines()
    offset = max(int(a.get("offset", 1)), 1)
    limit = int(a.get("limit", READ_DEFAULT_LIMIT))
    sel = lines[offset - 1: offset - 1 + limit]
    return "\n".join(f"{offset + i:6d}\t{ln}" for i, ln in enumerate(sel)) or "(empty file)"


def tool_Write(cwd: Path, a: dict) -> str:
    p = _resolve(cwd, a["file_path"])
    p.parent.mkdir(parents=True, exist_ok=True)
    content = a.get("content", "")
    p.write_text(content)
    return f"Wrote {len(content)} bytes to {p}"


def _apply_edit(text: str, old: str, new: str, replace_all: bool) -> tuple[str, str]:
    if old == new:
        return text, "ERROR: old_string and new_string are identical"
    cnt = text.count(old)
    if cnt == 0:
        return text, "ERROR: old_string not found"
    if cnt > 1 and not replace_all:
        return text, f"ERROR: old_string not unique ({cnt} matches); add context or set replace_all"
    out = text.replace(old, new) if replace_all else text.replace(old, new, 1)
    return out, f"OK ({cnt if replace_all else 1} occurrence(s))"


def tool_Edit(cwd: Path, a: dict) -> str:
    p = _resolve(cwd, a["file_path"])
    if not p.exists():
        return f"ERROR: file not found: {p}"
    text, msg = _apply_edit(p.read_text(), a["old_string"], a["new_string"],
                            bool(a.get("replace_all")))
    if msg.startswith("ERROR"):
        return msg
    p.write_text(text)
    return f"Edited {p} {msg}"


def tool_MultiEdit(cwd: Path, a: dict) -> str:
    p = _resolve(cwd, a["file_path"])
    if not p.exists():
        return f"ERROR: file not found: {p}"
    text = p.read_text()
    for k, e in enumerate(a.get("edits", [])):
        text, msg = _apply_edit(text, e["old_string"], e["new_string"], bool(e.get("replace_all")))
        if msg.startswith("ERROR"):
            return f"ERROR on edit #{k}: {msg} (no changes written)"
    p.write_text(text)
    return f"Applied {len(a.get('edits', []))} edits to {p}"


def tool_Glob(cwd: Path, a: dict) -> str:
    base = _resolve(cwd, a["path"]) if a.get("path") else cwd
    matches = sorted(str(m) for m in base.glob(a["pattern"]))
    return "\n".join(matches[:500]) or "(no matches)"


def tool_Grep(cwd: Path, a: dict) -> str:
    om = a.get("output_mode", "files_with_matches")
    cmd = ["rg", "--no-heading", "--color", "never"]
    if om == "files_with_matches":
        cmd.append("-l")
    elif om == "count":
        cmd.append("-c")
    else:
        cmd.append("--line-number")
    if a.get("-i"):
        cmd.append("-i")
    if a.get("glob"):
        cmd += ["--glob", a["glob"]]
    cmd += ["-e", a["pattern"], a.get("path", ".")]
    try:
        r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=60)
        return r.stdout or r.stderr or "(no matches)"
    except FileNotFoundError:
        g = ["grep", "-rn"] + (["-i"] if a.get("-i") else []) + ["-e", a["pattern"], a.get("path", ".")]
        r = subprocess.run(g, cwd=str(cwd), capture_output=True, text=True, timeout=60)
        return r.stdout or r.stderr or "(no matches)"


def tool_LS(cwd: Path, a: dict) -> str:
    p = _resolve(cwd, a.get("path", "."))
    if not p.exists():
        return f"ERROR: not found: {p}"
    if p.is_file():
        return str(p)
    items = sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name))
    return "\n".join(("[d] " if e.is_dir() else "    ") + e.name for e in items) or "(empty dir)"


def tool_Bash(cwd: Path, a: dict) -> str:
    timeout = int(a.get("timeout", 120000)) / 1000.0
    try:
        r = subprocess.run(a["command"], shell=True, cwd=str(cwd),
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"ERROR: command timed out after {timeout:.0f}s"
    out = (r.stdout or "")
    if r.stderr:
        out += ("\n[stderr]\n" + r.stderr)
    return f"[exit {r.returncode}]\n{out}" if out.strip() else f"[exit {r.returncode}] (no output)"


EXECUTORS: dict[str, Callable[[Path, dict], str]] = {
    "Read": tool_Read, "Write": tool_Write, "Edit": tool_Edit, "MultiEdit": tool_MultiEdit,
    "Glob": tool_Glob, "Grep": tool_Grep, "LS": tool_LS, "Bash": tool_Bash,
}


# ====================================================================
# The agent session (drop-in for the ClaudeSDKClient session loop)
# ====================================================================
HookFn = Callable[[dict, Any, Any], Awaitable[dict]]


class OpenAIAgentSession:
    """Async context manager mirroring the runner's ClaudeSDKClient usage.

    Usage in dosguide.async_main:
        async with OpenAIAgentSession(...) as client:
            for i in (1, 2, 3):
                full, text_only, sid, cost = await client.query_block(prompt)
    """

    def __init__(self, *, base_url: str, api_key: str, model: str, system_prompt: str,
                 cwd: str, source_root: str, hook: HookFn, max_turns: int = 50,
                 usage_dir: Any = None, temperature: float | None = None,
                 context_tokens: int = CONTEXT_TOKENS):
        self.base_url = base_url
        self.api_key = api_key or "EMPTY"
        self.model = model
        self.cwd = Path(cwd).resolve()
        self.source_root = str(source_root)
        self.hook = hook
        self.max_turns = max_turns
        self.usage_dir = Path(usage_dir) if usage_dir else self.cwd
        self.temperature = temperature
        self.context_tokens = int(context_tokens)
        self.messages: list[dict] = [{"role": "system", "content": system_prompt}]
        self._block = 0
        self._client = None
        self._calibration: tuple[int, int] | None = None  # (prompt tokens, prompt chars) of the last request
        self._compactions: list[dict[str, Any]] = []        # this block's compactions, for the usage log
        self._summary_tokens = (0, 0)                       # (input, output) tokens of this block's summaries

    async def __aenter__(self):
        from openai import AsyncOpenAI  # imported lazily so the module loads without openai
        self._client = AsyncOpenAI(base_url=self.base_url, api_key=self.api_key)
        print(f"  [OSS] endpoint={self.base_url} model={self.model}")
        return self

    async def __aexit__(self, *exc):
        if self._client is not None:
            await self._client.close()
        return False

    async def _denied(self, name: str, targs: dict) -> str | None:
        out = await self.hook({"tool_name": name, "tool_input": targs}, None, None)
        if isinstance(out, dict):
            hs = out.get("hookSpecificOutput", {})
            if hs.get("permissionDecision") == "deny":
                return hs.get("permissionDecisionReason", "denied by policy")
        return None

    @staticmethod
    def _marker(name: str, targs: dict) -> str:
        if name in ("Read", "Write", "Edit", "MultiEdit"):
            return f"file_path: {targs.get('file_path', '')}"
        if name == "Bash":
            return f"command: {targs.get('command', '')}"
        if name in ("Glob", "Grep"):
            return f"path: {targs.get('pattern', targs.get('path', ''))}"
        return ""

    # ----------------------------------------------------------------
    # Context compaction
    # ----------------------------------------------------------------
    @staticmethod
    def _message_chars(m: dict) -> int:
        n = len(m.get("content") or "")
        for tc in m.get("tool_calls") or []:
            n += len(tc["function"].get("arguments") or "") + len(tc["function"].get("name") or "")
        return n

    def _chars(self) -> int:
        return sum(self._message_chars(m) for m in self.messages)

    def _estimate_tokens(self) -> int:
        """The prompt size of the next request: the last reported size plus what was added since, else by length."""
        chars = self._chars()
        if self._calibration is not None:
            tokens, at_chars = self._calibration
            return int(tokens + (chars - at_chars) / CHARS_PER_TOKEN)
        return int((chars + len(json.dumps(TOOL_SCHEMAS))) / CHARS_PER_TOKEN)

    def _budget(self) -> int:
        return int(self.context_tokens * COMPACT_AT) - MAX_TOKENS_PER_CALL

    def _elide(self, keep_tool_results: int) -> int:
        """Stage 1: replace tool results older than the last `keep_tool_results`, and long arguments of the tool
        calls before them, by short notes. Returns the number of characters removed."""
        before = self._chars()
        tool_idx = [i for i, m in enumerate(self.messages) if m["role"] == "tool"]
        old = set(tool_idx[:-keep_tool_results] if keep_tool_results else tool_idx)
        first_kept = min(set(tool_idx) - old, default=len(self.messages))
        for i in old:
            c = self.messages[i].get("content") or ""
            if len(c) > 2 * ELIDE_PREVIEW_CHARS and not c.startswith("[earlier tool output elided"):
                self.messages[i]["content"] = (f"[earlier tool output elided to save context ({len(c)} chars); "
                                               f"it began: {c[:ELIDE_PREVIEW_CHARS]!r}]")
        for m in self.messages[:first_kept]:
            for tc in m.get("tool_calls") or []:
                args = tc["function"].get("arguments") or ""
                if len(args) > ELIDE_ARG_CHARS:
                    try:
                        parsed = json.loads(args)
                    except json.JSONDecodeError:
                        parsed = {}
                    keep = {k: parsed[k] for k in ("file_path", "path", "pattern") if isinstance(parsed, dict) and k in parsed}
                    keep["note"] = f"[arguments elided to save context ({len(args)} chars); the result is in the workspace]"
                    tc["function"]["arguments"] = json.dumps(keep)
        return before - self._chars()

    @staticmethod
    def _render(messages: list[dict]) -> str:
        """A plain-text transcript of `messages` for the summarizer, each message cut to a bounded length."""
        out = []
        for m in messages:
            c = (m.get("content") or "").strip()
            if len(c) > SUMMARY_INPUT_CHARS_PER_MESSAGE:
                h = SUMMARY_INPUT_CHARS_PER_MESSAGE // 2
                c = c[:h] + f"\n... [{len(c) - 2 * h} chars left out] ...\n" + c[-h:]
            if m["role"] == "assistant":
                calls = "; ".join(f"{tc['function']['name']}({(tc['function'].get('arguments') or '')[:300]})"
                                  for tc in m.get("tool_calls") or [])
                out.append(f"ASSISTANT: {c}" + (f"\nTOOL CALLS: {calls}" if calls else ""))
            elif m["role"] == "tool":
                out.append(f"TOOL RESULT: {c}")
            else:
                out.append(f"{m['role'].upper()}: {c}")
        return "\n\n".join(out)

    async def _summarize(self) -> bool:
        """Stage 2: summarize everything before the last KEEP_RECENT_GROUPS assistant turns, keeping the current
        request verbatim. The new history is: system, one user message (current request + summary), the kept turns.
        Cuts only before an assistant message, so a tool call is never separated from its result."""
        p = max(i for i, m in enumerate(self.messages) if m["role"] == "user")
        groups = [i for i in range(p + 1, len(self.messages)) if self.messages[i]["role"] == "assistant"]
        cut = groups[-KEEP_RECENT_GROUPS] if len(groups) > KEEP_RECENT_GROUPS else p + 1
        request, _, earlier = self.messages[p]["content"].partition(SUMMARY_MARKER)
        region = ([{"role": "user", "content": "[Summary of the conversation before this point]\n" + earlier.strip()}]
                  if earlier else []) + [m for i, m in enumerate(self.messages[1:cut], 1) if i != p]
        if not region or (len(region) == 1 and earlier):
            return False
        transcript = self._render(region)
        limit = int((self._budget() - SUMMARY_MAX_TOKENS) * CHARS_PER_TOKEN)
        if len(transcript) > limit:  # keep the start (the task) and the end (the latest work)
            transcript = transcript[: limit // 3] + "\n\n... [middle of the conversation left out] ...\n\n" \
                + transcript[-(2 * limit // 3):]
        resp = await self._client.chat.completions.create(
            model=self.model, max_tokens=SUMMARY_MAX_TOKENS,
            messages=[{"role": "system", "content": SUMMARY_INSTRUCTION},
                      {"role": "user", "content": transcript}],
            **({"temperature": self.temperature} if self.temperature is not None else {}))
        u = getattr(resp, "usage", None)
        if u:
            self._summary_tokens = (self._summary_tokens[0] + (getattr(u, "prompt_tokens", 0) or 0),
                                    self._summary_tokens[1] + (getattr(u, "completion_tokens", 0) or 0))
        summary = (resp.choices[0].message.content or "").strip()
        merged = request.rstrip() + SUMMARY_MARKER + summary
        self.messages = [self.messages[0], {"role": "user", "content": merged}] + self.messages[cut:]
        self._calibration = None
        return True

    def _keep_count(self, share: float) -> int:
        """How many of the newest tool results stage 1 keeps: as many as fit in `share` of the budget, between
        MIN_KEPT_TOOL_RESULTS and KEEP_RECENT_TOOL_RESULTS."""
        room, kept = share * self._budget() * CHARS_PER_TOKEN, 0
        for m in reversed(self.messages):
            if m["role"] != "tool":
                continue
            room -= len(m.get("content") or "")
            if room < 0 or kept == KEEP_RECENT_TOOL_RESULTS:
                break
            kept += 1
        return max(kept, MIN_KEPT_TOOL_RESULTS)

    async def _maybe_compact(self, turn: int, force: int = 0) -> None:
        """Compact when the next request would not fit (stages 1-3, each only if the one before was not enough).
        `force` > 0 after the server rejected a request as too long: every stage runs, keeping less each time."""
        before = self._estimate_tokens()
        if not force and before <= self._budget():
            return
        stages = []
        self._elide(self._keep_count(KEPT_SHARE / (1 + force)))
        stages.append("elide")
        if force or self._estimate_tokens() > self._budget():
            if await self._summarize():
                stages.append("summarize")
        if force or self._estimate_tokens() > self._budget():
            self._elide(max(MIN_KEPT_TOOL_RESULTS - force, 1) if force else MIN_KEPT_TOOL_RESULTS)
            p = max(i for i, m in enumerate(self.messages) if m["role"] == "user")
            for m in self.messages[p + 1:]:
                if m["role"] == "assistant" and len(m.get("content") or "") > SUMMARY_INPUT_CHARS_PER_MESSAGE:
                    c = m["content"]
                    m["content"] = c[:SUMMARY_INPUT_CHARS_PER_MESSAGE] + f"\n... [{len(c) - SUMMARY_INPUT_CHARS_PER_MESSAGE} chars cut]"
            stages.append("shorten")
        after = self._estimate_tokens()
        self._compactions.append({"turn": turn, "forced": bool(force), "stages": stages,
                                  "estimated_tokens_before": before, "estimated_tokens_after": after})
        print(f"  [OSS] compacted the context ({'+'.join(stages)}): ~{before:,} -> ~{after:,} tokens "
              f"(window {self.context_tokens:,})")

    @staticmethod
    def _too_long(e: Exception) -> bool:
        s = str(e).lower()
        return any(k in s for k in ("context length", "maximum context", "context window", "max_model_len",
                                    "too many tokens", "prompt is too long", "input is too long"))

    async def _create(self, kwargs: dict[str, Any], turn: int) -> Any:
        """One request of the agent loop, after compacting the context if the request would not fit."""
        await self._maybe_compact(turn)
        for attempt in range(COMPACT_RETRIES + 1):
            kwargs["messages"] = self.messages
            try:
                resp = await self._client.chat.completions.create(**kwargs)
            except Exception as e:  # noqa: BLE001 - only a too-long request is retried
                if attempt < COMPACT_RETRIES and self._too_long(e):
                    print(f"  [OSS] the server rejected the request as too long: {str(e)[:160]}")
                    await self._maybe_compact(turn, force=attempt + 1)
                    continue
                raise
            u = getattr(resp, "usage", None)
            if u and getattr(u, "prompt_tokens", None):
                self._calibration = (int(u.prompt_tokens), self._chars())
            return resp

    async def query_block(self, prompt: str) -> tuple[str, str, str | None, float | None]:
        self._block += 1
        self._compactions = []
        self._summary_tokens = (0, 0)
        self.messages.append({"role": "user", "content": prompt})
        full: list[str] = []        # transcript incl. tool markers (for scan/validation/tool-log)
        text_only: list[str] = []   # assistant prose only (for target-register extraction)
        in_tok = out_tok = 0

        for _turn in range(self.max_turns):
            kwargs: dict[str, Any] = dict(model=self.model, messages=self.messages,
                                          tools=TOOL_SCHEMAS, tool_choice="auto",
                                          max_tokens=MAX_TOKENS_PER_CALL)
            if self.temperature is not None:
                kwargs["temperature"] = self.temperature
            resp = await self._create(kwargs, _turn)

            u = getattr(resp, "usage", None)
            if u:
                in_tok += getattr(u, "prompt_tokens", 0) or 0
                out_tok += getattr(u, "completion_tokens", 0) or 0

            msg = resp.choices[0].message
            assistant: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                assistant["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in msg.tool_calls
                ]
            self.messages.append(assistant)

            if msg.content:
                text_only.append(msg.content)
                full.append(msg.content)

            if not msg.tool_calls:
                break

            for tc in msg.tool_calls:
                name = tc.function.name
                try:
                    targs = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    targs = {}
                full.append(f">> [TOOL: {name}]")
                mk = self._marker(name, targs)
                if mk:
                    full.append(mk)

                reason = await self._denied(name, targs)
                if reason:
                    result = f"BLOCKED BY POLICY: {reason}"
                    print(f"  [GUARD] denied {name}: {reason}")
                elif name not in EXECUTORS:
                    result = f"ERROR: unknown tool {name}"
                else:
                    try:
                        result = EXECUTORS[name](self.cwd, targs)
                    except Exception as e:  # noqa: BLE001 - surface tool errors to the model
                        result = f"ERROR: {type(e).__name__}: {e}"

                self.messages.append({"role": "tool", "tool_call_id": tc.id,
                                      "content": _truncate(result)})
        else:
            full.append("[NOTE] max_turns reached for this block.")

        self._log_usage(in_tok, out_tok)
        print(f"  [OSS] block {self._block}: in={in_tok:,} out={out_tok:,} tok")
        return "\n".join(full), "\n".join(text_only), None, None

    def _log_usage(self, in_tok: int, out_tok: int) -> None:
        try:
            self.usage_dir.mkdir(parents=True, exist_ok=True)
            (self.usage_dir / f"oss_usage_block{self._block}.json").write_text(json.dumps({
                "model": self.model, "block": self._block,
                "input_tokens": in_tok, "output_tokens": out_tok,
                "total_tokens": in_tok + out_tok,
                "context_tokens": self.context_tokens,
                "summary_input_tokens": self._summary_tokens[0], "summary_output_tokens": self._summary_tokens[1],
                "compactions": self._compactions,
            }, indent=2))
        except Exception as e:  # noqa: BLE001
            print(f"  [OSS] usage log failed: {e}")
