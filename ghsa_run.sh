#!/usr/bin/env bash
set -euo pipefail
usage() {
  cat >&2 <<'EOF'
Usage:
  ghsa_run.sh GHSA-xxxx-xxxx-xxxx [--run-arg "<arg>"]
Behavior:
  1) Resolve advisory -> clone URL + vulnerable SHA + fix SHA
     Primary: patch_github_advisor.py (commit/PR based)
     Fallback: ghsa_version_resolver.py (version→tag matching)
  2) Clone repo and checkout vulnerable SHA (optionally apply fix)
  3) Infer likely fuzzing main class from advisory PR/commit changes
     (1 and 3 are skipped for a subject in campaign/synthesis_inputs.json: its checkout and Main class are fixed)
  4) Run the synthesis (dosguide.py), including
     CheckPath, PlanCheck and ValidateArtifact (see the runner's --no-* flags)
Environment (optional):
    PYTHON_BIN, ADVISOR_PATH, VERSION_RESOLVER_PATH, WORKDIR, APPLY_FIX, REPO_DIR
    MAINCLASS_ADVISOR_PATH, MAIN_CLASS, SOURCE_ROOT, PROJECT_ID
    MAINCLASS_SELECTOR (heuristic|llm), MAINCLASS_MODEL, MAINCLASS_LLM_TIMEOUT_SEC
    DOSGUIDE_PATH, PROMPT_PATH, CLAUDE_MODEL, MAX_TURNS (Blocks 2-3, default 80), MAX_TURNS_BLOCK1 (default 80)
    NO_SESSION (default: 0; if 1, disable session resumption between blocks)
    NO_EXEC (default: 1; if 1, block test/fuzzer execution — compile only)
    WORKSPACES_ROOT
    AUTO_COMMIT (default: 0; if 1, copy run dir to RESULTS_REPO and commit)
    RESULTS_REPO (path to a git repo for storing run outputs)
    COMMIT_ON_RUN (default: 1; if 1, commit after claude run)
    COMMIT_MSG_PREFIX (default: [ghsa])
    AUTO_PUSH (default: 0; if 1, push after each commit)
    PUSH_REMOTE (default: origin; remote name to push)
    PUSH_BRANCH (default: current branch; if set, push this branch)
    COMMIT_MSG_SUMMARY (default: 0; if 1, append git diff --cached --stat)
    CLONE_URL, VULN_SHA, FIX_SHA (CLONE_URL and VULN_SHA, plus FIX_SHA if APPLY_FIX=1, skip advisor API lookup)
    SYNTHESIS_INPUTS (default campaign/synthesis_inputs.json: fixed Main class and optional pinned
      checkout per subject; empty = use the Main-class selector)
    SKIP_FETCH (if 1, skip git fetch for offline/local-only runs)
  Directory layout:
    Each GHSA gets its own clone and workspace so that multiple advisories
    targeting the same repo at different vulnerable commits don't collide.
      projects/<reponame>_<GHSA-ID>/    (clone dir, one per advisory)
      workspaces/<reponame>_<GHSA-ID>/  (run dirs, one per advisory)
    Override with REPO_DIR / PROJECT_ID to use a custom layout.
  For MAINCLASS_SELECTOR=llm:
    Requires OPENAI_API_KEY in environment.
EOF
}
if [[ $# -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
  usage
  exit 0
fi
if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi
GHSA_ID="$1"
shift

CLONE_URL_ARG=""
VULN_REF_ARG=""
FIX_REF_ARG=""

extract_ref() {
  local x="$1"

  # Strip query string and fragment (safe for both GitHub/Bitbucket URLs)
  x="${x%%\?*}"
  x="${x%%\#*}"

  # Handle common commit URL patterns:
  #   GitHub:    https://github.com/org/repo/commit/<sha>
  #   Bitbucket: https://bitbucket.org/org/repo/commits/<sha>
  if [[ "$x" == *"/commit/"* || "$x" == *"/commits/"* ]]; then
    x="${x%/}"     # remove trailing slash if present
    x="${x##*/}"   # last path segment -> the SHA
  fi

  printf '%s' "$x"
}

RUN_EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-arg)
      [[ $# -ge 2 ]] || { echo "Missing value for --run-arg" >&2; exit 1; }
      RUN_EXTRA_ARGS+=("$2")
      shift 2
      ;;
    --clone-url)
      [[ $# -ge 2 ]] || { echo "Missing value for --clone-url" >&2; exit 1; }
      CLONE_URL_ARG="$2"
      shift 2
      ;;
    --vuln-ref)
      [[ $# -ge 2 ]] || { echo "Missing value for --vuln-ref" >&2; exit 1; }
      VULN_REF_ARG="$2"
      shift 2
      ;;
    --fix-ref)
      [[ $# -ge 2 ]] || { echo "Missing value for --fix-ref" >&2; exit 1; }
      FIX_REF_ARG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"
ADVISOR_PATH="${ADVISOR_PATH:-$SCRIPT_DIR/patch_github_advisor.py}"
MAINCLASS_ADVISOR_PATH="${MAINCLASS_ADVISOR_PATH:-$SCRIPT_DIR/ghsa_suggest_main_class.py}"
VERSION_RESOLVER_PATH="${VERSION_RESOLVER_PATH:-$SCRIPT_DIR/ghsa_version_resolver.py}"
MAINCLASS_SELECTOR="${MAINCLASS_SELECTOR:-llm}"
MAINCLASS_MODEL="${MAINCLASS_MODEL:-gpt-5.2-codex}"
MAINCLASS_LLM_TIMEOUT_SEC="${MAINCLASS_LLM_TIMEOUT_SEC:-90}"
WORKDIR="${WORKDIR:-projects}"
APPLY_FIX="${APPLY_FIX:-0}"
DOSGUIDE_PATH="${DOSGUIDE_PATH:-$SCRIPT_DIR/dosguide.py}"
# The synthesis prompt (rules, the three blocks, and the scale measurement).
PROMPT_PATH="${PROMPT_PATH:-$SCRIPT_DIR/prompt/prompt.txt}"
CLAUDE_MODEL="${CLAUDE_MODEL:-claude-opus-4-6}"
MAX_TURNS="${MAX_TURNS:-80}"
MAX_TURNS_BLOCK1="${MAX_TURNS_BLOCK1:-80}"
NO_SESSION="${NO_SESSION:-0}"
NO_EXEC="${NO_EXEC:-1}"
WORKSPACES_ROOT="${WORKSPACES_ROOT:-$SCRIPT_DIR/workspaces}"
AUTO_COMMIT="${AUTO_COMMIT:-0}"
RESULTS_REPO="${RESULTS_REPO:-}"
COMMIT_ON_RUN="${COMMIT_ON_RUN:-1}"
COMMIT_MSG_PREFIX="${COMMIT_MSG_PREFIX:-[ghsa]}"
AUTO_PUSH="${AUTO_PUSH:-0}"
COMMIT_MSG_SUMMARY="${COMMIT_MSG_SUMMARY:-0}"
MAIN_CLASS="${MAIN_CLASS:-}"
SOURCE_ROOT="${SOURCE_ROOT:-}"
PROJECT_ID="${PROJECT_ID:-}"
SKIP_FETCH="${SKIP_FETCH:-0}"
PUSH_REMOTE="${PUSH_REMOTE:-origin}"
PUSH_BRANCH="${PUSH_BRANCH:-}"
MAINCLASS_REQUIRE_LLM="${MAINCLASS_REQUIRE_LLM:-0}"   # if 1, fail if selector != llm
# Optional override: let caller pass focus paths directly (comma-separated or space-separated)
FOCUS_PATHS="${FOCUS_PATHS:-}"
# Fixed synthesis inputs of the evaluation subjects (campaign/synthesis_inputs.json, see README.md):
# the Main class given to the analysis and, where pinned, the checkout. A listed subject never goes through
# the LLM Main-class selector, so it gets no focus paths either. SYNTHESIS_INPUTS= (empty) restores the selector.
SYNTHESIS_INPUTS="${SYNTHESIS_INPUTS-$SCRIPT_DIR/campaign/synthesis_inputs.json}"
if [[ -n "$SYNTHESIS_INPUTS" ]]; then
  INPUTS_SH="$("$PYTHON_BIN" - "$SYNTHESIS_INPUTS" "$GHSA_ID" <<'PY'
import json, shlex, sys
table = json.load(open(sys.argv[1], encoding="utf-8"))
keys = [k for k in table if k == sys.argv[2] or k.endswith("_" + sys.argv[2])]
if len(keys) != 1:
    sys.exit(f"{sys.argv[1]}: {'no' if not keys else 'more than one'} entry for {sys.argv[2]}; add one, "
             "or set SYNTHESIS_INPUTS= to use the Main-class selector")
e = table[keys[0]]
values = {"INPUT_SUBJECT": keys[0], "INPUT_MAIN_CLASS": e["main_class"], "INPUT_CLONE_URL": e.get("clone_url", ""),
          "INPUT_VULN_REF": e.get("vuln_ref", ""), "INPUT_FIX_REF": e.get("fix_ref", "")}
print("\n".join(f"{k}={shlex.quote(v)}" for k, v in values.items()))
PY
)"
  eval "$INPUTS_SH"
  MAIN_CLASS="${MAIN_CLASS:-$INPUT_MAIN_CLASS}"
  PROJECT_ID="${PROJECT_ID:-$INPUT_SUBJECT}"
  REPO_DIR="${REPO_DIR:-$INPUT_SUBJECT}"
  # A pinned checkout replaces the advisory lookup (command-line --clone-url/--vuln-ref/--fix-ref still win).
  if [[ -n "$INPUT_CLONE_URL" ]]; then
    CLONE_URL="${CLONE_URL:-$INPUT_CLONE_URL}"
    VULN_SHA="${VULN_SHA:-$INPUT_VULN_REF}"
    FIX_SHA="${FIX_SHA:-$INPUT_FIX_REF}"
  fi
  INPUT_CHECKOUT="from the advisory"
  if [[ -n "$INPUT_CLONE_URL" ]]; then INPUT_CHECKOUT="pinned ($INPUT_CLONE_URL @ $INPUT_VULN_REF)"; fi
  echo "[inputs] $SYNTHESIS_INPUTS: subject=$INPUT_SUBJECT main=$MAIN_CLASS checkout=$INPUT_CHECKOUT"
fi
git_commit_run() {
  local stage="$1"
  if [[ "$AUTO_COMMIT" != "1" ]]; then
    return 0
  fi
  if [[ -z "$RESULTS_REPO" ]]; then
    echo "[commit] AUTO_COMMIT=1 but RESULTS_REPO is unset" >&2
    return 1
  fi
  if [[ ! -d "$RESULTS_REPO/.git" ]]; then
    echo "[commit] RESULTS_REPO is not a git repo: $RESULTS_REPO" >&2
    return 1
  fi
  if [[ "$AUTO_PUSH" == "1" ]]; then
    if ! git -C "$RESULTS_REPO" remote get-url "$PUSH_REMOTE" >/dev/null 2>&1; then
      echo "[commit] AUTO_PUSH=1 but remote '$PUSH_REMOTE' is not configured in $RESULTS_REPO" >&2
      return 1
    fi
  fi
  local run_base dest_root dest
  run_base="$(basename "$RUN_DIR")"
  dest_root="$RESULTS_REPO/runs/$PROJECT_ID/$GHSA_ID"
  dest="$dest_root/$run_base"
  mkdir -p "$dest"
  cp -a "$RUN_DIR/." "$dest/"
  pushd "$RESULTS_REPO" >/dev/null
  git add -A "$dest_root" || true
  if git diff --cached --quiet; then
    echo "[commit] no changes to commit for $stage"
    popd >/dev/null
    return 0
  fi
  local commit_msg
  commit_msg="${COMMIT_MSG_PREFIX} ${GHSA_ID} ${PROJECT_ID} ${stage} ${run_base}"
  if [[ "$COMMIT_MSG_SUMMARY" == "1" ]]; then
    local stat
    stat="$(git diff --cached --stat | tr '\n' '; ' | sed 's/; $//')"
    if [[ -n "$stat" ]]; then
      commit_msg="${commit_msg} | ${stat}"
    fi
  fi
  git commit -m "$commit_msg" || true
  if [[ "$AUTO_PUSH" == "1" ]]; then
    if [[ -n "$PUSH_BRANCH" ]]; then
      git push "$PUSH_REMOTE" "$PUSH_BRANCH" || true
    else
      git push "$PUSH_REMOTE" || true
    fi
  fi
  popd >/dev/null
}
if [[ ! -f "$ADVISOR_PATH" ]]; then
  echo "Advisor script not found: $ADVISOR_PATH" >&2
  exit 1
fi
if [[ ! -f "$MAINCLASS_ADVISOR_PATH" ]]; then
  echo "Main-class advisor script not found: $MAINCLASS_ADVISOR_PATH" >&2
  exit 1
fi
if [[ ! -f "$DOSGUIDE_PATH" ]]; then
  echo "Run script not found: $DOSGUIDE_PATH" >&2
  exit 1
fi
if [[ ! -f "$PROMPT_PATH" ]]; then
  echo "Prompt file not found: $PROMPT_PATH" >&2
  exit 1
fi

# Defaults to keep set -u happy in manual-override path
ADVISOR_FAILED=0
NEED_FALLBACK=0
RESOLVER_REPO_PATH=""
RESOLVER_OUT=""
ADVISOR_OUT=""

# CLI override takes precedence
CLONE_URL="${CLONE_URL_ARG:-${CLONE_URL:-}}"
VULN_SHA="${VULN_REF_ARG:-${VULN_SHA:-}}"
FIX_SHA="${FIX_REF_ARG:-${FIX_SHA:-}}"

# Normalize refs (commit URL -> SHA)
if [[ -n "$VULN_SHA" ]]; then VULN_SHA="$(extract_ref "$VULN_SHA")"; fi
if [[ -n "$FIX_SHA"  ]]; then FIX_SHA="$(extract_ref "$FIX_SHA")"; fi

if [[ -n "$CLONE_URL" || -n "$VULN_SHA" || -n "$FIX_SHA" ]]; then
  if [[ -z "$CLONE_URL" || -z "$VULN_SHA" || ( -z "$FIX_SHA" && "$APPLY_FIX" == "1" ) ]]; then
    echo "When overriding advisory resolution, set --clone-url and --vuln-ref, and --fix-ref if APPLY_FIX=1 (or env CLONE_URL/VULN_SHA/FIX_SHA)." >&2
    exit 1
  fi
  echo "[advisor] using manual override (clone=$CLONE_URL vuln=$VULN_SHA fix=$FIX_SHA)"
else
  # ---------------------------------------------------------------------------
  # Two-stage advisory resolution
  # ---------------------------------------------------------------------------
  ADVISOR_FAILED=0
  ADVISOR_OUT="$("$PYTHON_BIN" "$ADVISOR_PATH" "$GHSA_ID" 2>&1)" || ADVISOR_FAILED=1
  if [[ "$ADVISOR_FAILED" == "0" ]]; then
    printf "%s\n" "$ADVISOR_OUT"
    CLONE_URL="$(printf "%s\n" "$ADVISOR_OUT" | sed -n 's/^Clone URL: //p' | head -n1)"
    VULN_SHA="$(printf "%s\n" "$ADVISOR_OUT" | sed -n 's/^Parent (likely vulnerable): //p' | head -n1)"
    FIX_SHA="$(printf "%s\n" "$ADVISOR_OUT" | sed -n 's/^Fix commit: //p' | head -n1)"
  fi

  NEED_FALLBACK=0
  if [[ "$ADVISOR_FAILED" == "1" ]]; then
    echo "[advisor] primary advisor failed, trying version-based fallback..." >&2
    NEED_FALLBACK=1
  elif [[ -z "$CLONE_URL" || "$CLONE_URL" == "(unknown)" \
       || -z "$VULN_SHA" || "$VULN_SHA" == "(unknown)" \
       || -z "$FIX_SHA" || "$FIX_SHA" == "(unknown)" ]]; then
    echo "[advisor] primary advisor returned incomplete results (clone=$CLONE_URL vuln=$VULN_SHA fix=$FIX_SHA), trying version-based fallback..." >&2
    NEED_FALLBACK=1
  fi

  if [[ "$NEED_FALLBACK" == "1" ]]; then
    if [[ ! -f "$VERSION_RESOLVER_PATH" ]]; then
      echo "Version resolver not found: $VERSION_RESOLVER_PATH" >&2
      echo "Cannot resolve advisory without fix commit or version-to-tag fallback." >&2
      exit 1
    fi
    RESOLVER_ARGS=("$GHSA_ID" "--workdir" "$WORKDIR")
    if [[ -n "$CLONE_URL" && "$CLONE_URL" != "(unknown)" ]]; then
      RESOLVER_ARGS+=("--repo-url" "$CLONE_URL")
    fi
    if [[ "$SKIP_FETCH" == "1" ]]; then
      RESOLVER_ARGS+=("--skip-fetch")
    fi
    echo "[advisor] running: $PYTHON_BIN $VERSION_RESOLVER_PATH ${RESOLVER_ARGS[*]}"
    RESOLVER_OUT="$("$PYTHON_BIN" "$VERSION_RESOLVER_PATH" "${RESOLVER_ARGS[@]}")"
    printf "%s\n" "$RESOLVER_OUT"
    CLONE_URL="$(printf "%s\n" "$RESOLVER_OUT" | sed -n 's/^Clone URL: //p' | head -n1)"
    VULN_SHA="$(printf "%s\n" "$RESOLVER_OUT" | sed -n 's/^Parent (likely vulnerable): //p' | head -n1)"
    FIX_SHA="$(printf "%s\n" "$RESOLVER_OUT" | sed -n 's/^Fix commit: //p' | head -n1)"
    RESOLVER_REPO_PATH="$(printf "%s\n" "$RESOLVER_OUT" | sed -n 's/^Repo path: //p' | head -n1)"
  fi
fi

if [[ -z "$CLONE_URL" || "$CLONE_URL" == "(unknown)" ]]; then
  echo "Cannot continue: clone URL missing from both primary advisor and version resolver." >&2
  exit 1
fi
if [[ -z "$VULN_SHA" || "$VULN_SHA" == "(unknown)" ]]; then
  echo "Cannot continue: vulnerable SHA missing from both primary advisor and version resolver." >&2
  exit 1
fi
if [[ "$APPLY_FIX" == "1" && ( -z "$FIX_SHA" || "$FIX_SHA" == "(unknown)" ) ]]; then
  echo "Cannot continue: APPLY_FIX=1 but the fix SHA is missing from both primary advisor and version resolver." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# GHSA-scoped directories
# Each GHSA gets its own clone directory under projects/ so that two
# advisories targeting the same repo at different
# vulnerable commits don't clobber each other's working tree.
#   Default:  projects/<reponame>_GHSA-xxxx-xxxx-xxxx/
#   Override: REPO_DIR=<reponame>  (one clone shared by the advisories)
# ---------------------------------------------------------------------------
REPO_NAME="$(basename "${CLONE_URL%.git}")"
REPO_DIR="${REPO_DIR:-${REPO_NAME}_${GHSA_ID}}"

mkdir -p "$WORKDIR"
pushd "$WORKDIR" >/dev/null

# If the version resolver already cloned the repo, reuse it instead of cloning again.
# The resolver outputs "Repo path: <abs-path>" pointing to its clone.
RESOLVER_CLONE_REUSED=0
if [[ -n "${RESOLVER_REPO_PATH:-}" && -d "$RESOLVER_REPO_PATH/.git" ]]; then
  RESOLVER_ABS="$(cd "$RESOLVER_REPO_PATH" && pwd -P)"
  TARGET_ABS="$(pwd -P)/$REPO_DIR"
  if [[ "$RESOLVER_ABS" == "$TARGET_ABS" ]]; then
    echo "[repo] resolver already cloned to $REPO_DIR"
    RESOLVER_CLONE_REUSED=1
  elif [[ ! -d "$REPO_DIR/.git" ]]; then
    echo "[repo] reusing resolver clone: moving $(basename "$RESOLVER_ABS") → $REPO_DIR"
    mv "$RESOLVER_ABS" "$REPO_DIR"
    RESOLVER_CLONE_REUSED=1
  else
    echo "[repo] $REPO_DIR already exists, skipping resolver clone reuse"
  fi
elif [[ ! -d "$REPO_DIR/.git" ]]; then
  git clone "$CLONE_URL" "$REPO_DIR"
fi
pushd "$REPO_DIR" >/dev/null
if [[ "$RESOLVER_CLONE_REUSED" == "1" ]]; then
  echo "[repo] skipping fetch — resolver already fetched all tags"
elif [[ "$SKIP_FETCH" == "1" ]]; then
  echo "[repo] SKIP_FETCH=1, skipping git fetch"
elif git cat-file -e "$VULN_SHA^{commit}" 2>/dev/null; then
  echo "[repo] $VULN_SHA is already in the clone, skipping git fetch"
else
  # --force: an upstream tag that moved would otherwise fail the fetch.
  git fetch --all --tags --prune --force
fi
git checkout -B "${GHSA_ID,,}-vuln" "$VULN_SHA"
if [[ "$APPLY_FIX" == "1" ]]; then
  if ! git cat-file -e "$FIX_SHA^{commit}" 2>/dev/null; then
    git fetch origin "$FIX_SHA" || true
  fi
  git diff --binary "$VULN_SHA" "$FIX_SHA" | git apply --index -3
fi
REPO_ROOT="$(pwd -P)"
popd >/dev/null
popd >/dev/null
if [[ -z "$SOURCE_ROOT" ]]; then
  SOURCE_ROOT="$REPO_ROOT"
fi

# PROJECT_ID also scoped by GHSA so workspaces/ dirs are distinct.
#   Default:  <reponame>_GHSA-xxxx-xxxx-xxxx
#   Override: PROJECT_ID=my-custom-id
if [[ -z "$PROJECT_ID" ]]; then
  PROJECT_ID="${REPO_NAME}_${GHSA_ID}"
fi

if [[ -z "$MAIN_CLASS" ]]; then
  MAINCLASS_CMD=(
    "$PYTHON_BIN" "$MAINCLASS_ADVISOR_PATH" "$GHSA_ID"
      --repo-root "$REPO_ROOT"
      --selector "$MAINCLASS_SELECTOR"
      --model "$MAINCLASS_MODEL"
      --llm-timeout-sec "$MAINCLASS_LLM_TIMEOUT_SEC"
      --main-class-only
      --json
  )
  # Pass resolved SHAs so the advisor can use local git diff
  # instead of re-discovering via GitHub API (critical for
  # advisories resolved via version-tag fallback).
  if [[ -n "$FIX_SHA" ]]; then
    MAINCLASS_CMD+=(--fix-sha "$FIX_SHA")
  fi
  if [[ -n "$VULN_SHA" ]]; then
    MAINCLASS_CMD+=(--vuln-sha "$VULN_SHA")
  fi
  MAIN_ADVICE_JSON="$("${MAINCLASS_CMD[@]}")"
  MAIN_CLASS_SELECTOR_USED="$(
    printf "%s\n" "$MAIN_ADVICE_JSON" | "$PYTHON_BIN" -c '
import json, sys
data = json.load(sys.stdin)
print((data.get("selector") or "unknown"))
')"
  MAIN_CLASS_SELECTOR_NOTES="$(
    printf "%s\n" "$MAIN_ADVICE_JSON" | "$PYTHON_BIN" -c '
import json, sys
data = json.load(sys.stdin)
notes = data.get("notes") or []
if isinstance(notes, list):
    print("; ".join(str(n) for n in notes))
else:
    print("")
')"
  MAIN_CLASS="$(
    printf "%s\n" "$MAIN_ADVICE_JSON" | "$PYTHON_BIN" -c '
import json, sys
data = json.load(sys.stdin)
print((data.get("entrypoint_path") or ""))
')"
  # focus_paths returned by ghsa_suggest_main_class.py (json)
  FOCUS_PATHS_CSV="$(
    printf "%s\n" "$MAIN_ADVICE_JSON" | "$PYTHON_BIN" -c '
import json, sys
d=json.load(sys.stdin)
fps=d.get("focus_paths") or []
print(",".join(str(x) for x in fps if isinstance(x,str)))
')"

    # Allow explicit env override (takes precedence)
  if [[ -n "$FOCUS_PATHS" ]]; then
    FOCUS_PATHS_CSV="$FOCUS_PATHS"
  fi
  if [[ -n "$FOCUS_PATHS_CSV" ]]; then
    echo "[config] FOCUS_PATHS=$FOCUS_PATHS_CSV"
  fi

  echo "[main-class-selector] requested=$MAINCLASS_SELECTOR used=$MAIN_CLASS_SELECTOR_USED model=$MAINCLASS_MODEL"
  if [[ "$MAINCLASS_SELECTOR" == "llm" && "$MAIN_CLASS_SELECTOR_USED" != "llm" ]]; then
    echo "MAINCLASS_SELECTOR=llm but selector fallback occurred (used=$MAIN_CLASS_SELECTOR_USED)." >&2
    if [[ -n "${MAIN_CLASS_SELECTOR_NOTES:-}" ]]; then
      echo "Selector notes: $MAIN_CLASS_SELECTOR_NOTES" >&2
    fi
    echo "Selector debug payload: $MAIN_ADVICE_JSON" >&2
    exit 1
  fi
fi
if [[ -z "$MAIN_CLASS" ]]; then
  echo "Could not infer MAIN_CLASS from advisory. Set MAIN_CLASS explicitly and rerun." >&2
  exit 1
fi
if [[ "$MAIN_CLASS" = /* ]]; then
  MAIN_CLASS_PATH="$MAIN_CLASS"
else
  MAIN_CLASS_PATH="$SOURCE_ROOT/$MAIN_CLASS"
fi
if [[ ! -f "$MAIN_CLASS_PATH" ]]; then
  echo "Selected MAIN_CLASS does not exist: $MAIN_CLASS_PATH" >&2
  echo "Set MAIN_CLASS to an existing source file and rerun." >&2
  exit 1
fi
echo "[config] GHSA_ID=$GHSA_ID"
echo "[config] REPO_NAME=$REPO_NAME"
echo "[config] REPO_DIR=$REPO_DIR"
echo "[config] REPO_ROOT=$REPO_ROOT"
echo "[config] SOURCE_ROOT=$SOURCE_ROOT"
echo "[config] PROJECT_ID=$PROJECT_ID"
echo "[config] MAIN_CLASS=$MAIN_CLASS"
RUN_LOG="$(mktemp -t ghsa-run-XXXXXX.log)"
cleanup() {
  rm -f "$RUN_LOG"
}
trap cleanup EXIT
pushd "$SCRIPT_DIR" >/dev/null
RUN_CMD=(
  "$PYTHON_BIN" "$DOSGUIDE_PATH"
  --project-id "$PROJECT_ID"
  --prompt "$PROMPT_PATH"
  --main-class "$MAIN_CLASS"
  --source-root "$SOURCE_ROOT"
  --workspaces-root "$WORKSPACES_ROOT"
  --model "$CLAUDE_MODEL"
  --max-turns "$MAX_TURNS"
  --max-turns-block1 "$MAX_TURNS_BLOCK1"
)

# Pass focus paths into dosguide.py
if [[ -n "${FOCUS_PATHS_CSV:-}" ]]; then
  RUN_CMD+=(--focus-paths "$FOCUS_PATHS_CSV")
fi

if [[ "$NO_SESSION" == "1" ]]; then
  RUN_CMD+=(--no-session)
fi
if [[ "$NO_EXEC" == "1" ]]; then
  RUN_CMD+=(--no-exec)
fi
if [[ ${#RUN_EXTRA_ARGS[@]} -gt 0 ]]; then
  RUN_CMD+=("${RUN_EXTRA_ARGS[@]}")
fi
echo "[run] ${RUN_CMD[*]}"
"${RUN_CMD[@]}" | tee "$RUN_LOG"
RUN_DIR="$(sed -n 's/^\[Run dir\] *//p' "$RUN_LOG" | tail -n1)"
if [[ -z "$RUN_DIR" || ! -d "$RUN_DIR" ]]; then
  echo "Could not locate run dir from dosguide.py output." >&2
  exit 1
fi
echo "[run-dir] $RUN_DIR"
if [[ "$COMMIT_ON_RUN" == "1" ]]; then
  git_commit_run "run"
fi
popd >/dev/null