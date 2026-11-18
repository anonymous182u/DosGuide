# DoSGuide synthesis pipeline

DoSGuide synthesizes, for one vulnerability advisory, a JQF guidance that drives fuzzing toward a
denial-of-service failure. A Claude agent works in one continuous session through three blocks; after each
block DoSGuide checks the agent's output and sends failed checks back for repair.

The prompt is `prompt/prompt.txt`. A target that still fails a check after its repair rounds is dropped;
a synthesis fails when no target is left.

## Layout

```
dosguide.py                  the three blocks and their checks
prompt_parser.py             splits the prompt into its blocks
prompt/prompt.txt            the synthesis prompt
campaign/synthesis_inputs.json   per subject: main_class, clone_url, vuln_ref, and the fix commit
scripts/oracle_config.py     reads a subject's oracle.json (evaluation limits, fixed version)
scripts/guidance_launch.py   builds and starts a guidance from analysis/launch.json (validation and campaign)
scripts/run_guided.py        one campaign run of a synthesized guidance
scripts/generate_llm_oneshot.py  the LLM one-shot baseline: asks the model for one JUnit test per target and writes
                             it with its run_llm_oneshot.sh to engines/llm_oneshot/generated/
tools/checkpath/             CheckPath and PlanCheck (Python front end, Java source index)
tools/validate/              ValidateArtifact and the scale probe (Python front end, Java runner)
tools/launch/                campaign launcher: runs a guidance or a baseline and decides failures
install_dependencies.sh      JDKs, Maven, Python virtualenv (requirements.txt), and the tool builds
oss_backend.py               optional OpenAI-compatible backend (--backend openai)
ghsa_version_resolver.py     advisory lookup (version -> tag matching) for an advisory that has no entry in
                             campaign/synthesis_inputs.json (not used for the listed subjects)
benchmarks/                  the frozen fixtures of the 33 subjects and fetch.py (see benchmarks/README.md)
guidance/                    the synthesized guidance of each subject: phase1/ (target register, CheckPath and
                             scale reports), phase2_plan/ (plan, PlanCheck reports), phase2_guidance/
                             (guidance sources, launch.json, validation reports)
transcripts_dosguide/        the agent's session of each synthesis (INDEX.md lists them)
results/                     campaign results of the four engines (see Results)
wild/                        CodeQL DoS queries (queries/) and the LLM triage of their findings (llm-filter/)
```

## Requirements

JDK 17 (8 and 21 for some library builds), Maven, Python 3.12, git, network access to GitHub and Maven Central,
and Claude Code logged in with a subscription (`claude`, then `/login`; no API key is needed).
`install_dependencies.sh` installs and checks these and builds the tools; `install_dependencies.sh --check`
only checks.

The runner needs the frozen benchmark fixtures in `benchmarks/<subject>/` (`--benchmarks-root`): the harness
(`src/`), `pom.xml`, the library under test built from the vulnerable commit (`lib/`), and `oracle.json`.

## Synthesize one subject

Look the subject up in `campaign/synthesis_inputs.json`, clone `clone_url` at `vuln_ref`, and start the runner
with `main_class` (a file the advisory's fix commit changes, described in `fix`) as the starting point of the
analysis. For snappy-java (GHSA-55g7-9cwv-5qfv):

```
git clone https://github.com/xerial/snappy-java.git projects/snappy-java_GHSA-55g7-9cwv-5qfv
git -C projects/snappy-java_GHSA-55g7-9cwv-5qfv checkout 49d700175f18ed5f8c5d371b7c2f80c75979bd68
.venv/bin/python dosguide.py --project-id snappy-java_GHSA-55g7-9cwv-5qfv --prompt prompt/prompt.txt \
    --source-root projects/snappy-java_GHSA-55g7-9cwv-5qfv \
    --main-class src/main/java/org/xerial/snappy/SnappyInputStream.java --no-exec --freeze-harness
```

`--project-id` is the subject's folder name in `benchmarks/`. `--freeze-harness` copies the fixture's harness and
`pom.xml` into the run directory, so that every synthesis and every baseline fuzzes the same tests. `--no-exec`
keeps the agent from running Java, tests or fuzzers (it compiles only). Further options: `--model` (default
`claude-opus-4-6`), `--max-turns` and `--max-turns-block1` (turn limits per block), `--workspaces-root` (default
`workspaces/`).

Each run writes `workspaces/<subject>/run-<time>-<pid>/`. Its `analysis/` holds the target register
(`target_register.json`), the CheckPath, scale and PlanCheck reports, the plan (`guidance_plan.json`), the
validation reports (`validate.json`, `validate.roundN.json`), `launch.json` and `outcome.json` (status and the
targets that passed every check). The guidance sources are in the run directory's `src/`.

Further runner options: `--phase2-from RUN_DIR` runs Phases 2 and 3 again from the Phase 1 of an earlier run;
`--stop-after-block 1` stops after Phase 1; `--no-session` runs each block as an independent query with a
truncated summary of the earlier blocks (sessionless mode).

## Open-weight models

`--backend openai --openai-base-url http://<host>:8000/v1 --model <served model name>` runs the same three blocks,
prompt, tool restrictions and checks on a model behind an OpenAI-compatible endpoint (e.g. vLLM with
`--enable-auto-tool-choice` and the model's `--tool-call-parser`), with the tools re-implemented in `oss_backend.py`.
Give the served context window with `--openai-context-tokens` (vLLM `--max-model-len`, default 131072): before a
request would pass 75% of it, the session elides older tool results, then lets the model summarize the earlier
conversation (the current block prompt or repair message stays verbatim), and a request the server rejects as too
long is compacted harder and sent again. Each block's token use and compactions are in
`analysis/oss_usage_block<N>.json`. This backend does not support `--phase2-from` or `--no-session`.

## Run a synthesized guidance

The campaign builds a copy of the run directory without its build outputs (`target`, `out`, `build-tmp`, `.m2`,
`node_modules`) and runs one target's guidance through the launcher:

```
python3 scripts/run_guided.py --run-dir <copy of the run directory> --target V1 \
    --oracle benchmarks/<subject>/oracle.json \
    --launcher tools/launch/target/campaign-launcher.jar --budget-sec 900 --out <out dir>
```

The JVM options, the per-execution time limit and the input size limit come from `oracle.json`, not from
`launch.json`. The launcher records a failure when the fuzz test fails (an exception or an assertion of the
harness) or an execution runs longer than the time limit, and confirms it by replaying the input without the
guidance. With a `fixed` entry in `oracle.json` (`{"lib": <class path of the fixed version's jars>, "drop": <regex
of the class path entries they replace>}`) it also replays each failure on the fixed version and sets aside the
failures that the fixed version reproduces. The result is `<out dir>/result.json`. Whether a confirmed failure
is the vulnerability (resource exhaustion on the attack path that the fixed version does not reproduce) is
decided when the results are scored.

## Results

`results/<engine>/results.csv` holds one engine's campaign runs, 20 per subject for each of the 33 subjects;
`results/fuzz_results.csv` holds the four files together. The engines are `llm_guided`, `llm_oneshot`, `perfuzz`
and `zest`. One row per run:

| Column | Content |
|---|---|
| `project` | the subject, named as its folder in `benchmarks/` |
| `engine` | `llm_guided`, `llm_oneshot`, `perfuzz` or `zest` |
| `run_num` | the run, `001` to `020` |
| `wall_time_secs` | the run's duration in seconds (its end minus its start; the start and end times are not recorded) |
| `outcome` | `failure`, `timeout` or `error`; |
| `time_to_first_failure_secs` | seconds from the start of the run to its first failure, at most `wall_time_secs`; empty without a failure |
| `first_failure_path` | where the campaign saved the run's first failing input (not included here); empty for `llm_oneshot` |
