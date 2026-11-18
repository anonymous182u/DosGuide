# OpenSearch_GHSA-mw3v-mmfw-3x2g

## Block 1

```text
$ cd <run_dir>; find . -type f | grep -v '/target/' | head; cat $(find . -name '*FuzzTest.java' | head -1)
$ cd <run_dir>; cat analysis/run_config.json; ls lib; S=<source_root>/server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java; wc -l $S; grep -n "Reg …
$ S=<source_root>/server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java; sed -n 160,320p $S; sed -n 680,865p $S
$ R=<source_root> cd $R; git log --oneline -3 2>/dev/null; grep -n "lucene" buildSrc/version.properties gradle/libs.versions.toml 2>/dev/null | head; Q=server/src/main/java/org/opensearch/index/query/QueryStringQueryBuilder.java; grep -n "do …
$ R=<source_root> cd $R; grep -n "lucene" gradle/libs.versions.toml buildSrc/version.properties 2>/dev/null | head -3; Q=server/src/main/java/org/opensearch/index/query/QueryStringQueryBuilder.java; grep -n "doToQuery" -A90 $Q | grep -n "par …
```

Reading the Lucene classic parser to confirm the recursion depth per nesting level.

```text
$ ls ~/.m2/repository/org/apache/lucene/lucene-queryparser/9.12.2/ ~/.m2/repository/org/apache/lucene/lucene-core/9.12.2/ 2>&1; ls <run_dir>/; sed -n 1,80p <source_root>/ …
$ ls ~/.m2/repository/org/apache/lucene/lucene-queryparser/9.12.2/ ~/.m2/repository/org/apache/lucene/lucene-core/9.12.2/ 2>&1
Read <source_root>/server/src/main/java/org/apache/lucene/queryparser/classic/XQueryParser.java
$ cd /tmp; J=~/.m2/repository/org/apache/lucene/lucene-queryparser/9.12.2/lucene-queryparser-9.12.2.jar; javap -cp $J -p org.apache.lucene.queryparser.classic.QueryParser 2>&1 | grep -i "Query(\|Clause(\|Term(\|jj_" | head -30
$ J=~/.m2/repository/org/apache/lucene/lucene-core/9.12.2/lucene-core-9.12.2.jar; javap -cp $J -p org.apache.lucene.util.automaton.RegExp | grep -v "^  public static final\|private static final" | head -60
$ J=~/.m2/repository/org/apache/lucene/lucene-core/9.12.2/lucene-core-9.12.2.jar; javap -cp $J -p -c org.apache.lucene.util.automaton.RegExp | awk '/toAutomatonInternal\(/,/^$/' | grep "invoke" | sed 's/.*Method //' | sort | uniq -c
```

Confirming whether Lucene's regex repeat count `{n}` has an upper bound (a candidate memory/CPU blowup).

```text
$ J=~/.m2/repository/org/apache/lucene/lucene-core/9.12.2/lucene-core-9.12.2.jar; javap -cp $J -p -c org.apache.lucene.util.automaton.RegExp | awk '/RegExp parseRepeatExp\(/,/^$/' | grep -i "invoke\|ldc\|sipush" | head -30; javap -cp $J -p -c org.apache.lucene.util.automaton.Operations | awk '/Automat …
```

Checking the RegexpQuery constructor chain and QueryParserBase.newRegexpQuery to pin the V2 path.

```text
$ J=~/.m2/repository/org/apache/lucene/lucene-core/9.12.2/lucene-core-9.12.2.jar; Q=~/.m2/repository/org/apache/lucene/lucene-queryparser/9.12.2/lucene-queryparser-9.12.2.jar; javap -cp $J -p -c org.apache.lucene.search.RegexpQuery | grep "invoke" | grep -i "regexp\|automaton" | head; javap -cp $Q:$J  …
```

Writing the scale-measurement series: V1 is nested `(` groups, V2 is regex repeat counts.

```text
$ python3 -I - <<'EOF' …
```

I found two DoS targets reachable through the frozen harness's `fuzzQueryStringQueryBuilderToQuery(InputStream)` entry point, and wrote the scale series for both. Nothing was run: execution is blocked in this block, so every scale figure below is an estimate from reading source and bytecode until DoSGuide measures the series.

**What the harness does.** `QueryParserFuzzTest` has four `@Fuzz` methods, each reading the whole stream as UTF-8. For the main target, the query goes to `new QueryStringQueryBuilder(query).toQuery(CONTEXT)`. The only declared exceptions are `IOException`, `QueryShardException` and `IllegalArgumentException`. So a `StackOverflowError`, an `OutOfMemoryError` or a run over 20 s counts as a failure.

#### Phase A — Analysis

**V1: deeply nested groups overflow the stack (CWE-674).**
- **Input:** the whole query string.
- **Mechanism:** Lucene's classic parser handles a group by having `QueryParser.Clause()` call `Query()` again on `'(' Query ')'`. Each `(` adds one `Query` frame and one `Clause` frame.
- **No limit anywhere:** `QueryStringQueryBuilder.doToQuery` only catches `ParseException`, and `QueryStringQueryParser.parse` only checks for an empty string.
- **Lookahead stays flat:** the `jj_2_*` lookahead only checks for a short `field:` token pair, so it doesn't add recursion.
- **Balance doesn't matter:** the recursion happens on the way down, before any `)` is needed, so unbalanced input still overflows.
- **Resource:** stack depth.
- **Failure mode:** `stack_overflow`.
- **Scale:** about 2 frames × 100–200 bytes per level, so about 3,000–5,000 levels overflow 1 MB. That is 1 byte per level, about 4 KB.
- **Classification:** CWE-674 Uncontrolled Recursion.

**V2: an unbounded regex repeat count exhausts the heap (CWE-770).**
- **Input:** a `/regexp/` term in the query.
- **Path:** the term reaches `QueryStringQueryParser.getRegexpQuery`, which goes on to the Lucene 9.12.2 `RegexpQuery` constructor and then `RegExp.toAutomaton`.
- **Why the guards don't help:**
  - The only OpenSearch check is `index.max_regex_length`, a character limit (default 1,000).
  - `RegExp.parseRepeatExp` reads `{n}` and `{n,m}` with `Integer.parseInt` and no upper bound.
  - `Operations.repeat(a, n)` puts `n` references into an `ArrayList` and `Operations.concatenate` copies the automaton `n` times.
  - Only after that does `MinimizationOperations.minimize(..., 10000)` apply the determinize work limit.
- **Resource:** heap, growing linearly with `n` (roughly 50 bytes or more per copy).
- **Failure mode:** `out_of_memory` under `-Xmx1g`.
- **Scale:** about 2×10⁷ to 3×10⁷ copies. The densest form is a few bytes of syntax plus 8 digits, about 14 bytes.
- **Classification:** CWE-770 Allocation of Resources Without Limits or Throttling (CWE-400 family).

#### Dependency risks
- **PkgRisk-1:** `org.apache.lucene.util.automaton.Operations.repeat/concatenate` and `RegExp` (lucene-core 9.12.2). The repeat count is unbounded and the copies are built before the work-limit check (fails with `out_of_memory`). It is the same mechanism as V2, so it is covered through the V2 target, not as a separate one.
- **PkgRisk-2:** the JavaCC-generated recursive descent in `org.apache.lucene.queryparser.classic.QueryParser` (lucene-queryparser 9.12.2), which fails with `stack_overflow`. It is the same mechanism as V1 and covered by V1.
- **Excluded:**
  - Wildcard and prefix queries: the determinize work limit stops them during automaton building.
  - Fuzzy queries: no automaton is built in `toQuery`.
  - Very wide boolean queries: 1,024 max clauses, and the error is rethrown as the declared `QueryShardException`.
  - `RegExp.parseConcatExp`, which recurses once per character: through query_string the regex is limited to 1,000 characters, too short to overflow.

#### Scale-measurement files
- `analysis/scale/V1/`: 128 to 8,192 opening parentheses followed by one term, doubling (7 files plus `series.json`).
- `analysis/scale/V2/`: a `/regexp/` term with a repeat count from 16,384 to 1,048,576, doubling (7 files plus `series.json`).

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V2",
      "name": "query_string regexp term with unbounded repeat count {n} expands into n concatenated automaton copies (heap exhaustion)",
      "entrypoint": "QueryParserFuzzTest.fuzzQueryStringQueryBuilderToQuery(InputStream) → AbstractQueryBuilder.toQuery(QueryShardContext) → QueryStringQueryBuilder.doToQuery(QueryShardContext) → QueryStringQueryParser.parse(String) → QueryParserBase.parse(String) → QueryParser.TopLevelQuery(String) → QueryParser.Query(String) → QueryParser.Clause(String) → QueryParser.Term(String) → QueryParserBase.handleBareTokenQuery(String, Token, Token, boolean, boolean, boolean, boolean) → QueryStringQueryParser.getRegexpQuery(String, String) → QueryStringQueryParser.getRegexpQuerySingle(String, String) → QueryParserBase.getRegexpQuery(String, String) → QueryParserBase.newRegexpQuery(Term) → RegexpQuery.<init>(Term, int, int, AutomatonProvider, int, RewriteMethod) → RegExp.toAutomaton(AutomatonProvider, int) → RegExp.toAutomatonInternal(Map, AutomatonProvider, int) → Operations.repeat(Automaton, int) → Operations.concatenate(List)",
      "source_path": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java",
      "sink": "org.apache.lucene.util.automaton.Operations#repeat",
      "mechanism": "QueryStringQueryParser.getRegexpQuery bounds only the regex character length (index.max_regex_length=1000) and forwards the term to Lucene RegExp; parseRepeatExp accepts any int repeat count via Integer.parseInt, and Operations.repeat/concatenate materialize n copies of the sub-automaton (list of n refs + concatenated states/transitions) before minimize/determinize applies the 10000 work limit",
      "resource": "heap memory: automaton states/transitions and list entries allocated linearly in the repeat count n inside Operations.repeat/concatenate",
      "failure_mode": "out_of_memory",
      "scale": "about 2e7-3e7 repeated copies (~40-50+ bytes each incl. array growth) exhaust the 1 GB heap; the count is written in decimal, so the input is ~14 bytes (regex delimiters, one atom, braces, 8 digits)",
      "input_bytes": 14,
      "cwe": "CWE-770"
    },
    {
      "slot": 2,
      "id": "V1",
      "name": "query_string deeply nested parenthesized groups cause unbounded recursive descent in classic QueryParser (stack exhaustion)",
      "entrypoint": "QueryParserFuzzTest.fuzzQueryStringQueryBuilderToQuery(InputStream) → AbstractQueryBuilder.toQuery(QueryShardContext) → QueryStringQueryBuilder.doToQuery(QueryShardContext) → QueryStringQueryParser.parse(String) → QueryParserBase.parse(String) → QueryParser.TopLevelQuery(String) → QueryParser.Query(String) → QueryParser.Clause(String) → QueryParser.Query(String) → QueryParser.Clause(String)",
      "source_path": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java",
      "sink": "org.apache.lucene.queryparser.classic.QueryParser#Clause",
      "mechanism": "recursive descent: each '(' makes Clause() call Query() which calls Clause() again; QueryStringQueryParser.parse/QueryStringQueryBuilder.doToQuery impose no nesting limit and only catch ParseException",
      "resource": "stack depth: two parser frames (Query + Clause) per nesting level",
      "failure_mode": "stack_overflow",
      "scale": "about 3,000-5,000 nesting levels overflow the 1 MB thread stack (~200-300 bytes of frames per level); one '(' byte per level, so about 4 KB",
      "input_bytes": 4096,
      "cwe": "CWE-674"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

```text
Grep <source_root> \b(Query|Clause|Term)\(String
Grep <source_root> class QueryParser\b
```

CheckPath rejected the library hops `QueryParser.Query(String)` and `QueryParser.Term(String)`. Those names match the `Query`/`Term` classes, and the source tree has a `Term(String, ...)` constructor in `TermVectorsResponse`, so the checker resolves them as constructors that make no calls. The source tree has no `QueryParser` class. `org.apache.lucene.queryparser.classic` only contains `XQueryParser`, which does not declare `Clause`.

What I changed:
- **Paths:** I removed the `Query` and `Term` hops. Each was a single call between its neighbours, so leaving it out is within the 2-call gap allowed between hops. The recursion `Clause → Query → Clause` is unchanged.
- **V1 sink:** it is now `QueryStringQueryParser#parse`, the project method in `source_path` that starts the recursive descent. The parser frames still build up in the Lucene `Clause`/`Query` methods it calls; I've kept that in `resource`.

IDs, mechanisms, resources, failure modes and scales are unchanged.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V2",
      "name": "query_string regexp term with unbounded repeat count {n} expands into n concatenated automaton copies (heap exhaustion)",
      "entrypoint": "QueryParserFuzzTest.fuzzQueryStringQueryBuilderToQuery(InputStream) → AbstractQueryBuilder.toQuery(QueryShardContext) → QueryStringQueryBuilder.doToQuery(QueryShardContext) → QueryStringQueryParser.parse(String) → QueryParserBase.parse(String) → QueryParser.TopLevelQuery(String) → QueryParser.Clause(String) → QueryParserBase.handleBareTokenQuery(String, Token, Token, boolean, boolean, boolean, boolean) → QueryStringQueryParser.getRegexpQuery(String, String) → QueryStringQueryParser.getRegexpQuerySingle(String, String) → QueryParserBase.getRegexpQuery(String, String) → QueryParserBase.newRegexpQuery(Term) → RegexpQuery.<init>(Term, int, int, AutomatonProvider, int, RewriteMethod) → RegExp.toAutomaton(AutomatonProvider, int) → RegExp.toAutomatonInternal(Map, AutomatonProvider, int) → Operations.repeat(Automaton, int) → Operations.concatenate(List)",
      "source_path": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java",
      "sink": "org.apache.lucene.util.automaton.Operations#repeat",
      "mechanism": "QueryStringQueryParser.getRegexpQuery bounds only the regex character length (index.max_regex_length=1000) and forwards the term to Lucene RegExp; parseRepeatExp accepts any int repeat count via Integer.parseInt, and Operations.repeat/concatenate materialize n copies of the sub-automaton (list of n refs + concatenated states/transitions) before minimize/determinize applies the 10000 work limit",
      "resource": "heap memory: automaton states/transitions and list entries allocated linearly in the repeat count n inside Operations.repeat/concatenate",
      "failure_mode": "out_of_memory",
      "scale": "about 2e7-3e7 repeated copies (~40-50+ bytes each incl. array growth) exhaust the 1 GB heap; the count is written in decimal, so the input is ~14 bytes (regex delimiters, one atom, braces, 8 digits)",
      "input_bytes": 14,
      "cwe": "CWE-770"
    },
    {
      "slot": 2,
      "id": "V1",
      "name": "query_string deeply nested parenthesized groups cause unbounded recursive descent in classic QueryParser (stack exhaustion)",
      "entrypoint": "QueryParserFuzzTest.fuzzQueryStringQueryBuilderToQuery(InputStream) → AbstractQueryBuilder.toQuery(QueryShardContext) → QueryStringQueryBuilder.doToQuery(QueryShardContext) → QueryStringQueryParser.parse(String) → QueryParserBase.parse(String) → QueryParser.TopLevelQuery(String) → QueryParser.Clause(String) → QueryParser.Clause(String)",
      "source_path": "server/src/main/java/org/opensearch/index/search/QueryStringQueryParser.java",
      "sink": "QueryStringQueryParser#parse",
      "mechanism": "recursive descent: each '(' makes Clause() call Query() which calls Clause() again; QueryStringQueryParser.parse/QueryStringQueryBuilder.doToQuery impose no nesting limit and only catch ParseException",
      "resource": "stack depth: two parser frames (Query + Clause) per nesting level, accumulated beneath QueryStringQueryParser.parse",
      "failure_mode": "stack_overflow",
      "scale": "about 3,000-5,000 nesting levels overflow the 1 MB thread stack (~200-300 bytes of frames per level); one '(' byte per level, so about 4 KB",
      "input_bytes": 4096,
      "cwe": "CWE-674"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

V1's measurements support a revised scale. V2's do not grow at all, so I'm marking V2 as unable to fail in this evaluation.

- **V1:** 256 nesting levels fit in the probe's 256 KB stack and 512 did not. That puts the cost at about 0.5–1 KB of stack per level, higher than my estimate of 200–300 bytes. Extrapolated to the 1 MB stack, the failure needs about 1,000–2,000 levels, so about 2 KB of input.
- **V2:** allocation stayed at 4.1 MB and CPU time at about 50 ms from a repeat count of 16,384 up to 1,048,576. A 64× increase in the count changed nothing, so the copies are never built. I believe Lucene rejects the repeat before expanding it. That explanation comes from bytecode I listed but did not read in detail. `RegExp.toAutomatonInternal` calls `Automaton.getNumStates()` twice and creates `TooComplexToDeterminizeException` twice, which looks like a size check before `Operations.repeat`.
  - With the default fields (`*`), query_string runs in lenient mode. `getRegexpQuerySingle` then catches that exception and returns a lenient query.
  - Nested repeats would be checked the same way at each level.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: 256 nesting levels fit in the 256 KB probe stack, 512 do not, so the classic QueryParser recursion costs about 0.5-1 KB of stack per '(' level (interpreted frames; the parser's per-level cost is higher than the 200-300 B estimate). CPU and heap stay flat (~50 ms, ~5 MB), so stack depth is the only growing resource. Extrapolated to the fixed 1 MB stack (4x the cap): about 1,000-2,000 levels overflow with interpreted frames. JIT-compiled frames are smaller and may need up to ~2-3x more levels. One '(' byte per level is already the densest encoding, so about 2 KB of input, with up to ~4-6 KB if the frames are compiled.",
    "input_bytes": 2048
  },
  "V2": {
    "scale": "Measured: does NOT grow. Allocation (4.1 MB), peak heap (4-5 MB) and CPU (~50 ms) stay constant from repeat count 16,384 to 1,048,576 (64x). The n copies are never built. Likely cause, from the bytecode: RegExp.toAutomatonInternal (lucene-core 9.12.2) checks the sub-automaton's state count against the determinize work limit (getNumStates plus TooComplexToDeterminizeException) before calling Operations.repeat. In the default all-fields mode, query_string is lenient, so QueryStringQueryParser.getRegexpQuerySingle turns that exception into a lenient query. Nested repeats are checked the same way at each level, and regexes are limited to 1,000 characters. The resource does not grow with the parameter as the mechanism stated, so no input within the 131,072-byte limit reaches out_of_memory. The failure cannot occur in this evaluation.",
    "input_bytes": 131073
  }
}
END_SCALE_REVISION_JSON

## Scale revision 2

The estimate holds, so V2 cannot fail in this evaluation, and I've kept `input_bytes` at 131073 on purpose to say so. The size series showed no growth at all: allocation stayed at 4.1 MB and CPU near 50 ms while the repeat count rose 64×, so the copies are never built. My explanation for that is still an inference from bytecode, not code I read line by line. Lucene appears to check the size before expanding the repeat, and query_string's lenient mode turns that rejection into an ordinary query. If you want only feasible targets, drop V2; V1 is unchanged.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: 256 nesting levels fit in the 256 KB probe stack, 512 do not, so the classic QueryParser recursion costs about 0.5-1 KB of stack per '(' level (interpreted frames; the parser's per-level cost is higher than the 200-300 B estimate). CPU and heap stay flat (~50 ms, ~5 MB), so stack depth is the only growing resource. Extrapolated to the fixed 1 MB stack (4x the cap): about 1,000-2,000 levels overflow with interpreted frames. JIT-compiled frames are smaller and may need up to ~2-3x more levels. One '(' byte per level is already the densest encoding, so about 2 KB of input, with up to ~4-6 KB if the frames are compiled.",
    "input_bytes": 2048
  },
  "V2": {
    "scale": "CANNOT FAIL IN THIS EVALUATION (confirmed). Measured: no growth. Allocation (4.1 MB), peak heap (4-5 MB) and CPU (~50 ms) stay constant from repeat count 16,384 to 1,048,576 (64x), so Operations.repeat never builds the n copies. Likely cause, from the bytecode: RegExp.toAutomatonInternal (lucene-core 9.12.2) checks the sub-automaton's state count against the determinize work limit (getNumStates plus TooComplexToDeterminizeException) before repeating. In the default all-fields mode, query_string is lenient, so QueryStringQueryParser.getRegexpQuerySingle turns that exception into a lenient query. Nested repeats are checked the same way at each level, and regexes are limited to 1,000 characters (index.max_regex_length). No input up to the 131,072-byte limit makes heap use grow with the repeat count, so out_of_memory cannot be reached. input_bytes is set above the limit on purpose to record this.",
    "input_bytes": 131073
  }
}
END_SCALE_REVISION_JSON

## Block 2

Checking the provided pom.xml and that it compiles.

```text
$ cd <run_dir>; ls; cat pom.xml 2>/dev/null | head -150; cat src/test/java/dosguide/validate/SignalSource.java
Glob <run_dir> *
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/pom.xml
```

The provided pom.xml looks complete. I'll confirm it resolves and compiles the frozen harness, and check that ASM is on the test classpath (it comes in transitively through jqf-instrument).

```text
$ mvn -q test-compile 2>&1 | tail -20; echo EXIT=$?; mvn -q dependency:build-classpath -Dmdep.outputFile=/dev/stdout -Dmdep.includeScope=test 2>&1 | tr ':' '\n' | grep -i "asm\|jqf\|queryparser" | head
$ mvn -q compile 2>&1 | tail -20; echo EXIT=$?
$ mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt 2>&1 | tail -5; tr ':' '\n' < target/cp.txt | grep -i "asm\|jqf\|queryparser\|lib/opensearch-2"
$ mkdir -p target/tc && javac -d target/tc -cp "$(cat target/cp.txt)" $(find src/test -name '*.java') 2>&1 | tail -10; echo EXIT=$?; ls target/tc/org/opensearch/fuzz/tests/; Q=~/.m2/repository/org/apache/lucene/lucene-queryparser/9.12.2/lucene-queryparser-9.12.2.jar; javap -cp $Q -p -c org.apache.luce …
$ Q=~/.m2/repository/org/apache/lucene/lucene-queryparser/9.12.2/lucene-queryparser-9.12.2.jar; javap -cp $Q -p -c org.apache.lucene.queryparser.classic.QueryParser > /tmp/qp.txt; awk '/Query Clause\(/,/^$/' /tmp/qp.txt | grep "Method" | sed 's/.*Method //' | sort -u; echo ---; awk '/Query Query\(/,/^ …
$ cd <run_dir>; Q=~/.m2/repository/org/apache/lucene/lucene-queryparser/9.12.2/lucene-queryparser-9.12.2.jar; javap -cp $Q -p -c org.apache.lucene.queryparser.classic.QueryParser > target/qp.txt; awk '/Query Clause\(/,/^$/' target …
$ mkdir -p src/main/java src/test/java/org/opensearch/fuzz/agent src/test/java/org/opensearch/fuzz/guidance src/test/java/org/opensearch/fuzz/runner src/test/java/org/opensearch/fuzz/repro src/test/resources/META-INF out/V1/corpus out/V1/logs && find src out -type d | sort; grep -n "Premain\|Agent-Cla …
$ mkdir -p src/main/java src/test/java/org/opensearch/fuzz/agent src/test/java/org/opensearch/fuzz/guidance src/test/java/org/opensearch/fuzz/runner src/test/java/org/opensearch/fuzz/repro src/test/resources/META-INF out/V1/corpus out/V1/logs && find src out -type d | sort
$ for d in src/main/java/ src/test/java/org/opensearch/fuzz/agent/ src/test/java/org/opensearch/fuzz/guidance/ src/test/java/org/opensearch/fuzz/runner/ src/test/java/org/opensearch/fuzz/repro/ src/test/resources/META-INF/ out/V1/corpus/ out/V1/logs/; do mkdir -p "$d"; done; find src out -type d | sor …
```

### Block 2: build check and measurement plan for V1

The provided pom.xml builds as is: `mvn -q compile` succeeded, and `javac` compiled the frozen `QueryParserFuzzTest` against the full resolved classpath with no errors. I made no changes to pom.xml, wrote no files, and created only empty directories. Nothing was run, since execution is blocked in this block.

#### Step 2: Maven layout and scopes
- **Vulnerable code:** the OpenSearch 2.19.3-SNAPSHOT jars in `${project.basedir}/lib/` are system-scope dependencies, built from source per the pom's comment. `QueryStringQueryParser` is in `lib/opensearch-2.19.3-SNAPSHOT.jar`.
- **Lucene:** lucene-core and lucene-queryparser 9.12.2 come from Maven Central. They are third-party code, not the fuzzed project.
- **Fuzzing libraries:** JQF 2.1 (`jqf-fuzz`, `jqf-instrument`) and JUnit 4.13.2 are test-scope.
- **ASM:** asm 9.8, asm-commons 9.5 and asm-tree 9.5 reach the test classpath transitively through jqf-instrument; I checked this with `dependency:build-classpath`. The custom agent will use ASM directly as a library, not JQF's instrumentation agent.
- **Scope split:**
  - `src/main/java/` stays empty, since no project classes are missing.
  - `src/test/java/` will hold all fuzzing code: the agent, `V1Guidance`, the runner, repro/replay, and the frozen harness.

#### Step 3: missing-symbol audit and stub report
- **Unresolved symbols:** none. The harness and every class it imports resolve against the declared dependencies.
- **Stubs:** none needed, so there is nothing to list in the stub report.

#### Step 4a: directory tree
```
pom.xml                                  (provided, unchanged)
lib/*.jar                                (vulnerable OpenSearch artifacts)
src/main/java/                           (empty: no stubs)
src/test/java/org/opensearch/fuzz/tests/QueryParserFuzzTest.java   (frozen)
src/test/java/dosguide/validate/SignalSource.java                  (provided)
src/test/java/org/opensearch/fuzz/agent/      V1MeasureAgent, V1ParserTransformer, V1Counters
src/test/java/org/opensearch/fuzz/guidance/   V1Guidance (implements Guidance, SignalSource)
src/test/java/org/opensearch/fuzz/runner/     FuzzRunner (CLI: target id / @Fuzz method, time bound)
src/test/java/org/opensearch/fuzz/repro/      V1Repro, MetadataReplay
src/test/resources/META-INF/                  agent MANIFEST (Premain-Class, Can-Retransform-Classes)
out/V1/corpus/, out/V1/logs/                  V1-only corpus and logs
```

#### Input model
The input model is `InputStream`, which the frozen harness fixes. `V1Guidance.getInput()` returns the raw bytes of the input, and the harness decodes them as UTF-8. There are no quickcheck generators.

#### Step 5: strategy

| Target | Selected strategy | Why Zest fails (mechanistic) | Why this strategy wins |
|---|---|---|---|
| V1 | VDF + CGF hybrid: hill-climbs the measured parser recursion depth, with shape-aware repetition | Zest rewards new coverage. Every branch of `Clause`/`Query` is already covered at nesting depth 1–2, so depths 3 to about 2,000 add no coverage and Zest discards them. Its byte-level mutations grow an input by about 1 byte per kept input, so it can't build about 2,000 nested levels. PerfFuzz rewards the hit count of the most-hit edge, a generic proxy. Tokenizer and whitespace loops grow with any input length, so it spends its budget on long flat queries that never deepen the recursion. | The signal is the actual maximum number of active `Clause`/`Query` frames, measured inside the recursion that uses up the stack. Repetition can double a region, so depth grows geometrically, and parent selection favours inputs that gain the most depth per byte. |

**Metrics where V1Guidance should beat Zest and PerfFuzz:**
- maximum `maxClauseDepth` reached over time;
- time to the first `StackOverflowError` (recorded by the evaluation, not the Guidance);
- time until a generated input reaches 2,048 bytes;
- depth per input byte of the best input in the corpus.

#### Step 6: measurement plan (Tier 1, custom agent)

**What gets instrumented.** All three methods are in classes loaded by the app class loader:
- `org.apache.lucene.queryparser.classic.QueryParser#Clause(String)` and `#Query(String)`: the two recursive productions, which my Block 1 bytecode check confirmed call each other.
- `org.opensearch.index.search.QueryStringQueryParser#parse(String)`: the register's sink. It is used only to gate counting to the parse itself and not to the harness's static setup.

**How the counters work** (ASM `AdviceAdapter`):
- **On entry:** increment `V1Counters.cur`, update `V1Counters.max`, and increment `V1Counters.visits`.
- **On exit:** decrement `cur`. A try/catch region around the whole method body decrements and rethrows on exceptional exit, including the `StackOverflowError` itself.
- **Storage:** plain static fields in `V1Counters`. JQF runs the fuzz method on its one fuzzing thread, and the fields are only active between `parse` entry and exit.

**Signals and where they flow:**
- **`maxClauseDepth`** is the peak number of `Clause` frames active at once, one per nesting level.
- **`parserVisits`** is the total number of `Clause` and `Query` invocations, i.e. parse nodes visited.
- **Reset:** `V1Guidance.getInput()` calls `V1Counters.reset()` immediately before handing over the input.
- **Read:** `V1Guidance.handleResult()` reads both values, and `lastSignals()` returns them.

**JVM flags:**
- `-Xmx1g -Xss1m -javaagent:target/v1-agent.jar`; no `--add-opens` is needed because both classes are in the unnamed module.
- The agent is packaged with `jar` in Block 3, with `Premain-Class` and `Can-Retransform-Classes: true`. It retransforms the two classes if they are already loaded.

**Why measure here.** The register's sink is `QueryStringQueryParser#parse`. Stack depth is used up in the Lucene `Clause`/`Query` frames that `parse` runs, so the counters sit inside the sink's execution, which satisfies [R47].

**Mutation operators:**
- **Byte level:** bit/byte flip, insert, delete, and splicing two corpus inputs.
- **[R45](a) Repetition:** pick a chunk, either at random or starting at a group boundary from the dictionary, and repeat it k times in place. k goes up to whatever fills `jqf.ei.MAX_INPUT_SIZE` (131,072 bytes), and the operator includes doubling a region or the whole input. Doubling a 1-byte chunk reaches 2,048 bytes in about 11 steps, well within a minute.
- **[R45](b) Dictionary:** single tokens from the classic QueryParser grammar and the harness mapping: `(` `)` `+` `-` `!` `AND` `OR` `NOT` `&&` `||` `:` `^` `~` `"` `*` `?` `[` `]` `{` `}` `TO` `/` `\` and whitespace. Field names come from the mapping: `f1` `f2` `f3` `f_multi` `f_int` `f_date`, and so on. Each is inserted or overwritten at a random position. There are no assembled sequences.
- **[R45](c) Encoder:** not applicable, since the input is plain UTF-8 text with no compression, checksums or length fields.
- **Seeds:** a few short benign queries such as one term, a `field:term` pair, or two terms joined by an operator. None of them is nested.

**Retention, from most to least important:**
1. Keep the input if `maxClauseDepth` beats the best seen so far.
2. Otherwise keep it if `parserVisits` reaches a new maximum while depth is no worse than its parent's.
3. While depth is flat ([R46]): keep it if it is longer than the longest kept input, and its measured depth is at least its parent's depth. This lets inputs grow towards 2,048 bytes.
4. Inputs whose run ended in a throwable are kept like any other, using the counters measured up to that point. The Guidance never labels a run as failed and never writes failure files ([R6]).

**Prioritization:** parents are weighted towards the highest `maxClauseDepth` and the highest depth per input byte. This rule is specific to this method (R19): in the classic QueryParser one `(` byte should add one recursion level, so a high ratio marks a dense nesting chain worth repeating. Repetition is used more often on such parents.

**Run control:** runs indefinitely by default and accepts a time bound through a CLI option or system property. Structured logs go to `out/V1/logs` every second with: executions, corpus size, best depth, best visits, and the longest input.

#### IMPORT AUDIT (symbols the Block 3 code will use)
```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz            (frozen harness only)
@RunWith → org.junit.runner.RunWith              (frozen harness only)
JQF → edu.berkeley.cs.jqf.fuzz.JQF               (frozen harness only)
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent  (only in generateCallBack's signature; no JQF tracing used)
SignalSource → dosguide.validate.SignalSource
ClassReader/ClassWriter/ClassVisitor/MethodVisitor/Opcodes/Label/Type → org.objectweb.asm.*  (explicit imports)
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter
Instrumentation/ClassFileTransformer → java.lang.instrument.*  (explicit imports)
```

#### Self-checklist
| Check | Answer | Note |
|---|---|---|
| JDK 17+ only | YES | `maven.compiler` release is 17 |
| No hallucinated APIs | YES | JQF 2.1 and ASM 9.x classes are on the resolved classpath |
| Guidance implements Guidance directly | YES | `V1Guidance implements Guidance, SignalSource` |
| No existing guidance extended | YES | |
| V* vulnerabilities identified | YES | V1 (V2 was dropped by the scale probe) |
| V* IDs sequential [R42] | YES | |
| Official names applied | YES | CWE-674 |
| PkgRisk-* identified | YES | PkgRisk-1 is covered by the dropped V2; PkgRisk-2 is the V1 mechanism |
| Every PkgRisk executed or justified | YES | PkgRisk-2 runs through V1; PkgRisk-1 was shown not to grow by the measurement |
| Guidance targets V*/PkgRisk | YES | |
| One fuzz method per target | YES | `fuzzQueryStringQueryBuilderToQuery` |
| CLI method selection | YES | FuzzRunner (Block 3) |
| byte[]/InputStream only | YES | |
| No quickcheck generators | YES | |
| All mutation inside Guidance | YES | |
| Repetition, dictionary, encoder [R45] | YES | Encoder not needed for plain text |
| Retention progresses while flat; reaches input_bytes within a minute [R46] | YES | Length-frontier retention plus doubling |
| Signals measured at the sink [R47] | YES | `Clause`/`Query` frames under `QueryStringQueryParser#parse` |
| Logging every 1 second | YES | |
| Guidance decides no failures [R6] | YES | |
| Corrupted inputs saved with metadata | YES | Corpus entries plus JSON metadata |
| Replay/feeder implemented | YES | Planned for Block 3 |
| Infinite and time-bounded runs | YES | |
| src/main vs src/test separation | YES | |
| Maven scopes consistent | YES | |
| No wildcard JQF imports | YES | |
| TraceEvent import audited | YES | |

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "maxClauseDepth",
          "quantity": "peak number of simultaneously active classic-parser recursive production frames (Clause entries minus exits), i.e. the recursion depth reached by nested groups while QueryStringQueryParser.parse runs",
          "aggregation": "max",
          "locations": ["org.apache.lucene.queryparser.classic.QueryParser#Clause", "org.apache.lucene.queryparser.classic.QueryParser#Query", "org.opensearch.index.search.QueryStringQueryParser#parse"],
          "technique": "bytecode",
          "storage": "static int cur/max fields in org.opensearch.fuzz.agent.V1Counters (single JQF fuzzing thread), incremented on method entry and decremented on normal or exceptional exit by ASM AdviceAdapter hooks injected by V1MeasureAgent; counting is active only between QueryStringQueryParser#parse entry and exit",
          "reset": "V1Guidance.getInput() calls V1Counters.reset() immediately before handing the input to the harness",
          "read": "V1Guidance.handleResult()"
        },
        {
          "name": "parserVisits",
          "quantity": "total invocations of the recursive productions Clause and Query during the parse (parse nodes visited)",
          "aggregation": "count",
          "locations": ["org.apache.lucene.queryparser.classic.QueryParser#Clause", "org.apache.lucene.queryparser.classic.QueryParser#Query"],
          "technique": "bytecode",
          "storage": "static long visits field in org.opensearch.fuzz.agent.V1Counters, incremented by the same entry hooks",
          "reset": "V1Guidance.getInput() calls V1Counters.reset()",
          "read": "V1Guidance.handleResult()"
        }
      ],
      "retention": "Keep an input if maxClauseDepth exceeds the best so far (primary); else if parserVisits reaches a new maximum while depth is at least the parent's; else, while depth is flat, keep it if it is longer than the longest kept input and its measured depth is no lower than its parent's, so inputs keep growing towards input_bytes ([R46]). Inputs ending in a throwable are kept like any other, using the measured counters; the Guidance never labels a run as failed. Parent selection is weighted towards the highest maxClauseDepth and the highest measured depth per input byte (specific to this method: one group-open token should yield one Clause frame), and repetition is applied more often to such parents.",
      "retention_signals": ["maxClauseDepth", "parserVisits"],
      "mutation": [
        "byte-level: random bit/byte flip, byte insert, byte delete, splice of two corpus inputs",
        "repetition: copy a chunk (random, or starting at a group-boundary dictionary token) and repeat it k times in place, k up to filling jqf.ei.MAX_INPUT_SIZE, including doubling a region or the whole input; about 11 doublings reach 2048 bytes",
        "dictionary insert/overwrite of single tokens from the classic QueryParser grammar and harness mapping: ( ) + - ! AND OR NOT && || : ^ ~ \" * ? [ ] { } TO / \\ whitespace, and field names f1 f2 f3 f_multi f_int f_date",
        "no encoder: input is plain UTF-8 query text with no compression, checksum or length fields"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

Writing the V1 agent, guidance, runner and replay now. First I'll check the JQF 2.1 `Guidance` and `GuidedFuzzing` signatures.

```text
$ cd <run_dir>; J=~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar; javap -cp "$(cat target/cp.txt)" edu.berkeley.cs.jqf.fuzz.guidance.Guidance edu.berkeley.cs.jqf.fuzz.guidance.Result edu.berkeley.cs.jqf.fuzz.ju …
Write <run_dir>/src/test/java/org/opensearch/fuzz/agent/V1Counters.java
Write <run_dir>/src/test/java/org/opensearch/fuzz/agent/V1ParserTransformer.java
Write <run_dir>/src/test/java/org/opensearch/fuzz/agent/V1MeasureAgent.java
Write <run_dir>/src/test/resources/v1-agent.mf
```

Agent files are written. Next is the V1 Guidance.

```text
Write <run_dir>/src/test/java/org/opensearch/fuzz/guidance/V1Guidance.java
```

Now the runner, repro and metadata replay classes.

```text
Write <run_dir>/src/test/java/org/opensearch/fuzz/runner/FuzzRunner.java
Write <run_dir>/src/test/java/org/opensearch/fuzz/repro/V1Repro.java
Write <run_dir>/src/test/java/org/opensearch/fuzz/repro/MetadataReplay.java
```

Compiling everything and packaging the agent jar.

```text
$ mvn -q compile 2>&1 | tail -30 && mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt 2>&1 | tail -10 && mkdir -p target/test-classes && javac -Xlint:-options -d target/test-classes -cp "target/classes:$(cat target/cp.txt)" $(find src/test/ -name '*.java') 2>&1 | tail -30 && jar cfm ta …
$ mvn -q compile 2>&1 | tail -30; mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt 2>&1 | tail -10; echo done
$ mkdir -p target/test-classes && javac -d target/test-classes -cp "target/classes:$(cat target/cp.txt)" $(find src/test/ -name '*.java') 2>&1 | tail -30 && jar cfm target/v1-agent.jar src/test/resources/v1-agent.mf -C target/test-classes org/opensearch/fuzz/agent && jar tf target/v1-agent.jar && unzi …
```

Everything compiles. Checking that the descriptors for `parse`, `Clause` and `Query` match what the transformer looks for.

```text
$ javap -s -cp lib/opensearch-2.19.3-SNAPSHOT.jar org.opensearch.index.search.QueryStringQueryParser | grep -A1 " parse(" ; javap -s -cp ~/.m2/repository/org/apache/lucene/lucene-queryparser/9.12.2/lucene-queryparser-9.12.2.jar org.apache.lucene.queryparser.classic.QueryParser | grep -A1 "Query Clause …
```

Descriptors match. Next: run.sh, launch.json, the validation inputs and the README.

```text
$ ls analysis/ && head -c 600 analysis/guidance_plan.json 2>/dev/null
Write <run_dir>/run.sh
Write <run_dir>/analysis/launch.json
$ chmod +x run.sh && mkdir -p analysis/validation_inputs && cd analysis/validation_inputs && printf 'hello' > q1.txt && printf 'f1:hello AND f2:world' > q2.txt && printf '(a OR b) AND c' > q3.txt && printf '"quick brown"~2 -fox' > q4.txt && printf 'f_int:[1 TO 5] OR f1:te*' > q5.txt && printf '+(f1:a  …
Write <run_dir>/README.md
```

I wrote and compiled the V1 fuzzing setup: a custom measurement agent, `V1Guidance`, the runner, and repro/replay tools. Nothing has been run: execution is blocked here, so whether the agent rewrites classes, the signals vary, and inputs reach 2,048 bytes within a minute is unconfirmed until DoSGuide's checks. This includes the Class Origin Check, which `FuzzRunner` prints on startup but which has not printed yet.

**Build status:** `mvn -q compile` and `dependency:build-classpath` succeeded. `javac` compiled all test sources with no errors, and `target/v1-agent.jar` was packaged with the right manifest. The frozen harness and `pom.xml` are unchanged.

**What I verified by inspecting bytecode:** with `javap` I confirmed that `QueryStringQueryParser.parse`, `QueryParser.Clause` and `QueryParser.Query` all have the descriptor `(Ljava/lang/String;)Lorg/apache/lucene/search/Query;`, which is what the transformer looks for. I also confirmed the JQF 2.1 `Guidance` interface the guidance implements.

#### Part A: measurement agent
- **What it instruments:** ASM hooks on Lucene's `QueryParser#Clause` (entry and exit) and `#Query` (entry). Counting only happens while `QueryStringQueryParser#parse` is running, so the recursion is measured inside the sink. The Lucene parser run by the harness's other fuzz methods reads as zero.
- **Signals:** `maxClauseDepth` is the peak number of `Clause` calls active at once, one per nesting level. `parserVisits` counts calls to `Clause` and `Query`.
- **Storage:** plain static fields in `V1Counters`, which is safe because JQF runs everything on one thread.
- **Exit hooks:** they run only on normal returns. An exception in the recursion (a `ParseException` or the `StackOverflowError` itself) ends the whole parse after the peak is recorded. The counters are reset before every execution.
- **JVM flags:** `-Xmx1g -Xss1m -javaagent:target/v1-agent.jar`; no `--add-opens` is needed.

#### Part B: `V1Guidance`
- **Input model:** raw bytes passed straight through; the frozen harness decodes them as UTF-8.
- **Size limit:** the maximum length comes from `jqf.ei.MAX_INPUT_SIZE` when the guidance is created, and every operator caps its output at that size.
- **Retention:**
  - a new best depth;
  - more parser visits at no less depth than the parent;
  - while depth is flat, a longer input at no less depth than the parent, so inputs keep growing;
  - a depth value not seen before.
- **Parent choice:** weighted towards measured depth per input byte. This is the rule specific to this target, since each `(` should add exactly one level.
- **Mutations:**
  - repetition: repeat a chunk once, log-uniform times, or enough to fill the size limit, plus whole-input doubling;
  - a dictionary of single grammar tokens and mapping field names;
  - flip, set, insert and delete bytes;
  - splice two corpus inputs.

  No encoder is needed for plain text.
- **Seeds:** benign queries; the deepest is one group, `(a)`.
- **Logging:** one JSON stats line per second to the console and `out/V1/logs/V1-stats.jsonl`.
- **Corpus:** each kept input is saved as `.bin` plus `.json` metadata recording the JQF result as reported. The guidance never decides that a run failed and writes no failure files.

#### Part C: runner, repro, scripts
- **`FuzzRunner`:** takes a target ID or method name, an optional duration (0 or absent means run forever, or `-Dfuzz.durationSec`), and an output directory. It exposes `createGuidance` and runs `GuidedFuzzing.run(...)` with the context class loader.
- **`V1Repro`:** replays one input through the frozen harness method and reports whether the error is one the harness declares or not.
- **`MetadataReplay`:** reads corpus metadata, prints it with an input preview, and replays (`--top N`, `--only-throwable`).
- **`run.sh`:** builds and then runs `FuzzRunner V1` with `-Xmx1g -Xss1m` and the agent, defaulting to 60 s.
- **Other files:** `analysis/launch.json`, six benign example queries in `analysis/validation_inputs/`, and `README.md`.

Files are in the workspace:
- `src/test/java/org/opensearch/fuzz/agent/` (`V1Counters`, `V1ParserTransformer`, `V1MeasureAgent`)
- `src/test/java/org/opensearch/fuzz/guidance/V1Guidance.java`
- `src/test/java/org/opensearch/fuzz/runner/FuzzRunner.java`
- `src/test/java/org/opensearch/fuzz/repro/` (`V1Repro`, `MetadataReplay`)
- `src/test/resources/v1-agent.mf`
- `run.sh`
- `analysis/launch.json`
- `analysis/validation_inputs/`
- `README.md`

#### Strategy

| Target | Strategy | Why Zest fails (mechanistic) | Why this wins |
|---|---|---|---|
| V1 | Hybrid: hill-climbing on the measured depth (VDF + CGF), with shape-aware repetition | Coverage is saturated by nesting depth 1–2, so Zest discards deeper inputs, and byte mutations grow inputs about one byte at a time. PerfFuzz's per-edge hit counts are a generic proxy that tokenizer and whitespace loops inflate on any long input. | It uses the measured peak recursion depth inside the sink, weights parents by depth per byte, and can double or fill an input in one step. |

The custom guidance should beat Zest on:
- the highest `maxClauseDepth` reached over time;
- time to the first `StackOverflowError`, as recorded by the evaluation;
- time until a generated input reaches 2,048 bytes.

#### IMPORT AUDIT
```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz                      (frozen harness)
@RunWith → org.junit.runner.RunWith                        (frozen harness)
JQF → edu.berkeley.cs.jqf.fuzz.JQF                         (frozen harness)
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent   (generateCallBack signature only; no JQF tracing)
SignalSource → dosguide.validate.SignalSource
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
ClassVisitor → org.objectweb.asm.ClassVisitor
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter
ClassFileTransformer → java.lang.instrument.ClassFileTransformer
Instrumentation → java.lang.instrument.Instrumentation
```

#### Self-checklist
| Check | Answer | Note |
|---|---|---|
| JDK 17+ only | YES | Compiled with JDK 17 |
| No hallucinated APIs | YES | JQF signatures checked with `javap`; ASM 9.8/asm-commons 9.5 are on the classpath |
| Guidance implements Guidance directly | YES | `V1Guidance implements Guidance, SignalSource` |
| No existing guidance extended | YES | |
| V* vulnerabilities identified | YES | V1, CWE-674 |
| V* IDs sequential [R42] | YES | |
| Official names applied | YES | CWE-674 Uncontrolled Recursion |
| PkgRisk-* identified | YES | Lucene classic parser recursion runs through V1; the Lucene regex repeat risk was ruled out by the scale measurements |
| Every PkgRisk executed or justified | YES | |
| Guidance targets V*/PkgRisk | YES | V1 only |
| One fuzz method per target | YES | `fuzzQueryStringQueryBuilderToQuery` |
| CLI method selection | YES | Target ID or method name |
| Byte[]/InputStream only | YES | |
| No junit-quickcheck generators | YES | |
| All mutation inside Guidance | YES | |
| Repetition, dictionary, encoder [R45] | YES | No encoder needed for plain text |
| Retention progresses while flat; reaches input_bytes within a minute [R46] | YES (unconfirmed) | Length-frontier retention plus fill-repetition; not yet run |
| Signals measured where the resource is consumed [R47] | YES | `Clause`/`Query` frames, counted only inside `QueryStringQueryParser#parse` |
| Logging every 1 second | YES | Daemon scheduled logger |
| Guidance decides no failures [R6] | YES | It only records the JQF result in corpus metadata |
| Inputs saved with metadata | YES | `.bin` plus `.json` per corpus entry |
| Replay/feeder implemented | YES | `MetadataReplay`, `V1Repro` |
| Infinite and time-bounded runs | YES | |
| src/main vs src/test separation | YES | All fuzzing code is in src/test; no stubs needed |
| Maven scopes consistent | YES | Provided pom unchanged |
| No wildcard JQF imports | YES | |
| TraceEvent import verified and audited | YES | |

## Validation repair 1

The likely cause: the validator loads the fuzz classpath in its own class loader, while the `-javaagent` jar sits on the system class path without ASM. When the transformer then ran, ASM classes would have failed to load, the `catch (Throwable)` would have swallowed it, and nothing was rewritten. I'll make the agent jar self-contained by bundling the ASM classes into it.

```text
$ cd <run_dir> && tr ':' '\n' < target/cp.txt | grep -E "/org/ow2/asm/asm(-commons|-tree)?/"
Write <run_dir>/build-agent.sh
$ cd <run_dir> && chmod +x build-agent.sh && ./build-agent.sh 2>&1 | tail -5 && jar tf target/v1-agent.jar | grep -E "AdviceAdapter|ClassWriter.class|fuzz/agent"
```

The agent jar now bundles ASM. I'll make transform failures print a full stack trace instead of being silently swallowed, and switch the build steps in launch.json and run.sh to the new agent build.

```text
Edit <run_dir>/src/test/java/org/opensearch/fuzz/agent/V1ParserTransformer.java
Write <run_dir>/analysis/launch.json
Edit <run_dir>/run.sh
Write <run_dir>/src/test/resources/v1-agent.mf
Edit <run_dir>/build-agent.sh
$ javac -d target/test-classes -cp "target/classes:$(cat target/cp.txt)" $(find src/test/ -name '*.java') 2>&1 | tail -10 && bash build-agent.sh 2>&1 | tail -3 && jar tf target/v1-counters.jar && unzip -p target/v1-agent.jar META-INF/MANIFEST.MF
```

I rebuilt the agent with two fixes. I couldn't run anything here, so whether the agent now rewrites classes and the signal varies is unconfirmed until your validation reruns.

My best explanation for "rewrote no class" is that ASM wasn't on the agent's class path. The agent jar held only my agent classes, and the ASM library it uses came from the Maven class path. If the validator loads that class path in its own class loader, ASM can't be loaded when the transform runs. The transformer caught that error and silently gave up, so nothing was rewritten and both signals stayed at 0.

What I changed:
- **Self-contained agent jar:** a new `build-agent.sh` copies the ASM classes (asm, asm-commons and asm-tree from the Maven class path) into `target/v1-agent.jar` alongside the agent classes. It no longer depends on how the validator sets up class loaders.
- **One shared set of counters:** the agent manifest now has `Boot-Class-Path: v1-counters.jar`, a small jar holding only `V1Counters`. That puts the counters on the bootstrap class path. The rewritten Lucene `QueryParser`, OpenSearch's `QueryStringQueryParser`, the agent and `V1Guidance` then all use the same counter fields, even across different class loaders.
- **Visible failures:** the transformer now prints the full stack trace if instrumenting a class fails, so a remaining problem will show up in the logs.
- **Build wiring:** `analysis/launch.json` and `run.sh` now run `bash build-agent.sh` as the last build step instead of the plain `jar` command.

The rebuild succeeded: the agent jar has 108 classes including `AdviceAdapter` and `ClassWriter`, and the manifest now includes `Boot-Class-Path`.

I didn't change the guidance plan, the signal names (`maxClauseDepth`, `parserVisits`), the hooked methods (`QueryParser#Clause`, `QueryParser#Query`, `QueryStringQueryParser#parse`), the guidance logic, or the frozen harness.

## Validation repair 2

Still no rewrite. I'll check whether DoSGuide left validation logs in the workspace.

```text
$ ls -la analysis/ target/ | head -60; ls out/V1 2>/dev/null | head
Read <run_dir>/analysis/validate.round1.json
$ diff <(python3 -I -m json.tool analysis/validate.round0.json) <(python3 -I -m json.tool analysis/validate.round1.json) | head -30; python3 -I -c "import json;d=json.load(open('analysis/validate.repair1.json'));print(json.dumps(d)[:1500])"
Edit <run_dir>/src/test/java/org/opensearch/fuzz/agent/V1ParserTransformer.java
Edit <run_dir>/src/test/java/org/opensearch/fuzz/agent/V1MeasureAgent.java
```

Rebuilding the classes, the agent jar and the counters jar.

```text
$ javac -d target/test-classes -cp "target/classes:$(cat target/cp.txt)" $(find src/test/ -name '*.java') 2>&1 | tail -10 && bash build-agent.sh 2>&1 | tail -3 && javap -c -p -cp target/v1-agent.jar org.opensearch.fuzz.agent.V1ParserTransformer | grep -n "accept\|bipush\|iconst" | head
```

I found and fixed the bug that stopped the agent from rewriting any class. The fix compiles and the agent jar is rebuilt, but I couldn't run anything here to confirm the classes now get rewritten. That will only show when your validation reruns.

**The bug:** the transformer uses ASM's `AdviceAdapter`, which only accepts class files read with the `ClassReader.EXPAND_FRAMES` option. I was reading them without that flag (`cr.accept(cv, 0)`). So instrumenting `QueryParser` and `QueryStringQueryParser` threw an `IllegalArgumentException` every time. The transformer caught it and left each class unchanged, which matches `transformed_classes: []` and both signals stuck at 0.

**What I changed:**
- **`V1ParserTransformer`:** it now reads classes with `cr.accept(cv, ClassReader.EXPAND_FRAMES)`. I confirmed in the compiled bytecode that the flag is passed. Any remaining transform error now prints a full stack trace instead of failing silently.
- **`V1MeasureAgent`:** the transformer is now registered as an ordinary load-time transformer instead of a retransform-capable one. Any class-load observer the validator registers later should then see the rewritten classes, though I'm guessing at how it detects them. The parser classes load during the first fuzz run, after the agent starts, so nothing needs retransforming. If either class had already loaded, the agent prints a warning.
- **Rebuilt:** `target/test-classes`, `target/v1-agent.jar` (now with the ASM classes inside) and `target/v1-counters.jar` (on the boot class path, so all loaders share one counter).

The guidance plan, the signal names (`maxClauseDepth`, `parserVisits`), the hooked methods, `V1Guidance` and the frozen harness are unchanged.
