# JSON-java_GHSA-3vqj-43w4-2q58

## Block 1

```text
Read <source_root>/src/main/java/org/json/JSONML.java
Glob <run_dir> *FuzzTest.java
Glob <run_dir> **/*
Read <run_dir>/src/test/java/fuzzing/harness/XmlFuzzTest.java
Read <run_dir>/pom.xml
Read <run_dir>/analysis/run_config.json
```

Now let me examine the related source files to understand the full vulnerability surface:

```text
Glob <source_root> src/main/java/org/json/*.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <source_root>/src/main/java/org/json/XML.java
Read <source_root>/src/main/java/org/json/XMLTokener.java
```

Now let me check the XMLParserConfiguration to understand the default max nesting depth for XML.parse:

```text
Read <source_root>/src/main/java/org/json/XMLParserConfiguration.java
```

Now I have a thorough understanding of the codebase. Let me examine the JSONTokener base class briefly:

```text
Read <source_root>/src/main/java/org/json/JSONTokener.java
```

Good. Now I have all the information I need. Let me create the scale measurement files.

```text
$ mkdir -p <run_dir>/analysis/scale/V1
```

Now I'll generate the scale measurement input files. Each file is `<a>` repeated N times (3 bytes per nesting level), encoded as UTF-8:

```text
$ cd <run_dir>/analysis/scale/V1 && python3 -c " …
Read <run_dir>/analysis/scale/V1/series.json
```

Good. Let me verify the file contents are correct:

```text
$ head -c 30 n64.bin && echo "" && wc -c *.bin
```

All files are correct. Now let me complete the full analysis and emit the target register.

---

#### PHASE A — Vulnerability Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: JSONML.parse() Unbounded Recursive Descent (StackOverflowError)

**Fuzzable entrypoint and user-controlled input:**
- The fuzz test `XmlFuzzTest.fuzzJSONMLToJSONArray(InputStream)` reads the InputStream as a UTF-8 string and passes it to `JSONML.toJSONArray(String)`. The string content is entirely user-controlled.
- `JSONML.toJSONArray(String)` at line 227 creates an `XMLTokener` and calls the private `JSONML.parse(XMLTokener, boolean, JSONArray, boolean)` method.

**Mechanism:**
The `JSONML.parse()` method (line 26) is a recursive descent parser. When it encounters an opening XML tag followed by `>` (indicating content, not a self-closing tag), it makes a recursive call at line 184:
```java
closeTag = (String)parse(x, arrayForm, newja, keepStrings);
```
This recursive call processes the content between `<tag>` and `</tag>`. Each level of XML nesting (e.g., `<a><a><a>...`) adds one recursive stack frame. **Crucially, there is NO nesting depth limit** — unlike `XML.parse()` (line 239) which has an explicit check:
```java
if (currentNestingDepth == config.getMaxNestingDepth()) {
    throw x.syntaxError("Maximum nesting depth of " + ... + " reached");
}
```
`JSONML.parse()` does not accept a depth parameter and has no such guard. This is exactly the vulnerability described by GHSA-3vqj-43w4-2q58.

**Exhausted resource:** Stack depth — one `JSONML.parse()` stack frame per nesting level.

**Stack frame size estimation:**
The `parse()` method has these local variables: `attribute` (String ref, 8B), `c` (char, padded to 8B), `closeTag` (String ref, 8B), `i` (int, 4B), `newja` (JSONArray ref, 8B), `newjo` (JSONObject ref, 8B), `token` (Object ref, 8B), `tagName` (String ref, 8B). Parameters: `x` (8B), `arrayForm` (boolean, 4B), `ja` (8B), `keepStrings` (boolean, 4B). Frame overhead (return address, saved registers, alignment): ~40-80 bytes. **Total per frame: ~200-280 bytes.**

**Scale estimation:**
With `-Xss1m` (1,048,576 bytes), the base stack usage (JVM bootstrap, JQF framework, `fuzzJSONMLToJSONArray`, `readUtf8`, `toJSONArray`) consumes roughly 50-100 KB. The remaining ~900 KB is available for recursive `parse()` frames. At ~250 bytes/frame: **900,000 / 250 ≈ 3,600 nesting levels** to trigger StackOverflowError. Conservative estimate: **3,000-5,000 levels**.

**Input encoding:** Each nesting level requires `<a>` (3 bytes). For ~4,000 levels: **4,000 × 3 = 12,000 bytes**. Well within the 65,536-byte input size limit.

**Failure mode:** `stack_overflow` (StackOverflowError — an undeclared throwable that the fuzz harness does not catch).

##### 1.2 Official Classification

**V1:** CWE-674 (Uncontrolled Recursion) — The `JSONML.parse()` method recurses without a depth bound, allowing an attacker to cause StackOverflowError via deeply nested XML input. This is the vulnerability described in GHSA-3vqj-43w4-2q58.

##### 1.3 Dependency / Package-Level Risks

I examined the following dependency categories along the attack path:

1. **Regex engines (java.util.regex):** Not used in the JSONML/XML parsing path. No PkgRisk.

2. **BigInteger/BigDecimal (java.math):** Used in `XML.stringToValue()` → `XML.stringToNumber()` (called when `keepStrings=false` for numeric text content and attribute values). However, JDK 17's BigInteger(String) uses efficient Schoenhage divide-and-conquer parsing. For the maximum possible numeric string within the 65,536-byte input limit, parsing takes <100ms. **Not a viable timeout vector under these limits.**

3. **HashMap (java.util.HashMap):** Used internally by JSONObject. JDK 17 HashMap uses treeification (red-black trees) for buckets with >8 entries, mitigating hash collision DoS. Keys come from XML attribute names which are constrained by input size. **Not a viable DoS vector.**

4. **StringBuilder:** Used in XMLTokener for tokenization. Growth is proportional to input size with no amplification. **Not a PkgRisk.**

5. **No recursive entity expansion:** The XMLTokener resolves entities directly (e.g., `&amp;` → `&`). There is no DTD processing or recursive entity expansion, so billion-laughs style attacks are not possible. **Not a PkgRisk.**

**Conclusion:** No PkgRisk targets identified that could cause DoS failure within the fixed evaluation limits.

##### R18 — Zest Baseline Comparison

**For V1 (JSONML recursive descent StackOverflowError):**

- **Closest Zest equivalent:** Zest (coverage-guided greybox fuzzing) on the same `fuzzJSONMLToJSONArray` method.
- **Why Zest underperforms:** Zest optimizes for code coverage. Once it covers the recursive `parse()` call path (which happens at nesting depth 1-2), it has no signal to drive inputs deeper. Zest does not measure stack depth or recursion count. It will explore breadth (many sibling elements, different tag names, attributes) rather than depth, because deeper nesting does not reveal new code branches. The StackOverflowError requires ~3,500+ nesting levels — Zest has no signal that correlates with this quantity.
- **Custom Guidance advantage — mechanism-aligned signal:** A custom Guidance measures actual recursion depth (via bytecode instrumentation of `JSONML.parse()` entry/exit) and retains inputs that achieve deeper recursion. This is a **mechanism-aligned signal** (recursion depth directly causes the failure) vs. Zest's **proxy signal** (code coverage, which saturates early and doesn't track depth).
- **Measurable metric:** Time-to-first-StackOverflowError. The custom Guidance should find it orders of magnitude faster because it actively drives toward deeper nesting, while Zest has no gradient toward depth after initial coverage saturation.

---

#### PHASE B — Target Register

Based on the analysis, only one DoS target was identified. The JSONML recursive descent vulnerability is the sole actionable target. No PkgRisk targets met the DoS failure criteria within the fixed evaluation limits.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "JSONML.parse() unbounded recursive descent on nested XML",
      "entrypoint": "XmlFuzzTest.fuzzJSONMLToJSONArray(InputStream) → JSONML.toJSONArray(String) → JSONML.parse(XMLTokener, boolean, JSONArray, boolean)",
      "source_path": "src/main/java/org/json/JSONML.java",
      "sink": "JSONML#parse",
      "mechanism": "Each nested XML element (e.g. <a>) triggers a recursive call to JSONML.parse() at line 184 without any depth limit, unlike XML.parse() which enforces maxNestingDepth (default 512). Unbounded nesting causes unbounded recursion.",
      "resource": "stack depth: one JSONML.parse() frame (~250 bytes) per XML nesting level",
      "failure_mode": "stack_overflow",
      "scale": "About 3600 nesting levels overflow the 1 MB stack (900 KB available after base usage, at ~250 bytes/frame). Each level is encoded as '<a>' (3 bytes), so about 10800 bytes of input.",
      "input_bytes": 10800,
      "cwe": "CWE-674"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

#### Scale Revision Analysis

##### V1 — Measured Stack Growth

**Observations from the probe data:**

| Nesting levels | Outcome | Notes |
|---|---|---|
| 64–512 | completed | Stack fits within 256 KB cap |
| 1024 | exceeds 256 KB stack cap | Stack overflow at the probe's cap |
| 2048 | exceeds 256 KB stack cap | Same |

The stack consumption grows **linearly** with nesting depth, as expected for simple recursion. The transition from "fits" to "doesn't fit" in the 256 KB probe stack occurs between 512 and 1024 levels.

**Estimating frame size from the transition:**

Let B = base stack (JVM bootstrap + JQF framework + fuzz test method) and F = bytes per recursive `JSONML.parse()` frame.

- At 512 levels: `B + 512·F ≤ 262,144` (fits)
- At 1024 levels: `B + 1024·F > 262,144` (overflows)

Taking the midpoint (~768 levels) as the approximate breakpoint, and estimating B ≈ 50 KB (JVM + framework overhead):

`50,000 + 768·F ≈ 262,144` → `F ≈ 276 bytes/frame`

This is consistent with the method's local variables (8 references × 8 bytes + 2 primitives + 4 parameters + frame overhead ≈ 250–300 bytes).

**Extrapolation to the evaluation's -Xss1m (1,048,576 bytes):**

- Available for recursion: `1,048,576 − 50,000 ≈ 998,576 bytes`
- Max nesting levels before StackOverflowError: `998,576 / 276 ≈ 3,618 levels`
- Conservative floor (using 512 as the known-safe point plus the extra 786 KB): `512 + 786,432/276 ≈ 3,361 levels`
- Estimate: **~3,500 nesting levels** to trigger StackOverflowError with 1 MB stack.

**Input encoding:** `<a>` = 3 bytes per level. At ~3,500 levels: **3,500 × 3 = 10,500 bytes**. Well within the 65,536-byte input size limit. No denser encoding exists for this mechanism — `<a>` (3 bytes: open angle bracket, single-character tag name, close angle bracket) is the minimum-size XML open tag that triggers the recursive `parse()` call.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: 512 nesting levels fit in 256 KB stack; 1024 levels exceed it. Estimated ~276 bytes per recursive JSONML.parse() frame. Extrapolating to 1 MB stack (-Xss1m): approximately 3500 nesting levels trigger StackOverflowError. Each level is '<a>' (3 bytes), so about 10500 bytes of input.",
    "input_bytes": 10500
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by examining the workspace structure, the existing pom.xml, and verifying the vulnerable jar exists.

```text
Glob <run_dir> **/*
$ ls -la <run_dir>/lib/
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/fuzzing/harness/XmlFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Let me verify the pom.xml compiles correctly with the existing frozen files:

```text
$ mvn compile 2>&1 | tail -20
$ mvn test-compile 2>&1 | tail -20
$ mvn package -DskipTests 2>&1 | tail -30
$ ls <run_dir>/target/test-classes/fuzzing/harness/ 2>/dev/null && echo "---" && jar tf <run_dir>/lib/json-20220924-2391d24.jar | head -30
```

Let me verify the JQF Guidance API to plan correctly:

```text
$ jar tf target/deps/jqf-fuzz-2.1.jar | grep -E "(Guidance|GuidedFuzzing)" | head -20
$ javap -classpath target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1
$ javap -classpath target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ javap -classpath target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1
$ javap -classpath target/deps/jqf-instrument-2.1.jar edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent 2>&1
```

Now let me verify the exact method signature of `JSONML.parse()` in the jar:

```text
$ javap -p -classpath lib/json-20220924-2391d24.jar org.json.JSONML 2>&1
```

Good. Now I have all the information needed. Let me verify one more JQF class:

```text
$ javap -classpath target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException 2>&1
```

Now I have everything needed. The pom.xml is correct as-is — no changes needed. Let me now create the directory structure and produce the full strategy document.

```text
$ mkdir -p src/test/java/fuzzing/guidance src/test/java/fuzzing/agent src/test/java/fuzzing/runner src/test/java/fuzzing/replay && ls -R src/
```

Good. Directory tree is set up. Now let me deliver the complete strategy document.

---

#### Step 2 — Maven Layout & Scope

**pom.xml status:** The existing pom.xml is correct and requires NO changes:
- Vulnerable jar: `lib/json-20220924-2391d24.jar` is referenced via `<scope>system</scope>` + `<systemPath>` — confirmed present and contains `org.json.JSONML`
- JQF 2.1 (`jqf-fuzz`, `jqf-instrument`): test scope ✓
- JUnit 4.13.2: test scope ✓
- ASM 9.6 (`asm`, `asm-commons`, `asm-tree`, `asm-analysis`): test scope — needed for custom Java agent bytecode transformer ✓
- No forbidden `org.json:json` Maven Central dependency ✓

**Layout:**
```
src/main/java/          — (empty; no production code needed; all org.json classes come from lib/ jar)
src/test/java/          — all fuzzing infrastructure
  fuzzing/harness/      — XmlFuzzTest.java (FROZEN, READ-ONLY)
  fuzzing/guidance/     — V1Guidance.java
  fuzzing/agent/        — V1MeasureAgent.java, V1DepthCounters.java, V1DepthTransformer.java
  fuzzing/runner/       — FuzzRunner.java
  fuzzing/replay/       — ReplayRunner.java
  dosguide/validate/    — SignalSource.java (FROZEN, READ-ONLY)
lib/                    — json-20220924-2391d24.jar (vulnerable artifact)
```

#### Step 3 — Compilation Closure & Stub Audit

##### 3.1 Missing Symbol Audit

All symbols used by the frozen harness (`XmlFuzzTest.java`) resolve:

| Symbol | Package | Source |
|--------|---------|--------|
| `JSONML` | `org.json` | `lib/json-20220924-2391d24.jar` |
| `XML` | `org.json` | `lib/json-20220924-2391d24.jar` |
| `XMLParserConfiguration` | `org.json` | `lib/json-20220924-2391d24.jar` |
| `JSONException` | `org.json` | `lib/json-20220924-2391d24.jar` |
| `@Fuzz` | `edu.berkeley.cs.jqf.fuzz` | `jqf-fuzz-2.1.jar` (test scope) |
| `JQF` | `edu.berkeley.cs.jqf.fuzz` | `jqf-fuzz-2.1.jar` (test scope) |
| `@RunWith` | `org.junit.runner` | `junit-4.13.2.jar` (test scope) |

For the code I will write in Block 3:

| Symbol | Package | Source |
|--------|---------|--------|
| `Guidance` | `edu.berkeley.cs.jqf.fuzz.guidance` | `jqf-fuzz-2.1.jar` |
| `Result` | `edu.berkeley.cs.jqf.fuzz.guidance` | `jqf-fuzz-2.1.jar` |
| `GuidanceException` | `edu.berkeley.cs.jqf.fuzz.guidance` | `jqf-fuzz-2.1.jar` |
| `GuidedFuzzing` | `edu.berkeley.cs.jqf.fuzz.junit` | `jqf-fuzz-2.1.jar` |
| `TraceEvent` | `edu.berkeley.cs.jqf.instrument.tracing.events` | `jqf-instrument-2.1.jar` |
| `SignalSource` | `dosguide.validate` | Frozen in workspace |
| ASM (`ClassVisitor`, `MethodVisitor`, `ClassReader`, `ClassWriter`, `Opcodes`, `AdviceAdapter`) | `org.objectweb.asm` / `org.objectweb.asm.commons` | `asm-9.6.jar`, `asm-commons-9.6.jar` |
| `Instrumentation`, `ClassFileTransformer` | `java.lang.instrument` | JDK |

**Classification:** All symbols are either (A) external libraries already in pom.xml or (B) JDK standard. **No internal project stubs are needed.**

##### 3.2 Stub Generation

**No stubs required.** The vulnerable jar contains all `org.json` classes. The test infrastructure uses only JQF, JUnit, ASM, and JDK classes — all available via Maven or JDK.

##### 3.3 Stub Report

| Item | Status |
|------|--------|
| Missing internal project types | NONE |
| Stubs generated | NONE |
| Justification | All org.json classes are in the vulnerable jar; all other dependencies are resolved via Maven or JDK |

---

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|-------------------|------------------------------|------------------------|
| V1 | VDF + CGF (Vulnerability-Directed + Cost-Gradient) | Zest's coverage signal saturates at recursion depth 1-2: all branches in `JSONML.parse()` are visited by a two-level nested XML `<a><b></b></a>`. After that, Zest has zero gradient toward deeper nesting — no new branches are discovered at depth 3, 4, ..., 3500. Zest's proxy signal (coverage) is orthogonal to the mechanism (stack depth). | V1Guidance hill-climbs on the **actual recursion depth** of `JSONML.parse()`, measured by bytecode instrumentation (entry/exit hooks). This is mechanism-aligned: recursion depth is the exact quantity that causes StackOverflowError. Each deeper-nesting input is retained and mutated preferentially. Structure-aware mutation (XML-token dictionary + chunk repetition) efficiently builds deeply nested XML, while Zest's random byte-level mutations rarely produce valid nesting structure. |

**Method-specific optimization [R19]:** The V1Guidance includes a dictionary of tokens extracted specifically from the `JSONML.parse()` → `XMLTokener.nextToken()` / `nextContent()` code path: `<`, `>`, `/`, `=`, `!`, `?`, `"`, `'`, `</`, `/>`, `<!--`, `-->`, `<![CDATA[`, `]]>`, `<?`, `?>`. These are the exact comparison characters/strings that the XML tokenizer uses on this method's attack path. Additionally, the repetition operator specifically targets `<X>` patterns (3-byte chunks) because the attack mechanism requires repeated opening tags.

---

#### Step 6 — Measurement Plan

##### V1: JSONML.parse() Recursion Depth

**Primary Vulnerability Mechanism:** Parser Depth / Recursion (category 2 from [R36])

**Signal: `maxDepth`**

| Aspect | Detail |
|--------|--------|
| **What is measured** | Maximum recursion depth of `JSONML.parse()` — the count of concurrently active recursive frames |
| **Aggregation** | max (peak depth within a single execution) |
| **Where the cost is incurred** | `org.json.JSONML#parse(XMLTokener, boolean, JSONArray, boolean)` — the recursive call at line 184 |
| **Why this is mechanism-aligned** | Each recursive `parse()` call pushes one ~276-byte stack frame. Stack overflow occurs at ~3500 frames. The signal measures the exact resource being consumed (stack frames). |
| **Technique** | Tier 1: bytecode instrumentation via custom Java agent |
| **Instrumentation target** | Class: `org/json/JSONML`, Method: `parse`, Descriptor: `(Lorg/json/XMLTokener;ZLorg/json/JSONArray;Z)Ljava/lang/Object;` |
| **Agent mechanism** | ASM-based `ClassFileTransformer` instruments method entry (increment depth, update max) and method exit including exceptional exit (decrement depth) using `AdviceAdapter.onMethodEnter()`/`onMethodExit()` |
| **Storage** | `ThreadLocal<long[]>` in `fuzzing.agent.V1DepthCounters` where `[0]` = current depth, `[1]` = max depth seen this execution |
| **Reset** | `V1DepthCounters.reset()` called by `V1Guidance.getInput()` before each execution begins |
| **Read** | `V1DepthCounters.maxDepth()` called by `V1Guidance.handleResult()` after each execution completes |
| **JVM flags** | `-javaagent:<path-to-agent.jar>` — no `--add-opens` needed since `org.json.JSONML` is an application class, not a JDK class |

**[R35] Instrumentation Feasibility Check:**
- **Exact classes/methods:** `org.json.JSONML#parse(Lorg/json/XMLTokener;ZLorg/json/JSONArray;Z)Ljava/lang/Object;`
- **JVM flags:** `-javaagent:target/v1-agent.jar` — no `--add-opens` required (application code, not JDK modules)
- **Signal export:** `V1DepthCounters` exposes `ThreadLocal<long[]>` static field; the Guidance reads `V1DepthCounters.maxDepth()` in `handleResult()`
- **Minimal agent plan:** `V1MeasureAgent.premain()` registers a `ClassFileTransformer` that matches class `org/json/JSONML`, method `parse`. Uses ASM `AdviceAdapter` to inject `onMethodEnter` (increment `[0]`, update `[1]`) and `onMethodExit` (decrement `[0]`). The counters class `V1DepthCounters` is packaged in the agent jar alongside the transformer.

---

#### Step 7 — Custom Guidance Design (V1Guidance)

**Class:** `fuzzing.guidance.V1Guidance implements Guidance, SignalSource`

**Corpus directory:** `out/V1/corpus`

**Core design:**

1. **`getInput()`**: Resets `V1DepthCounters`, then either:
   - Returns a mutated version of a corpus input (selected by max-depth priority), or
   - Returns a fresh random input (exploration phase)
   
2. **`handleResult(Result, Throwable)`**: Reads `V1DepthCounters.maxDepth()`. The Guidance **never decides failures** ([R6]); it only uses the depth signal for retention:
   - If `maxDepth > bestDepthSoFar`: retain input in corpus, update priority
   - If `maxDepth == bestDepthSoFar` but `inputLength > bestLength`: retain (growth [R46])
   - Saves corpus entries to disk with metadata (input bytes + depth achieved)
   
3. **`hasInput()`**: Returns true indefinitely (infinite by default), or checks time bound from system property `jqf.ei.maxDurationMillis`

4. **`generateCallBack(Thread)`**: Returns a no-op consumer (the agent handles measurement; we do NOT use JQF's built-in tracing for measurement [R43])

5. **`lastSignals()`** (from `SignalSource`): Returns `{"maxDepth": <value>}` for the most recently completed execution

**Mutation operators [R45]:**

| Operator | Description | How it reaches `input_bytes` |
|----------|-------------|------------------------------|
| Byte flip | Flip 1-8 random bits | Explores minor variants |
| Byte insert | Insert 1-4 random bytes at random position | Minor length growth |
| Byte delete | Delete 1-4 bytes at random position | Shrinks |
| Byte overwrite | Overwrite 1-4 bytes with random values | Explores variants |
| **Chunk repetition** | Select a random chunk (1-128 bytes), repeat it k times (k chosen to grow toward max input size) | Doubles input each step: 10B → 20B → 40B → ... → 10240B → 20480B. Reaches `input_bytes` (10,500) in ~10 doublings from a 10-byte seed |
| **Dictionary insert** | Insert a random token from the XML dictionary at a random position | Builds XML structure: `<`, `>`, tag names, `</`, `/>` |
| **Dictionary overwrite** | Overwrite bytes at a random position with a dictionary token | Converts random bytes into XML tokens |

**Dictionary tokens (from attack path source code):**
`<`, `>`, `/`, `=`, `!`, `?`, `"`, `'`, `</`, `/>`, `<a`, `a>`, `<!--`, `-->`, `<![CDATA[`, `]]>`, `<?`, `?>`

These are individual syntactic units from `XMLTokener.nextToken()`, `nextContent()`, `nextMeta()`, and `JSONML.parse()`. They are NOT assembled inputs [R23].

**Retention [R46] — progress while signal is flat:**
- When `maxDepth` is 0 (input doesn't reach the parser, e.g., garbage bytes), keep inputs that are longer (growing toward 10,500 bytes) as secondary criterion
- When `maxDepth` > 0 but not improving, keep inputs that are at least as deep but longer (wider corpus diversity)
- The repetition operator ensures input size growth is rapid (doubling per step), so the guidance can reach `input_bytes` = 10,500 within the first minute even from tiny seeds

**Growth guarantee [R46]:** Starting from empty/random seeds of ~10-64 bytes, the chunk-repetition operator doubles input size per mutation. At 1000+ mutations/second, reaching 10,500 bytes takes ~10-14 doublings = well under 1 second. The dictionary tokens make some of those bytes valid XML open tags, and the depth signal retains those that parse deeper.

**Logging [R5]:** Structured log line every 1 second: `[V1] executions=N, bestDepth=D, corpusSize=C, lastLength=L, time=T`

**Stop/continue:** Infinite by default. Time-bounded via `System.getProperty("jqf.ei.maxDurationMillis")`.

---

#### Step 8 — Fuzz Test Plan

The FROZEN harness `XmlFuzzTest.fuzzJSONMLToJSONArray(InputStream)` is the fuzz method for V1:
- Consumes `InputStream` directly ✓ [R31]
- Decodes to UTF-8 `String` inside the harness ✓
- Passes to `JSONML.toJSONArray(String)` which triggers the recursive `parse()` ✓
- Declares `JSONException` (so it's a normal result) ✓
- Does NOT use junit-quickcheck generators ✓

**Covered target:** V1 (JSONML.parse() unbounded recursion)

The Guidance `V1Guidance` targets this specific `@Fuzz` method via `GuidedFuzzing.run("fuzzing.harness.XmlFuzzTest", "fuzzJSONMLToJSONArray", cl, guidance, System.out)`.

---

#### Step 9 — Metadata Replay / Feeder

**Class:** `fuzzing.replay.ReplayRunner`

Design:
1. Reads a saved corpus entry from a specified path (e.g., `out/V1/corpus/id_000042.bin`)
2. Loads the associated metadata JSON file (e.g., `out/V1/corpus/id_000042.meta.json`) containing: depth achieved, input size, timestamp, execution result
3. Feeds the input to `JSONML.toJSONArray(new String(bytes, UTF_8))` directly (deterministic UTF-8 decode)
4. Prints reproduction info: input hex dump (truncated), UTF-8 string (truncated), metadata fields, and the result (exception type or success)
5. CLI: `java -cp ... fuzzing.replay.ReplayRunner <input-file> [meta-file]`

---

#### Step 10 — Maven Configuration

**pom.xml:** No changes needed (verified: builds and compiles correctly).

**Directory layout:**
```
pom.xml
lib/json-20220924-2391d24.jar
src/test/java/
  fuzzing/harness/XmlFuzzTest.java          (FROZEN)
  fuzzing/guidance/V1Guidance.java
  fuzzing/agent/V1MeasureAgent.java
  fuzzing/agent/V1DepthCounters.java
  fuzzing/agent/V1DepthTransformer.java
  fuzzing/runner/FuzzRunner.java
  fuzzing/replay/ReplayRunner.java
  dosguide/validate/SignalSource.java        (FROZEN)
```

**Commands:**

Build:
```bash
mvn package -DskipTests
```

Agent jar (assembled from test classes + MANIFEST with Premain-Class):
```bash
jar cfm target/v1-agent.jar agent-manifest.txt \
  -C target/test-classes fuzzing/agent/V1MeasureAgent.class \
  -C target/test-classes fuzzing/agent/V1DepthCounters.class \
  -C target/test-classes fuzzing/agent/V1DepthTransformer.class
```

Fuzzing (V1, infinite):
```bash
java -Xmx1g -Xss1m -javaagent:target/v1-agent.jar \
  -cp target/test-classes:lib/json-20220924-2391d24.jar:target/deps/* \
  fuzzing.runner.FuzzRunner V1
```

Time-bounded (e.g., 5 minutes):
```bash
java -Xmx1g -Xss1m -javaagent:target/v1-agent.jar \
  -Djqf.ei.maxDurationMillis=300000 \
  -cp target/test-classes:lib/json-20220924-2391d24.jar:target/deps/* \
  fuzzing.runner.FuzzRunner V1
```

Replay:
```bash
java -Xmx1g -Xss1m \
  -cp target/test-classes:lib/json-20220924-2391d24.jar:target/deps/* \
  fuzzing.replay.ReplayRunner out/V1/corpus/id_000042.bin
```

---

#### R18 — Zest Baseline Comparison

| Dimension | Zest | V1Guidance |
|-----------|------|------------|
| **Signal type** | Code coverage (proxy) | Recursion depth (mechanism-aligned) |
| **Why it fails/wins** | Coverage saturates at depth 2 — all `JSONML.parse()` branches covered. No gradient toward depth 3500. | Recursion depth is the exact resource that causes StackOverflowError. Each deeper input is retained. |
| **Mutation** | Random byte-level only | Dictionary + chunk repetition + byte-level |
| **Expected metric** | Time-to-first-StackOverflow: likely never or >10min | Time-to-first-StackOverflow: expected <60 seconds |
| **Root cause** | Proxy signal (coverage) vs mechanism signal (depth) | Direct mechanism measurement |

---

#### IMPORT AUDIT

```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent
SignalSource → dosguide.validate.SignalSource
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
ClassVisitor → org.objectweb.asm.ClassVisitor
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter
Instrumentation → java.lang.instrument.Instrumentation
ClassFileTransformer → java.lang.instrument.ClassFileTransformer
```

---

#### Mandatory Self-Checklist

| Check | Status | Justification |
|-------|--------|---------------|
| JDK 17+ only | YES | No preview/incubator APIs; ASM 9.6 supports JDK 17+ |
| No hallucinated APIs | YES | All APIs verified via `javap` against actual jars |
| Guidance implements Guidance directly | YES | `V1Guidance implements Guidance, SignalSource` |
| No existing guidance extended | YES | Does not extend Zest, PerfFuzz, or any other guidance |
| V* vulnerabilities identified | YES | V1: JSONML.parse() unbounded recursion |
| V* IDs sequential [R42] | YES | V1 is the only target, assigned in discovery order |
| Official vulnerability names applied | YES | CWE-674 (Uncontrolled Recursion) |
| PkgRisk-* identified | YES | None identified (justified: no dependency-level DoS vectors found within evaluation limits) |
| Every PkgRisk executed or justified | YES | No PkgRisks to execute; justified in Block 1 analysis |
| Guidance targets V* and PkgRisk-* | YES | V1Guidance targets V1 |
| One fuzz method per V* | YES | `fuzzJSONMLToJSONArray` for V1 |
| CLI method selection supported | YES | `FuzzRunner V1` selects the method |
| byte[]/InputStream input model | YES | Harness uses InputStream; Guidance provides byte[] stream |
| No junit-quickcheck Generators | YES | All mutation in Guidance |
| All mutation in Guidance | YES | Dictionary, repetition, byte-level ops in V1Guidance |
| Repetition, dictionary, encoder [R45] | YES | Chunk repetition + XML token dictionary; no encoder needed (plaintext format) |
| Retention while signal flat [R46] | YES | Secondary: retain longer inputs growing toward input_bytes |
| Signals at sink, not before [R47] | YES | Measured at `JSONML#parse` entry/exit (the sink) |
| Logging every 1 second | YES | Structured log line with execution count, best depth, corpus size |
| Guidance decides no failures [R6] | YES | Only uses depth for retention/priority; never writes failure files |
| Corrupted inputs saved with metadata | YES | Corpus entries saved with .meta.json |
| Replay/feeder implemented | YES | `ReplayRunner` reads input + metadata, replays deterministically |
| Infinite + time-bounded | YES | Infinite default; `jqf.ei.maxDurationMillis` for time bound |
| src/main vs src/test separation | YES | src/main empty; all infra in src/test |
| Maven scopes consistent | YES | org.json=system; JQF/JUnit/ASM=test |
| No wildcard imports for JQF/tracing | YES | All explicit imports |
| TraceEvent import verified | YES | `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` confirmed in jqf-instrument-2.1.jar |

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "maxDepth",
          "quantity": "maximum recursion depth of JSONML.parse() — count of concurrently active recursive frames",
          "aggregation": "max",
          "locations": ["JSONML#parse"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in fuzzing.agent.V1DepthCounters where [0]=current depth, [1]=max depth this execution",
          "reset": "V1DepthCounters.reset() called in V1Guidance.getInput() before each execution",
          "read": "V1DepthCounters.maxDepth() called in V1Guidance.handleResult() after each execution"
        }
      ],
      "retention": "Primary: retain inputs that achieve strictly higher maxDepth than any corpus entry. Secondary (flat signal per R46): retain inputs that are longer (growing toward input_bytes=10500) or achieve equal maxDepth with different structure. Corpus entries are prioritized by maxDepth for mutation selection (highest depth mutated most often). When maxDepth=0 (no parsing reached), retain inputs that grow in length to cross the parsing threshold.",
      "retention_signals": ["maxDepth"],
      "mutation": [
        "Byte flip: flip 1-8 random bits at random positions",
        "Byte insert: insert 1-4 random bytes at random position",
        "Byte delete: delete 1-4 bytes from random position",
        "Byte overwrite: overwrite 1-4 bytes with random values at random position",
        "Chunk repetition (R45a): select a random chunk of the input (1-128 bytes) and repeat it k times in place, where k is chosen to grow toward MAX_INPUT_SIZE (from jqf.ei.MAX_INPUT_SIZE, default 65536). Includes whole-input doubling. From a 10-byte seed, 10 doublings reach 10240 bytes in <1 second at 1000+ execs/sec.",
        "Dictionary insert (R45b): insert a random token from the XML attack-path dictionary at a random position. Tokens from JSONML.parse()/XMLTokener source: '<', '>', '/', '=', '!', '?', '\"', \"'\", '</', '/>', '<a', 'a>', '<!--', '-->', '<![CDATA[', ']]>', '<?', '?>'",
        "Dictionary overwrite (R45b): overwrite bytes at a random position with a random dictionary token"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

Let me start by reading the existing workspace files and understanding the current state:

```text
Glob <run_dir> **/*
Read <run_dir>/analysis/guidance_plan.json
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/src/test/java/fuzzing/harness/XmlFuzzTest.java
Read <run_dir>/pom.xml
```

Now I have a complete picture. Let me implement all files. I'll start with the Java agent (Part A), then the Guidance (Part B), then runner/replay (Part C).

```text
Write <run_dir>/src/test/java/fuzzing/agent/V1DepthCounters.java
Write <run_dir>/src/test/java/fuzzing/agent/V1DepthTransformer.java
Write <run_dir>/src/test/java/fuzzing/agent/V1MeasureAgent.java
```

Now Part B — the Guidance:

```text
Write <run_dir>/src/test/java/fuzzing/guidance/V1Guidance.java
```

Now FuzzRunner.java:

```text
Write <run_dir>/src/test/java/fuzzing/runner/FuzzRunner.java
```

Now ReplayRunner.java:

```text
Write <run_dir>/src/test/java/fuzzing/runner/ReplayRunner.java
```

Now run.sh:

```text
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh
```

Now analysis/launch.json:

```text
Write <run_dir>/analysis/launch.json
```

Now write a couple of validation input samples:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
Write <run_dir>/analysis/validation_inputs/simple_nested.xml
Write <run_dir>/analysis/validation_inputs/flat.xml
```

Now let me generate a deeper nesting sample for validation:

```text
$ python3 -c " …
```

Now compile everything to verify it builds:

```text
$ mvn package -DskipTests 2>&1 | tail -30
```

Build succeeds. Now assemble the agent jar and verify:

```text
$ \ …
```

Agent jar is correct. Now verify that the vulnerable artifact is the one on the classpath by checking where `org.json.JSONML` comes from:

```text
Write <run_dir>/src/test/java/fuzzing/runner/VerifyArtifact.java
$ mvn package -DskipTests -q 2>&1 | tail -5
$ \ …
```

Execution is blocked by policy. Let me verify the artifact is correct by checking that there's no competing json jar in deps/:

```text
$ ls -la <run_dir>/lib/*.jar && echo "---" && ls <run_dir>/target/deps/ | grep -i json
```

The only json jar in the classpath is `json-20220924-2391d24.jar` from `lib/` (and its copy in `target/deps/`). Both are the same vulnerable artifact from SOURCE_ROOT (commit 2391d24). There's no Maven Central version competing.

Let me also verify the pom.xml has no normal Maven dependency for org.json:

```text
Grep <run_dir>/pom.xml org\.json
Read <run_dir>/pom.xml
```

Confirmed: `<scope>system</scope>` with `<systemPath>` pointing to our local vulnerable jar. No normal Maven dependency that could pull from Maven Central.

Now let me verify all files are in place with a final listing:

```text
$ find src/test/java -name "*.java" -type f | sort && echo "---" && ls -la run.sh && echo "---" && ls analysis/ && echo "---" && ls analysis/validation_inputs/
Glob <run_dir> src/test/java/**/*.java
Glob <run_dir> analysis/**/*
```

All files present. Let me verify the run.sh is executable:

```text
Glob <run_dir> run.sh
```

Let me do one final compile to make sure everything including VerifyArtifact builds cleanly:

```text
$ mvn package -DskipTests 2>&1 | tail -15
```

**BUILD SUCCESS** — all files compile cleanly.

---

#### Block 3 — Complete Summary

All implementation files have been emitted and compile successfully:

##### Part A — Java Agent (3 files)
| File | Purpose |
|------|---------|
| `src/test/java/fuzzing/agent/V1DepthCounters.java` | ThreadLocal `long[2]` counters — `[0]=current depth`, `[1]=max depth`. Methods: `reset()`, `onEnter()`, `onExit()`, `maxDepth()` |
| `src/test/java/fuzzing/agent/V1DepthTransformer.java` | ASM ClassFileTransformer — injects `onEnter()` at entry and `onExit()` before each `ARETURN` in `JSONML.parse(XMLTokener,boolean,JSONArray,boolean)` |
| `src/test/java/fuzzing/agent/V1MeasureAgent.java` | `premain()` registers V1DepthTransformer |

##### Part B — Guidance (1 file)
| File | Purpose |
|------|---------|
| `src/test/java/fuzzing/guidance/V1Guidance.java` | Implements `Guidance` + `SignalSource`. Hill-climbs on `maxDepth`. 7 mutation operators (byte flip/insert/delete/overwrite, chunk repeat [R45a], dictionary insert/overwrite [R45b]). Retention: new-best depth (primary), longer input at equal depth (secondary), length growth [R46]. Corpus: 70% top-depth / 30% random selection. Logging every 1s. `lastSignals()` → `{"maxDepth": <last exec depth>}` |

##### Part C — Runner/Replay/Shell (3 files)
| File | Purpose |
|------|---------|
| `src/test/java/fuzzing/runner/FuzzRunner.java` | CLI entry point + `createGuidance(String, File, long, PrintStream)` factory |
| `src/test/java/fuzzing/runner/ReplayRunner.java` | Single-file replay harness printing `result=... maxDepth=... inputSize=...` |
| `run.sh` | Build script: compile → assemble agent jar → copy deps → launch with `-Xmx1g -Xss1m -javaagent:target/v1-agent.jar` |

##### Part D — Launch & Validation
| File | Purpose |
|------|---------|
| `analysis/launch.json` | Full build/run/replay commands, classpath, JVM args, signal source contract, artifact verification |
| `analysis/validation_inputs/simple_nested.xml` | 5-level nested XML (expects maxDepth≈5) |
| `analysis/validation_inputs/flat.xml` | Flat XML (expects maxDepth=1) |
| `analysis/validation_inputs/deep_nested_50.xml` | 50-level nested XML (expects maxDepth≈50) |

##### Artifact Verification
- Vulnerable jar: `lib/json-20220924-2391d24.jar` (commit 2391d24)
- Maven scope: `system` with `systemPath` — **not** from Maven Central
- No competing `org.json:json` dependency in `target/deps/` (only the same system jar)
- `VerifyArtifact.java` utility included for runtime verification via `Class.getProtectionDomain().getCodeSource()`

**HARD STOP** — Block 3 complete.

## Validation repair 1

Let me fix `analysis/launch.json` to match the expected format exactly.

```text
Read <run_dir>/analysis/launch.json
```

Now I need to build the classpath string. Let me check what jars are in target/deps/:

```text
$ ls <run_dir>/target/deps/ | sort
```

Now I'll use a `classpath_command` since there are many jars. Let me rewrite launch.json in the exact expected format:

```text
Write <run_dir>/analysis/launch.json
```

Let me verify the classpath_command works:

```text
$ echo -n target/test-classes; for j in target/deps/*.jar lib/*.jar; do [ -f "$j" ] && echo -n ":$j"; done; echo
```

The classpath command works correctly. Now let me also make sure the build compiles cleanly one more time:

```text
$ mvn package -DskipTests -q 2>&1 | tail -5
```

Clean build, no output means success.

**Summary of changes:**

Rewrote `analysis/launch.json` to match the exact expected format:
- `"build"`: list of shell commands (was `"build_commands"`)
- `"classpath_command"`: shell command that prints the classpath (replaces the old nested `"run_command"` structure)
- `"javaagent"`: `{"jar": "target/v1-agent.jar", "args": ""}` (was buried in nested structure)
- `"jvm_args"`: `[]` (evaluation fixes JVM options per R41)
- `"guidance_factory"`: `"fuzzing.runner.FuzzRunner#createGuidance"` (was a nested object with class/method/returns)
- `"targets"`: map from target ID to `{"test_class", "method"}` (was an array of objects with different keys)

No changes to the guidance, agent, runner, or harness code — only the launch.json schema was wrong.

## Validation repair 2

The core problem is clear: the guidance generates random bytes, but JSONML.toJSONArray() requires well-formed XML to recurse. Random bytes get rejected immediately (maxDepth=1), so the signal never varies. I need to generate structurally valid nested XML from the start.

Let me study the harness and the JSONML source to understand exactly what's needed:

```text
Read <run_dir>/src/test/java/fuzzing/harness/XmlFuzzTest.java
Read <source_root>/src/main/java/org/json/JSONML.java
```

Now I understand the issue. Looking at the JSONML.parse() code, recursion happens at line 184 after seeing `<tagName>` — each `<a>` open tag adds one recursion level. With 3 bytes per `<a>`, 6144 bytes = 2048 copies = depth ~2049. My guidance generates random bytes that never look like XML, so depth is always 1 (the initial call hits "Bad XML" immediately).

The fix: bootstrap with valid XML fragments (sequences of open tags with varied tag names) and add mutation operators that insert whole `<X>` open tags. Let me rewrite V1Guidance:

```text
Read <run_dir>/src/test/java/fuzzing/guidance/V1Guidance.java
```

Now I'll rewrite the entire guidance with XML-structure-aware generation:

```text
Write <run_dir>/src/test/java/fuzzing/guidance/V1Guidance.java
```

Now compile to verify:

```text
$ mvn package -DskipTests 2>&1 | tail -15
```

Build succeeds. Let me also update the guidance plan to reflect the new mutation strategy:

**Summary of changes:**

1. **V1Guidance.java — complete rewrite of input generation strategy:**
   - **Bootstrap**: Now generates well-formed XML open tags (`<a>`, `<b>`, ..., `<z>`, then small groups of 2-20 nested tags) instead of random bytes. Each `<X>` is an ordinary XML fragment, not a failure-inducing input.
   - **New mutation: `mutateTagBlockInsert` (25%)**: Inserts 1-to-many complete `<X>` open tags at a random position, enabling rapid structural growth.
   - **Improved chunk repetition (30%)**: Now 70% of the time tries to align chunks to 3-byte tag boundaries (finding `<` characters), so it naturally repeats sequences of `<X>` tags.
   - **New mutation: `mutateTagNames` (3%)**: Randomizes tag names in existing `<X>` patterns for diversity while preserving structure.
   - **Dictionary expanded [R45b]**: Now includes 26 complete XML open tags (`<a>` through `<z>`) alongside structural tokens.
   - **Byte-level mutations reduced**: From ~30% to ~17% total, since they mostly break XML structure.
   - **Operator probabilities**: chunk repeat 30%, tag block insert 25%, dictionary insert 15%, dictionary overwrite 10%, byte-level 17%, tag name randomize 3%.

2. **Root cause**: Random bytes never parse as XML, so JSONML.parse() threw "Bad XML" on the first `x.nextContent()` call — depth was always 1. Now every bootstrap input starts as valid XML open tags that immediately trigger the recursive descent.

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "maxDepth",
          "quantity": "maximum recursion depth of JSONML.parse() — count of concurrently active recursive frames",
          "aggregation": "max",
          "locations": ["JSONML#parse"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in fuzzing.agent.V1DepthCounters where [0]=current depth, [1]=max depth this execution",
          "reset": "V1DepthCounters.reset() called in V1Guidance.getInput() before each execution",
          "read": "V1DepthCounters.maxDepth() called in V1Guidance.handleResult() after each execution"
        }
      ],
      "retention": "Primary: retain inputs that achieve strictly higher maxDepth than any corpus entry. Secondary (flat signal per R46): retain inputs that are longer (growing toward input_bytes=10500) or achieve equal maxDepth with different structure. Corpus entries are prioritized by maxDepth for mutation selection (highest depth mutated 70% of the time). When maxDepth=0, retain inputs that grow in length to cross the parsing threshold. Bootstrap generates well-formed XML open tags (<X>) that immediately reach the recursive code.",
      "retention_signals": ["maxDepth"],
      "mutation": [
        "XML tag block insert (25%): insert 1-to-many complete <X> open tags (3 bytes each, varied single-char tag names a-z) at a random position, with aggressive growth bias (60% of the time inserts enough to approximately double the input)",
        "Tag-aligned chunk repetition (R45a, 30%): select a random chunk, preferring alignment to <X> tag boundaries (70% tries to start at a '<' character), and repeat it k times to grow toward MAX_INPUT_SIZE",
        "Dictionary insert (R45b, 15%): insert a random token from the XML dictionary at a random position. Dictionary includes 26 complete open tags (<a> through <z>) plus structural tokens (<, >, /, =, </, />, <!--, -->, <?, ?>, <![CDATA[, ]]>, etc.)",
        "Dictionary overwrite (R45b, 10%): overwrite bytes at a random position with a random dictionary token",
        "Byte flip (6%): flip 1-8 random bits for diversity",
        "Byte insert (5%): insert 1-4 random bytes at a random position",
        "Byte delete (3%): delete 1-4 bytes from a random position",
        "Byte overwrite (3%): overwrite 1-4 bytes with random values",
        "Tag name randomization (3%): change tag names in existing <X> patterns to random letters, preserving XML structure while varying diversity"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON
