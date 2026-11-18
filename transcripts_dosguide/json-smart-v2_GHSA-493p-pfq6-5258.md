# json-smart-v2_GHSA-493p-pfq6-5258

## Block 1

I'll start by reading the frozen fuzz test harness and the main parser source code to understand the entry points and potential DoS vulnerabilities.

```text
Glob <run_dir> **/FuzzTest.java
Glob <run_dir> **/*.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java
Read <run_dir>/src/test/java/edu/berkeley/cs/jqf/examples/json/JsonSmartFuzzTest.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java
Read <run_dir>/pom.xml
```

Let me continue reading the parser and check for the lib jars and the rest of the parser source:

```text
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java
$ ls -la <run_dir>/lib/ 2>/dev/null || echo "No lib dir"
Glob <source_root>/json-smart/src/main/java/net/minidev/json/parser **/*.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParser.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserString.java
```

Now let me check the JSONParserMemory class and the full extent of the recursion:

```text
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserMemory.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me read the remaining parser classes to understand the complete recursion chain:

```text
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java
Glob <source_root> json-smart/src/main/java/net/minidev/json/writer/**/*.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/writer/DefaultMapper.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/writer/JsonReaderI.java
```

Let me check for any depth-limiting mechanisms and verify the JSONArray class:

```text
Grep <source_root>/json-smart/src/main/java/net/minidev/json/parser depth|maxDepth|maxNest|nestLevel|MAX_DEPTH|recursion|limit|nesting
Grep <source_root>/json-smart/src/main/java/net/minidev/json class JSONArray
```

Confirmed: there is **no depth limiting mechanism** in any parser class. The `JSONArray` extends `ArrayList<Object>`. Now let me create the scale measurement directories and files.

```text
$ mkdir -p <run_dir>/analysis/scale/V1 …
```

Now I'll create the scale measurement input files. Each input is a properly nested array: N `[` chars + N `]` chars. The fuzz test reads bytes as UTF-8 String, so each `[` or `]` is 1 byte.

```text
$ # Generate scale measurement inputs for V1 (fuzzJSONParserParsePermissive, array nesting) …
Write <run_dir>/analysis/scale/V1/series.json
```

Now create the same inputs for V2 (RFC4627 mode — same array nesting structure but different fuzz method):

```text
$ # Generate scale measurement inputs for V2 (fuzzJSONParserParseRFC4627, array nesting) …
Write <run_dir>/analysis/scale/V2/series.json
```

Now let me verify the file contents are correct:

```text
$ # Verify first and last bytes of each file …
```

All input files are correct — N `[` bytes followed by N `]` bytes. Now let me produce the complete analysis and target register.

---

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: Deep JSON Array Nesting → StackOverflowError (via `fuzzJSONParserParsePermissive`)

**Fuzzable entrypoint:** `JsonSmartFuzzTest.fuzzJSONParserParsePermissive(InputStream)` — attacker controls the full input string.

**Mechanism:** The parser uses mutually recursive methods `readArray` and `readMain` (in `JSONParserBase`) to process nested JSON structures. When processing `[`, `readFirst`/`readMain` calls `readArray`, which for each element calls `readMain`, which upon seeing `[` again calls `readArray` recursively. There is **no depth limit check** anywhere in the parser code. Each nesting level adds two stack frames (one `readArray` + one `readMain`).

**Exhausted resource:** Stack depth — each `readArray`+`readMain` frame pair consumes approximately 250–400 bytes of stack space (method parameters, local variables `current`, `needData`, `acceptData`, loop state, JVM bookkeeping).

**Failure mode:** `stack_overflow` (StackOverflowError)

**Scale:** With `-Xss1m` (1,048,576 bytes), after ~50–150 KB of base stack for thread initialization and the call chain to the parser, approximately 900 KB remains for recursion. At ~300 bytes per nesting level pair, approximately 3,000 nesting levels overflow the stack. Using array nesting (`[[[...]]]`), each nesting level costs 1 byte for `[` + 1 byte for `]` = 2 bytes per level. Thus ~3,000 levels = ~6,000 bytes of input, well within the 10,240 byte limit.

**Input bytes:** ~6,000

**Call chain:**
`JsonSmartFuzzTest.fuzzJSONParserParsePermissive(InputStream)` → `JSONParser.parse(String)` → `JSONParserString.parse(String, JsonReaderI)` → `JSONParserBase.parse(JsonReaderI)` → `JSONParserBase.readFirst(JsonReaderI)` → `JSONParserBase.readArray(JsonReaderI)` → `JSONParserBase.readMain(JsonReaderI, boolean[])` → `JSONParserBase.readArray(JsonReaderI)` [recursive cycle]

**Sink:** `JSONParserBase#readArray` (mutually recursive with `readMain`)

---

###### V2: Deep JSON Array Nesting → StackOverflowError (via `fuzzJSONParserParseRFC4627`)

**Fuzzable entrypoint:** `JsonSmartFuzzTest.fuzzJSONParserParseRFC4627(InputStream)` — same input control, different parser mode.

**Mechanism:** Identical to V1. `MODE_RFC4627` sets different flags (`USE_INTEGER_STORAGE | USE_HI_PRECISION_FLOAT | ACCEPT_TAILLING_SPACE`) but none of these affect the array/object nesting recursion. The `readArray` ↔ `readMain` mutual recursion is the same code path with no depth guard.

**Exhausted resource:** Stack depth — same as V1.

**Failure mode:** `stack_overflow`

**Scale:** Same as V1: ~3,000 levels ≈ ~6,000 bytes of input.

**Input bytes:** ~6,000

**Call chain:**
`JsonSmartFuzzTest.fuzzJSONParserParseRFC4627(InputStream)` → `JSONParser.parse(String)` → `JSONParserString.parse(String, JsonReaderI)` → `JSONParserBase.parse(JsonReaderI)` → `JSONParserBase.readFirst(JsonReaderI)` → `JSONParserBase.readArray(JsonReaderI)` → `JSONParserBase.readMain(JsonReaderI, boolean[])` → `JSONParserBase.readArray(JsonReaderI)` [recursive cycle]

**Sink:** `JSONParserBase#readArray` (mutually recursive with `readMain`)

---

##### 1.2 Official Classification

- **V1:** CWE-674 (Uncontrolled Recursion). The parser recursively descends into nested structures with no depth limit, leading to stack exhaustion. Also classifiable under CWE-400 (Uncontrolled Resource Consumption). This matches **GHSA-493p-pfq6-5258**.

- **V2:** CWE-674 (Uncontrolled Recursion). Same classification as V1 — identical vulnerability mechanism through a different parser mode entry point.

---

##### 1.3 Dependency / Package-Level Risks

**PkgRisk-1: java.math.BigDecimal / BigInteger allocation from large numeric strings**

- **Package/class:** `java.math.BigDecimal`, `java.math.BigInteger` (used in `JSONParserBase.extractFloat()` and `JSONParserBase.parseNumber()`)
- **Why input-sensitive:** When a JSON numeric literal is longer than 18 characters and cannot be represented as a double without precision loss, the parser constructs a `new BigDecimal(xs)`. Similarly, integers exceeding 19 digits create `new BigInteger(s, 10)`. These constructors process each digit.
- **Trigger shapes:** A numeric string like `99999...9` (up to ~10 KB of digits), or `1.0000...01` with many fractional digits.
- **Exhausted resource:** CPU time — O(n) construction for n-digit numbers, plus potential O(n²) for BigDecimal/BigInteger arithmetic in later operations.
- **Failure mode:** `timeout` (if parsing the number takes >20s)
- **Scale:** With the input size limit of 10,240 bytes, the longest numeric string is ~10 KB of digits. `new BigDecimal(str)` for a 10KB string completes in sub-millisecond on modern JVMs (JDK 17). This is **NOT feasible** to cause timeout within the input size limit. The BigDecimal constructor is linear in string length and 10,240 digits is far too small for 20s of CPU time.
- **Fuzzing strategy:** Not viable — excluded due to infeasible scale.
- **Execution justification:** EXCLUDED — BigDecimal/BigInteger construction for a 10KB string is sub-millisecond on JDK 17+, orders of magnitude below the 20s timeout threshold. The vulnerability requires multi-megabyte inputs that exceed the 10,240-byte cap.

No other dependency/package-level risks identified:
- No regex usage in the parser code
- No compression/decompression
- No URL/path parsing
- No hash collision risk within 10 KB input (JDK 17+ HashMap treeifies long chains)
- The internal `MSB` string builder doubles capacity but is bounded by input size

---

#### PHASE B — Target Selection

##### Selection Controls Applied
- **Execute V*:** ONLY DoS-related items → V1, V2 (both are stack overflow DoS)
- **Execute PkgRisk-*:** ONLY DoS-related → PkgRisk-1 excluded (infeasible scale)
- **Max 3 targets, ordered by implementation priority**

##### Targets Selected

| Slot | ID | Vulnerability | Fuzz Method | Priority |
|------|----|---------------|-------------|----------|
| 1 | V1 | Deep array nesting → StackOverflow | fuzzJSONParserParsePermissive | Highest — MODE_PERMISSIVE is the default mode, most permissive, densest array encoding |
| 2 | V2 | Deep array nesting → StackOverflow | fuzzJSONParserParseRFC4627 | High — same mechanism through stricter mode |

##### Scale Measurement Data

Written to `analysis/scale/V1/` and `analysis/scale/V2/` with these files:
- `n64.bin` (128 bytes): 64 nested arrays
- `n128.bin` (256 bytes): 128 nested arrays
- `n256.bin` (512 bytes): 256 nested arrays
- `n512.bin` (1024 bytes): 512 nested arrays
- `n1024.bin` (2048 bytes): 1024 nested arrays

Each file is `N` `[` bytes followed by `N` `]` bytes — a valid deeply nested empty JSON array structure. The `series.json` in each directory maps filenames to nesting level values. These measurements will show linear growth in stack usage (~300 bytes per level) and heap allocation (one `JSONArray`/`ArrayList` per level), with the 1024-level input likely reaching or approaching the 256 KB stack measurement cap.

---

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Deep JSON array nesting causes StackOverflowError (MODE_PERMISSIVE)",
      "entrypoint": "JsonSmartFuzzTest.fuzzJSONParserParsePermissive(InputStream) → JSONParser.parse(String) → JSONParserString.parse(String, JsonReaderI) → JSONParserBase.parse(JsonReaderI) → JSONParserBase.readFirst(JsonReaderI) → JSONParserBase.readArray(JsonReaderI) → JSONParserBase.readMain(JsonReaderI, boolean[]) → JSONParserBase.readArray(JsonReaderI)",
      "source_path": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java",
      "sink": "JSONParserBase#readArray",
      "mechanism": "Mutual recursion between readArray and readMain with no depth limit; each nested '[' triggers readArray→readMain→readArray, consuming two stack frames per level",
      "resource": "stack depth: one readArray + one readMain frame per nesting level, approximately 300 bytes per level",
      "failure_mode": "stack_overflow",
      "scale": "approximately 3000 nesting levels overflow the 1 MB stack; 1 byte per '[' in array nesting, so about 6000 bytes (3000 opening + 3000 closing brackets)",
      "input_bytes": 6000,
      "cwe": "CWE-674"
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "Deep JSON array nesting causes StackOverflowError (MODE_RFC4627)",
      "entrypoint": "JsonSmartFuzzTest.fuzzJSONParserParseRFC4627(InputStream) → JSONParser.parse(String) → JSONParserString.parse(String, JsonReaderI) → JSONParserBase.parse(JsonReaderI) → JSONParserBase.readFirst(JsonReaderI) → JSONParserBase.readArray(JsonReaderI) → JSONParserBase.readMain(JsonReaderI, boolean[]) → JSONParserBase.readArray(JsonReaderI)",
      "source_path": "json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java",
      "sink": "JSONParserBase#readArray",
      "mechanism": "Mutual recursion between readArray and readMain with no depth limit; identical code path as V1 since MODE_RFC4627 flags do not guard nesting depth",
      "resource": "stack depth: one readArray + one readMain frame per nesting level, approximately 300 bytes per level",
      "failure_mode": "stack_overflow",
      "scale": "approximately 3000 nesting levels overflow the 1 MB stack; 1 byte per '[' in array nesting, so about 6000 bytes (3000 opening + 3000 closing brackets)",
      "input_bytes": 6000,
      "cwe": "CWE-674"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

#### Scale Measurement Analysis

##### Key Observations

**Both V1 and V2 show identical behavior:**
- 64, 128, 256, 512 nesting levels: completed within 256 KB stack cap (CPU ~10 ms, allocation ~1 MB — flat, not growing)
- 1024 nesting levels: **exceeds 256 KB stack cap**

This confirms:
1. **Stack is the bottleneck resource** — CPU and heap allocation are flat (~10 ms, ~1 MB) regardless of nesting depth. The failure is purely stack exhaustion.
2. **Stack growth is linear** with nesting depth, as expected from the `readArray` ↔ `readMain` mutual recursion.
3. The mechanism is correctly identified.

##### Per-Level Stack Cost Estimation

The stack cap (256 KB) is crossed somewhere between 512 and 1024 levels:
- At 512 levels: `B + 512C < 256 KB` (completed)  
- At 1024 levels: `B + 1024C > 256 KB` (exceeded)

Where B = base stack overhead (~50 KB for thread init + call chain to parser), C = per-level cost:
- From 512 case: `C < (256 - 50) KB / 512 ≈ 402 bytes/level`
- From 1024 case: `C > (256 - 50) KB / 1024 ≈ 201 bytes/level`
- **Midpoint estimate: ~250 bytes per nesting level**

##### Extrapolation to 1 MB Stack (-Xss1m)

With C ≈ 250 bytes/level and B ≈ 50 KB:
- `N_overflow = (1024 KB - 50 KB) / 250 bytes ≈ 3,994 levels`

Conservative range: 3,300–5,000 levels (depending on exact B and C).

**Densest encoding:** Just opening `[` characters — the StackOverflowError occurs during descent through the `[` brackets, before any closing `]` is processed. So ~4,000 bytes of `[` characters suffice. Even with closing brackets: ~8,000 bytes, still within 10,240.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: 512 levels (1024 bytes) completes within the 256 KB stack probe cap; 1024 levels (2048 bytes) exceeds it. Per-level stack cost approximately 250 bytes (two frames: readArray + readMain). Extrapolating linearly to the evaluation 1 MB stack with approximately 50 KB base overhead: about 4000 nesting levels to cause StackOverflowError. Densest encoding is one byte per opening bracket (overflow occurs during descent before closing brackets are reached), so approximately 4000 bytes.",
    "input_bytes": 4000
  },
  "V2": {
    "scale": "Measured: 512 levels (1024 bytes) completes within the 256 KB stack probe cap; 1024 levels (2048 bytes) exceeds it. Per-level stack cost approximately 250 bytes (two frames: readArray + readMain). Extrapolating linearly to the evaluation 1 MB stack with approximately 50 KB base overhead: about 4000 nesting levels to cause StackOverflowError. Densest encoding is one byte per opening bracket (overflow occurs during descent before closing brackets are reached), so approximately 4000 bytes.",
    "input_bytes": 4000
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by reading the workspace structure and existing files, then develop the complete measurement strategy.

```text
$ find <run_dir> -type f | head -30
Read <run_dir>/pom.xml
```

Let me read the key source files needed for instrumentation planning:

```text
Read <run_dir>/src/test/java/edu/berkeley/cs/jqf/examples/json/JsonSmartFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java
```

Now let me verify the ASM version available and check the existing pom.xml can compile:

```text
$ mvn compile 2>&1 | tail -20
$ mvn test-compile 2>&1 | tail -20
$ mvn compile -DskipTests 2>&1 | tail -20
```

Good — the build works. Now let me check the ASM dependency version available (needed for the custom Java agent) and verify that it doesn't conflict with the one already declared:

```text
$ jar tf <run_dir>/lib/json-smart-2.4.8.jar | head -30
$ jar tf <run_dir>/lib/json-smart-2.4.8.jar | grep -i "parser"
```

The pom.xml is already correct with proper systemPath values and the vulnerable jars exist. Let me verify compilation works:

```text
$ mvn package -DskipTests 2>&1 | tail -30
```

Important finding: `asm-commons-9.5.jar` is already available as a transitive dependency of `jqf-instrument`. This means I can use `AdviceAdapter` for clean try-finally instrumentation without modifying the pom.xml.

The pom.xml is correct as-is — no systemPath changes needed. The vulnerable jars are properly located in `lib/`. Now I'll produce the complete measurement strategy.

---

#### Step 2 — Maven Layout & Scope Verification

**Confirmed layout:**
- `lib/json-smart-2.4.8.jar` — vulnerable artifact, system scope ✓
- `lib/accessors-smart-2.4.8.jar` — dependency of json-smart, system scope ✓
- `org.ow2.asm:asm:9.1` — compile scope, used by agent transformer ✓
- `asm-commons:9.5` — transitive from jqf-instrument, available in test scope for AdviceAdapter ✓
- `jqf-fuzz:2.1`, `jqf-instrument:2.1` — test scope ✓
- `junit:4.13.2` — test scope ✓
- `junit-quickcheck-core:1.0`, `junit-quickcheck-generators:1.0` — test scope ✓

**No forbidden coordinates used.** The pom.xml does NOT declare `net.minidev:json-smart` or `net.minidev:accessors-smart` as normal Maven dependencies. They are system-scoped pointing to local vulnerable jars.

**Class Origin Check (to be executed in Block 3):**
Will print `JSONParser.class.getProtectionDomain().getCodeSource().getLocation()` to prove the class is loaded from `lib/json-smart-2.4.8.jar`, NOT from `target/classes`.

#### Step 3 — Missing Symbol Audit & Stub Report

##### 3.1 Missing Symbol Audit

**Fuzz test (FROZEN):**
- `edu.berkeley.cs.jqf.fuzz.Fuzz` → jqf-fuzz (test scope) ✓
- `edu.berkeley.cs.jqf.fuzz.JQF` → jqf-fuzz (test scope) ✓
- `net.minidev.json.parser.JSONParser` → lib/json-smart-2.4.8.jar (system) ✓
- `net.minidev.json.parser.ParseException` → lib/json-smart-2.4.8.jar (system) ✓
- `org.junit.runner.RunWith` → junit (test scope) ✓

**Guidance classes (planned):**
- `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` → jqf-fuzz (test scope) ✓
- `edu.berkeley.cs.jqf.fuzz.guidance.Result` → jqf-fuzz (test scope) ✓
- `edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing` → jqf-fuzz (test scope) ✓
- `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` → jqf-instrument (test scope) ✓
- `dosguide.validate.SignalSource` → already present in workspace ✓

**Agent classes (planned):**
- `org.objectweb.asm.ClassReader`, `ClassWriter`, `ClassVisitor`, `MethodVisitor`, `Opcodes` → asm:9.1 (compile scope) ✓
- `org.objectweb.asm.commons.AdviceAdapter` → asm-commons:9.5 (transitive from jqf-instrument) ✓
- `java.lang.instrument.Instrumentation`, `ClassFileTransformer` → JDK (built-in) ✓

##### 3.2 Stub Generation

**NO STUBS NEEDED.** All symbols resolve to existing jars (vulnerable artifact or Maven dependencies). No missing internal project types.

##### 3.3 Stub Report

| Stub File | Status |
|-----------|--------|
| (none) | All required symbols resolve to declared dependencies. No stubs required. |

#### Step 4 — GuidedFuzzing Usage Plan

```java
ClassLoader cl = Thread.currentThread().getContextClassLoader();
GuidedFuzzing.run(testClassName, testMethod, cl, guidance, System.out);
```

The `FuzzRunner` CLI will accept: `FuzzRunner <V1|V2> [durationSeconds]`
- V1 → testClass=`edu.berkeley.cs.jqf.examples.json.JsonSmartFuzzTest`, testMethod=`fuzzJSONParserParsePermissive`
- V2 → testClass=`edu.berkeley.cs.jqf.examples.json.JsonSmartFuzzTest`, testMethod=`fuzzJSONParserParseRFC4627`

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|-------------------|------------------------------|----------------------|
| V1 | CGF (Cost-Gradient Guidance) | Zest retains inputs that discover new code branches. After the first input containing `[` hits `readArray→readMain→readArray`, all branches in the recursive loop are covered. Deeper nesting traverses the **same** code paths with zero new coverage edges. Zest has no pressure to increase depth — it plateaus at ~5-10 nesting levels once coverage saturates. This is a proxy signal failure: coverage growth does not correlate with stack consumption depth. | CGF measures `maxDepth` (recursion depth) directly via bytecode instrumentation of `readArray`/`readObject`. Each input reaching deeper recursion is retained and mutated. Repetition operators double `[` sequences, growing depth exponentially. Measurable advantage: **time-to-first-StackOverflow** — CGF should trigger it within seconds; Zest may never reach the ~4000-level threshold. |
| V2 | CGF (Cost-Gradient Guidance) | Same as V1 — identical recursive code path via RFC4627 mode. Coverage saturates identically. | Same mechanism-aligned depth signal. Independent corpus directory ensures V2 search isn't contaminated by V1 inputs with MODE_PERMISSIVE-specific features. |

#### Step 6 — Strategy-Specific Guidance Design

##### Measurement Plan

###### Signal: `maxDepth` (primary, both V1 and V2)

| Aspect | Detail |
|--------|--------|
| **What** | Maximum recursion depth during one parse execution — the peak value of concurrent `readArray`/`readObject` frames on the call stack |
| **Where produced** | Agent-instrumented bytecode in `JSONParserBase#readArray(JsonReaderI)` and `JSONParserBase#readObject(JsonReaderI)` — these are the two methods that each open one level of JSON nesting |
| **Why this region** | Each entry to `readArray`/`readObject` consumes one stack frame (~250 bytes). The stack overflow occurs when these frames exhaust the 1 MB stack at ~4000 concurrent frames. `maxDepth` directly measures the quantity that causes the failure. |
| **How stored** | `ThreadLocal<long[]>` in `DepthCounters` class. Index 0 = currentDepth, Index 1 = maxDepth. `enterDepth()`: currentDepth++; maxDepth = max(maxDepth, currentDepth). `exitDepth()`: currentDepth--. |
| **Reset** | `DepthCounters.reset()` called from `Guidance.getInput()` before returning the input stream for each new execution |
| **Read** | `DepthCounters.getMaxDepth()` called from `Guidance.handleResult()` after each execution |

###### Signal: `nodeCount` (secondary, both V1 and V2)

| Aspect | Detail |
|--------|--------|
| **What** | Total number of parser production entries — calls to `readArray` + `readObject` + `readMain` during one parse |
| **Where produced** | Agent-instrumented bytecode in `JSONParserBase#readMain(JsonReaderI, boolean[])`, plus the enter counts from `readArray`/`readObject` above |
| **Why this region** | `readMain` is the dispatch point for every JSON value. Total node count measures parser work, complementing depth (breadth vs. depth signal). |
| **How stored** | Same `ThreadLocal<long[]>` in `DepthCounters`. Index 2 = nodeCount. Incremented at entry to each of the three methods. |
| **Reset** | Same reset call in `getInput()` |
| **Read** | `DepthCounters.getNodeCount()` in `handleResult()` |

##### Instrumentation Plan (Tier 1: bytecode agent) [R35]

| Item | Detail |
|------|--------|
| **Exact classes** | `net.minidev.json.parser.JSONParserBase` (abstract class containing `readArray`, `readObject`, `readMain`) |
| **Exact methods** | `readArray(Lnet/minidev/json/writer/JsonReaderI;)Ljava/lang/Object;` — enter/exit depth tracking. `readObject(Lnet/minidev/json/writer/JsonReaderI;)Ljava/lang/Object;` — enter/exit depth tracking. `readMain(Lnet/minidev/json/writer/JsonReaderI;[Z)Ljava/lang/Object;` — entry node count only. |
| **JVM flags** | None needed; JSONParserBase is a user class, not a JDK class. No `--add-opens` required. |
| **Signal export** | `ThreadLocal<long[]>` in `fuzzing.agent.DepthCounters`. Static methods: `enterDepth()`, `exitDepth()`, `enterNode()`, `reset()`, `getMaxDepth()`, `getNodeCount()`. |
| **Agent implementation** | `fuzzing.agent.DepthMeasureAgent` — premain registers a `ClassFileTransformer`. Transformer matches class name `net/minidev/json/parser/JSONParserBase`. Uses ASM `AdviceAdapter` (from asm-commons, available as transitive dep) to wrap `readArray` and `readObject` with try-finally (enter on method entry, exit in finally block). For `readMain`, only inserts `enterNode()` call on method entry. |

##### Mutation Operators [R45]

Both V1Guidance and V2Guidance implement:

**(a) Repetition:** Select a random region of the current input (random offset, random length). Copy it and repeat it k times where k is chosen to fill up to `MAX_INPUT_SIZE` (from system property `jqf.ei.MAX_INPUT_SIZE`, default 10240). Includes a "double entire input" operator. This grows a small seed like `[` into `[[[[...` rapidly — within 14 doublings, a single `[` becomes 10240+ bytes (2^14 = 16384). Far faster than single-byte mutations.

**(b) Dictionary tokens** from the code on the attack path (parser source):
- `[` (0x5B) — array open (readArray entry point)
- `]` (0x5D) — array close (readArray exit)
- `{` (0x7B) — object open (readObject entry point)
- `}` (0x7D) — object close (readObject exit)
- `:` (0x3A) — key-value separator (readObject key-colon dispatch)
- `,` (0x2C) — element separator (readArray/readObject comma handling)
- `"` (0x22) — string delimiter (readString)
- `'` (0x27) — single-quote (permissive mode)
- `n`, `u`, `l` — components of `null` literal
- `t`, `r`, `e` — components of `true` literal
- `f`, `a`, `s` — components of `false` literal

Tokens are inserted or overwritten at random positions. Each is a single syntactic unit from the source. No assembled triggering inputs ([R23]).

**(c) Encoding:** Not needed — JSON is plain UTF-8 text with no checksums, length fields, or compression. Random bytes that are valid UTF-8 can reach the parser; invalid UTF-8 produces replacement characters which the parser handles normally.

##### Retention & Prioritization [R46]

**Primary retention:** Input is kept if `maxDepth > bestMaxDepth` (new depth record).

**Secondary retention (flat signal):** When maxDepth is zero or hasn't improved for many executions:
- Keep inputs that grow in length toward `input_bytes` (4000), so the search builds material for repetition operators to work on
- Keep inputs where `nodeCount > bestNodeCount`, indicating the parser did more structural work

**Prioritization:** Inputs in the corpus are selected for mutation proportional to their `maxDepth` value. Higher-depth inputs are mutated more frequently.

**Input growth guarantee [R46]:** The repetition operator (doubling) can grow a 1-byte seed to 10240 bytes in 14 steps. Within 60 seconds of fuzzing at typical throughput (1000+ exec/s), the search will explore inputs across the full size range.

##### Input Model [R25, R31]

The fuzz test consumes `InputStream`. The Guidance's `getInput()` returns a `ByteArrayInputStream` wrapping the mutated byte array. Input model is **byte[] only**. Conversion to `String` via UTF-8 happens inside the FROZEN fuzz harness. No junit-quickcheck generators are used.

Maximum input length: `Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240)` — the Guidance reads this property and caps inputs at this size.

##### Stop/Continue Conditions [R8]

- **Default:** Run indefinitely (infinite loop in `hasInput()` returning true).
- **Time-bounded:** Honor `jqf.ei.MAX_DURATION` system property (duration in milliseconds). Also support CLI argument for duration in seconds.

##### Logging [R5]

Every 1 second, each Guidance logs:
```
[V1Guidance] executions=NNNN | maxDepth=NNN | nodeCount=NNN | corpusSize=NN | lastNewDepth=NNN | inputLen=NNNN | elapsed=NNs
```

##### Corpus Isolation [R20]

- V1: `out/V1/corpus/`
- V2: `out/V2/corpus/`

Independent corpus per target. No cross-method reuse.

##### Failure Handling [R6]

The Guidance **never** decides that an execution failed and **never** writes failure files. `handleResult()` receives the `Result` enum from JQF and uses it only to update the signal (maxDepth, nodeCount) for retention decisions. The evaluation framework records actual failures (StackOverflowError, timeouts) externally.

#### Step 7 — Custom Guidance Design (Per-Target)

**V1Guidance:** Implements `Guidance` directly and `SignalSource`. Targets `fuzzJSONParserParsePermissive`. Corpus at `out/V1/corpus/`. Measures `maxDepth` and `nodeCount` via DepthCounters. Implements all mutation operators above. One dedicated class.

**V2Guidance:** Identical design to V1Guidance but independent class, targeting `fuzzJSONParserParseRFC4627`. Corpus at `out/V2/corpus/`. Same signals, same operators.

#### Step 8 — Fuzz Tests

The FROZEN `JsonSmartFuzzTest` provides:
- `fuzzJSONParserParsePermissive(InputStream)` — covers V1
- `fuzzJSONParserParseRFC4627(InputStream)` — covers V2

Both consume `InputStream` directly. Semantic decoding (bytes → UTF-8 String) is inside the harness. No generators used.

#### Step 9 — Metadata Replay / Feeder

`ReplayRunner` will:
1. Accept a corpus file path on the command line
2. Read the saved input bytes
3. Load metadata (maxDepth, nodeCount, timestamp) from a companion `.meta` JSON file
4. Replay the input through the original parser deterministically
5. Print: input hex dump, measured signals, exception (if any), input as UTF-8 string

#### Step 10 — Build & Run Commands

```bash
### Build everything
mvn package -DskipTests

### Create agent jar (manual — pom.xml unchanged)
echo -e "Premain-Class: fuzzing.agent.DepthMeasureAgent\nCan-Retransform-Classes: true" > target/agent-manifest.txt
jar cfm target/depth-agent.jar target/agent-manifest.txt -C target/test-classes fuzzing/agent/

### Fuzz V1 (infinite)
java -Xmx1g -Xss1m -javaagent:target/depth-agent.jar \
  -cp "target/test-classes:target/deps/*:lib/*" \
  fuzzing.runner.FuzzRunner V1

### Fuzz V1 (time-bounded, 300 seconds)
java -Xmx1g -Xss1m -javaagent:target/depth-agent.jar \
  -cp "target/test-classes:target/deps/*:lib/*" \
  fuzzing.runner.FuzzRunner V1 300

### Fuzz V2 (time-bounded, 300 seconds)
java -Xmx1g -Xss1m -javaagent:target/depth-agent.jar \
  -cp "target/test-classes:target/deps/*:lib/*" \
  fuzzing.runner.FuzzRunner V2 300

### Replay a saved input
java -Xmx1g -Xss1m -javaagent:target/depth-agent.jar \
  -cp "target/test-classes:target/deps/*:lib/*" \
  fuzzing.replay.ReplayRunner out/V1/corpus/input_42.bin
```

#### Planned Directory Tree

```
src/
  test/
    java/
      edu/berkeley/cs/jqf/examples/json/
        JsonSmartFuzzTest.java               (FROZEN — do not touch)
      dosguide/validate/
        SignalSource.java                    (FROZEN — do not touch)
      fuzzing/
        agent/
          DepthCounters.java                 (ThreadLocal signal counters)
          DepthMeasureAgent.java             (Java agent premain + ASM transformer)
        guidance/
          V1Guidance.java                    (CGF Guidance for V1)
          V2Guidance.java                    (CGF Guidance for V2)
        runner/
          FuzzRunner.java                    (CLI runner with method selection)
        replay/
          ReplayRunner.java                  (Metadata replay / feeder)
lib/
  json-smart-2.4.8.jar                      (vulnerable artifact — existing)
  accessors-smart-2.4.8.jar                 (dependency — existing)
pom.xml                                     (canonical build — unchanged)
```

#### IMPORT AUDIT

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
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

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — all code targets Java 17, no preview/incubator APIs
- [YES] No hallucinated APIs — all imports verified against JQF 2.1, ASM 9.1/9.5, JDK 17
- [YES] Guidance implements Guidance directly — V1Guidance/V2Guidance implement `edu.berkeley.cs.jqf.fuzz.guidance.Guidance`
- [YES] No existing guidance extended — no extension/delegation of Zest or any existing Guidance
- [YES] V* vulnerabilities identified — V1 (permissive mode), V2 (RFC4627 mode)
- [YES] V* IDs are sequential — V1, V2 assigned in discovery order, not from library version numbers
- [YES] Official vulnerability names applied — CWE-674 (Uncontrolled Recursion)
- [YES] PkgRisk-* identified — PkgRisk-1 (BigDecimal) identified and excluded as infeasible (scale analysis)
- [YES] Every PkgRisk-* executed or justified — PkgRisk-1 explicitly justified as untestable (10KB input insufficient for BigDecimal DoS)
- [YES] Guidance targets V* — V1Guidance targets V1, V2Guidance targets V2
- [YES] One fuzz method per V* — V1 uses fuzzJSONParserParsePermissive, V2 uses fuzzJSONParserParseRFC4627
- [YES] CLI method selection supported — FuzzRunner accepts V1/V2 argument
- [YES] Byte[]/InputStream input model used exclusively — getInput() returns ByteArrayInputStream
- [YES] No junit-quickcheck Generators used — all mutation inside Guidance
- [YES] All mutation implemented inside Guidance — byte-level + repetition + dictionary
- [YES] Repetition, dictionary, encoder operators — repetition (chunk doubling), dictionary (12 tokens from parser source), encoder not needed (JSON is plain text)
- [YES] Retention progresses while signal flat — secondary criterion keeps length-growing and nodeCount-improving inputs; doubling operator reaches input_bytes (4000) in <14 steps within first minute
- [YES] Retention signals measured at sink — maxDepth measured inside readArray/readObject (the recursive sink), not before it
- [YES] Logging every 1 second — structured log with executions, maxDepth, nodeCount, corpusSize, elapsed
- [YES] Guidance decides no failures, writes no failure files — handleResult only updates signals for retention
- [YES] Corrupted inputs saved with metadata — corpus entries saved with .meta JSON (maxDepth, nodeCount, timestamp)
- [YES] Replay/feeder implemented — ReplayRunner reads saved input + metadata and replays deterministically
- [YES] Infinite + time-bounded fuzzing — default infinite, CLI seconds argument for bounded
- [YES] src/main vs src/test separation — no production code in workspace src/main; all fuzzing infra in src/test
- [YES] Maven scopes consistent — JQF/JUnit test scope, ASM compile scope, json-smart system scope
- [YES] No wildcard imports for JQF/tracing — all explicit imports per audit
- [YES] TraceEvent import verified — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` from jqf-instrument

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "maxDepth",
          "quantity": "maximum concurrent recursion depth of readArray/readObject frames during one parse execution",
          "aggregation": "max",
          "locations": ["JSONParserBase#readArray", "JSONParserBase#readObject"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in fuzzing.agent.DepthCounters, index 0 = currentDepth, index 1 = maxDepth",
          "reset": "DepthCounters.reset() called at the start of V1Guidance.getInput()",
          "read": "DepthCounters.getMaxDepth() called in V1Guidance.handleResult()"
        },
        {
          "name": "nodeCount",
          "quantity": "total number of parser production entries (readArray + readObject + readMain invocations) during one parse execution",
          "aggregation": "count",
          "locations": ["JSONParserBase#readArray", "JSONParserBase#readObject", "JSONParserBase#readMain"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in fuzzing.agent.DepthCounters, index 2 = nodeCount",
          "reset": "DepthCounters.reset() called at the start of V1Guidance.getInput()",
          "read": "DepthCounters.getNodeCount() called in V1Guidance.handleResult()"
        }
      ],
      "retention": "Primary: keep input if maxDepth > bestMaxDepth (new depth record). Secondary (when signal is flat): keep inputs that grow in byte length toward input_bytes=4000 or that improve nodeCount, so the search can build material for the repetition operator to push past the threshold. Inputs in the corpus are prioritized for mutation proportional to their maxDepth value.",
      "retention_signals": ["maxDepth", "nodeCount"],
      "mutation": [
        "Byte-level: random byte flip (single byte), random byte insertion, random byte deletion, random byte overwrite at random position",
        "Repetition [R45a]: select random region [offset, offset+len), repeat it k times in-place where k is chosen so the result fills up to MAX_INPUT_SIZE (10240). Includes 'double entire input' as a special case. A 1-byte seed reaches 10240 bytes in 14 doubling steps.",
        "Dictionary [R45b]: tokens from the parser source on the attack path — single bytes: '[' (0x5B), ']' (0x5D), '{' (0x7B), '}' (0x7D), ':' (0x3A), ',' (0x2C), '\"' (0x22), '\\'' (0x27); multi-byte tokens: 'null', 'true', 'false', 'NaN'. Inserted or overwritten at random positions. Each token is a syntactic unit from the source; no assembled payloads.",
        "No encoder [R45c]: JSON is plain UTF-8 text with no checksums, length-prefixes, or compression. Random bytes that decode as valid UTF-8 reach the parser directly."
      ]
    },
    {
      "target": "V2",
      "signals": [
        {
          "name": "maxDepth",
          "quantity": "maximum concurrent recursion depth of readArray/readObject frames during one parse execution",
          "aggregation": "max",
          "locations": ["JSONParserBase#readArray", "JSONParserBase#readObject"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in fuzzing.agent.DepthCounters, index 0 = currentDepth, index 1 = maxDepth",
          "reset": "DepthCounters.reset() called at the start of V2Guidance.getInput()",
          "read": "DepthCounters.getMaxDepth() called in V2Guidance.handleResult()"
        },
        {
          "name": "nodeCount",
          "quantity": "total number of parser production entries (readArray + readObject + readMain invocations) during one parse execution",
          "aggregation": "count",
          "locations": ["JSONParserBase#readArray", "JSONParserBase#readObject", "JSONParserBase#readMain"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in fuzzing.agent.DepthCounters, index 2 = nodeCount",
          "reset": "DepthCounters.reset() called at the start of V2Guidance.getInput()",
          "read": "DepthCounters.getNodeCount() called in V2Guidance.handleResult()"
        }
      ],
      "retention": "Primary: keep input if maxDepth > bestMaxDepth (new depth record). Secondary (when signal is flat): keep inputs that grow in byte length toward input_bytes=4000 or that improve nodeCount. Inputs prioritized for mutation proportional to maxDepth. Independent corpus directory out/V2/corpus/.",
      "retention_signals": ["maxDepth", "nodeCount"],
      "mutation": [
        "Byte-level: random byte flip (single byte), random byte insertion, random byte deletion, random byte overwrite at random position",
        "Repetition [R45a]: select random region [offset, offset+len), repeat it k times in-place where k is chosen so the result fills up to MAX_INPUT_SIZE (10240). Includes 'double entire input' as a special case. A 1-byte seed reaches 10240 bytes in 14 doubling steps.",
        "Dictionary [R45b]: tokens from the parser source on the attack path — single bytes: '[' (0x5B), ']' (0x5D), '{' (0x7B), '}' (0x7D), ':' (0x3A), ',' (0x2C), '\"' (0x22), '\\'' (0x27); multi-byte tokens: 'null', 'true', 'false', 'NaN'. Inserted or overwritten at random positions.",
        "No encoder [R45c]: JSON is plain UTF-8 text with no checksums or length-prefixes."
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

I'll start by reading the existing workspace files and source code, then implement all files.

```text
$ find <run_dir> -type f | sort
```

Let me read the guidance plan and existing frozen files:

```text
Read <run_dir>/analysis/guidance_plan.json
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me create all the implementation files. I'll start with the agent infrastructure.

```text
Write <run_dir>/src/test/java/fuzzing/agent/DepthCounters.java
Write <run_dir>/src/test/java/fuzzing/agent/DepthMeasureAgent.java
```

Now the Guidance classes. First V1Guidance:

```text
Write <run_dir>/src/test/java/fuzzing/guidance/V1Guidance.java
```

Now V2Guidance:

```text
Write <run_dir>/src/test/java/fuzzing/guidance/V2Guidance.java
```

Now the FuzzRunner with the required `createGuidance` factory method:

```text
Write <run_dir>/src/test/java/fuzzing/runner/FuzzRunner.java
```

Now the ReplayRunner:

```text
Write <run_dir>/src/test/java/fuzzing/replay/ReplayRunner.java
```

Now create validation inputs and launch.json:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
$ cd <run_dir>/analysis/validation_inputs …
```

Now write the launch.json:

```text
Write <run_dir>/analysis/launch.json
```

Now write the run.sh script:

```text
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh
```

Now let me verify everything compiles:

```text
$ cd <run_dir> && mvn package -DskipTests 2>&1 | tail -30
```

Build succeeds. Now let me build the agent jar and verify all compiled classes exist:

```text
$ \ …
```

Let me verify the current state of the workspace to ensure everything is intact after the context compaction:

```text
$ find . -type f \( -name "*.java" -o -name "*.json" -o -name "*.sh" -o -name "*.bin" -o -name "pom.xml" \) | sort
$ ls -la target/depth-agent.jar target/test-classes/fuzzing/runner/FuzzRunner.class target/test-classes/fuzzing/guidance/V1Guidance.class target/test-classes/fuzzing/guidance/V2Guidance.class target/test-classes/fuzzing/agent/DepthCounters.class target/test-classes/fuzzing/agent/DepthMeasureAgent.clas …
$ ls -la target/depth-agent.jar && ls target/test-classes/fuzzing/runner/ && ls target/test-classes/fuzzing/guidance/ && ls target/test-classes/fuzzing/agent/ && ls target/test-classes/fuzzing/replay/
```

All compiled artifacts are intact. Block 3 implementation is complete with:

**Agent files:**
- `fuzzing/agent/DepthCounters.java` — ThreadLocal counters for recursion depth/node tracking
- `fuzzing/agent/DepthMeasureAgent.java` — ASM-based Java agent instrumenting `JSONParserBase.readArray`, `readObject` (depth), and `readMain` (nodeCount)
- `target/depth-agent.jar` — built agent jar with proper manifest

**Guidance files:**
- `fuzzing/guidance/V1Guidance.java` — Cost-Gradient Guidance for MODE_PERMISSIVE (V1)
- `fuzzing/guidance/V2Guidance.java` — Cost-Gradient Guidance for MODE_RFC4627 (V2)
- Both implement `Guidance` and `SignalSource`, with corpus management, weighted parent selection, and 6-operator mutation strategy

**Runner + Replay:**
- `fuzzing/runner/FuzzRunner.java` — CLI runner with `createGuidance()` factory method, class origin verification
- `fuzzing/replay/ReplayRunner.java` — Replays saved corpus inputs with signal measurement

**Build/Launch:**
- `pom.xml` — system-scoped deps pointing to `lib/json-smart-2.4.8.jar` and `lib/accessors-smart-2.4.8.jar`
- `run.sh` — Build + fuzz script with `-Xmx1g -Xss1m`
- `analysis/launch.json` — Machine-readable build/launch configuration

**Validation inputs:** 8 `.bin` files covering simple objects, arrays, nesting, literals, escapes, and empty input.

All code compiles cleanly via `mvn package -DskipTests` → BUILD SUCCESS. The workspace is ready for DoSGuide validation.

## Validation repair 1

Let me analyze the failure. The signals are always 0 on guidance-generated inputs, meaning the inputs never reach the instrumented methods. Let me trace through the code path carefully.

```text
Read <run_dir>/src/test/java/fuzzing/agent/DepthMeasureAgent.java
Glob <source_root> **/*.java
```

Let me trace the exact parser call chain to understand why signals are 0:

```text
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParser.java
Grep <source_root> class JSONParserString
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserMemory.java
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserString.java
```

Now let me look at the `parse()` method in `JSONParserBase` to see the actual call chain:

```text
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java
Grep <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java protected.*parse\(JsonReaderI
Grep <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java readFirst
Grep <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java readFirst
Grep <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java protected.*readMain|protected.*readArray|protected.*readObject
```

Let me read the full `readArray` and `readObject` methods to understand exactly when `readMain` is called:

```text
Read <source_root>/json-smart/src/main/java/net/minidev/json/parser/JSONParserBase.java
```

Now I fully understand the issue. The call chain is:
- `parse()` → `readFirst()` → if first char is `[` → `readArray()` → `readMain()` for each element
- If first char is NOT `[` or `{`, `readArray`/`readObject`/`readMain` are **never called**

The guidance seeds with `new byte[]{'a'}`, which hits the `default` case in `readFirst()` and never reaches the instrumented methods. All 81 mutated variants of `'a'` also never produce valid `[` or `{` as the first character, so signals stay at 0.

**Fix 1:** Change seeds to ordinary well-formed JSON examples (`[]` and `[0]`) so the parser actually enters `readArray`/`readMain`.

**Fix 2:** Make the agent's `ClassWriter` robust against classloader issues with `COMPUTE_FRAMES` by overriding `getCommonSuperClass` to use the target classloader.

Let me implement both fixes:

```text
Read <run_dir>/src/test/java/fuzzing/guidance/V1Guidance.java
```

Now I'll implement all fixes. First, fix the seed inputs and improve the retention logic in both guidances, and fix the agent's ClassWriter for classloader robustness:

```text
Edit <run_dir>/src/test/java/fuzzing/guidance/V1Guidance.java
Edit <run_dir>/src/test/java/fuzzing/guidance/V1Guidance.java
```

Now also update the R46 flat-signal retention logic to also keep inputs whose depth is growing (not just when depth is 0):

```text
Edit <run_dir>/src/test/java/fuzzing/guidance/V1Guidance.java
```

Now apply the same fixes to V2Guidance:

```text
Edit <run_dir>/src/test/java/fuzzing/guidance/V2Guidance.java
Edit <run_dir>/src/test/java/fuzzing/guidance/V2Guidance.java
Edit <run_dir>/src/test/java/fuzzing/guidance/V2Guidance.java
```

Now fix the agent's `ClassWriter` to handle JQF's `InstrumentingClassLoader` properly by overriding `getCommonSuperClass`:

```text
Edit <run_dir>/src/test/java/fuzzing/agent/DepthMeasureAgent.java
```

Now let me recompile and rebuild the agent jar:

```text
$ mvn package -DskipTests -q 2>&1 | tail -20
$ \ …
```

Build successful. Note the new `Transformer$1.class` — that's the anonymous `ClassWriter` subclass with the custom `getCommonSuperClass` override. Let me verify all the changes are correct:

```text
$ ls -la target/test-classes/fuzzing/guidance/V1Guidance.class target/test-classes/fuzzing/guidance/V2Guidance.class target/test-classes/fuzzing/agent/DepthMeasureAgent*.class target/depth-agent.jar
```

All files compiled and rebuilt successfully. Here's a summary of the changes:

#### Changes Made

##### Root Cause
The guidance seeded with `new byte[]{'a'}` — a single byte that doesn't start with `[` or `{`. The json-smart parser's `readFirst()` method dispatches to `readArray()` only on `[` and to `readObject()` only on `{`. Any other first character goes through primitive/string parsing paths that **never call** the instrumented methods (`readArray`, `readObject`, `readMain`). Since all 81 mutated variants of `'a'` also lacked `[`/`{` as the first character, signals stayed at 0.

##### Fix 1: Better seed inputs (V1Guidance.java, V2Guidance.java)
Changed the initial corpus seeds from `new byte[]{'a'}` to three ordinary well-formed JSON examples:
- `[]` — empty array (triggers `readArray`, depth=1)
- `[0]` — array with one element (triggers `readArray` + `readMain`, depth=1, nodeCount=1)
- `[[]]` — nested array (triggers `readArray` twice, depth=2)

These are the smallest valid JSON structures — not failure-inducing inputs. From the very first execution, the parser enters `readArray`/`readMain` and signals become non-zero. The mutation operators (especially repetition of `[` and dict-insert of `[`) can then grow depth from there.

##### Fix 2: Relaxed R46 retention (V1Guidance.java, V2Guidance.java)
Changed the flat-signal retention rule from `lastMaxDepth == 0 && length > bestLen` to just `length > bestLen`. This ensures length-growing inputs are kept even when depth is already non-zero, helping the guidance reach `input_bytes` within the 60s window.

##### Fix 3: Robust agent ClassWriter (DepthMeasureAgent.java)
Overrode `getCommonSuperClass()` in the `ClassWriter` to resolve classes using the target's own classloader (the one passed to `transform()`). This prevents `COMPUTE_FRAMES` failures when JQF's `InstrumentingClassLoader` triggers the transformation — the default `ClassWriter` uses `Class.forName()` with the system classloader, which can't resolve classes only visible to JQF's loader. Also added diagnostic logging to confirm transformations occur.
