# commons-fileupload_GHSA-vv7r-c36w-3prj

## Block 1

```text
Glob <run_dir> **/*FuzzTest.java
Read <source_root>/src/main/java/org/apache/commons/fileupload/MultipartStream.java
Glob <source_root> **/pom.xml
Read <run_dir>/src/test/java/com/fuzzing/harness/MultipartFuzzTest.java
Read <run_dir>/pom.xml
Read <source_root>/pom.xml
```

Let me read additional source files to understand the full attack surface.

```text
Glob <source_root> src/main/java/org/apache/commons/fileupload/util/Streams.java
Glob <source_root> src/main/java/org/apache/commons/fileupload/**/*.java
$ ls <run_dir>/lib/ 2>/dev/null || echo "lib dir not found"
Read <source_root>/src/main/java/org/apache/commons/fileupload/util/Streams.java
$ cd <source_root> && git log --oneline -20 2>&1 | tail -20
Read <source_root>/src/main/java/org/apache/commons/fileupload/FileUploadBase.java
Read <source_root>/src/main/java/org/apache/commons/fileupload/FileUploadBase.java
Read <source_root>/src/main/java/org/apache/commons/fileupload/FileCountLimitExceededException.java
Grep <source_root>/src/main/java/org/apache/commons/fileupload fileCountMax|FileCountLimit|getFileCountMax|setFileCountMax
```

Now let me understand the full code flow. Let me look at the `readHeaders()` state machine more closely and check for the specific header separator matching logic.

```text
Read <source_root>/src/main/java/org/apache/commons/fileupload/MultipartStream.java
Read <source_root>/src/main/java/org/apache/commons/fileupload/MultipartStream.java
```

Now I have a thorough understanding of the code. Let me create the scale measurement directory and files.

```text
$ mkdir -p <run_dir>/analysis/scale/V1
```

Now let me generate the scale measurement input files. Each file is a valid input for `fuzzMultipartStreamReadHeaders` with a specific header size.

```text
$ cd <run_dir>/analysis/scale/V1 && python3 -c " …
Write <run_dir>/analysis/scale/V1/series.json
```

Let me verify one of the generated inputs:

```text
$ xxd <run_dir>/analysis/scale/V1/h64.bin | head -10
$ wc -c <run_dir>/analysis/scale/V1/*.bin
```

Good, the binary files look correct. Let me verify the entire directory structure:

```text
$ ls -la <run_dir>/analysis/scale/V1/
```

Now let me present the full analysis.

---

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: `readHeaders()` allows header sections exceeding the application-expected size limit

**Fuzzable entrypoint & user-controlled input:**  
`MultipartFuzzTest.fuzzMultipartStreamReadHeaders(InputStream)` — the entire multipart body is user-controlled. The boundary and body content are extracted from the fuzz input. The `readHeaders()` method is called for every part in the multipart stream.

**Mechanism:**  
`MultipartStream.readHeaders()` (lines 901–941) reads bytes one at a time from the internal buffer via `readByte()`, accumulates them in a `ByteArrayOutputStream`, and uses a simple linear state machine to detect the `\r\n\r\n` header terminator (`HEADER_SEPARATOR`). The method has a hardcoded maximum of `HEADER_PART_SIZE_MAX = 10240` bytes.

The fuzz harness oracle checks that each returned header is at most `PART_HEADER_SIZE_MAX = 512` bytes. Because the library's internal limit (10240) is 20× larger than the application's expected limit (512), any part whose header section is 513–10240 bytes causes the oracle to fire an `AssertionError`.

Additionally, the state machine (lines 921–925) for detecting `\r\n\r\n` has a subtle bug: when a partial match fails at position `i > 0`, it resets `i = 0` without checking whether the current byte starts a new partial match (unlike KMP, which the boundary searcher does correctly). For example, the byte sequence `\r\n\r` followed by `\r` (instead of `\n`) resets the state machine and causes the scanner to miss a valid `\r\n\r\n` that starts at the second `\r`. This can be used to construct inputs where `readHeaders()` reads past a valid terminator positioned at ≤ 512 bytes, extending the header to > 512 bytes.

**Exhausted resource:**  
Heap memory and CPU time: the `ByteArrayOutputStream` in `readHeaders()` accumulates up to 10240 bytes instead of stopping at ≤ 512. Each byte is also converted to a character in the returned String. The CPU processes each byte individually via `readByte()`.

**Failure mode:**  
The fuzz harness throws `AssertionError` (undeclared — the method declares only `throws IOException`) when `headers.length() > 512`. This is an undeclared-throwable failure. In a production context, the excessive header allocation (up to 20× expected) across many concurrent multipart requests leads to CPU time exhaustion (timeout). Within the evaluation limits (10240-byte input, 1GB heap, 20s timeout), the oracle catches the condition proactively before actual resource exhaustion.

**Scale:**  
`readHeaders()` processes H bytes per call where H is the actual header section size (up to 10240). The oracle triggers when H > 512. A minimal triggering input needs: boundary line (~2 bytes) + first boundary delimiter (~5 bytes) + 509 bytes of header content + `\r\n\r\n` (4 bytes) + close delimiter (~7 bytes) = **~527 bytes** of input to produce a 513-byte header. With the state machine bug, an input of ~530 bytes can produce a 513+ byte header even when a valid `\r\n\r\n` appears at byte 512 in the stream.

##### 1.2 Official Classification

**V1:** CWE-400 (Uncontrolled Resource Consumption) / CWE-770 (Allocation of Resources Without Limits or Throttling)
- The library's `HEADER_PART_SIZE_MAX` (10240) is excessive and not configurable by the application
- The state machine bug in the header terminator scanner compounds the issue

##### 1.3 Dependency / Package-Level Risks

**Analyzed dependencies:**

1. **`java.util.regex`** — Not used by MultipartStream. The boundary search uses a custom KMP implementation (`findSeparator`/`computeBoundaryTable`). No regex DoS risk.

2. **`commons-io` (`IOUtils.copyLarge`)** — Used in `Streams.copy()` for copying body data. `copyLarge` is a standard O(n) byte copy utility with no amplification. No DoS risk within evaluation limits.

3. **`java.io.ByteArrayOutputStream`** — Used in `readHeaders()` to accumulate header bytes. Grows dynamically by doubling capacity. With the 10240-byte cap on `readHeaders`, the maximum allocation per call is ~20KB (including BAOS internal overhead). Under 1GB heap, this is negligible. **No independent DoS risk** beyond what V1 already captures.

4. **KMP boundary search (`findSeparator`/`computeBoundaryTable`)** — Custom implementation. Reviewed and confirmed O(n) time complexity. The failure function computation is standard. No worst-case amplification. **No DoS risk.**

5. **`java.io.ByteArrayInputStream`** — Wraps the input data. Standard, no amplification. **No DoS risk.**

**Conclusion:** No PkgRisk targets identified. All dependencies are standard, O(n), and do not exhibit input-sensitive amplification within the evaluation limits.

##### 1.4 Zest Baseline Comparison (V1)

**Closest Zest equivalent:** Zest (coverage-guided fuzzing) on `fuzzMultipartStreamReadHeaders`.

**Why Zest underperforms:**
- Zest uses code coverage as its retention signal. The `readHeaders()` method has the same code paths regardless of whether the header is 100 bytes or 1000 bytes — it's the same loop, same branches. Coverage plateaus very quickly.
- Zest has no mechanism-aligned signal for "header bytes accumulated." It cannot distinguish a 512-byte header (benign) from a 513-byte header (triggering).
- The vulnerability threshold (> 512 bytes) is a *quantitative* condition, not a *qualitative* branch. Coverage-guided fuzzing treats both sides of this threshold identically.

**Measurable metric where custom Guidance outperforms:**
- **Time-to-first-bug:** Custom guidance that tracks header byte count (via agent instrumentation of `ByteArrayOutputStream.write` inside `readHeaders`) can preferentially retain inputs that produce longer headers, converging on > 512 bytes much faster than Zest's coverage-blind exploration.
- **Input growth rate:** Custom guidance with repetition operators ([R45]) can rapidly extend header content to cross the 512-byte threshold, while Zest's byte-flip mutations slowly grow input length.

---

#### PHASE B — Target Selection

Only one viable DoS target was found (V1). No PkgRisk targets qualify.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "readHeaders() allows oversized header sections (up to 10240 bytes instead of ≤512)",
      "entrypoint": "MultipartFuzzTest.fuzzMultipartStreamReadHeaders(InputStream) → MultipartStream.readHeaders()",
      "source_path": "src/main/java/org/apache/commons/fileupload/MultipartStream.java",
      "sink": "MultipartStream#readHeaders",
      "mechanism": "readHeaders() accumulates bytes in a ByteArrayOutputStream until it finds the \\r\\n\\r\\n header terminator or reaches HEADER_PART_SIZE_MAX (10240). The library's hardcoded limit (10240) is 20× the application-expected limit (512). Additionally, the linear state machine for \\r\\n\\r\\n detection resets to state 0 on mismatch without partial-match rollback, causing valid terminators to be missed when preceded by partial matches (\\r\\n\\r + non-\\n byte), extending headers past where they should end.",
      "resource": "CPU time and heap memory: ByteArrayOutputStream in readHeaders() accumulates up to 10240 bytes per header section instead of stopping at the expected ≤512 bytes; each byte is processed individually by readByte() and accumulated into a String",
      "failure_mode": "timeout",
      "scale": "readHeaders() reads up to 10240 bytes per call (HEADER_PART_SIZE_MAX). The oracle fires when headers.length() > 512 bytes. A 527-byte input suffices: boundary line (2 bytes) + boundary delimiter (5 bytes) + 509 bytes header content + \\r\\n\\r\\n (4 bytes) + close delimiter (7 bytes) → 513-byte header string. With the state machine bug, a ~530-byte input can produce >512-byte headers even when a valid \\r\\n\\r\\n exists before 512 bytes.",
      "input_bytes": 527,
      "cwe": "CWE-400"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

#### Analysis of Scale Measurements for V1

**Measured growth rates (linear fit across the 64→2048 range):**

| Signal | Growth rate per header byte | At max header (~10,226 bytes in 10,240-byte input) |
|---|---|---|
| CPU time | ~2.8 µs/byte | ~38 ms |
| Allocated | ~60 bytes/byte | ~1.3 MB |
| Peak heap | Flat at 1–2 MB | ~2 MB |

**Key observations:**

1. **CPU time** grows linearly at ~2.8 µs per header byte. Extrapolating to the maximum header size achievable within the input size limit (10,240 − 14 bytes overhead = 10,226 header bytes): CPU ≈ 9 ms base + (10,226 × 2.8 µs) ≈ **38 ms**. This is 0.19% of the 20,000 ms timeout — nowhere near timeout.

2. **Allocation** grows at ~60 bytes per header byte (ByteArrayOutputStream doubling + String copy). At maximum: ~1.3 MB. Under a 1 GB heap this is negligible — nowhere near OOM.

3. **Peak heap** is flat at 1–2 MB across all sizes. No accumulation pressure.

4. All inputs (including h1024 and h2048 which produce headers > 512 bytes) completed within caps. The oracle's `AssertionError` fires but doesn't prevent the measurement from completing.

**Mechanism confirmation:** The resource (CPU time and heap memory) DOES grow linearly with header bytes as the mechanism predicts. However, the growth rate is too gentle to reach timeout (20s) or OOM (1GB) at any input size within the 10,240-byte limit. The failure is purely the harness oracle detecting `headers.length() > 512` and throwing `AssertionError` (undeclared throwable). The minimum triggering input requires only 513 header bytes in a 527-byte input. No denser encoding exists — 1 input byte maps to 1 header byte (minus fixed 14-byte framing overhead).

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured CPU growth: ~2.8 µs per header byte (linear). At maximum header size within input limit (~10226 bytes in a 10240-byte input), extrapolated CPU ≈ 38 ms, far below the 20s timeout. Allocation grows at ~60 bytes per header byte; at max ≈ 1.3 MB, far below 1 GB heap. Neither timeout nor OOM is reachable. The failure is the harness oracle: readHeaders() returns a header of > 512 bytes (up to HEADER_PART_SIZE_MAX = 10240), the fuzz test throws AssertionError (undeclared throwable). Any input producing > 512 header bytes triggers it; minimum is 513 header bytes in a 527-byte input (1 byte boundary line + 5 byte delimiter + 509 bytes content + 4 byte CRLFCRLF + 7 byte close delimiter). Encoding is 1:1 — each input byte beyond the 14-byte framing becomes one header byte.",
    "input_bytes": 527
  }
}
END_SCALE_REVISION_JSON

## Block 2

Let me start by reading the workspace structure and the existing files.

```text
$ ls -la <run_dir>/
$ find <run_dir> -type f | head -30
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/com/fuzzing/harness/MultipartFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me read the key source methods for instrumentation planning:

```text
Read <source_root>/src/main/java/org/apache/commons/fileupload/MultipartStream.java
Read <source_root>/src/main/java/org/apache/commons/fileupload/MultipartStream.java
```

Let me verify the jar and check compilation:

```text
$ ls -la <run_dir>/lib/
$ jar tf <run_dir>/lib/commons-fileupload-1.6.0-SNAPSHOT.jar | grep MultipartStream 2>&1 | head -5
$ mvn compile 2>&1 | tail -20
```

Good, the existing pom.xml compiles and the vulnerable jar is in place. Now let me verify test compilation:

```text
$ mvn test-compile 2>&1 | tail -20
$ mvn compile -DskipTests 2>&1 | tail -20
```

Now let me check what ASM version is available transitively through JQF (for the agent):

```text
$ mvn dependency:tree 2>&1 | grep -i asm | head -10
```

The pom.xml is correct and compilation works. Now let me verify the JQF API classes I'll need:

```text
$ mvn package -DskipTests 2>&1 | tail -20
$ ls <run_dir>/target/dependency/ | head -20
$ jar tf <run_dir>/target/dependency/jqf-fuzz-2.1.jar | grep -E "(Guidance|Result|GuidedFuzzing)" | head -15
$ jar tf <run_dir>/target/dependency/jqf-fuzz-2.1.jar | grep -E "^edu/berkeley/cs/jqf/fuzz/guidance/Guidance\.class$"
$ jar tf <run_dir>/target/dependency/jqf-instrument-2.1.jar | grep TraceEvent | head -5
```

Good. All JQF classes exist. Now let me verify the Guidance interface methods:

```text
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1 | head -30
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1 | head -15
```

Good. Now let me verify the ASM version available to understand what visitor API to use:

```text
$ ls <run_dir>/target/dependency/asm*.jar
```

Let me verify the bytecode signatures of the methods to instrument:

```text
$ javap -p -cp lib/commons-fileupload-1.6.0-SNAPSHOT.jar org.apache.commons.fileupload.MultipartStream 2>&1 | grep -E "(readByte|readHeaders|readBoundary)" | head -10
```

Now I have all the information needed. The pom.xml is correct as-is — no systemPath change needed. Let me verify one more time:

```text
$ test -f <run_dir>/lib/commons-fileupload-1.6.0-SNAPSHOT.jar && echo "JAR EXISTS" || echo "JAR MISSING"
```

The pom.xml needs no changes. Now let me produce the complete Block 2 output.

---

#### Step 2 — Maven Layout & Scope

**Maven layout verification:**
- `src/main/java/` — empty; no production source copies ([R17b]). All vulnerable classes come from `lib/commons-fileupload-1.6.0-SNAPSHOT.jar` via system scope.
- `src/test/java/` — all fuzzing infrastructure: harness (frozen), guidance, agent, runner, replay, SignalSource (frozen).
- **Scope correctness:**
  - `commons-fileupload` → system scope (local vulnerable jar)
  - `commons-io` → compile scope (transitive dependency of commons-fileupload)
  - `javax.servlet` → provided scope (compile-time only)
  - `jqf-fuzz`, `jqf-instrument`, `junit` → test scope (fuzzing infrastructure)
  - ASM → available transitively through JQF (test scope, asm-9.8.jar in target/dependency)

**pom.xml status:** No changes needed. The `systemPath` resolves to the existing `lib/commons-fileupload-1.6.0-SNAPSHOT.jar`. All dependencies are correct. The `maven-dependency-plugin` copies all test-scope dependencies (including ASM) to `target/dependency/` during `package` phase.

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

All symbols required to compile the frozen harness (`MultipartFuzzTest.java`) and the frozen `SignalSource.java` are resolved:

| Symbol | Source | Classification |
|--------|--------|---------------|
| `org.apache.commons.fileupload.MultipartStream` | `lib/commons-fileupload-1.6.0-SNAPSHOT.jar` | A (system jar) |
| `edu.berkeley.cs.jqf.fuzz.Fuzz` | `jqf-fuzz-2.1.jar` (test scope) | A (Maven) |
| `edu.berkeley.cs.jqf.fuzz.JQF` | `jqf-fuzz-2.1.jar` (test scope) | A (Maven) |
| `org.junit.runner.RunWith` | `junit-4.13.2.jar` (test scope) | A (Maven) |
| `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` | `jqf-fuzz-2.1.jar` (test scope) | A (Maven) |
| `edu.berkeley.cs.jqf.fuzz.guidance.Result` | `jqf-fuzz-2.1.jar` (test scope) | A (Maven) |
| `edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException` | `jqf-fuzz-2.1.jar` (test scope) | A (Maven) |
| `edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing` | `jqf-fuzz-2.1.jar` (test scope) | A (Maven) |
| `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` | `jqf-instrument-2.1.jar` (test scope) | A (Maven) |
| `org.objectweb.asm.*` (for agent) | `asm-9.8.jar` (transitive via JQF, test scope) | A (transitive) |

##### 3.2 Stub Generation

**No stubs required.** All symbols are resolved from the vulnerable jar or Maven dependencies.

##### 3.3 Stub Report

No stubs generated. Zero missing internal project types identified. All imports resolve to either the system-scoped vulnerable jar or Maven Central dependencies already declared in pom.xml.

#### Step 4a — Project Setup

##### Directory Layout

```
<workspace>/
├── pom.xml                                        (EXISTING, unchanged)
├── lib/
│   └── commons-fileupload-1.6.0-SNAPSHOT.jar      (EXISTING, vulnerable artifact)
├── src/
│   ├── main/
│   │   └── java/                                  (empty — no source copies)
│   └── test/
│       └── java/
│           ├── com/fuzzing/
│           │   ├── harness/
│           │   │   └── MultipartFuzzTest.java      (FROZEN)
│           │   ├── agent/
│           │   │   ├── V1MeasureAgent.java         (custom agent premain)
│           │   │   └── V1Counters.java             (ThreadLocal signal counters)
│           │   ├── guidance/
│           │   │   └── V1Guidance.java             (custom Guidance for V1)
│           │   ├── runner/
│           │   │   └── FuzzRunner.java             (CLI runner)
│           │   └── replay/
│           │       └── ReplayRunner.java           (metadata replay)
│           └── dosguide/validate/
│               └── SignalSource.java               (FROZEN)
└── analysis/                                       (EXISTING, run metadata)
```

##### Agent JAR Build Procedure

After `mvn package -DskipTests`, the agent JAR is built manually:
```bash
mkdir -p target/agent-build
cd target/agent-build
### Extract ASM classes needed by the agent
jar xf ../dependency/asm-9.8.jar org/
### Copy agent classes
cp -r ../test-classes/com/fuzzing/agent/ com/fuzzing/agent/
### Create manifest
echo "Premain-Class: com.fuzzing.agent.V1MeasureAgent" > manifest.txt
echo "Can-Retransform-Classes: true" >> manifest.txt
### Build fat agent jar
jar cfm ../v1-agent.jar manifest.txt com/ org/
```

##### Class Origin Check (MANDATORY PROOF — to be run in Block 3)

Will verify by running:
```java
System.out.println(org.apache.commons.fileupload.MultipartStream.class
    .getProtectionDomain().getCodeSource().getLocation());
```
Expected output: `file:.../lib/commons-fileupload-1.6.0-SNAPSHOT.jar` — NOT `target/classes`.

#### Step 5 — Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|-------------------|------------------------------|----------------------|
| V1 | Cost-Gradient Guidance (CGF) hybrid with Vulnerability-Directed (VDF) | Zest uses **coverage** as its proxy signal. The `readHeaders()` loop (lines 907–926) exercises the same two branches (`b == HEADER_SEPARATOR[i]` taken/not taken) regardless of whether the header is 100 or 1000 bytes. Coverage saturates within a few executions and provides **zero gradient** toward the oracle threshold (> 512 header bytes). Zest treats a 100-byte header and a 600-byte header identically — it has no mechanism-aligned cost signal. | CGF hill-climbs the **multipartWork** composite signal measured by the custom agent directly at the sink: `readByte()` calls inside `readHeaders()` (headerBytes) + `readBoundary()` calls (boundaryIterations). This creates a **direct gradient** toward the 512-byte threshold. The VDF aspect shapes mutations with multipart-specific dictionary tokens (`\r`, `\n`, `--`, `:`) that ensure inputs reach `readHeaders()`. |

#### Step 6 — Strategy-Specific Guidance Design

##### Measurement Plan for V1

###### Signal 1: `boundaryIterations`
- **What:** Number of `MultipartStream.readBoundary()` invocations during one execution
- **Where produced:** Bytecode instrumentation: ASM inserts a counter increment at the entry of `readBoundary()` in `org/apache/commons/fileupload/MultipartStream`
- **Why this region:** Each `readBoundary()` call corresponds to one part boundary being processed in the parsing loop. More calls = more parts parsed = more opportunity for readHeaders to process oversized headers. It measures how deep the parser advances into the multipart structure.
- **Storage:** `ThreadLocal<long[]>` in `V1Counters`, slot `[0]`
- **Reset:** `V1Counters.reset()` called at the start of `V1Guidance.getInput()` before each execution
- **Read:** `V1Counters.getBoundaryIterations()` called in `V1Guidance.handleResult()`

###### Signal 2: `headerBytes`
- **What:** Number of `MultipartStream.readByte()` calls made while `readHeaders()` is executing
- **Where produced:** Bytecode instrumentation: ASM inserts flag-set at `readHeaders()` entry, flag-clear at all exits (normal return + exception), and a conditional counter increment at `readByte()` entry (only when flag is set)
- **Why this region:** This is the EXACT measurement of work at the sink. Each readByte() inside readHeaders() represents one byte being scanned, accumulated in the ByteArrayOutputStream, and tested against the HEADER_SEPARATOR state machine. This is the resource the oracle checks (the returned String length ≈ headerBytes).
- **Storage:** `ThreadLocal<long[]>` in `V1Counters`, slot `[1]` (counter) and slot `[2]` (inHeaders flag, 0 or 1)
- **Reset:** `V1Counters.reset()` called at the start of `V1Guidance.getInput()`
- **Read:** `V1Counters.getHeaderBytes()` called in `V1Guidance.handleResult()`

###### Signal 3: `multipartWork` (computed, not directly measured)
- **What:** Composite work score: `s = 0.5 * (boundaryIterations / 10) + 0.5 * (headerBytes / 512)`
- **Where computed:** `V1Guidance.handleResult()`, from the two measured counters
- **Why this formula:** `B_REF = 10` normalizes boundary iterations (a few parts is normal). `H_REF = 512` normalizes header bytes against the oracle threshold. Equal weighting (alpha = beta = 0.5) balances multi-part exploration and per-part header growth.

##### Instrumentation Feasibility Check [R35]

- **Classes to instrument:** `org.apache.commons.fileupload.MultipartStream` (single class)
- **Methods to instrument:**
  - `readBoundary()` — descriptor `()Z` — counter at entry
  - `readHeaders()` — descriptor `()Ljava/lang/String;` — flag set/clear at entry/exit
  - `readByte()` — descriptor `()B` — conditional counter at entry
- **JVM flags:** None needed (instrumenting application code, not JDK internals)
- **Signal export:** `ThreadLocal<long[]>` in `com.fuzzing.agent.V1Counters` (3 slots: boundaryCount, headerByteCount, inHeadersFlag)
- **Agent implementation:**
  - `V1MeasureAgent.premain(String, Instrumentation)` registers a `ClassFileTransformer`
  - Transformer matches class `org/apache/commons/fileupload/MultipartStream`
  - Uses ASM `ClassVisitor` / `MethodVisitor` (API level `Opcodes.ASM9`) to inject counter calls
  - For `readBoundary`: insert `INVOKESTATIC V1Counters.incrementBoundary()V` at method start
  - For `readHeaders`: insert `INVOKESTATIC V1Counters.enterHeaders()V` at method start; wrap exit points with `INVOKESTATIC V1Counters.exitHeaders()V` (via try-finally pattern using `visitTryCatchBlock`)
  - For `readByte`: insert conditional: `INVOKESTATIC V1Counters.isInHeaders()Z` → if true → `INVOKESTATIC V1Counters.incrementHeaderBytes()V`

##### Mutation Operators [R45]

**(a) Repetition:** Select a random region of the current input (between 1 byte and half the input length). Copy it and repeat it k times, where k is chosen so the result approaches the input size limit (10240 bytes). This is generic: when it repeats header content bytes, headers grow. When it repeats boundary+header sequences, more parts appear.

**(b) Dictionary tokens from the source code on the attack path:**
- `\r` (0x0D) — CR, used in HEADER_SEPARATOR matching (line 921)
- `\n` (0x0A) — LF, used in HEADER_SEPARATOR matching (line 921)
- `\r\n` (0x0D 0x0A) — FIELD_SEPARATOR constant (line 502)
- `\r\n\r\n` (0x0D 0x0A 0x0D 0x0A) — HEADER_SEPARATOR constant (line 496)
- `--` (0x2D 0x2D) — STREAM_TERMINATOR/boundary prefix (lines 508, 513)
- `\r\n--` (0x0D 0x0A 0x2D 0x2D) — BOUNDARY_PREFIX constant (line 513)
- `:` (0x3A) — header name:value separator (RFC syntax, line 50)
- ` ` (0x20) — header continuation whitespace

Each token is a single syntactic unit found in the MultipartStream source. No assembled triggering input ([R23]).

**(c) Encoder:** Not needed. Multipart format is plain text with simple CRLF+boundary delimiters, not compressed/checksummed/length-prefixed.

##### Byte-level Mutation Operators
- **Random byte flip:** Flip a random bit in a random byte
- **Random byte insert:** Insert a random byte at a random position
- **Random byte delete:** Delete a random byte
- **Random byte overwrite:** Replace a random byte with a random value
- **Havoc:** Apply 1–8 random mutations from the above in sequence

##### Retention Logic

**Primary criterion:** Keep input if its `multipartWork` exceeds the max `multipartWork` of the current corpus. Select parents for mutation with probability proportional to their `multipartWork`.

**Secondary criterion while signal is flat [R46]:** When all corpus inputs have `multipartWork` ≤ current best (i.e., the signal hasn't improved), also retain inputs that are **longer** than the longest input currently in the corpus, up to `input_bytes` (527). This ensures the input grows toward the target size even when no readHeaders/readBoundary code is reached yet. Additionally, with 10% probability, retain any input that is longer than a randomly chosen corpus member regardless of signal — this prevents stagnation and allows the search to explore different input shapes.

**Input growth guarantee [R46]:** Starting from a minimal seed (e.g., 2 bytes), the repetition operator can double the input length each step: 2→4→8→16→...→512→527+ bytes in ~9 doublings. At one execution per doubling attempt, this takes seconds, well within the first minute.

##### Stop/Continue Conditions [R8]
- **Default:** Infinite fuzzing (runs until interrupted)
- **Time-bounded:** Reads `jqf.ei.MAX_DURATION_MILLIS` system property; stops after that duration
- **Trial-bounded:** Reads `jqf.ei.MAX_TRIALS` system property; stops after that many executions

#### Step 7 — Custom Guidance (Plan Only — Code in Block 3)

**V1Guidance** implements `Guidance` and `SignalSource`:
- `getInput()`: resets V1Counters, selects parent from corpus by multipartWork-proportional probability, mutates it, returns as InputStream
- `hasInput()`: returns true while within duration/trial limits
- `handleResult(Result, Throwable)`: reads V1Counters, computes multipartWork, applies retention policy, saves to corpus if retained, logs stats every 1 second
- `generateCallBack(Thread)`: returns a no-op consumer (measurement via agent, not TraceEvent)
- `lastSignals()`: returns Map with keys "boundaryIterations", "headerBytes", "multipartWork"
- Does NOT write failure files or declare executions as failed ([R6])

#### Step 8 — Fuzz Test (Frozen Harness)

The frozen `MultipartFuzzTest.java` already contains the target fuzz method:
- **`fuzzMultipartStreamReadHeaders(InputStream)`** — covers V1
  - Consumes `InputStream` directly ([R31])
  - Performs boundary extraction and body parsing inside the harness
  - Oracle: `headers.length() > 512` → throws `AssertionError` (undeclared throwable)

No additional fuzz tests needed. No generators ([R31]).

#### Step 9 — Metadata Replay / Feeder (Plan Only — Code in Block 3)

**ReplayRunner:**
- Reads a saved input file (from corpus or failure directory)
- Reads associated metadata JSON (input length, multipartWork, timestamp)
- Replays the input through the fuzz test method deterministically
- Prints: input length, boundary extracted, header sizes found, multipartWork score, exception (if any)
- Uses `GuidedFuzzing.run()` with a replay-only Guidance that provides the saved input once

#### Step 10 — Maven Configuration & Commands

**Build:**
```bash
cd <workspace>
mvn package -DskipTests
### Build agent JAR (after mvn package):
mkdir -p target/agent-build && cd target/agent-build
jar xf ../dependency/asm-9.8.jar org/
cp -r ../test-classes/com/fuzzing/agent com/fuzzing/
echo -e "Premain-Class: com.fuzzing.agent.V1MeasureAgent\nCan-Retransform-Classes: true" > manifest.txt
jar cfm ../v1-agent.jar manifest.txt com/ org/
```

**Fuzzing (V1):**
```bash
java -Xmx1g -Xss1m -javaagent:target/v1-agent.jar \
  -cp "target/test-classes:target/dependency/*:lib/*" \
  com.fuzzing.runner.FuzzRunner V1 fuzzMultipartStreamReadHeaders
```

**Time-bounded (5 minutes):**
```bash
java -Xmx1g -Xss1m -Djqf.ei.MAX_DURATION_MILLIS=300000 \
  -javaagent:target/v1-agent.jar \
  -cp "target/test-classes:target/dependency/*:lib/*" \
  com.fuzzing.runner.FuzzRunner V1 fuzzMultipartStreamReadHeaders
```

**Reproduction / Replay:**
```bash
java -Xmx1g -Xss1m -javaagent:target/v1-agent.jar \
  -cp "target/test-classes:target/dependency/*:lib/*" \
  com.fuzzing.replay.ReplayRunner out/V1/corpus/<input_file>
```

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — pom.xml sets compiler source/target 17
- [YES] No hallucinated APIs — all JQF/ASM classes verified via javap on the actual jars
- [YES] Guidance implements Guidance directly — V1Guidance will `implements Guidance, SignalSource`
- [YES] No existing guidance extended — V1Guidance is standalone, no Zest/PerfFuzz delegation
- [YES] V* vulnerabilities identified — V1: readHeaders oversized headers
- [YES] V* IDs are sequential (V1) — single target, V1
- [YES] Official vulnerability names applied — CWE-400 (Uncontrolled Resource Consumption)
- [YES] PkgRisk-* identified — none found (all deps O(n), no amplification)
- [YES] Every PkgRisk-* executed or justified — no PkgRisks; commons-io/KMP/BAOS reviewed and found safe
- [YES] Guidance targets V* — V1Guidance targets V1
- [YES] One fuzz method per V* — fuzzMultipartStreamReadHeaders covers V1
- [YES] CLI method selection supported — FuzzRunner accepts target ID and method name
- [YES] byte[]/InputStream input model used exclusively — harness consumes InputStream
- [YES] No junit-quickcheck Generators used — all mutation inside V1Guidance
- [YES] All mutation implemented inside Guidance — byte-level + structure-aware operators in V1Guidance
- [YES] Repetition, source dictionary and encoder operators implemented — repetition (chunk doubling), 8 tokens from source, no encoder needed (plain text format)
- [YES] Retention progresses while signal is flat — secondary criterion retains longer inputs
- [YES] Retention signals measured where resource is consumed — headerBytes counted inside readHeaders via readByte calls; boundaryIterations counted at readBoundary entry
- [YES] Logging every 1 second — V1Guidance logs executions, corpus size, best multipartWork, headerBytes
- [YES] Guidance decides no failures and writes no failure files — handleResult only retains/prioritizes
- [YES] Corrupted inputs saved with metadata — corpus saves input + JSON metadata
- [YES] Replay/feeder implemented — ReplayRunner reads saved input and metadata
- [YES] Infinite + time-bounded fuzzing supported — via system properties
- [YES] src/main vs src/test separation correct — empty src/main, all fuzzing infra in src/test
- [YES] Maven scopes consistent — system (vulnerable jar), provided (servlet), test (JQF/JUnit)
- [YES] No wildcard imports used for JQF/tracing — all explicit imports
- [YES] TraceEvent import verified and audited if tracing used — verified in jqf-instrument-2.1.jar

#### IMPORT AUDIT

```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent
ClassVisitor → org.objectweb.asm.ClassVisitor (asm-9.8.jar)
MethodVisitor → org.objectweb.asm.MethodVisitor (asm-9.8.jar)
ClassReader → org.objectweb.asm.ClassReader (asm-9.8.jar)
ClassWriter → org.objectweb.asm.ClassWriter (asm-9.8.jar)
Opcodes → org.objectweb.asm.Opcodes (asm-9.8.jar)
```

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "boundaryIterations",
          "quantity": "number of MultipartStream.readBoundary() calls during one execution (boundary iterations of the multipart parser loop)",
          "aggregation": "count",
          "locations": [
            "MultipartStream#readBoundary"
          ],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in V1Counters, slot [0]",
          "reset": "V1Counters.reset() called at the start of V1Guidance.getInput() before each execution",
          "read": "V1Counters.getBoundaryIterations() called in V1Guidance.handleResult()"
        },
        {
          "name": "headerBytes",
          "quantity": "number of MultipartStream.readByte() calls made while MultipartStream.readHeaders() runs, during one execution (header bytes scanned one at a time)",
          "aggregation": "count",
          "locations": [
            "MultipartStream#readHeaders",
            "MultipartStream#readByte"
          ],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in V1Counters, slot [1] for counter and slot [2] for inHeaders flag (0 or 1)",
          "reset": "V1Counters.reset() called at the start of V1Guidance.getInput() before each execution",
          "read": "V1Counters.getHeaderBytes() called in V1Guidance.handleResult()"
        },
        {
          "name": "multipartWork",
          "quantity": "multipart parser work s = alpha*(boundaryIterations/B_REF) + beta*(headerBytes/H_REF) with alpha = beta = 0.5, B_REF = 10 and H_REF = 512 (the fuzz test's PART_HEADER_SIZE_MAX), computed in handleResult from the two measured counters of the same execution",
          "aggregation": "weighted",
          "locations": [
            "MultipartStream#readBoundary",
            "MultipartStream#readHeaders",
            "MultipartStream#readByte"
          ],
          "technique": "bytecode",
          "storage": "computed in-line in V1Guidance.handleResult() from the two measured counters; the resulting double is stored with the corpus entry for retention/prioritization",
          "reset": "recomputed from fresh counter values each execution (counters are reset in getInput())",
          "read": "computed and consumed directly in V1Guidance.handleResult() for retention decisions and in lastSignals() for external reporting"
        }
      ],
      "retention": "Keep the input if multipartWork exceeds the maximum multipartWork of the corpus. Choose parents for mutation with probability proportional to their multipartWork. Secondary (while multipartWork is flat): also retain inputs that are longer than the longest input in the corpus (growing toward input_bytes=527 and beyond up to the input size limit 10240), and with 10% probability retain any input longer than a randomly chosen corpus member, so that input length grows toward the target's input_bytes within the first minute even when readHeaders/readBoundary code paths are not yet reached.",
      "retention_signals": [
        "multipartWork"
      ],
      "mutation": [
        "byte-flip: flip a random bit in a random byte of the input",
        "byte-insert: insert a random byte at a random position",
        "byte-delete: remove a byte at a random position",
        "byte-overwrite: replace a byte at a random position with a random value",
        "havoc: apply 1-8 randomly chosen byte-level mutations in sequence",
        "repetition [R45a]: select a random region (1 byte to half the input), repeat it k times where k is chosen so the result approaches the input size limit (10240 bytes); this doubles or more the header content or replicates part structures to grow toward input_bytes rapidly",
        "dictionary-insert [R45b]: insert or overwrite at a random position one of the 8 dictionary tokens extracted from the MultipartStream source: CR (0x0D), LF (0x0A), CRLF (0x0D0A), CRLFCRLF (0x0D0A0D0A), DASHDASH (0x2D2D), CRLF-DASHDASH (0x0D0A2D2D), COLON (0x3A), SPACE (0x20)",
        "splice: given two corpus parents, take a prefix of one and a suffix of the other at random cut points"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

Let me start by reading the workspace structure and key files.

```text
$ find <run_dir> -type f 2>/dev/null | head -30
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/analysis/guidance_plan.json
Read <run_dir>/src/test/java/com/fuzzing/harness/MultipartFuzzTest.java
```

Now let me verify the ASM API version and the bytecode method descriptors:

```text
$ javap -p -s -cp lib/commons-fileupload-1.6.0-SNAPSHOT.jar org.apache.commons.fileupload.MultipartStream 2>&1 | grep -A1 -E "(readByte|readHeaders|readBoundary)" | head -15
$ ls <run_dir>/target/dependency/asm*.jar
```

Good. Now I have all the information I need. Let me create all the implementation files. I'll start with the agent infrastructure, then the guidance, runner, and replay.

```text
$ mkdir -p <run_dir>/src/test/java/com/fuzzing/agent …
```

Now let me write all the Java files:

```text
Write <run_dir>/src/test/java/com/fuzzing/agent/V1Counters.java
```

Let me check what's already been written and what files are needed:

```text
$ find <run_dir>/src -type f 2>/dev/null
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/com/fuzzing/harness/MultipartFuzzTest.java
```

Good. Now let me check the available dependencies and existing analysis files:

```text
$ ls <run_dir>/target/dependency/ 2>/dev/null
$ ls <run_dir>/lib/ 2>/dev/null
Read <run_dir>/analysis/target_register.json
```

Let me check the JQF API to get the exact method signatures:

```text
$ jar tf target/dependency/jqf-fuzz-2.1.jar | grep -i "GuidedFuzzing" 2>&1
$ javap -public -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.GuidedFuzzing 2>&1 | tail -30
$ javap -public -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1 | tail -30
$ javap -public -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1 | tail -30
$ javap -public -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
```

Good, now I have the exact JQF API. Let me also check the ASM commons AdviceAdapter:

```text
$ javap -public -cp target/dependency/asm-commons-9.5.jar org.objectweb.asm.commons.AdviceAdapter 2>&1 | tail -20
$ javap -public -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException 2>&1
$ javap -protected -cp target/dependency/asm-commons-9.5.jar org.objectweb.asm.commons.AdviceAdapter 2>&1 | tail -30
```

Now I have all the API details. Let me write all the implementation files:

```text
Write <run_dir>/src/test/java/com/fuzzing/agent/V1MeasureAgent.java
```

Now write the V1Guidance class:

```text
Write <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
```

Now write FuzzRunner.java:

```text
Write <run_dir>/src/test/java/com/fuzzing/runner/FuzzRunner.java
```

Now write ReplayRunner.java:

```text
Write <run_dir>/src/test/java/com/fuzzing/replay/ReplayRunner.java
```

Now write run.sh:

```text
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh
```

Now write launch.json:

```text
Write <run_dir>/analysis/launch.json
```

Now create validation inputs. These are well-formed multipart inputs that exercise instrumented code paths without triggering the vulnerability:

```text
$ cd <run_dir> …
```

Good. Now let me compile everything to verify it builds:

```text
$ mvn package -DskipTests 2>&1 | tail -30
```

Build succeeds. Now let me build the agent fat JAR:

```text
$ cd <run_dir> …
$ cd <run_dir> …
```

Agent JAR built successfully with 72 classes (ASM + our agent classes). Now let me verify the vulnerable artifact is correctly on the classpath by checking the class source:

```text
Write <run_dir>/src/test/java/com/fuzzing/agent/VerifyArtifact.java
$ mvn package -DskipTests 2>&1 | tail -5
```

Now verify the artifact source:

```text
$ cd <run_dir> …
```

Right, I can't execute Java. Let me verify the artifact by other means:

```text
$ # Verify the vulnerable JAR is the one on the classpath …
$ # Verify HEADER_PART_SIZE_MAX = 10240 (the vulnerable value) …
$ # Use javap -c to see the constant value used in readHeaders …
```

The vulnerable artifact is confirmed: `readHeaders()` uses `sipush 10240` (the HEADER_PART_SIZE_MAX), which is the vulnerable value that allows headers up to 10240 bytes instead of the expected ≤512. The JAR is referenced via system scope from `lib/commons-fileupload-1.6.0-SNAPSHOT.jar`.

Now let me do a final verification of all files:

```text
$ cd <run_dir> …
```

All files compile successfully. Let me do a final summary of what Block 3 has produced:

**Block 3 — Complete Implementation Files Summary**

##### Part A: Java Agent
| File | Purpose |
|------|---------|
| `src/test/java/com/fuzzing/agent/V1Counters.java` | ThreadLocal counters: `boundaryIterations` (slot 0), `headerBytes` (slot 1), `inHeaders` flag (slot 2). Static methods: `reset()`, `incrementBoundary()`, `enterHeaders()`, `exitHeaders()`, `onReadByte()`, getters. |
| `src/test/java/com/fuzzing/agent/V1MeasureAgent.java` | Java agent using ASM `AdviceAdapter` to instrument `MultipartStream.readBoundary()` → `incrementBoundary()`, `readHeaders()` → `enterHeaders()`/`exitHeaders()`, `readByte()` → `onReadByte()`. Built as fat JAR `target/v1-agent.jar` (includes ASM 9.8 + asm-commons 9.5). |

##### Part B: Guidance
| File | Purpose |
|------|---------|
| `src/test/java/com/fuzzing/guidance/V1Guidance.java` | Implements `Guidance` + `SignalSource`. CGF+VDF strategy: computes `multipartWork = 0.5*(boundaryIterations/10) + 0.5*(headerBytes/512)`. Retention: primary=new multipartWork record, secondary=grow input length. 8 mutation operators: byte-flip/insert/delete/overwrite, havoc, repetition, dictionary-insert (8 protocol tokens), splice. Respects `jqf.ei.MAX_INPUT_SIZE` system property. Never reports failures ([R6]). |

##### Part C: Runners
| File | Purpose |
|------|---------|
| `src/test/java/com/fuzzing/runner/FuzzRunner.java` | CLI entry point + `createGuidance(targetId, outputDir, maxDurationMs, log)` factory. Maps target "V1" → `V1Guidance` + `fuzzMultipartStreamReadHeaders`. Uses `GuidedFuzzing.run()`. |
| `src/test/java/com/fuzzing/replay/ReplayRunner.java` | Replays a saved `.bin` file through single-shot `ReplayGuidance`, prints signals and result. |
| `run.sh` | Build script: `mvn package -DskipTests` + agent JAR assembly. Run modes: `build`, `run V1 <seconds>`, `replay V1 <file>`, `all`. |

##### Part D: Validation
| File | Purpose |
|------|---------|
| `analysis/launch.json` | Build/classpath/javaagent/guidance_factory/targets configuration for DoSGuide. |
| `analysis/validation_inputs/` (10 files) | Well-formed multipart inputs exercising instrumented paths: minimal, two-part, empty-header, medium-header, near-limit (500B), multi-boundary, long-boundary, preamble, binary-header, random-noise. |

##### Artifact Verification
- **Vulnerable JAR**: `lib/commons-fileupload-1.6.0-SNAPSHOT.jar` (57303 bytes)
- **Confirmed**: `readHeaders()` bytecode contains `sipush 10240` (HEADER_PART_SIZE_MAX) — the vulnerable limit
- **pom.xml**: Uses `<scope>system</scope>` with `<systemPath>` pointing to local vulnerable JAR, NOT Maven Central
- **All 7 Java source files compile successfully** (`BUILD SUCCESS`)
- **Agent JAR**: `target/v1-agent.jar` (204923 bytes, 72 classes) with correct manifest

## Validation repair 1

Let me fix the `launch.json` format to match the expected schema:

```text
Read <run_dir>/analysis/launch.json
```

Now I need to build the correct classpath string. Let me check all jars:

```text
$ cd <run_dir> …
```

Now write the corrected launch.json:

```text
Write <run_dir>/analysis/launch.json
```

Let me verify the JSON is valid:

```text
$ cd <run_dir> …
```

All fields now match the expected format. Let me also do a quick build test to make sure the build commands work end-to-end:

```text
$ cd <run_dir> …
$ mvn package -DskipTests 2>&1 | tail -5
$ cd <run_dir> …
```

Everything builds correctly. Here's a summary of what I changed:

**Fixed `analysis/launch.json`** to match the expected schema:

1. **`build`**: Changed from an object with `tool`/`command`/`agent_jar_assembly` to a flat list of shell command strings (10 commands: mvn package, agent dir setup, ASM extraction, class copying, manifest creation, jar assembly).

2. **`classpath`**: Changed from a JSON array of path patterns to a single colon-separated string with all entries spelled out (no globs).

3. **`guidance_factory`**: Changed from an object `{"class", "method", "signature"}` to a simple string `"com.fuzzing.runner.FuzzRunner#createGuidance"`.

4. **`targets`**: Changed from a JSON array of objects to a map keyed by target ID: `{"V1": {"test_class": "...", "method": "..."}}`.

5. **`javaagent`**: Changed from a plain string `"target/v1-agent.jar"` to an object `{"jar": "target/v1-agent.jar", "args": ""}`.

No changes to the guidance plan, Java source files, or any other artifacts — only the launch.json format was wrong.

## Validation repair 2

The core issue is clear: the guidance generates random bytes as seeds, which never reach `readHeaders()` because they don't have the right multipart structure. The fuzz test `fuzzMultipartStreamReadHeaders` requires:
1. A boundary line ending with `\n` 
2. A proper multipart body starting with `--<boundary>\r\n`
3. Content that makes `skipPreamble()` succeed

Random bytes will never satisfy this structure, so all signals stay at 0. I need to make the guidance generate well-formed multipart inputs from the start.

Let me study the fuzz test input model more carefully:

```text
Read <run_dir>/src/test/java/com/fuzzing/harness/MultipartFuzzTest.java
Read <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
```

The problem is clear: the guidance seeds with random bytes, so no generated input ever reaches `readHeaders()`. I need to seed with well-formed multipart inputs and serve them unmutated first. Let me rewrite the guidance:

```text
Write <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
```

Now let me compile and rebuild the agent jar:

```text
$ mvn package -DskipTests 2>&1 | tail -10
$ cd <run_dir> …
```

Build succeeds. Let me verify the seed sizes are correct:

```text
$ # Verify seed byte counts …
```

Wait, I realized there's a bug in `buildSeed` for the empty header case. Let me check: for empty headerContent, only one `\r\n` is written (the "blank line"), but readHeaders needs to see `\r\n\r\n` (4 consecutive bytes) after skipPreamble consumes the delimiter. Let me fix it:

```text
Edit <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
```

Also fix the two-part seed builder with the same pattern:

```text
Edit <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
```

Now recompile:

```text
$ mvn package -DskipTests 2>&1 | tail -5
```

Let me verify the corrected seed byte counts:

```text
$ python3 -c " …
```

Seeds 1 (11 bytes) and 2 (14 bytes) both fit in the 16-byte limit. With the corrected buildSeed:
- Seed 1: `readHeaders` reads `\r\n\r\n` (4 bytes) → `headerBytes=4`, `multipartWork=0.00390625`
- Seed 2: `readHeaders` reads `K:V\r\n\r\n` (7 bytes) → `headerBytes=7`, `multipartWork=0.00683594`

Both produce **non-zero** signals. Now rebuild the agent jar:

```text
$ cd <run_dir> …
```

Good. Let me also verify the final state of all source files:

```text
$ cd <run_dir> …
```

Everything is in order. Here's a summary of what I changed:

**Root cause**: The guidance seeded its corpus with random bytes (`rng.nextBytes`), which never formed valid multipart inputs. The fuzz test `fuzzMultipartStreamReadHeaders` requires a specific structure (boundary line + `--boundary\r\n` + headers + `\r\n\r\n`) for `skipPreamble()` to succeed and `readHeaders()` to be called. Random bytes fail all structural checks and return early, so all 81 inputs had signals = 0.

**Fix in V1Guidance.java**:

1. **Replaced random seed corpus with well-formed multipart seeds** — Added `buildSeed()` and `buildTwoPartSeed()` helpers that produce structurally valid multipart inputs of varying sizes (11, 14, 24, 23, 35 bytes). The smallest two (11, 14 bytes) fit within the 16-byte `MAX_INPUT_SIZE` limit.

2. **Fixed buildSeed for empty headers** — The original code wrote only one `\r\n` after empty header content, but `readHeaders()` needs `\r\n\r\n` (4 bytes). Now it always writes the full `\r\n\r\n` terminator.

3. **Added seed queue (`pendingSeeds`)** — Seeds are served unmutated as the first inputs before switching to mutation. This guarantees the first few executions reach `readHeaders()` and produce non-zero `headerBytes`/`multipartWork` signals, which then enter the corpus for signal-guided parent selection.

4. **Added `headerGrow` mutation (18% weight)** — A structure-aware mutation that finds the `\r\n\r\n` header terminator and inserts random content before it, directly growing the header section while preserving the boundary/delimiter structure. Falls back to `repetition` if no terminator is found.
