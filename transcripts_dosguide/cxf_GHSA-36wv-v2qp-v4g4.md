# cxf_GHSA-36wv-v2qp-v4g4

## Block 1

I'll start by reading the target source file, the frozen fuzz test harness, and the workspace pom.xml to understand the setup.

```text
Read <source_root>/core/src/main/java/org/apache/cxf/io/DelayedCachedOutputStreamCleaner.java
Glob <run_dir> *FuzzTest.java
Glob <run_dir> pom.xml
Read <run_dir>/src/test/java/org/apache/cxf/io/fuzz/CachedOutputStreamFuzzTest.java
Read <run_dir>/pom.xml
```

Now let me explore the CachedOutputStream and related classes to understand the vulnerability mechanism.

```text
Glob <source_root>/core/src/main/java/org/apache/cxf/io **/org/apache/cxf/io/CachedOutputStream.java
Glob <source_root>/core/src/main/java/org/apache/cxf/io *.java
Read <source_root>/core/src/main/java/org/apache/cxf/io/CachedOutputStream.java
```

Now let me look at additional classes to understand the full vulnerability path.

```text
Read <source_root>/core/src/main/java/org/apache/cxf/io/CachedConstants.java
Read <source_root>/core/src/main/java/org/apache/cxf/io/CachedOutputStreamCleaner.java
Read <source_root>/core/src/main/java/org/apache/cxf/io/AbstractThresholdOutputStream.java
```

Let me look at the helpers used in the toString path, and check if there are any additional classes I need to understand.

```text
Grep <source_root>/core/src/main/java class LoadingByteArrayOutputStream
Grep <source_root>/core/src/main/java public static.*newStringFromBytes
Read <source_root>/core/src/main/java/org/apache/cxf/helpers/LoadingByteArrayOutputStream.java
```

Let me verify the vulnerable jar exists in the workspace lib directory:

```text
$ ls -la <run_dir>/lib/ 2>&1
```

Good, the vulnerable jar exists. Now let me verify that the `CachedOutputStream.toString()` method is indeed the vulnerability in this jar, and understand the full mechanism. Let me also check if there are any other fuzz methods or interesting paths I should consider.

```text
Read <source_root>/core/src/main/java/org/apache/cxf/io/CachedOutputStream.java
```

Now I have a thorough understanding of the vulnerability. Let me create the scale measurement directory and files.

```text
$ mkdir -p <run_dir>/analysis/scale/V1
$ cd <run_dir>/analysis/scale/V1 && python3 -c " …
Write <run_dir>/analysis/scale/V1/series.json
```

Now let me verify the files are correct:

```text
$ ls -la <run_dir>/analysis/scale/V1/
```

All files are in place. Now let me produce the complete analysis and target register.

---

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: Unbounded Content in CachedOutputStream.toString() Leaked into Cleaner Log Messages

**Source file**: `core/src/main/java/org/apache/cxf/io/CachedOutputStream.java` (toString, lines 423–433) and `core/src/main/java/org/apache/cxf/io/DelayedCachedOutputStreamCleaner.java` (clean, line 122)

**Fuzzable entrypoint & user-controlled input**: The fuzz test `fuzzCachedOutputStreamCleanerForceClean(InputStream)` writes the entire input to a `CachedOutputStream` under a Bus with a spill threshold of 1024 bytes. The COS is intentionally left unclosed. Then `forceClean()` is called on the bus's `DelayedCachedOutputStreamCleaner`.

**Attack path (call chain)**:

1. `CachedOutputStreamFuzzTest.fuzzCachedOutputStreamCleanerForceClean(InputStream)` — receives raw bytes from fuzzer
2. `InputStream.transferTo(CachedOutputStream)` → `CachedOutputStream.write(byte[], int, int)` — writes all input bytes
3. `CachedOutputStream.enforceLimits()` — checks `totalLength > threshold` (threshold = 1024)
4. `CachedOutputStream.createFileOutputStream()` — spills content to temp file, calls `cachedOutputStreamCleaner.register(this)`
5. `DelayedCachedOutputStreamCleaner.forceClean()` → `DelayedCleanerImpl.forceClean()` → `DelayedCleanerImpl.clean(Collection<DelayedCloseable>)`
6. At line 122: `LOG.warning("Unclosed (leaked?) stream detected: " + next.closeable)` — Java's `+` operator calls `CachedOutputStream.toString()`
7. `CachedOutputStream.toString()` builds a StringBuilder, then calls `writeCacheTo(builder)` → `writeCacheTo(builder, "UTF-8")`
8. `CachedOutputStream.writeCacheTo(StringBuilder, String)` (lines 385–409) — when `inmem == false`, opens the temp file with `createInputStream(tempFile)`, reads the **entire file content** into the StringBuilder via a 1024-char buffer loop. No size limit is applied.

**Sink**: `CachedOutputStream#writeCacheTo(StringBuilder, String)` — reads the entire cached content (from file or memory) into a StringBuilder without any size bound.

**Mechanism**: When the input exceeds the spill threshold (1024 bytes in the test bus), `CachedOutputStream` writes content to a temp file and registers itself with the bus's `DelayedCachedOutputStreamCleaner`. When `forceClean()` runs, the cleaner iterates registered streams and logs a warning for each. The log message uses string concatenation with the stream object, triggering `CachedOutputStream.toString()`, which reads the **entire cached content** back from the temp file into a `StringBuilder`. The resulting log message grows linearly with the input size. The fuzz test's assertion checks that no log message exceeds 1024 characters. Any input > 1024 bytes triggers the spill, and since the resulting log message length ≈ 85 (prefix/suffix) + content_length, which for any content > 1024 bytes far exceeds the 1024-char assertion threshold, the test throws `AssertionError` (an undeclared throwable — the method declares only `throws IOException`).

**Resource exhausted**: Heap memory — the StringBuilder allocation grows linearly with input size (one char per content byte for ASCII; the full content is duplicated into a String for the log message). At real-world scale (no input limit, no assertion), the String from `toString()` would exhaust the JVM heap. In the test, the assertion fires first.

**Failure mode**: `out_of_memory` — the fundamental resource is heap memory consumed by the unbounded StringBuilder/String creation. Under the test's evaluation limits (10240 byte input, 1GB heap), the concrete failure is an `AssertionError` (undeclared throwable) that fires when log messages exceed 1024 characters, before actual OOM occurs. This assertion is the harness's detection mechanism for the memory amplification vulnerability.

**Scale estimate**:
- Spill threshold: 1024 bytes. Input must be > 1024 bytes for the COS to spill to file and register with the cleaner.
- The log message length = "Unclosed (leaked?) stream detected: " (37 chars) + "[org.apache.cxf.io.CachedOutputStream Content: " (47 chars) + content_length + "]" (1 char) = 85 + content_length chars.
- For 1025 bytes of content: message = 1110 chars > 1024 → assertion fires.
- For real OOM with 1GB heap: the String + StringBuilder would need ~500M chars → ~500MB of content. Unachievable with 10240 byte input limit.
- But the assertion-based failure is trivially achievable: input_bytes ≥ 1025.

**input_bytes**: 1025

##### 1.2 Official Classification

**V1**: 
- **CWE-400**: Uncontrolled Resource Consumption — the `toString()` method creates an unbounded string from the full cached content, consumed by the cleaner's logging code.
- **CWE-770**: Allocation of Resources Without Limits or Throttling — no size limit on the StringBuilder/String created by `toString()`.
- Primary: **CWE-400**

##### 1.3 Dependency / Package-Level Risks

After thorough analysis, there are no significant package-level DoS risks for the code paths exercised by the frozen harness:

1. **java.util.logging.Logger**: The logging framework is used to emit the unbounded message, but the Logger itself does not amplify — it's the content being logged that's the problem. The custom log handler in the fuzz test just stores strings in a List. No DoS risk in the logger.

2. **java.lang.StringBuilder**: Used by `toString()` to accumulate the content. This is the allocation mechanism, but it's a direct linear copy — no amplification beyond the content size. It's part of V1's mechanism, not a separate risk.

3. **java.io.File / java.nio.file**: File I/O for temp file creation and reading. Bounded by input size (max 10240 bytes). No amplification.

4. **java.util.concurrent.DelayQueue**: Used by the cleaner for scheduling. The queue operations (put, drain, iterate) are O(n) where n is the number of registered items. In the fuzz test, only one COS is registered per execution. No DoS risk.

5. **javax.crypto.Cipher**: CipherTransformation is null in the test bus (not set), so no cipher code path is exercised. N/A.

No PkgRisk items are justified for separate targets — the vulnerability is entirely in the CXF code path (V1).

##### 1.8 Zest Baseline Comparison [R18]

**Why Zest underperforms on V1**: Zest optimizes for code coverage. The critical transition in V1 is the spill threshold at 1024 bytes. Once Zest discovers an input that covers the spill path and the clean path, it has no incentive to grow the input further. It may find the bug incidentally (any input > 1024 bytes triggers it), but Zest's retention signal (new coverage) doesn't prioritize input size growth. A custom Guidance that measures allocation size in the `writeCacheTo(StringBuilder)` path will systematically prefer larger inputs that amplify the memory consumption, and will grow inputs toward the maximum size limit.

**Measurable metric**: A custom Guidance should reliably trigger the assertion failure (input > 1024 bytes) within fewer trials than Zest by prioritizing inputs that grow toward and past the spill threshold, using allocation byte count as the retention signal.

---

#### PHASE B — Target Selection

The only DoS target found in the analysis is V1. The other three fuzz methods (`fuzzCachedOutputStreamWriteRange`, `fuzzCachedOutputStreamToString`, `fuzzCachedOutputStreamWriteChunks`) do not set the thread default bus, use the default 128KB threshold (unreachable with 10240-byte input limit), and have no assertion checks — they cannot produce DoS failures within the evaluation limits.

No PkgRisk items warrant separate targets.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unbounded CachedOutputStream.toString() in cleaner log messages",
      "entrypoint": "CachedOutputStreamFuzzTest.fuzzCachedOutputStreamCleanerForceClean(InputStream) → CachedOutputStream.write(byte[], int, int) → CachedOutputStream.enforceLimits() → CachedOutputStream.createFileOutputStream() → DelayedCachedOutputStreamCleaner.forceClean() → DelayedCleanerImpl.clean(Collection) → CachedOutputStream.toString() → CachedOutputStream.writeCacheTo(StringBuilder, String)",
      "source_path": "core/src/main/java/org/apache/cxf/io/CachedOutputStream.java",
      "sink": "CachedOutputStream#writeCacheTo(StringBuilder, String)",
      "mechanism": "When content exceeds the 1024-byte spill threshold, CachedOutputStream spills to a temp file and registers with the cleaner. forceClean() logs a warning that string-concatenates the COS object, triggering toString() which reads the entire file content into a StringBuilder without any size limit. The resulting log message grows linearly with input size.",
      "resource": "heap memory: StringBuilder char[] allocation grows linearly with content bytes (one char per byte for ASCII content)",
      "failure_mode": "out_of_memory",
      "scale": "Input > 1024 bytes triggers file spill and cleaner registration. The log message length = 85 + content_length chars. Any input > 1024 bytes produces a log message > 1024 chars, triggering the harness assertion (AssertionError, an undeclared throwable). Minimum triggering input: 1025 bytes. At real-world scale (no input cap), the unbounded String creation would exhaust the heap.",
      "input_bytes": 1025,
      "cwe": "CWE-400"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

Let me re-read the relevant source to trace the correct call path from the fuzz method to the sink.

```text
Read <run_dir>/src/test/java/org/apache/cxf/io/fuzz/CachedOutputStreamFuzzTest.java
Read <source_root>/core/src/main/java/org/apache/cxf/io/DelayedCachedOutputStreamCleaner.java
Read <source_root>/core/src/main/java/org/apache/cxf/io/DelayedCachedOutputStreamCleaner.java
Read <source_root>/core/src/main/java/org/apache/cxf/io/CachedOutputStream.java
```

Now I understand the issue. The original path incorrectly chained `createFileOutputStream()` → `forceClean()` — these are separate calls from the fuzz method, not a caller-callee chain. The write path is a setup precondition; the actual attack path from entry to sink goes directly from the fuzz method to `forceClean()`.

The corrected path:
1. `fuzzCachedOutputStreamCleanerForceClean` directly calls `DelayedCachedOutputStreamCleaner.forceClean()` at line 94
2. `forceClean()` (line 253) delegates to `cleaner.forceClean()` → `DelayedCleanerImpl.forceClean()` (line 106) → `clean(queue)` (line 107)
3. `clean(Collection)` (line 116) does string concatenation at line 122: `"..." + next.closeable` → implicit call to `CachedOutputStream.toString()`
4. `toString()` (line 423) calls `writeCacheTo(builder)` (line 428) → `writeCacheTo(builder, "UTF-8")` (line 382)
5. `writeCacheTo(StringBuilder, String)` (line 385) reads entire file content into StringBuilder

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unbounded CachedOutputStream.toString() in cleaner log messages",
      "entrypoint": "CachedOutputStreamFuzzTest.fuzzCachedOutputStreamCleanerForceClean(InputStream) → DelayedCachedOutputStreamCleaner.forceClean() → DelayedCleanerImpl.clean(Collection) → CachedOutputStream.toString() → CachedOutputStream.writeCacheTo(StringBuilder, String)",
      "source_path": "core/src/main/java/org/apache/cxf/io/CachedOutputStream.java",
      "sink": "CachedOutputStream#writeCacheTo(StringBuilder, String)",
      "mechanism": "When content exceeds the 1024-byte spill threshold, CachedOutputStream spills to a temp file and registers with the cleaner. forceClean() logs a warning that string-concatenates the COS object, triggering toString() which reads the entire file content into a StringBuilder without any size limit. The resulting log message grows linearly with input size.",
      "resource": "heap memory: StringBuilder char[] allocation grows linearly with content bytes (one char per byte for ASCII content)",
      "failure_mode": "out_of_memory",
      "scale": "Input > 1024 bytes triggers file spill and cleaner registration. The log message length = 85 + content_length chars. Any input > 1024 bytes produces a log message > 1024 chars, triggering the harness assertion (AssertionError, an undeclared throwable). Minimum triggering input: 1025 bytes. At real-world scale (no input cap), the unbounded String creation would exhaust the heap.",
      "input_bytes": 1025,
      "cwe": "CWE-400"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

#### Analysis of V1 Measurements

**Below threshold (64–1024 bytes):** Flat at ~204 KB allocation, ~4 ms CPU, 1.0 MB peak heap. The COS stays in-memory; no file spill, no cleaner interaction, no `toString()` of content.

**Above threshold (2048 bytes):** Allocation jumps to 436.4 KB (+232 KB over baseline), peak heap doubles to 2.0 MB, CPU rises to 9.7 ms. This reflects the file spill path activating: temp file creation, BufferedOutputStream, and the `toString()` → `writeCacheTo(StringBuilder)` chain that reads the full content back into a StringBuilder + String.

**Growth per content byte above threshold:** With only one data point above threshold, the 232 KB extra at 2048 bytes includes both fixed overhead (temp file, stream buffers, ~200 KB) and content-proportional cost (StringBuilder char[] + String ≈ 2 × 2048 chars × 2 bytes/char ≈ 8 KB, plus log message string overhead). The per-byte marginal cost is modest (~4 bytes/input-byte for the char duplication).

**Extrapolation to max input (10240 bytes):** Fixed overhead (~200 KB) + content allocation (~10240 × 4 bytes ≈ 40 KB) + baseline (204 KB) ≈ 444 KB total. Peak heap ~3–4 MB. With 1 GB heap, actual OutOfMemoryError is unreachable at the 10240-byte input size limit.

**Failure mechanism confirmed:** The failure is the harness's `AssertionError` (an undeclared throwable — the method declares only `throws IOException`), triggered when any cleaner log message exceeds 1024 characters. The log message length = ~85 (prefix) + content_length chars. Since the spill threshold is 1024 bytes and any spilled input produces a message of 1024 + 85 = 1109+ chars > 1024, the assertion fires for every input > 1024 bytes. The encoding is already maximally dense: one raw byte per content byte.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: allocation is flat at 204 KB for inputs ≤1024 bytes (below spill threshold). At 2048 bytes, allocation jumps to 436 KB (fixed overhead ~200 KB for temp file/streams + ~4 bytes per content byte for StringBuilder/String duplication in toString()). Extrapolating to 10240-byte max input: ~500 KB total allocation, ~4 MB peak heap — far below the 1 GB heap limit, so actual OutOfMemoryError is unreachable. The concrete failure is the harness's AssertionError (undeclared throwable): any input > 1024 bytes triggers file spill, and the cleaner's log message (85 + content_length chars) always exceeds the 1024-char assertion threshold. Minimum triggering input: 1025 raw bytes.",
    "input_bytes": 1025
  }
}
END_SCALE_REVISION_JSON

## Block 2

Let me start by reading the workspace structure and existing files, then plan the measurement strategy.

```text
Glob <run_dir> **/*
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/org/apache/cxf/io/fuzz/CachedOutputStreamFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Let me verify the existing pom.xml compiles correctly and check for ASM availability through transitive deps:

```text
$ ls -la lib/
$ mvn compile 2>&1 | tail -30
```

Good. Now let me check that ASM is available transitively and verify the test classpath:

```text
$ mvn dependency:tree -Dscope=test 2>&1 | tail -50
$ mvn dependency:tree 2>&1 | tail -60
```

Good - ASM 9.8 (`asm`), ASM 9.5 (`asm-commons`, `asm-tree`) are all available transitively. Now let me verify the exact method signature in the vulnerable jar to plan instrumentation:

```text
$ jar tf <run_dir>/lib/cxf-core-4.1.1-SNAPSHOT.jar | head -20
$ javap -p -s <run_dir>/lib/cxf-core-4.1.1-SNAPSHOT.jar\!/org/apache/cxf/io/CachedOutputStream.class 2>/dev/null || (cd /tmp && jar xf <run_dir>/lib/cxf-core-4.1.1-SNAPSHOT.jar org/apache/cxf/io/CachedOutputStream.class && javap -p -s org/apache/cxf/io/CachedOutputStream.class 2>&1 | head -80)
$ cd /tmp && javap -p -s org/apache/cxf/io/CachedOutputStream.class 2>&1 | grep -A1 'writeCacheTo\|toString'
```

Let me verify the test classpath compiles correctly:

```text
$ mvn compile test-compile 2>&1 | tail -20
$ mvn compile 2>&1 | tail -20
```

Now let me also re-read the source of `writeCacheTo` to confirm the exact loop structure I need to instrument:

```text
Read <source_root>/core/src/main/java/org/apache/cxf/io/CachedOutputStream.java
```

Now I have all the information needed. Let me verify the existing workspace directory structure and check for `jqf-fuzz` API availability:

```text
$ mvn package -DskipTests 2>&1 | tail -30
$ ls <run_dir>/target/dependency/ | grep -i asm
$ jar tf <run_dir>/target/dependency/jqf-fuzz-2.1.jar | grep -E 'guidance/(Guidance|Result|GuidanceException)\.class$'
$ jar tf <run_dir>/target/dependency/jqf-fuzz-2.1.jar | grep -E 'GuidedFuzzing\.class$'
```

Now let me verify the Guidance interface's method signatures to plan correctly:

```text
$ cd /tmp && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class edu/berkeley/cs/jqf/fuzz/guidance/Result.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class 2>&1
$ cd /tmp && javap -p edu/berkeley/cs/jqf/fuzz/guidance/Result.class 2>&1
$ cd /tmp && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class && javap -p edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1 | head -30
```

Now I have all the information I need. The pom.xml is correct as-is — the `systemPath` resolves, compilation succeeds, all transitive dependencies including ASM are available. No changes needed to pom.xml.

Now let me produce the complete strategy document and guidance plan.

---

#### Step 2 — Maven Layout & Scope

The existing pom.xml is correct and needs no changes:
- **Vulnerable artifact**: `lib/cxf-core-4.1.1-SNAPSHOT.jar` as `system` scope ✓
- **Transitive deps**: jakarta.annotation-api, jaxb-runtime, woodstox-core, etc. — all in `compile` scope ✓
- **JQF/test deps**: jqf-fuzz, jqf-instrument, junit-quickcheck-core, junit — all in `test` scope ✓
- **ASM**: Available transitively via jqf-instrument (asm 9.8) and jacoco (asm-commons 9.5, asm-tree 9.5) ✓
- **No SLF4J binding**: Only slf4j-api 1.7.25 (from quickcheck), no binding jar → CXF uses j.u.l. ✓

Layout:
```
src/main/java/         — empty (no stubs needed)
src/test/java/         — all fuzzing infra
  org/apache/cxf/io/fuzz/CachedOutputStreamFuzzTest.java  (FROZEN)
  dosguide/validate/SignalSource.java                      (FROZEN)
  com/fuzzing/agent/V1MeasureAgent.java
  com/fuzzing/agent/V1Counters.java
  com/fuzzing/guidance/V1Guidance.java
  com/fuzzing/runner/FuzzRunner.java
  com/fuzzing/runner/ReplayRunner.java
lib/
  cxf-core-4.1.1-SNAPSHOT.jar  (FROZEN vulnerable artifact)
pom.xml                        (FROZEN canonical build)
```

#### Step 3 — Compilation Closure / Missing Symbol Audit

##### 3.1 Missing Symbol Audit

All symbols used by the frozen fuzz test come from declared dependencies:

| Symbol | Source | Classification |
|--------|--------|---------------|
| `org.apache.cxf.Bus` | cxf-core-4.1.1-SNAPSHOT.jar (system) | Already provided ✓ |
| `org.apache.cxf.BusFactory` | cxf-core-4.1.1-SNAPSHOT.jar (system) | Already provided ✓ |
| `org.apache.cxf.common.logging.LogUtils` | cxf-core-4.1.1-SNAPSHOT.jar (system) | Already provided ✓ |
| `org.apache.cxf.io.CachedConstants` | cxf-core-4.1.1-SNAPSHOT.jar (system) | Already provided ✓ |
| `org.apache.cxf.io.CachedOutputStream` | cxf-core-4.1.1-SNAPSHOT.jar (system) | Already provided ✓ |
| `org.apache.cxf.io.CachedOutputStreamCleaner` | cxf-core-4.1.1-SNAPSHOT.jar (system) | Already provided ✓ |
| `org.apache.cxf.io.DelayedCachedOutputStreamCleaner` | cxf-core-4.1.1-SNAPSHOT.jar (system) | Already provided ✓ |
| `edu.berkeley.cs.jqf.fuzz.Fuzz` | jqf-fuzz-2.1.jar (test) | Already provided ✓ |
| `edu.berkeley.cs.jqf.fuzz.JQF` | jqf-fuzz-2.1.jar (test) | Already provided ✓ |

Symbols needed by the custom Guidance / Agent / Runner (all available):

| Symbol | Source | Classification |
|--------|--------|---------------|
| `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` | jqf-fuzz-2.1.jar (test) | (A) External lib ✓ |
| `edu.berkeley.cs.jqf.fuzz.guidance.Result` | jqf-fuzz-2.1.jar (test) | (A) External lib ✓ |
| `edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException` | jqf-fuzz-2.1.jar (test) | (A) External lib ✓ |
| `edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing` | jqf-fuzz-2.1.jar (test) | (A) External lib ✓ |
| `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` | jqf-instrument-2.1.jar (test) | (A) External lib ✓ |
| `org.objectweb.asm.ClassReader` | asm-9.8.jar (transitive via jqf-instrument) | (A) External lib ✓ |
| `org.objectweb.asm.ClassVisitor` | asm-9.8.jar (transitive) | (A) External lib ✓ |
| `org.objectweb.asm.ClassWriter` | asm-9.8.jar (transitive) | (A) External lib ✓ |
| `org.objectweb.asm.MethodVisitor` | asm-9.8.jar (transitive) | (A) External lib ✓ |
| `org.objectweb.asm.Opcodes` | asm-9.8.jar (transitive) | (A) External lib ✓ |
| `org.objectweb.asm.commons.AdviceAdapter` | asm-commons-9.5.jar (transitive via jacoco) | (A) External lib ✓ |

##### 3.2 Stub Generation

**No stubs needed.** All symbols resolve from declared dependencies or the vulnerable jar.

##### 3.3 Stub Report

None. Every symbol used in the project (both the frozen harness and the planned custom infra) is resolved from:
- The vulnerable jar `lib/cxf-core-4.1.1-SNAPSHOT.jar` (CXF classes)
- Maven Central test-scope dependencies (JQF, JUnit, ASM)
- The JDK (java.io, java.util, java.lang.instrument, etc.)

---

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic Explanation) | Why This Strategy Wins |
|--------|-------------------|------------------------------------------|------------------------|
| V1 | Cost-Gradient Guidance (CGF) | Zest optimizes for code coverage. Once it covers the spill path (`enforceLimits` → `createFileOutputStream`) and the clean path (`forceClean` → `clean` → `toString` → `writeCacheTo`), no NEW branches are discovered as input grows. Coverage saturates at ~1025 bytes; Zest has zero incentive to retain larger inputs or continue growing. Its proxy signal (coverage) is uncorrelated with the actual vulnerability severity (unbounded allocation). | CGF hill-climbs `charsAppended` — the number of chars actually appended to the StringBuilder in `writeCacheTo(StringBuilder, String)`, which is the exact allocation at the sink. It retains inputs whose measured allocation exceeds the current best, directly rewarding inputs that cross the 1024-byte spill threshold. While the signal is flat (below-threshold inputs), it keeps longer inputs as a secondary criterion so the search grows toward the threshold. Repetition operators double chunks rapidly to cross 1024 bytes. |

#### Step 6 — Strategy-Specific Guidance Design

##### Measurement Plan for V1

**Signal: `charsAppended`**

| Aspect | Detail |
|--------|--------|
| **What** | Total characters appended to the StringBuilder during `CachedOutputStream.writeCacheTo(StringBuilder, String)` |
| **Why this corresponds to the DoS mechanism** | This method is the sink where the unbounded content is materialized into a String. When called from `toString()` during cleaner logging, it reads the *entire* cached content into a StringBuilder. The number of chars appended directly measures the log message amplification that triggers the harness's assertion. |
| **Where produced** | Java agent bytecode instrumentation of `org.apache.cxf.io.CachedOutputStream#writeCacheTo(StringBuilder, String)` — the ASM `AdviceAdapter` captures `StringBuilder.length()` at method entry and exit |
| **How stored** | `ThreadLocal<long[]>` in `V1Counters` class: index 0 = entry length, index 1 = chars appended |
| **Where reset** | `V1Counters.reset()` called in `V1Guidance.getInput()` before each execution |
| **Where consumed** | `V1Guidance.handleResult(Result, Throwable)` reads `V1Counters.getCharsAppended()` to decide retention |

##### Instrumentation Feasibility Check [R35]

1. **Exact class/method to instrument**: `org.apache.cxf.io.CachedOutputStream`, method `writeCacheTo`, descriptor `(Ljava/lang/StringBuilder;Ljava/lang/String;)V`
2. **JVM flags**: None special — CXF classes are not in `java.base`; they're in the application classloader, freely instrumentable.
3. **Signal export**: `V1Counters` class with static `ThreadLocal<long[]>` and static methods `onEntry(StringBuilder)` and `onExit(StringBuilder)` callable from injected bytecode.
4. **Agent implementation plan**:
   - `V1MeasureAgent.premain(String, Instrumentation)` registers a `ClassFileTransformer`
   - Transformer matches class name `org/apache/cxf/io/CachedOutputStream`
   - Uses ASM `ClassReader` → `ClassVisitor` → `ClassWriter` pipeline
   - For method `writeCacheTo(Ljava/lang/StringBuilder;Ljava/lang/String;)V`, replaces the `MethodVisitor` with an `AdviceAdapter` that:
     - `onMethodEnter()`: loads arg 1 (StringBuilder), calls `V1Counters.onEntry(StringBuilder)`
     - `onMethodExit(int)`: loads arg 1, calls `V1Counters.onExit(StringBuilder)`
   - Agent manifest: `Premain-Class: com.fuzzing.agent.V1MeasureAgent`, `Can-Retransform-Classes: true`

##### Mutation Operators [R45]

1. **Byte-level**: random byte flip, random byte insertion (1-8 bytes), random byte deletion (1-8 bytes)
2. **Repetition [R45(a)]**: Pick a random region of the current input [start, start+len). Copy and repeat it k times to fill up to `maxInputSize` (10240). Special case: double the entire input. This grows a 1-byte seed to 1024 bytes in ~10 steps, well within the first minute.
3. **Dictionary [R45(b)]**: Tokens from the source code on the attack path:
   - `\n` (0x0A) — newline, common in stream content
   - `\r` (0x0D) — carriage return
   - `[` (0x5B) — from `toString()` bracket formatting
   - `]` (0x5D) — from `toString()` bracket formatting
   - `Content: ` — prefix string in `toString()`
   - `cos` — temp file prefix in `createFileOutputStream()`
   - `tmp` — temp file suffix in `createFileOutputStream()`
   These tokens are inserted or overwritten at random positions. They are single syntactic units from the source, not assembled inputs.
4. **Encoding [R45(c)]**: Not needed — the input is raw bytes; no format check, no checksum, no compression. Any bytes pass through.

##### Retention Policy [R46]

- **Primary criterion**: If `charsAppended` > current best → retain (corpus entry saved with metadata)
- **Secondary criterion (flat signal)**: If `charsAppended` == 0 AND `input.length > longestSaved` → retain. This ensures the search grows toward the 1024-byte threshold even when no input has yet crossed it. Input growth from 1 byte to 1025 bytes takes ~10 doublings, achievable in seconds.
- **Progress guarantee**: The repetition operator can double the entire input each mutation. Starting from a 1-byte seed, this reaches 1025 bytes (the target's `input_bytes`) in ≤11 mutations. At even a modest throughput of 100 exec/s, this is under 1 second.

##### Stop/Continue Conditions

- **Default**: Infinite (continues until killed)
- **Time-bounded**: System property `jqf.guidance.duration` (seconds); `hasInput()` returns false after deadline
- **CLI**: `FuzzRunner V1 <seconds>`

##### Logging

- Structured log every 1 second: total executions, corpus size, best `charsAppended`, current input length, executions/sec

---

#### Step 7-10 Summary (Plans only — code in Block 3)

##### V1Guidance Design

Implements `Guidance` and `SignalSource` directly ([R3]).

| Method | Behavior |
|--------|----------|
| `getInput()` | Resets `V1Counters`. Mutates a corpus entry (or generates random seed if corpus empty). Returns `ByteArrayInputStream`. |
| `hasInput()` | Returns true until time deadline (if set). |
| `handleResult(Result, Throwable)` | Reads `V1Counters.getCharsAppended()`. Retention per policy above. Logs stats at 1s intervals. Does NOT decide failures or write failure files [R6]. |
| `generateCallBack(Thread)` | Returns empty `Consumer<TraceEvent>` (we use agent measurement, not trace events). |
| `lastSignals()` | Returns `Map.of("charsAppended", (double) lastCharsAppended)` |

##### Agent Jar Packaging

Post-compilation script (in Block 3):
```bash
mkdir -p target/agent-meta
echo "Premain-Class: com.fuzzing.agent.V1MeasureAgent" > target/agent-meta/MANIFEST.MF
echo "Can-Retransform-Classes: true" >> target/agent-meta/MANIFEST.MF
jar cfm target/v1-agent.jar target/agent-meta/MANIFEST.MF \
    -C target/test-classes com/fuzzing/agent/
```

##### Class Origin Check (Block 3 verification)

A helper that prints:
```java
System.out.println(CachedOutputStream.class.getProtectionDomain().getCodeSource().getLocation());
```
Must show: `lib/cxf-core-4.1.1-SNAPSHOT.jar`

##### FuzzRunner CLI

```
java -javaagent:target/v1-agent.jar -Xmx1g -Xss1m \
     -Djqf.ei.MAX_INPUT_SIZE=10240 \
     -cp <classpath> com.fuzzing.runner.FuzzRunner V1 <seconds>
```

##### ReplayRunner

Reads a saved corpus file, feeds it through the fuzz test, prints metadata (input length, charsAppended, exception if any).

---

#### Zest Baseline Comparison [R18]

**Zest** uses coverage as its retention signal. For V1, the code coverage saturates once the spill path and clean path are both covered, which happens with any input ≈1025 bytes. After that, Zest randomly mutates without preference for larger inputs. It may incidentally trigger the bug but has no signal to systematically drive toward it.

**V1Guidance (CGF)** uses `charsAppended` measured at the sink (`writeCacheTo`). This signal is directly correlated with the vulnerability severity. It retains inputs that cross the spill threshold and grow the allocation. The measurable metric where CGF outperforms Zest: **time-to-first-failure** — CGF systematically grows inputs past 1024 bytes using repetition operators, while Zest must stumble upon it via undirected mutations.

---

#### IMPORT AUDIT

```
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
ClassVisitor → org.objectweb.asm.ClassVisitor
ClassWriter → org.objectweb.asm.ClassWriter
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter
```

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — All code targets Java 17.
- [YES] No hallucinated APIs — All APIs verified against jar bytecode (javap).
- [YES] Guidance implements Guidance directly — V1Guidance implements `edu.berkeley.cs.jqf.fuzz.guidance.Guidance`.
- [YES] No existing guidance extended — Implements from scratch.
- [YES] V* vulnerabilities identified — V1 identified.
- [YES] V* IDs are sequential (V1) — not derived from software version numbers.
- [YES] Official vulnerability names applied — CWE-400.
- [YES] PkgRisk-* identified — None found (justified: no dependency-level amplification risks in this code path).
- [YES] Every PkgRisk-* executed or justified — N/A (none identified).
- [YES] Guidance targets V* — V1Guidance targets V1.
- [YES] One fuzz method per V* — `fuzzCachedOutputStreamCleanerForceClean` for V1 (frozen harness).
- [YES] CLI method selection supported — FuzzRunner takes target ID as CLI arg.
- [YES] Byte[]/InputStream input model used exclusively — Guidance provides raw bytes.
- [YES] No junit-quickcheck Generators used — All mutation inside Guidance.
- [YES] All mutation implemented inside Guidance — Byte-level + repetition + dictionary.
- [YES] Repetition, source dictionary and encoder operators implemented — Repetition (doubling), dictionary (tokens from source), no encoder needed (raw bytes format).
- [YES] Retention progresses while signal is flat; inputs can reach input_bytes within a minute — Secondary criterion retains longer inputs; repetition doubling reaches 1025 bytes in ~11 steps.
- [YES] Retention signals measured where resource is consumed, not before sink — `charsAppended` measured at `writeCacheTo(StringBuilder, String)`, which IS the sink.
- [YES] Logging every 1 second — Structured stats.
- [YES] Guidance decides no failures and writes no failure files — [R6] obeyed.
- [YES] Corrupted inputs saved with metadata — Corpus entries saved with length, signal, timestamp.
- [YES] Replay/feeder implemented — ReplayRunner loads saved corpus entry and replays.
- [YES] Infinite + time-bounded fuzzing supported — hasInput() respects deadline.
- [YES] src/main vs src/test separation correct — All fuzzing infra in src/test/java.
- [YES] Maven scopes consistent — JQF = test scope; cxf-core = system scope.
- [YES] No wildcard imports used for JQF/tracing — All explicit imports.
- [YES] TraceEvent import verified and audited — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` ✓

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "charsAppended",
          "quantity": "total characters appended to the StringBuilder during CachedOutputStream.writeCacheTo(StringBuilder, String) — measures the unbounded content materialized at the sink",
          "aggregation": "sum",
          "locations": ["CachedOutputStream#writeCacheTo(StringBuilder, String)"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in V1Counters: index 0 = StringBuilder.length() at method entry, index 1 = chars appended (exit length - entry length)",
          "reset": "V1Counters.reset() called in V1Guidance.getInput() before each execution",
          "read": "V1Guidance.handleResult() reads V1Counters.getCharsAppended()"
        }
      ],
      "retention": "Primary: retain inputs where charsAppended exceeds the current best (higher allocation at the sink). Secondary (while charsAppended is zero — signal flat because input has not yet crossed the 1024-byte spill threshold): retain inputs that are longer than the longest saved, so the search grows toward the threshold. Once any input crosses 1024 bytes and reaches the sink, charsAppended becomes non-zero and the primary criterion takes over.",
      "retention_signals": ["charsAppended"],
      "mutation": [
        "byte-level: random byte flip at a random position; random insertion of 1-8 random bytes; random deletion of 1-8 bytes",
        "repetition [R45(a)]: select a random region [start, start+len) of the input and repeat it k times in-place, with k chosen so the result approaches maxInputSize (10240); special case: double the entire input. Grows a 1-byte seed to 1025+ bytes in ~11 mutations.",
        "dictionary [R45(b)]: tokens from the code on the attack path — 0x0A (newline), 0x0D (carriage return), 0x5B '[', 0x5D ']', 'Content: ' (toString prefix), 'cos' (temp file prefix), 'tmp' (temp file suffix) — inserted or overwritten at random positions. These are single syntactic units from the source, not assembled triggering inputs.",
        "no encoder [R45(c)]: the input is raw bytes with no format checks, checksums, or compression; any bytes reach the sink once the total length exceeds the spill threshold"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

Let me start by reading all the necessary files to understand the workspace state and plan the implementation.

```text
Glob <run_dir> **/*
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/analysis/guidance_plan.json
Read <run_dir>/src/test/java/org/apache/cxf/io/fuzz/CachedOutputStreamFuzzTest.java
```

Now let me implement all files. I'll start with the Java agent (Part A), then the Guidance (Part B), then the runner/replay/launch (Part C/D).

```text
Write <run_dir>/src/test/java/com/fuzzing/agent/V1Counters.java
Write <run_dir>/src/test/java/com/fuzzing/agent/V1MeasureAgent.java
```

Now Part B — the V1Guidance:

```text
Write <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
```

Now Part C — FuzzRunner and ReplayRunner:

```text
Write <run_dir>/src/test/java/com/fuzzing/runner/FuzzRunner.java
Write <run_dir>/src/test/java/com/fuzzing/runner/ReplayRunner.java
```

Now let me compile to verify everything works:

```text
$ mvn package -DskipTests 2>&1 | tail -30
```

Compilation succeeded. Now let me create the agent jar:

```text
$ mkdir -p target/agent-meta && printf 'Premain-Class: com.fuzzing.agent.V1MeasureAgent\nCan-Retransform-Classes: true\n' > target/agent-meta/MANIFEST.MF && jar cfm target/v1-agent.jar target/agent-meta/MANIFEST.MF -C target/test-classes com/fuzzing/agent/ && jar tf target/v1-agent.jar
```

Now let me verify the manifest is correct:

```text
$ unzip -p target/v1-agent.jar META-INF/MANIFEST.MF
```

Now let me write the run.sh script:

```text
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh
```

Now write the launch.json for the DoSGuide validation:

```text
Write <run_dir>/analysis/launch.json
```

Now let me create the validation input examples:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs && cd <run_dir>/analysis/validation_inputs && python3 -c " …
$ cd <run_dir>/analysis/validation_inputs && python3 -c " …
```

Now let me verify the complete compilation one more time:

```text
$ cd <run_dir> && mvn package -DskipTests 2>&1 | tail -20
```

Let me verify all the compiled test classes are present:

```text
$ find <run_dir>/target/test-classes -name '*.class' | sort
```

All classes compiled. Let me also rebuild the agent jar with the latest classes:

```text
$ jar cfm target/v1-agent.jar target/agent-meta/MANIFEST.MF -C target/test-classes com/fuzzing/agent/ && echo "Agent jar rebuilt successfully"
```

Let me now verify the complete workspace file layout:

```text
$ find src -type f | sort
```

All files are in place. Now let me verify the launch.json classpath is accurate by cross-referencing with actual dependency jars:

```text
$ ls <run_dir>/target/dependency/ | sort
```

Good — all dependency jars are accounted for in the classpath. Let me do a final review of each file by reading back the key parts:

```text
Read <run_dir>/src/test/java/com/fuzzing/agent/V1MeasureAgent.java
Read <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
Read <run_dir>/src/test/java/com/fuzzing/runner/FuzzRunner.java
```

Let me verify the current state of the workspace and ensure everything is ready for validation.

```text
$ ls -la <run_dir>/
$ ls -la <run_dir>/target/v1-agent.jar 2>&1
$ ls <run_dir>/target/test-classes/com/fuzzing/agent/ 2>&1
$ ls <run_dir>/target/test-classes/com/fuzzing/guidance/ 2>&1
$ ls <run_dir>/target/test-classes/com/fuzzing/runner/ 2>&1
$ ls <run_dir>/target/test-classes/dosguide/validate/ 2>&1
$ jar tf <run_dir>/target/v1-agent.jar 2>&1
$ ls <run_dir>/target/dependency/ 2>&1 | head -40
$ ls <run_dir>/analysis/validation_inputs/ 2>&1
```

Everything is in place. Let me do one final clean rebuild to ensure all artifacts are fresh and consistent:

```text
$ mvn clean package -DskipTests -q 2>&1 | tail -20
$ mkdir -p target/agent-meta && printf 'Premain-Class: com.fuzzing.agent.V1MeasureAgent\nCan-Retransform-Classes: true\n' > target/agent-meta/MANIFEST.MF && jar cfm target/v1-agent.jar target/agent-meta/MANIFEST.MF -C target/test-classes com/fuzzing/agent/ 2>&1
$ unzip -p target/v1-agent.jar META-INF/MANIFEST.MF 2>&1
```

All artifacts are rebuilt and verified. Let me also verify the complete file tree matches what's expected:

```text
$ find src -type f -name '*.java' | sort && echo "---" && find analysis -type f | sort && echo "---" && echo "run.sh exists: $(test -f run.sh && echo yes || echo no)" && echo "target/v1-agent.jar exists: $(test -f target/v1-agent.jar && echo yes || echo no)"
```

All Block 3 deliverables are in place and compile cleanly:

| Deliverable | Path | Status |
|---|---|---|
| **Agent counter** | `src/test/java/com/fuzzing/agent/V1Counters.java` | ✅ compiled |
| **Agent transformer** | `src/test/java/com/fuzzing/agent/V1MeasureAgent.java` | ✅ compiled |
| **Guidance** | `src/test/java/com/fuzzing/guidance/V1Guidance.java` | ✅ compiled, implements `Guidance` + `SignalSource` |
| **FuzzRunner** | `src/test/java/com/fuzzing/runner/FuzzRunner.java` | ✅ compiled, has `createGuidance` factory |
| **ReplayRunner** | `src/test/java/com/fuzzing/runner/ReplayRunner.java` | ✅ compiled |
| **Agent JAR** | `target/v1-agent.jar` | ✅ manifest: `Premain-Class: com.fuzzing.agent.V1MeasureAgent` |
| **Run script** | `run.sh` | ✅ executable |
| **Launch config** | `analysis/launch.json` | ✅ guidance_factory, targets, classpath, javaagent |
| **Validation inputs** | `analysis/validation_inputs/` | ✅ 5 files (64–1024 bytes) |

The implementation is complete and ready for DoSGuide validation.
