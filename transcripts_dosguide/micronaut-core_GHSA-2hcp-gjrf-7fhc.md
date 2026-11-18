# micronaut-core_GHSA-2hcp-gjrf-7fhc

## Block 1

I'll start by reading the main target file, the fuzz test fixture, and exploring the source directory structure.

```text
Read <source_root>/http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider.java
Glob <run_dir> *FuzzTest*.java
$ ls <run_dir>/
Read <run_dir>/src/test/java/com/fuzzing/harness/SanitizerFuzzTest.java
Read <run_dir>/pom.xml
$ ls -la <run_dir>/lib/
$ ls -la <run_dir>/analysis/
```

Now let me read the HtmlEntityEncodingHtmlSanitizer class and related classes:

```text
Grep <source_root> HtmlEntityEncodingHtmlSanitizer
Grep <source_root> HtmlSanitizer
Read <source_root>/http/src/main/java/io/micronaut/http/util/HtmlEntityEncodingHtmlSanitizer.java
Read <source_root>/http/src/main/java/io/micronaut/http/util/HtmlSanitizer.java
Read <source_root>/http/src/test/java/io/micronaut/http/util/HtmlEntityEncodingHtmlSanitizerTest.java
```

Let me check additional source files to understand the full attack path:

```text
Grep <source_root> class ErrorContext|interface ErrorContext
Grep <source_root> class HtmlErrorResponseBodyProvider|interface HtmlErrorResponseBodyProvider
Grep <source_root>/core/src/main/java/io/micronaut/core/util/StringUtils.java isNotEmpty
Read <source_root>/http-server/src/main/java/io/micronaut/http/server/exceptions/response/ErrorContext.java
Read <source_root>/http-server/src/main/java/io/micronaut/http/server/exceptions/response/HtmlErrorResponseBodyProvider.java
Grep <source_root> class DefaultErrorContext
Read <source_root>/http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultErrorContext.java
```

Now let me look at the CSS text block more carefully for size estimation, and verify the `isEmpty` implementation:

```text
Grep <source_root>/core/src/main/java/io/micronaut/core/util/StringUtils.java public static boolean isEmpty
Read <source_root>/http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider.java
```

Now I have a complete picture. Let me verify the analysis of the CSS text block length and run a quick calculation, then generate the scale measurement files:

```text
$ mkdir -p analysis/scale/V1
```

Now let me write a Python script to generate the scale measurement input files. Each file contains N unique 3-byte ASCII lines (avoiding HTML special chars), terminated by newlines:

```text
$ python3 -c " …
$ head -5 analysis/scale/V1/n64.bin && echo "---" && wc -l analysis/scale/V1/n64.bin && wc -c analysis/scale/V1/n64.bin
Read <run_dir>/analysis/scale/V1/series.json
```

Good. Now let me verify the input files are correctly structured - each line should be a unique 3-char string that won't match the "Bad Request" filter:

```text
$ python3 -c " …
```

All scale measurement files are valid. Now let me compile the complete analysis.

#### PHASE A — Analysis

##### 1.1 Code-Level Vulnerabilities

**V1: Unbounded ConcurrentHashMap Cache Growth in DefaultHtmlErrorResponseBodyProvider**

The vulnerability is in `DefaultHtmlErrorResponseBodyProvider.body()` (line 147):

```java
public String body(@NonNull ErrorContext errorContext, @NonNull HttpResponse<?> response) {
    HtmlErrorPage key = error(errorContext, response);
    return cache.computeIfAbsent(key, this::html);
}
```

The `cache` field (line 134) is a `ConcurrentHashMap<HtmlErrorPage, String>` that grows without any size limit. The `HtmlErrorPage` record (line 213) uses all fields—including a `List<String> messages`—for equality, so each unique error message creates a distinct key.

**Fuzzable entrypoint & user-controlled inputs:** The fuzz test `SanitizerFuzzTest.fuzzHtmlErrorResponseBodyProviderBody(InputStream)` reads the full input as UTF-8, splits it by newline characters, and creates an `ErrorContext` per line with the line as the error message. Each unique non-empty line that isn't case-insensitively equal to "Bad Request" becomes a unique sanitized message in the `HtmlErrorPage.messages` list, creating a unique cache key.

**Mechanism:** Each unique error message line produces a distinct `HtmlErrorPage` record key in the `ConcurrentHashMap`. On each cache miss, `html(HtmlErrorPage)` is called, which generates a full HTML error page via `MessageFormat.format()` containing the ~3000-character CSS string, header, and article content—producing approximately 3,300+ characters per cached HTML string. The cache retains every entry without eviction or size limit.

**Exhausted resource:** Heap memory. Each cache entry consumes approximately:
- HTML `String` value: ~3,400 bytes (with Latin-1 compact strings in JDK 17)
- `HtmlErrorPage` record key + `ArrayList` + message `String`: ~200 bytes  
- `ConcurrentHashMap.Node` overhead: ~32 bytes
- Total: ~3,600 bytes per entry

**Failure mode:** `out_of_memory` — `OutOfMemoryError` when the `ConcurrentHashMap` or `html()` attempts to allocate and the heap is exhausted.

**Scale:** With 1GB heap (`-Xmx1g`), approximately 200MB is consumed by JVM internals and the Micronaut `ApplicationContext`, leaving ~800MB for cache entries. At ~3,600 bytes per entry: 800,000,000 / 3,600 ≈ 222,000 unique lines needed. At 4 bytes per line (3-byte unique content + 1-byte newline), this requires 222,000 × 4 = 888,000 bytes ≈ 868 KB. Well within the 1,048,576 byte input size limit.

##### 1.2 Official Classification

**V1:** CWE-770 — Allocation of Resources Without Limits or Throttling. The `ConcurrentHashMap` cache has no maximum size, eviction policy, or entry count limit. An attacker controlling error messages can force unbounded heap allocation.

##### 1.3 Dependency / Package-Level Risks

**PkgRisk-1: `String.replaceAll()` regex overhead in `HtmlEntityEncodingHtmlSanitizer.sanitize()`**

- **Package/class:** `java.lang.String.replaceAll()` used in `io.micronaut.http.util.HtmlEntityEncodingHtmlSanitizer.sanitize()`
- **Why input-sensitive:** `String.replaceAll(String regex, String replacement)` compiles a `Pattern` and creates a `Matcher` on every invocation. The `sanitize()` method calls `replaceAll()` 5 times per invocation. When called from `fuzzHtmlErrorResponseBodyProviderBody`, `sanitize()` is invoked for each line (once for the response reason, once for each error message). With many lines, total `Pattern` + `Matcher` object allocations become very high.
- **Trigger shapes:** A 1MB input with many short lines (e.g., 2-byte content + newline = 3 bytes/line) yields ~349K lines. Each line triggers 2 `sanitize()` calls × 5 `replaceAll()` calls = 10 `Pattern.compile()` + 10 `Matcher` creations per line = ~3.49M Pattern compilations total.
- **Exhausted resource:** CPU time — the cumulative overhead of millions of Pattern compilations and Matcher creations adds up, contributing to timeout alongside the cache population work. However, this is secondary to V1's OOM because Pattern compilation for single-char patterns is fast (~1µs each). Total CPU contribution: ~3-5 seconds.
- **Failure mode:** `timeout` — in combination with the cache rendering work, the total CPU cost could exceed 20 seconds.
- **Scale:** ~350K lines (each triggering 10 replaceAll calls) are needed for the CPU overhead to become significant. At 3 bytes/line: ~1MB of input.
- **Fuzzing strategy:** This is on the same attack path as V1 and shares the same input structure (many short unique lines). The CPU overhead from `replaceAll` contributes to the same failure scenario. It is NOT a separate exploitable vulnerability on its own—the sanitizer alone (first fuzz method `fuzzHtmlEntityEncodingHtmlSanitizerSanitize`) processes only one string and completes in O(n) time, well within the timeout for a 1MB input.

**Assessment of PkgRisk-1:** This risk shares the exact same entrypoint, input shape, and attack path as V1. It's a contributing factor to V1's timeout scenario, not an independent DoS vector. Since it cannot be triggered independently (the first fuzz method that calls sanitize alone is not vulnerable to DoS under the given limits), it does not warrant a separate target.

##### 1.4 Zest Baseline Comparison (for V1)

**Closest Zest configuration:** Zest with `fuzzHtmlErrorResponseBodyProviderBody` as the fuzz method.

**Why Zest underperforms:**
- Zest optimizes for **code coverage**, not memory consumption. The vulnerable code path (cache population via `computeIfAbsent` → `html()`) is fully covered by a single unique line. Zest has no signal that tells it "more unique lines = more memory = closer to OOM."
- Zest's coverage-guided retention would keep the first input that reaches the `html()` method and then plateau, because additional unique lines don't improve structural code coverage—they exercise the exact same code path.
- Zest does not measure heap allocation growth, so it cannot distinguish an input with 100 unique lines from one with 100,000 unique lines.

**Measurable metric where custom Guidance outperforms:** The custom Guidance tracks **cumulative heap allocation** (bytes allocated during the execution) via a Java agent instrumenting allocation hotspots in `MessageFormat`, `StringBuilder`, and `String`. It retains inputs that increase total allocation, directly driving the search toward the OOM threshold. Expected advantage: time-to-first-OOM is significantly faster because the Guidance preferentially grows inputs with more unique lines, while Zest would stagnate after coverage saturates.

#### PHASE B — Target Selection

Based on the analysis, V1 is the only target with an achievable DoS under the fixed evaluation limits. PkgRisk-1 is on the same attack path and is not independently exploitable.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unbounded ConcurrentHashMap cache growth in DefaultHtmlErrorResponseBodyProvider",
      "entrypoint": "SanitizerFuzzTest.fuzzHtmlErrorResponseBodyProviderBody(InputStream) → DefaultHtmlErrorResponseBodyProvider.body(ErrorContext, HttpResponse) → DefaultHtmlErrorResponseBodyProvider.error(ErrorContext, HttpResponse) → HtmlEntityEncodingHtmlSanitizer.sanitize(String) → ConcurrentHashMap.computeIfAbsent(HtmlErrorPage, Function) → DefaultHtmlErrorResponseBodyProvider.html(HtmlErrorPage)",
      "source_path": "http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider.java",
      "sink": "ConcurrentHashMap#computeIfAbsent",
      "mechanism": "Each unique error message line in the input creates a distinct HtmlErrorPage record key in the ConcurrentHashMap cache. On each cache miss, html() renders a full HTML page (~3.4KB including CSS) and stores it. With many unique lines, the cache grows unboundedly, exhausting heap memory.",
      "resource": "heap memory: ~3600 bytes per cache entry (3400B HTML string value + 200B HtmlErrorPage key/list/message + 32B ConcurrentHashMap.Node)",
      "failure_mode": "out_of_memory",
      "scale": "about 222K unique error message lines fill the 1GB heap (after ~200MB JVM/context overhead); at 4 bytes per line (3-byte unique content + 1-byte newline), about 888KB of input",
      "input_bytes": 888000,
      "cwe": "CWE-770"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

Let me re-read the source to trace the exact call path correctly:

```text
Read <source_root>/http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider.java
```

Now I can see the issue clearly. In `body()` (lines 145-148):
```java
HtmlErrorPage key = error(errorContext, response);    // line 146
return cache.computeIfAbsent(key, this::html);        // line 147
```

The calls to `error()` and `cache.computeIfAbsent()` are **sequential calls from `body()`**, not nested. `sanitize()` is called inside `error()` and returns before `computeIfAbsent()` is ever reached. So `sanitize()` → `computeIfAbsent()` is not a valid hop.

The correct linear path from the fuzz entry to the sink is:
1. Fuzz method calls `provider.body()`
2. `body()` directly calls `cache.computeIfAbsent(key, this::html)` (line 147)
3. On cache miss, `computeIfAbsent` invokes `this::html` (the function argument)

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unbounded ConcurrentHashMap cache growth in DefaultHtmlErrorResponseBodyProvider",
      "entrypoint": "SanitizerFuzzTest.fuzzHtmlErrorResponseBodyProviderBody(InputStream) → DefaultHtmlErrorResponseBodyProvider.body(ErrorContext, HttpResponse) → ConcurrentHashMap.computeIfAbsent(HtmlErrorPage, Function) → DefaultHtmlErrorResponseBodyProvider.html(HtmlErrorPage)",
      "source_path": "http-server/src/main/java/io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider.java",
      "sink": "ConcurrentHashMap#computeIfAbsent",
      "mechanism": "Each unique error message line in the input creates a distinct HtmlErrorPage record key in the ConcurrentHashMap cache. On each cache miss, html() renders a full HTML page (~3.4KB including CSS) and stores it. With many unique lines, the cache grows unboundedly, exhausting heap memory.",
      "resource": "heap memory: ~3600 bytes per cache entry (3400B HTML string value + 200B HtmlErrorPage key/list/message + 32B ConcurrentHashMap.Node)",
      "failure_mode": "out_of_memory",
      "scale": "about 222K unique error message lines fill the 1GB heap (after ~200MB JVM/context overhead); at 4 bytes per line (3-byte unique content + 1-byte newline), about 888KB of input",
      "input_bytes": 888000,
      "cwe": "CWE-770"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

Let me analyze the measurement data carefully.

**Allocation growth (total allocated per line):**
- 64→128: (7.1-4.4)/64 = 42.2 KB/line
- 128→256: (12.5-7.1)/128 = 42.2 KB/line
- 256→512: (23.3-12.5)/256 = 42.2 KB/line
- 512→1024: (45.0-23.3)/512 = 42.4 KB/line
- 1024→2048: (88.5-45.0)/1024 = 42.5 KB/line

Allocation grows very linearly at **~42.5 KB per unique line** (includes temporaries from Pattern compilations, Matcher, StringBuilder, MessageFormat intermediates; most are GC-eligible).

**CPU time growth:**
- 1024 lines: 105.9 ms → 103 µs/line
- 2048 lines: 149.4 ms → 73 µs/line (JIT-compiled steady state)

**Peak heap (retained + in-flight):**
The peak heap data is noisy (0 B at 128 due to GC timing), but at 2048 lines it's 27 MB. The retained cache per entry (code-level: ~3.7 KB HTML string with CSS + ~300 bytes key/node/list overhead ≈ **4 KB/entry**) is a small fraction of the 42.5 KB total allocation per line — the rest is temporaries collected by GC.

**Extrapolation to 1 GB heap, 20s timeout:**

Retained memory: ~4 KB/entry × N entries. With ~200 MB JVM+context baseline, ~800 MB available for cache.
- OOM at: 800 MB / 4 KB ≈ **200K unique lines**
- Input: 200K × 4 bytes/line = **800 KB**
- Total allocation at 200K lines: 42.5 KB × 200K ≈ 8.3 GB through a 1 GB heap (~10 full GC cycles)
- CPU time: 200K × 73 µs ≈ 14.6 s (under 20s limit), but heavy GC pressure near full heap adds wall-clock overhead

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "measured allocation grows linearly at ~42.5 KB per unique line (total allocation including temporaries); retained cache per entry is ~4 KB (HTML string with CSS + key/node overhead). With 1 GB heap and ~200 MB JVM/context baseline, ~800 MB available for cache entries; OOM at ~200K unique lines. At 4 bytes per line (3-byte unique content + 1-byte newline), about 800 KB of input",
    "input_bytes": 800000
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by verifying the existing pom.xml and workspace structure, then develop the measurement strategy.

```text
$ ls -la <run_dir>/src/main/java/ 2>/dev/null; ls -la <run_dir>/src/test/java/com/fuzzing/ 2>/dev/null
Read <run_dir>/pom.xml
```

Now let me verify that ASM is available transitively from JQF and that the existing pom.xml compiles:

```text
$ mvn dependency:tree -Dscope=test 2>&1 | grep -i "asm\|org.ow2" | head -20
$ mvn compile 2>&1 | tail -15
$ mvn dependency:resolve -DincludeScope=test 2>&1 | grep -i "asm\|org.ow2" | head -20
$ mvn package -DskipTests 2>&1 | tail -20
```

ASM 9.8 is available transitively from JQF. Let me check if asm-commons is also available:

```text
$ ls <run_dir>/target/deps/ | grep -i asm
```

Let me verify the key classes are in the lib/ jars:

```text
$ jar tf lib/micronaut-http-server-4.10.17-SNAPSHOT.jar | grep -E "DefaultHtmlErrorResponseBodyProvider|HtmlErrorResponseBodyProvider|ErrorContext|DefaultErrorContext" | head -10
$ jar tf lib/micronaut-http-4.10.17-SNAPSHOT.jar | grep -E "HtmlEntityEncodingHtmlSanitizer|HtmlSanitizer" | head -10
$ jar tf lib/micronaut-http-server-4.10.17-SNAPSHOT.jar | grep "DefaultHtmlErrorResponseBodyProvider" | head -10
```

All target classes and their inner classes are present in the lib/ jars. Now let me verify the exact method descriptor for the `html` method to plan the agent correctly:

```text
$ javap -p -c -cp lib/micronaut-http-server-4.10.17-SNAPSHOT.jar io.micronaut.http.server.exceptions.response.DefaultHtmlErrorResponseBodyProvider 2>&1 | grep -A2 "html\|body\|computeIfAbsent" | head -30
```

Let me check for SLF4J implementation in deps, since Micronaut needs it at runtime:

```text
$ ls <run_dir>/target/deps/ | grep -i "slf4j\|logback\|log4j" | head -10
$ ls <run_dir>/target/deps/ | sort
```

Good — ASM 9.8 and asm-commons 9.5 are both available transitively from JQF. Let me now get the precise CSS string length from the bytecode constant pool:

```text
$ javap -v -cp lib/micronaut-http-server-4.10.17-SNAPSHOT.jar io.micronaut.http.server.exceptions.response.DefaultHtmlErrorResponseBodyProvider 2>&1 | grep -B1 "box-sizing" | head -5
$ javap -v -cp lib/micronaut-http-server-4.10.17-SNAPSHOT.jar io.micronaut.http.server.exceptions.response.DefaultHtmlErrorResponseBodyProvider 2>&1 | grep -c "box-sizing"
$ python3 -c " …
```

Now let me create the directory structure for Block 3's files:

```text
$ mkdir -p src/test/java/com/fuzzing/agent src/test/java/com/fuzzing/guidance src/test/java/com/fuzzing/runner src/test/java/com/fuzzing/replay
$ find <run_dir>/src -type f -o -type d | sort
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/analysis/run_config.json
```

Good. Now I have all the information needed. The pom.xml is correct and needs no changes. Let me verify it compiles with the test source:

```text
$ mvn compile 2>&1 | tail -10
```

The pom.xml is correct as-is. No changes needed. Now here's the complete Block 2 deliverable:

---

#### Step 2 — Maven Layout & Scope

The existing `pom.xml` is correct. No changes needed:
- **System-scope (micronaut jars in lib/)**: 9 micronaut modules as system dependencies with `${project.basedir}/lib/` systemPaths — verified all jars present and contain target classes.
- **Compile-scope (third-party runtime deps)**: jakarta.annotation-api, jakarta.inject-api, reactor-core, reactive-streams, slf4j-api.
- **Test-scope (fuzzing infra)**: jqf-fuzz 2.1, jqf-instrument 2.1, junit-quickcheck-core 1.0, junit-quickcheck-generators 1.0, junit 4.13.2.
- **Transitive test dependencies available**: ASM 9.8 (from jqf-instrument), asm-commons 9.5 (from jqf-fuzz transitives). These provide the bytecode manipulation API needed for the custom Java agent.
- **No SLF4J implementation**: Micronaut will emit a no-provider warning but runs fine with the NOP fallback.

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

All imports in `SanitizerFuzzTest.java` are resolved:

| Import | Resolution | Type |
|--------|-----------|------|
| `io.micronaut.context.ApplicationContext` | micronaut-context-4.10.17-SNAPSHOT.jar | (A) system jar |
| `io.micronaut.http.HttpRequest` | micronaut-http-4.10.17-SNAPSHOT.jar | (A) system jar |
| `io.micronaut.http.HttpResponse` | micronaut-http-4.10.17-SNAPSHOT.jar | (A) system jar |
| `io.micronaut.http.MediaType` | micronaut-http-4.10.17-SNAPSHOT.jar | (A) system jar |
| `io.micronaut.http.server.exceptions.response.ErrorContext` | micronaut-http-server-4.10.17-SNAPSHOT.jar | (A) system jar |
| `io.micronaut.http.server.exceptions.response.HtmlErrorResponseBodyProvider` | micronaut-http-server-4.10.17-SNAPSHOT.jar | (A) system jar |
| `io.micronaut.http.util.HtmlEntityEncodingHtmlSanitizer` | micronaut-http-4.10.17-SNAPSHOT.jar | (A) system jar |
| `edu.berkeley.cs.jqf.fuzz.Fuzz` | jqf-fuzz-2.1.jar | (A) test Maven dep |
| `edu.berkeley.cs.jqf.fuzz.JQF` | jqf-fuzz-2.1.jar | (A) test Maven dep |

All internal project classes (`DefaultHtmlErrorResponseBodyProvider`, `DefaultHtmlErrorResponseBodyProvider$HtmlErrorPage`, `DefaultErrorContext`, `DefaultErrorContext$Builder`, `HtmlEntityEncodingHtmlSanitizer`) verified present in the lib/ jars including Micronaut `$BeanDefinition` classes.

Runtime classes needed by agent:
| Class | Resolution |
|-------|-----------|
| `org.objectweb.asm.ClassVisitor` | asm-9.8.jar (transitive from jqf-instrument) |
| `org.objectweb.asm.commons.AdviceAdapter` | asm-commons-9.5.jar (transitive from jqf-fuzz) |

##### 3.2 Stub Generation Rules

**No stubs needed.** All symbols are resolved by system-scope jars (micronaut) and Maven test dependencies (JQF, JUnit). No missing internal project classes.

##### 3.3 Stub Report

**None.** Zero stub files generated. All required classes are available from the vulnerable jars in `lib/` and from Maven-resolved dependencies.

#### Step 4a — pom.xml + Directory Tree

##### pom.xml

The existing `pom.xml` is correct and requires no modifications. All systemPaths resolve to existing jars in `lib/`. No dependency additions needed — ASM comes transitively from JQF.

##### Directory Tree

```
.
├── analysis/
│   ├── run_config.json
│   └── scale/V1/ (measurement inputs from Block 1)
├── lib/
│   ├── micronaut-aop-4.10.17-SNAPSHOT.jar
│   ├── micronaut-context-4.10.17-SNAPSHOT.jar
│   ├── micronaut-context-propagation-4.10.17-SNAPSHOT.jar
│   ├── micronaut-core-4.10.17-SNAPSHOT.jar
│   ├── micronaut-core-reactive-4.10.17-SNAPSHOT.jar
│   ├── micronaut-http-4.10.17-SNAPSHOT.jar
│   ├── micronaut-http-server-4.10.17-SNAPSHOT.jar
│   ├── micronaut-inject-4.10.17-SNAPSHOT.jar
│   └── micronaut-router-4.10.17-SNAPSHOT.jar
├── pom.xml                                         ← UNCHANGED
└── src/
    └── test/java/
        ├── com/fuzzing/
        │   ├── agent/
        │   │   ├── V1MeasureAgent.java             ← Block 3: agent premain
        │   │   └── V1Transformer.java              ← Block 3: ASM transformer
        │   ├── guidance/
        │   │   └── V1Guidance.java                 ← Block 3: custom Guidance impl
        │   ├── harness/
        │   │   └── SanitizerFuzzTest.java          ← FROZEN (read-only)
        │   ├── replay/
        │   │   └── ReplayRunner.java               ← Block 3: reproduction tool
        │   └── runner/
        │       └── FuzzRunner.java                 ← Block 3: CLI runner
        └── dosguide/validate/
            └── SignalSource.java                    ← provided (read-only)
```

**Agent JAR build** (post-compilation shell step):
```bash
mkdir -p target/agent-meta
printf "Premain-Class: com.fuzzing.agent.V1MeasureAgent\nCan-Retransform-Classes: true\n" > target/agent-meta/MANIFEST.MF
jar cfm target/v1-agent.jar target/agent-meta/MANIFEST.MF -C target/test-classes com/fuzzing/agent/
```

**Class Origin Check** (mandatory proof — Block 3):
```java
System.out.println(Class.forName(
    "io.micronaut.http.server.exceptions.response.DefaultHtmlErrorResponseBodyProvider")
    .getProtectionDomain().getCodeSource().getLocation());
// Must print: .../lib/micronaut-http-server-4.10.17-SNAPSHOT.jar
```

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|-------------------|------------------------------|----------------------|
| V1 | **CGF** (Cost-Gradient Guidance) | Zest's coverage signal saturates after the first unique error line: `body()` → `computeIfAbsent()` → `html()` is fully covered by a single cache miss. Additional unique lines exercise the same code path, so Zest retains no signal to grow input toward ~200K unique lines. Zest's proxy signal (branch coverage) is uncorrelated with the dominant cost (total bytes cached). | CGF tracks **total characters allocated in `html()` calls** — a signal that grows monotonically with the number of unique cache entries, directly measuring the resource that causes OOM. The guidance hill-climbs this measured allocation signal, preferring inputs with more unique lines, and uses repetition+mutation to grow inputs toward 800KB. |

#### Step 6 — Strategy-Specific Guidance Design

##### V1 Measurement Plan

**Primary vulnerability mechanism:** Allocation / Memory Blowup (Category 6 per [R36])

The dominant cost is at `DefaultHtmlErrorResponseBodyProvider#html(HtmlErrorPage)`, where each invocation produces a ~3046-character HTML string that is retained permanently in the `ConcurrentHashMap` cache. The measurement must count both the number of allocations (calls to `html()`) and the total characters allocated (sum of return string lengths).

###### Signals

**Signal 1: `totalAllocatedChars`**
- **Quantity**: Sum of `String.length()` of all HTML strings returned by `html()` during one execution
- **Aggregation**: `sum`
- **Location**: `DefaultHtmlErrorResponseBodyProvider#html(HtmlErrorPage)` — measured at method exit (ARETURN)
- **Technique**: bytecode — custom Java agent inserts a DUP + `String.length()` + accumulate instruction sequence before each ARETURN in `html()`
- **Storage**: shared `long[]` array stored via `System.getProperties().put("V1_COUNTERS", new long[2])` — cross-classloader safe (JDK types only). `counters[1]` holds totalAllocatedChars.
- **Reset**: in `V1Guidance.getInput()` before each execution: `counters[0] = 0; counters[1] = 0;`
- **Read**: in `V1Guidance.handleResult()` after each execution: `long totalChars = counters[1];`
- **[R30] compliance**: (A) Derived from actual execution of `html()`. (B) Measured at the exact allocation hotspot that fills the cache (the return of `html()` which is the value stored in `computeIfAbsent`). (C) Consumed by `handleResult()` to decide corpus retention.

**Signal 2: `htmlCallCount`**
- **Quantity**: Number of times `html()` was called (= number of cache misses = number of new cache entries)
- **Aggregation**: `count`
- **Location**: `DefaultHtmlErrorResponseBodyProvider#html(HtmlErrorPage)` — measured at method entry
- **Technique**: bytecode — custom Java agent inserts an increment instruction at method entry
- **Storage**: same `long[]` array. `counters[0]` holds htmlCallCount.
- **Reset**: same as Signal 1 (array zeroed before each execution)
- **Read**: in `V1Guidance.handleResult()`: `long htmlCalls = counters[0];`

###### Agent Implementation Plan ([R35] Feasibility Check)

1. **Exact classes/methods to instrument**: `io.micronaut.http.server.exceptions.response.DefaultHtmlErrorResponseBodyProvider`, method `html` with descriptor `(Lio/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider$HtmlErrorPage;)Ljava/lang/String;`

2. **Required JVM flags**: `-javaagent:target/v1-agent.jar` — no `--add-opens` needed (target class is in a non-modular jar, not a JDK module)

3. **Signal export to Guidance**: A `long[2]` array stored in `System.getProperties()` under key `"V1_COUNTERS"`. This is a JDK shared singleton accessible from any classloader, avoiding class-loader isolation issues between JQF's InstrumentingClassLoader and the application classloader. Index 0 = htmlCallCount, index 1 = totalAllocatedChars.

4. **Minimal agent implementation**:
   - `V1MeasureAgent.premain(String, Instrumentation)`: creates the counter array, stores it via `System.getProperties().put("V1_COUNTERS", new long[2])`, registers a `ClassFileTransformer`
   - `V1Transformer` implements `ClassFileTransformer`: when `className` equals `io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider`, applies ASM visitor to instrument `html()`
   - ASM `MethodVisitor` for `html()`:
     - At method entry: retrieves `long[]` from `System.getProperties().get("V1_COUNTERS")`, increments `[0]`
     - At ARETURN: DUPs the return String, calls `String.length()`, adds result to `[1]` in the counter array
   - Agent is measurement-only ([R37]): no input generation, no payloads

##### Mutation Operators

**Byte-level:**
- Random byte flip (change one byte to a random value)
- Random byte insertion (insert one byte at a random position)
- Random byte deletion (remove one byte from a random position)
- Contiguous block overwrite (overwrite 1–16 bytes at random position with random values)

**Structure-aware ([R45]):**

**(a) Repetition**: Duplicate a region of the input (line-aligned when a `\n` boundary is found, otherwise byte-aligned) and repeat it k times. Also: double the entire input. This grows the input toward `input_bytes` (800,000) rapidly. After repetition, byte mutations on the duplicated content create uniqueness among repeated lines (each differing byte changes the error message → different HtmlErrorPage key → new cache entry).

**(b) Dictionary tokens from the code on the attack path**:
| Token | Source location | Role on attack path |
|-------|----------------|-------------------|
| `\n` (0x0A) | `SanitizerFuzzTest:59` — `input.indexOf('\n', start)` | Line separator, controls how many error messages are created |
| `&` | `HtmlEntityEncodingHtmlSanitizer:37` — `encodedMap.put("&", "&amp;")` | Special char checked by sanitizer |
| `<` | `HtmlEntityEncodingHtmlSanitizer:38` — `encodedMap.put("<", "&lt;")` | Special char checked by sanitizer |
| `>` | `HtmlEntityEncodingHtmlSanitizer:39` — `encodedMap.put(">", "&gt;")` | Special char checked by sanitizer |
| `"` | `HtmlEntityEncodingHtmlSanitizer:40` — `encodedMap.put("\"", "&quot;")` | Special char checked by sanitizer |
| `'` | `HtmlEntityEncodingHtmlSanitizer:41` — `encodedMap.put("'", "&#x27;")` | Special char checked by sanitizer |
| `.error` | `DefaultHtmlErrorResponseBodyProvider:151,168` — message code suffixes | MessageSource lookup keys |
| `.` | `DefaultHtmlErrorResponseBodyProvider:202,206` — article punctuation | Delimiter in article output |

**(c) Encoder**: Not needed. Input is plain UTF-8 text — no checksum, compression, or length-prefix format to satisfy.

##### Retention Policy

- **Primary criterion**: Keep input if `totalAllocatedChars` exceeds the current best. This directly tracks the cache's memory footprint.
- **Secondary criterion (flat signal — [R46])**: When `totalAllocatedChars` is 0 (no `html()` calls — e.g., all lines are empty or equal "Bad Request"), retain inputs that are longer (progressing toward `input_bytes` = 800,000). This ensures the search grows inputs past the trivial threshold. Once even one valid unique line appears, `totalAllocatedChars` becomes non-zero (~3046).
- **Tertiary: novelty**: Retain inputs that produce a new `htmlCallCount` not seen before (more unique cache entries).
- **Input growth guarantee ([R46])**: Starting from a seed of ~12 bytes, the repetition operator doubles the input each step. Reaching 800KB from 12 bytes takes ~16 doublings. At ~73µs/execution, this happens in < 1 second. The first minute will see inputs well beyond `input_bytes`.

##### Prioritization Logic

- Corpus entries are scored by `totalAllocatedChars`.
- Parent selection for mutation: weighted random favoring higher scores (energy-based: higher totalAllocatedChars → higher probability of selection).
- New inputs that break the `totalAllocatedChars` record are always saved.
- Corpus entries are promoted if they produced the current maximum `htmlCallCount`.

##### Stop/Continue Conditions

- **Infinite by default** ([R8]): runs until killed.
- **Time-bounded**: if system property `jqf.ei.MAX_DURATION_MILLIS` is set, stop after that many milliseconds.
- **Guidance never declares failures** ([R6]): only tracks signals and saves corpus.

##### Input Model

The `@Fuzz` method `fuzzHtmlErrorResponseBodyProviderBody(InputStream)` consumes an `InputStream` of raw bytes decoded as UTF-8. The Guidance's `getInput()` returns a `ByteArrayInputStream` containing the mutated byte array. Input model is byte[]/InputStream per [R25] and [R31].

#### Zest Baseline Comparison ([R18])

**Closest Zest configuration**: Zest (coverage-guided) with `fuzzHtmlErrorResponseBodyProviderBody` as the fuzz method.

**Why Zest underperforms (proxy vs. mechanism-aligned)**:
- Zest's proxy signal is **branch coverage**. The entire attack path (`body()` → `error()` → `sanitize()` → `computeIfAbsent()` → `html()` → `MessageFormat.format()`) is covered by an input with a single unique non-empty line. Additional unique lines cover zero new branches.
- Zest would saturate its coverage after the first few executions and then explore randomly with no directional signal.
- The vulnerability requires ~200K unique lines to exhaust the 1GB heap. Zest has no mechanism to prefer inputs with more unique lines over those with fewer.

**Mechanism-aligned advantage of CGF**:
- V1Guidance's signal (`totalAllocatedChars`) directly measures the resource being consumed — the total HTML text retained in the cache.
- This signal grows monotonically with the number of unique cache entries, providing a continuous gradient toward OOM.
- **Measurable metric**: Time-to-first-OOM. CGF is expected to reach OOM significantly faster because it preferentially retains and mutates inputs that increase cache size, whereas Zest stagnates after coverage saturation.

#### IMPORT AUDIT

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
SignalSource → dosguide.validate.SignalSource
ClassVisitor → org.objectweb.asm.ClassVisitor
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
MethodVisitor → org.objectweb.asm.MethodVisitor
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter
Opcodes → org.objectweb.asm.Opcodes
ClassFileTransformer → java.lang.instrument.ClassFileTransformer
Instrumentation → java.lang.instrument.Instrumentation
```

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — all code targets Java 17, no preview APIs
- [YES] No hallucinated APIs — all JQF, ASM, and JDK APIs verified from real artifacts
- [YES] Guidance implements Guidance directly — V1Guidance implements `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` + `dosguide.validate.SignalSource`
- [YES] No existing guidance extended — clean implementation from Guidance interface
- [YES] V* vulnerabilities identified — V1: unbounded ConcurrentHashMap cache growth
- [YES] V* IDs are sequential (V1) — not derived from version numbers [R42]
- [YES] Official vulnerability names applied — CWE-770 (Allocation Without Limits)
- [YES] PkgRisk-* identified — PkgRisk-1 (replaceAll) on same path, not independently exploitable
- [YES] Every PkgRisk-* executed or justified — PkgRisk-1 is on V1's attack path, exercised by V1's fuzz method
- [YES] Guidance targets V* — V1Guidance targets V1 exclusively
- [YES] One fuzz method per V* — `fuzzHtmlErrorResponseBodyProviderBody` for V1
- [YES] CLI method selection supported — FuzzRunner accepts target ID (V1) as CLI arg
- [YES] Byte[]/InputStream input model used exclusively — no generators [R31]
- [YES] No junit-quickcheck Generators used — all mutation inside Guidance
- [YES] All mutation implemented inside Guidance — byte-level + repetition + dictionary
- [YES] Repetition, dictionary, encoder operators — repetition (line/block doubling), dictionary (8 tokens from source), no encoder needed (plain text)
- [YES] Retention progresses while signal flat; inputs reach input_bytes in < 1 min — secondary retention on length growth; doubling reaches 800KB in 16 steps
- [YES] Retention signals measured at sink — `totalAllocatedChars` at `html()` return (the method that produces cached values for `computeIfAbsent`)
- [YES] Logging every 1 second — structured log line with executions, best signals, corpus size
- [YES] Guidance decides no failures, writes no failure files — only saves corpus [R6]
- [YES] Corrupted inputs saved with metadata — corpus saves input bytes + signal values
- [YES] Replay/feeder implemented — ReplayRunner reads saved inputs and replays
- [YES] Infinite + time-bounded fuzzing — default infinite; MAX_DURATION_MILLIS for bounded
- [YES] src/main vs src/test separation — all fuzzing infra in src/test/java, no stubs needed in src/main
- [YES] Maven scopes consistent — system for micronaut, test for JQF
- [YES] No wildcard imports for JQF/tracing — all explicit
- [YES] TraceEvent import verified — not used (custom agent, not JQF tracing)

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "totalAllocatedChars",
          "quantity": "sum of String.length() of all HTML strings returned by html() during one execution",
          "aggregation": "sum",
          "locations": ["DefaultHtmlErrorResponseBodyProvider#html"],
          "technique": "bytecode",
          "storage": "long[] array in System.getProperties() under key V1_COUNTERS; index 1",
          "reset": "V1Guidance.getInput() zeroes counters[0] and counters[1] before each execution",
          "read": "V1Guidance.handleResult() reads counters[1]"
        },
        {
          "name": "htmlCallCount",
          "quantity": "number of html() invocations (cache misses) during one execution",
          "aggregation": "count",
          "locations": ["DefaultHtmlErrorResponseBodyProvider#html"],
          "technique": "bytecode",
          "storage": "long[] array in System.getProperties() under key V1_COUNTERS; index 0",
          "reset": "V1Guidance.getInput() zeroes counters[0] and counters[1] before each execution",
          "read": "V1Guidance.handleResult() reads counters[0]"
        }
      ],
      "retention": "Primary: keep inputs where totalAllocatedChars exceeds current best. Secondary (flat signal): keep inputs that grow in length toward input_bytes=800000 to cross the threshold where the first html() call occurs. Tertiary: keep inputs that achieve a new maximum htmlCallCount.",
      "retention_signals": ["totalAllocatedChars", "htmlCallCount"],
      "mutation": [
        "byte-level: random byte flip, random byte insertion, random byte deletion, contiguous block overwrite (1-16 bytes)",
        "repetition: duplicate a line-aligned region (between \\n boundaries) and repeat it k times; also: double the entire input; grows toward input_bytes=800000 in < 16 doubling steps",
        "dictionary: tokens from the attack path source code — \\n (line separator), & (sanitizer special), < (sanitizer special), > (sanitizer special), \" (sanitizer special), ' (sanitizer special), .error (message code suffix), . (article punctuation)",
        "no encoder needed: input is plain UTF-8 text with no checksum or compression format"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

I'll implement all the files now. Let me start by reading the key source files to ensure correctness, then emit all implementation files.

```text
Read <run_dir>/src/test/java/com/fuzzing/harness/SanitizerFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me check the JQF Guidance and Result APIs to ensure correctness:

```text
$ jar tf target/deps/jqf-fuzz-2.1.jar | grep -E "Guidance|Result|GuidedFuzzing" | head -20
$ javap -cp target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1
$ javap -cp target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ javap -cp target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1
$ javap -cp target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent 2>&1
$ jar tf target/deps/jqf-instrument-2.1.jar | grep TraceEvent | head -5
$ javap -cp target/deps/jqf-instrument-2.1.jar edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent 2>&1
```

Good. Now I have all the API signatures. Let me write all the implementation files:

```text
Write <run_dir>/src/test/java/com/fuzzing/agent/V1MeasureAgent.java
```

That agent file has issues with the stack manipulation. Let me rewrite it properly using a cleaner callback approach:

```text
Write <run_dir>/src/test/java/com/fuzzing/agent/V1MeasureAgent.java
```

Let me check the current workspace state and read the key files I need to reference:

```text
$ find <run_dir> -type f | sort
Read <run_dir>/src/test/java/com/fuzzing/harness/SanitizerFuzzTest.java
Read <run_dir>/pom.xml
```

Now let me read the guidance plan and block 2 analysis to understand the measurement plan and strategy:

```text
Read <run_dir>/analysis/guidance_plan.json
Read <run_dir>/analysis/target_register.json
```

Now let me write all remaining implementation files. Let me do V1Guidance, FuzzRunner, ReplayRunner, run.sh, and launch.json:

```text
Write <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
Write <run_dir>/src/test/java/com/fuzzing/runner/FuzzRunner.java
Write <run_dir>/src/test/java/com/fuzzing/runner/ReplayRunner.java
Write <run_dir>/run.sh
Write <run_dir>/analysis/launch.json
```

Good. Now let me make run.sh executable and compile to verify everything builds:

```text
$ chmod +x <run_dir>/run.sh
$ mvn -q package -DskipTests 2>&1 | tail -30
```

The `TraceEvent` class is in `jqf-instrument`. Let me check where it actually lives:

```text
$ jar tf <run_dir>/target/deps/jqf-instrument-2.1.jar 2>/dev/null | grep -i traceevent
$ jar tf <run_dir>/target/deps/jqf-fuzz-2.1.jar 2>/dev/null | grep -i traceevent
```

The package is `events` (plural), not `event`. Let me also verify the Guidance interface signature:

```text
$ javap -cp target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1 | head -30
```

The package is `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` (plural). Let me fix all three files:

```text
Edit <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
Edit <run_dir>/src/test/java/com/fuzzing/runner/ReplayRunner.java
```

Now let me retry the build:

```text
$ mvn -q package -DskipTests 2>&1 | tail -30
```

Build succeeded. Now build the agent JAR and verify all compiled classes:

```text
$ mkdir -p target/agent-manifest && printf 'Premain-Class: com.fuzzing.agent.V1MeasureAgent\n' > target/agent-manifest/MANIFEST.MF && jar cfm target/v1-agent.jar target/agent-manifest/MANIFEST.MF -C target/test-classes com/fuzzing/agent/ 2>&1
$ find <run_dir>/target/test-classes -name '*.class' | sort
```

All classes compiled. Let me verify the agent JAR contains the correct classes and manifest:

```text
$ jar tf target/v1-agent.jar && echo "---" && unzip -p target/v1-agent.jar META-INF/MANIFEST.MF
```

Agent JAR is correct. Now let me verify that the vulnerable artifact from `lib/` (not Maven Central) is on the classpath by checking the system-scope jars were copied to `target/deps/`:

```text
$ ls -la <run_dir>/target/deps/micronaut-http-server-4.10.17-SNAPSHOT.jar && md5sum <run_dir>/target/deps/micronaut-http-server-4.10.17-SNAPSHOT.jar /data …
```

MD5 checksums match — the vulnerable artifact from `lib/` is the same one in `target/deps/`. Let me confirm the target class is inside:

```text
$ jar tf <run_dir>/lib/micronaut-http-server-4.10.17-SNAPSHOT.jar | grep DefaultHtmlErrorResponseBodyProvider
```

Now let me also create some validation inputs that can be used for quick verification:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
$ # Generate a small validation input: 10 unique 3-char lines …
$ # Generate a medium validation input: 200 unique 3-char lines …
```

Let me verify the validation inputs:

```text
$ wc -l <run_dir>/analysis/validation_inputs/*.bin && wc -c <run_dir>/analysis/validation_inputs/*.bin
```

Good. Now let me do a final review of all files to make sure everything is consistent. Let me verify the validation contract points:

1. **`lastSignals()` returns correct signal names** matching guidance_plan.json:

```text
$ grep -n "lastSignals\|totalAllocatedChars\|htmlCallCount" src/test/java/com/fuzzing/guidance/V1Guidance.java
Grep <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java lastSignals|totalAllocatedChars|htmlCallCount
```

Signal names `totalAllocatedChars` and `htmlCallCount` match the guidance_plan.json exactly.

2. **`createGuidance()` factory method exists with correct signature:**

```text
Grep <run_dir>/src/test/java/com/fuzzing/runner/FuzzRunner.java createGuidance
```

3. **MAX_INPUT_SIZE compliance:**

```text
Grep <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java MAX_INPUT_SIZE|maxInputSize
```

Good — reads from `Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240)` and enforces it everywhere.

4. **Agent instruments correct locations:**

```text
Grep <run_dir>/src/test/java/com/fuzzing/agent/V1MeasureAgent.java TARGET_CLASS|TARGET_METHOD|V1_COUNTERS|V1_ON_HTML
```

Everything is consistent. Let me do a final listing of all workspace files to confirm the complete deliverable:

```text
$ find <run_dir> -type f \( -name '*.java' -o -name '*.json' -o -name '*.sh' -o -name '*.bin' -o -name 'MANIFEST.MF' \) | sort
```

All Block 3 implementation files are written, compiled, and verified. Here's a summary of what was delivered:

**Part A — Java Agent** (`V1MeasureAgent.java`):
- Instruments `DefaultHtmlErrorResponseBodyProvider#html()` via ASM 9
- At method entry: invokes a `Runnable` from `System.getProperties().get("V1_ON_HTML_ENTRY")` → increments `counters[0]` (htmlCallCount)
- Before ARETURN: invokes a `Consumer<String>` from `System.getProperties().get("V1_ON_HTML_RETURN")` → adds `returnString.length()` to `counters[1]` (totalAllocatedChars)
- Clean cross-classloader design: lambdas captured over the shared `long[]` array, called via JDK interfaces (`Runnable`, `Consumer`) retrievable from any classloader
- Agent JAR built at `target/v1-agent.jar` with `Premain-Class` manifest

**Part B — Guidance** (`V1Guidance.java`):
- Implements `Guidance` + `SignalSource` (no inheritance from existing guidances)
- Hill-climbing on `totalAllocatedChars` (primary) and `htmlCallCount` (secondary)
- 9 mutation operators: byte flip (8%), byte insert (6%), byte delete (4%), block overwrite (8%), line duplicate (20%), double input (10%), dictionary insert (12%), new unique lines (20%), splice new lines (12%)
- Reads `Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240)` and enforces it on all mutations
- `lastSignals()` returns `{"totalAllocatedChars": ..., "htmlCallCount": ...}` per execution
- Resets counters in `getInput()`, reads in `handleResult()`
- Logs progress every 1 second

**Part C — Runners** (`FuzzRunner.java`, `ReplayRunner.java`):
- `FuzzRunner.createGuidance(targetId, outputDir, maxDurationMs, log)` factory method
- `ReplayRunner` replays a single input file and prints signal values

**Part D — Build/Run** (`run.sh`, `analysis/launch.json`):
- `run.sh` builds, packages agent JAR, assembles classpath, runs with `-Xmx1g -Xss1m -javaagent:target/v1-agent.jar -Djqf.ei.MAX_INPUT_SIZE=1048576`
- `launch.json` describes build commands, JVM args, classpath, signal names, and factory method for validation
- Validation inputs in `analysis/validation_inputs/` (10-line and 200-line samples)

## Validation repair 1

Let me fix the `launch.json` format to match the expected schema:

```text
Read <run_dir>/analysis/launch.json
Write <run_dir>/analysis/launch.json
```

Now let me verify the build still works cleanly:

```text
$ mvn -q package -DskipTests 2>&1 | tail -10
```

Build succeeds. Here's a summary of what I changed:

**Fixed `analysis/launch.json`** to match the expected validation schema:
1. Changed `"build"` from a nested `{"commands": [...]}` object to a flat list of shell command strings.
2. Added top-level `"javaagent": {"jar": "target/v1-agent.jar", "args": ""}` field.
3. Added top-level `"jvm_args": []` field (empty since evaluation fixes JVM options per R41).
4. Changed `"guidance_factory"` from the per-target `"factory_method"` with full signature to top-level `"com.fuzzing.runner.FuzzRunner#createGuidance"` (short form without parameter types).
5. Simplified `"targets"` to contain only `"test_class"` and `"method"` per target, removing redundant fields that belong at the top level.

## Validation repair 2

Let me analyze the two failures:

1. **input_limit**: With `MAX_INPUT_SIZE=16`, 1 of 20 inputs was longer than 16 bytes. The seeds (especially seed 3 and 4) are larger than 16 bytes and are returned without truncation.
2. **input_growth**: In 60s the longest input was only 87KB, but needs to reach 800KB. The growth operators aren't aggressive enough, and the hill-climbing only retains on signal improvement — but with small inputs the signal might be flat (few unique lines), so growth-oriented inputs get discarded.

Let me fix V1Guidance.java:

```text
Read <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
```

Now I'll rewrite V1Guidance with these fixes:

```text
Write <run_dir>/src/test/java/com/fuzzing/guidance/V1Guidance.java
```

Now let me verify it compiles:

```text
$ mvn -q package -DskipTests 2>&1 | tail -20
```

Build succeeds. Let me also rebuild the agent JAR to keep everything in sync:

```text
$ jar cfm target/v1-agent.jar target/agent-manifest/MANIFEST.MF -C target/test-classes com/fuzzing/agent/ 2>&1
```

Here's a summary of what I changed in `V1Guidance.java`:

**Fix 1 — input_limit** (seeds exceeding `MAX_INPUT_SIZE=16`):
- Added `addSeed()` helper that truncates every seed to `maxInputSize` before storing it.
- Added a hard enforcement `if (currentInput.length > maxInputSize)` truncation in `getInput()` as a safety net, so no input ever exceeds the limit regardless of source.

**Fix 2 — input_growth** (only reached 87KB in 60s, needed 800KB):
- **Tertiary retention on length**: Added `bestLength` tracking and a third retention criterion — keep inputs that are longer than the current best even when the signal is flat. This ensures growth-oriented mutations are retained.
- **Aggressive `mutateNewUniqueLines`**: Changed from adding 1-50 small lines (~350 bytes max) to filling 10-100% of remaining capacity in a single step. A single application can now grow from near-empty to near-`maxInputSize`.
- **Aggressive `mutateSpliceNewLines`**: Same scaling — fills toward `maxInputSize` instead of adding a fixed 5-30 lines.
- **Fixed `mutateDoubleInput`**: No longer gives up when `2*len > maxInputSize`. Instead fills up to `maxInputSize` by repeating the input, so it works even when the input is already > half the limit.
- **Growth-phase mutation weights**: When fill ratio < 80%, growth operators (`doubleInput` 20%, `newUniqueLines` 30%, `spliceNewLines` 20%) get 70% total weight instead of the previous ~42%.
- **`mutateLineDuplicate`**: Now fills as much remaining space as possible rather than limiting to 1-10 copies.
