# elasticsearch_GHSA-gphj-4h6p-37xq

## Block 1

I'll start by reading the frozen fuzz test harness and the main source file to understand the entry points and vulnerability surface.

```text
Read <run_dir>
$ ls <run_dir>/
Glob <run_dir> **/*FuzzTest*.java
Read <run_dir>/src/test/java/org/elasticsearch/compute<data>/BlockBuilderFuzzTest.java
Read <run_dir>/pom.xml
Read <source_root>/x-pack/plugin/esql/compute/src/main/java/org/elasticsearch/compute<data>
```

Now let me trace deeper into the code. I need to understand how `BlockFactory`, `IntBlock.Builder`, and `LongBlock.Builder` work, and how `estimatedSize` is handled.

```text
Glob <source_root> **/compute<data>
Glob <source_root> **/compute<data>
Glob <source_root> **/compute<data>
Read <source_root>/x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute<data>
Read <source_root>/x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute<data>
Read <source_root>/x-pack/plugin/esql/compute/src/main/java/org/elasticsearch/compute<data>
```

Now let me look at Lucene's `ArrayUtil.oversize` and the `HierarchyCircuitBreakerService` defaults to understand the breaker limits:

```text
Grep <source_root> public static int oversize
Grep <source_root>/server/src/main/java/org/elasticsearch/indices/breaker/HierarchyCircuitBreakerService.java REQUEST.*setting|REQUEST.*default|TOTAL_CIRCUIT_BREAKER_LIMIT|REQUEST_CIRCUIT_BREAKER_LIMIT
```

Good. The REQUEST circuit breaker defaults to 60% of JVM heap = ~600MB with -Xmx1g. Now let me verify the `NUM_BYTES_ARRAY_HEADER` value and check the `ArrayUtil.oversize` from the Lucene dependency used:

```text
$ find <run_dir>/lib -name "*.jar" | head -5
Grep <source_root> NUM_BYTES_ARRAY_HEADER
$ ls <run_dir>/lib/ | sort
```

Now let me verify the vulnerability by examining the constructor arithmetic more carefully. Let me also check for any existing fix patterns:

```text
$ cd <source_root> && jar -tf lib/x-pack-esql-compute-8.19.7-SNAPSHOT.jar 2>/dev/null | head -10 || jar -tf x-pack/plugin/esql/compute/src/main/generated-src/../../../target/*.jar 2>/dev/null | head -10 || echo "checking workspace jar"; ja …
```

Now I have a clear picture of the vulnerability. Let me create the scale measurement data files and write the complete analysis.

```text
$ mkdir -p <run_dir>/analysis/scale/V1 …
```

Now generate the binary input files for V1 (IntBlockBuilder):

```text
$ cd <run_dir> …
```

Now write the series.json files:

```text
Write <run_dir>/analysis/scale/V1/series.json
Write <run_dir>/analysis/scale/V2/series.json
```

Let me verify the files are correct:

```text
$ cd <run_dir> …
```

Now let me verify the complete file structure:

```text
$ find <run_dir>/analysis -type f | sort
```

Good. All files are in place. Now let me compile the complete analysis.

---

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: Integer Overflow in IntBlockBuilder Constructor Breaker Accounting → OOM

**Fuzzable entrypoint & user-controlled inputs:**
- `BlockBuilderFuzzTest.fuzzBlockFactoryNewIntBlockBuilder(InputStream)` reads `estimatedSize` from bytes 4–7 of the input (via `data.getInt()`). This value flows directly into `BlockFactory.newIntBlockBuilder(estimatedSize)` → `IntBlockBuilder(estimatedSize, blockFactory)`.

**Mechanism:**
In the `IntBlockBuilder` constructor (line 29–34 of `IntBlockBuilder.java`):
```java
int initialSize = Math.max(estimatedSize, 2);
adjustBreaker(RamUsageEstimator.NUM_BYTES_ARRAY_HEADER + initialSize * elementSize());
values = new int[initialSize];
```
The expression `initialSize * elementSize()` is computed in **32-bit int arithmetic** (`int × int → int`). For `elementSize() = 4` (Integer.BYTES), when `initialSize ≥ 536870912` (0x20000000), the product `initialSize * 4` **overflows the int range**. For example:
- `initialSize = 536870912`: `536870912 * 4 = 2147483648L`, but as `int` it wraps to `-2147483648`
- `NUM_BYTES_ARRAY_HEADER (16) + (-2147483648) = -2147483632`
- `adjustBreaker(-2147483632)` → negative delta → breaker **decreases** (no trip check)

The circuit breaker is effectively **bypassed**. The subsequent `new int[536870912]` attempts to allocate 2 GB, which exceeds the 1 GB JVM heap → **`OutOfMemoryError`**.

**Exhausted resource:** Heap memory. The growing quantity is the actual allocated array size: `initialSize * 4` bytes (true value, not the overflowed tracked value).

**Failure mode:** `out_of_memory` — `OutOfMemoryError` thrown by `new int[initialSize]` when `initialSize * 4` exceeds the JVM heap. The harness does not declare `OutOfMemoryError`, so it is an undeclared throwable → failure.

**Scale:** The int overflow threshold is `initialSize ≥ 536870912` (= 2^29). At this value, the true allocation is 2 GB, far exceeding the 1 GB heap. The minimum `estimatedSize` for overflow is 536870912. The input needs only 8 bytes total (4 for `numAppends` which can be 0, 4 for `estimatedSize`). The breaker (default 60% of 1 GB ≈ 600 MB) would correctly trip for any `estimatedSize` where the product does NOT overflow (e.g., `estimatedSize = 268435456` → 1 GB → breaker trips at 600 MB). The vulnerability exists specifically in the gap where the product overflows int, making the breaker blind to the true allocation size.

**`input_bytes`:** 8

---

###### V2: Integer Overflow in LongBlockBuilder Constructor Breaker Accounting → OOM

**Fuzzable entrypoint & user-controlled inputs:**
- `BlockBuilderFuzzTest.fuzzBlockFactoryNewLongBlockBuilder(InputStream)` reads `estimatedSize` from bytes 4–7. Flows into `BlockFactory.newLongBlockBuilder(estimatedSize)` → `LongBlockBuilder(estimatedSize, blockFactory)`.

**Mechanism:**
Identical pattern in `LongBlockBuilder` constructor (line 29–34 of `LongBlockBuilder.java`):
```java
int initialSize = Math.max(estimatedSize, 2);
adjustBreaker(RamUsageEstimator.NUM_BYTES_ARRAY_HEADER + initialSize * elementSize());
values = new long[initialSize];
```
Here `elementSize() = 8` (Long.BYTES). Overflow occurs at `initialSize ≥ 268435456` (0x10000000):
- `initialSize = 268435456`: `268435456 * 8 = 2147483648L`, but as `int` wraps to `-2147483648`
- `NUM_BYTES_ARRAY_HEADER (16) + (-2147483648) = -2147483632` → breaker bypassed
- `new long[268435456]` = 2 GB → OOM

The overflow threshold is LOWER than for IntBlockBuilder because each long element is 8 bytes (twice int), so fewer elements are needed to overflow.

**Exhausted resource:** Heap memory. Growing quantity: `initialSize * 8` bytes.

**Failure mode:** `out_of_memory`

**Scale:** Overflow threshold at `initialSize ≥ 268435456` (= 2^28). True allocation is 2 GB. Input: 8 bytes. The breaker limit (~600 MB) correctly catches non-overflowing allocations but is bypassed when the int product wraps negative.

**`input_bytes`:** 8

---

##### 1.2 Official Classification

| Target | Classification |
|--------|---------------|
| V1 | **CWE-190** (Integer Overflow or Wraparound) leading to **CWE-770** (Allocation of Resources Without Limits or Throttling). The GHSA advisory GHSA-gphj-4h6p-37xq classifies this as Uncontrolled Resource Consumption. |
| V2 | **CWE-190** (Integer Overflow or Wraparound) leading to **CWE-770** (Allocation of Resources Without Limits or Throttling). Same vulnerability class as V1 in a parallel generated builder. |

---

##### 1.3 Dependency / Package-Level Risks

**Analysis of dependencies on the attack path:**

1. **`org.apache.lucene.util.ArrayUtil.oversize(int, int)`** (Lucene 9.12.2): Used in `AbstractBlockBuilder.ensureCapacity()` and `setFirstValue()` for array growth calculations. This method computes the new array size but does NOT perform the `size * elementSize` multiplication. The multiplication overflow is in Elasticsearch's calling code, not in Lucene. `ArrayUtil.oversize` itself returns a reasonable value. **Not a PkgRisk** — the vulnerability is in the caller's arithmetic.

2. **`org.apache.lucene.util.RamUsageEstimator.NUM_BYTES_ARRAY_HEADER`** (Lucene 9.12.2): A constant (typically 16). Just a constant added to the overflowed product. **Not a PkgRisk**.

3. **`org.elasticsearch.common.breaker.CircuitBreaker`** (Elasticsearch): The breaker itself works correctly — it trips when given a value above its limit. The bug is that the **wrong value** is passed to it (due to int overflow in the caller). **Not a PkgRisk**.

4. **No regex, JSON/XML parsing, compression, hashing, or URL parsing** is present on the attack path from the fuzz test entry points to the vulnerable constructors.

**Conclusion:** No PkgRisk targets identified. The vulnerability is entirely within the Elasticsearch compute module's own integer arithmetic in the block builder constructors.

---

##### `ensureCapacity()` overflow — analyzed and ruled out

The `ensureCapacity()` method in `AbstractBlockBuilder` (line 144–153) also computes `newSize * elementSize()` in int arithmetic. However, this path is **unreachable** as a vulnerability because:
- To reach a `newSize` large enough to overflow, `valueCount` must grow through all intermediate sizes
- Each intermediate growth correctly accounts memory with the breaker (no overflow at intermediate sizes)
- The breaker trips at ~600 MB (≈150M int elements or ≈75M long elements), well below the overflow threshold (536870912 for int, 268435456 for long)
- Therefore, the breaker prevents `ensureCapacity()` from ever reaching the overflow threshold via the `appendInt`/`appendLong` loop

---

#### PHASE B — Target Selection & Register

##### Target Selection Rationale

Both V1 and V2 are DoS vulnerabilities exploiting the same integer overflow pattern (CWE-190 → CWE-770) in parallel-generated block builder constructors. They differ in:
- **Entry point**: Different `@Fuzz` methods (`fuzzBlockFactoryNewIntBlockBuilder` vs `fuzzBlockFactoryNewLongBlockBuilder`)
- **Overflow threshold**: 536870912 for int (elementSize=4) vs 268435456 for long (elementSize=8)
- **Sink class**: `IntBlockBuilder` vs `LongBlockBuilder`

V2 (Long) is prioritized first because the lower overflow threshold makes it easier to trigger.

No PkgRisk targets are included because none were identified.

##### Scale measurement data

**V1 series** (`analysis/scale/V1/`): 6 inputs with `numAppends=0`, `estimatedSize` = 1024, 4096, 16384, 65536, 262144, 1048576. These create int arrays of 4KB to 4MB. The measurement will show heap allocation growing linearly with `estimatedSize` (4× the value). All inputs are 8 bytes, well within the 2560-byte cap.

**V2 series** (`analysis/scale/V2/`): 6 inputs with `numAppends=0`, `estimatedSize` = 1024, 4096, 16384, 65536, 262144, 1048576. These create long arrays of 8KB to 8MB. Allocation grows linearly at 8× the value.

---

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "IntBlockBuilder constructor integer overflow bypasses circuit breaker → OOM",
      "entrypoint": "BlockBuilderFuzzTest.fuzzBlockFactoryNewIntBlockBuilder(InputStream) → BlockFactory.newIntBlockBuilder(int) → IntBlockBuilder.<init>(int, BlockFactory) → AbstractBlockBuilder.adjustBreaker(long)",
      "source_path": "x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute<data>",
      "sink": "IntBlockBuilder#<init>(int, BlockFactory)",
      "mechanism": "estimatedSize from input bytes flows to Math.max(estimatedSize, 2) → initialSize; the expression initialSize * elementSize() (int * int) overflows for initialSize >= 536870912 (elementSize=4), producing a negative or small value; adjustBreaker receives the overflowed value and does not trip; the subsequent new int[initialSize] allocates 2+ GB exceeding the 1 GB heap",
      "resource": "heap memory: allocated array bytes = initialSize * 4 (true value), grows linearly with estimatedSize",
      "failure_mode": "out_of_memory",
      "scale": "initialSize >= 536870912 causes int overflow; true allocation = 2+ GB exceeds 1 GB heap; only 8 bytes of input needed (4 for numAppends=0, 4 for estimatedSize >= 0x20000000)",
      "input_bytes": 8,
      "cwe": "CWE-190"
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "LongBlockBuilder constructor integer overflow bypasses circuit breaker → OOM",
      "entrypoint": "BlockBuilderFuzzTest.fuzzBlockFactoryNewLongBlockBuilder(InputStream) → BlockFactory.newLongBlockBuilder(int) → LongBlockBuilder.<init>(int, BlockFactory) → AbstractBlockBuilder.adjustBreaker(long)",
      "source_path": "x-pack/plugin/esql/compute/src/main/generated-src/org/elasticsearch/compute<data>",
      "sink": "LongBlockBuilder#<init>(int, BlockFactory)",
      "mechanism": "estimatedSize from input bytes flows to Math.max(estimatedSize, 2) → initialSize; the expression initialSize * elementSize() (int * int) overflows for initialSize >= 268435456 (elementSize=8), producing a negative or small value; adjustBreaker receives the overflowed value and does not trip; the subsequent new long[initialSize] allocates 2+ GB exceeding the 1 GB heap",
      "resource": "heap memory: allocated array bytes = initialSize * 8 (true value), grows linearly with estimatedSize",
      "failure_mode": "out_of_memory",
      "scale": "initialSize >= 268435456 causes int overflow; true allocation = 2+ GB exceeds 1 GB heap; only 8 bytes of input needed (4 for numAppends=0, 4 for estimatedSize >= 0x10000000)",
      "input_bytes": 8,
      "cwe": "CWE-190"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

#### Analysis of Scale Measurements

##### V1 (IntBlockBuilder)

The `allocated` column shows a baseline of ~61.5 MB (JVM/framework overhead). The incremental growth above baseline:
- value=1024: ~0 MB above baseline (4 KB array, invisible in MB-level measurement)
- value=1048576: ~3.9 MB above baseline (expected: 1048576 × 4 = 4 MB)

**Measured cost per unit:** ~4 bytes per unit of `estimatedSize` — exactly `elementSize()` = `Integer.BYTES`. Linear growth confirmed.

**Extrapolation:** At 4 bytes/unit, the circuit breaker (60% of 1 GB heap ≈ 614 MB) trips at `estimatedSize ≈ 614 MB / 4 = ~153 million`. All values below 153M are safely caught by the breaker. At `estimatedSize = 536870912` (2^29), the int product `536870912 * 4 = 2147483648` overflows 32 bits to `−2147483648`, the breaker receives a negative delta and doesn't trip, and `new int[536870912]` requests 2 GB → `OutOfMemoryError` under -Xmx1g. The `peak heap` noise (8–45 MB) is GC-dependent and irrelevant; the failure is a single allocation that exceeds the entire heap.

##### V2 (LongBlockBuilder)

Incremental growth above ~61.5 MB baseline:
- value=1024: ~0 MB (8 KB array)
- value=1048576: ~7.7 MB (expected: 1048576 × 8 = 8 MB)

**Measured cost per unit:** ~8 bytes per unit of `estimatedSize` — exactly `elementSize()` = `Long.BYTES`. Linear growth confirmed.

**Extrapolation:** At 8 bytes/unit, the breaker trips at `estimatedSize ≈ 614 MB / 8 = ~76 million`. At `estimatedSize = 268435456` (2^28), the int product `268435456 * 8 = 2147483648` overflows to `−2147483648`, breaker bypassed, `new long[268435456]` requests 2 GB → OOM.

##### Encoding density

Both targets use the densest possible encoding: 8 bytes total (4 bytes `numAppends` = 0, 4 bytes `estimatedSize`). No denser encoding exists — the `estimatedSize` value is read as a single `int` from `ByteBuffer.getInt()`, so all 4 bytes are consumed in one read. `input_bytes` = 8 remains correct.

##### Mechanism confirmation

The measurements validate the linear allocation model at the expected rates (4 and 8 bytes per unit). The vulnerability mechanism is confirmed: it is a **threshold discontinuity** (integer overflow at a specific value), not a gradual resource exhaustion. The breaker works correctly below the threshold; at the threshold, int overflow causes the breaker to register a wrong (negative) amount, and the unchecked allocation exceeds heap.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured 4 bytes of heap allocation per unit of estimatedSize (linear, matches elementSize=4). Circuit breaker correctly trips at estimatedSize ~153 million (~614 MB). At estimatedSize = 536870912 (2^29), int product 536870912*4 overflows 32-bit int to -2147483648, breaker registers negative delta and does not trip, new int[536870912] requests 2 GB exceeding 1 GB heap → OutOfMemoryError. 8 bytes of input suffice.",
    "input_bytes": 8
  },
  "V2": {
    "scale": "Measured 8 bytes of heap allocation per unit of estimatedSize (linear, matches elementSize=8). Circuit breaker correctly trips at estimatedSize ~76 million (~614 MB). At estimatedSize = 268435456 (2^28), int product 268435456*8 overflows 32-bit int to -2147483648, breaker registers negative delta and does not trip, new long[268435456] requests 2 GB exceeding 1 GB heap → OutOfMemoryError. 8 bytes of input suffice.",
    "input_bytes": 8
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by reading the existing workspace structure and understanding what's already in place, then develop the measurement strategy.

```text
$ find <run_dir>/src -type f | sort
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/src/test/java/org/elasticsearch/compute<data>/BlockBuilderFuzzTest.java
```

Let me verify the existing pom.xml compiles correctly with the existing workspace structure:

```text
$ mvn compile 2>&1 | tail -20
$ mvn test-compile 2>&1 | tail -20
$ mvn package -DskipTests 2>&1 | tail -30
```

Build succeeds. I can see ASM 9.8 is already on the classpath transitively via jqf-instrument. Let me verify the available ASM classes and check if there are any compilation issues with the frozen test classes:

```text
$ ls <run_dir>/target/dependency/ | grep -i asm
$ ls <run_dir>/target/
$ find <run_dir>/target/test-classes -type f | sort
```

Good. Now let me look at the actual bytecode of `IntBlockBuilder.<init>` and `LongBlockBuilder.<init>` to understand how to instrument them:

```text
$ javap -c -p -cp lib/x-pack-esql-compute-8.19.7-SNAPSHOT.jar org.elasticsearch.compute.data.IntBlockBuilder 2>&1 | head -60
$ javap -c -p -cp lib/x-pack-esql-compute-8.19.7-SNAPSHOT.jar org.elasticsearch.compute.data.LongBlockBuilder 2>&1 | head -45
$ javap -c -p -cp lib/x-pack-esql-compute-8.19.7-SNAPSHOT.jar org.elasticsearch.compute.data.AbstractBlockBuilder 2>&1 | head -80
```

Now let me verify ASM is available with the right version for bytecode manipulation:

```text
$ jar tf target/dependency/asm-9.8.jar | grep "ClassVisitor\|MethodVisitor\|Opcodes\|ClassReader\|ClassWriter" | head -10
```

Good. Now let me verify there are no missing symbols for compilation. Let me check the Guidance interface in JQF to understand the exact API:

```text
$ jar tf target/dependency/jqf-fuzz-2.1.jar | grep "guidance/Guidance\|GuidedFuzzing\|Result" | head -20
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1
$ javap -cp target/dependency/jqf-instrument-2.1.jar edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent 2>&1
```

Now I have all the information needed. Let me verify the pom.xml is correct (it already is — all lib/ jars exist and dependencies are proper). The pom.xml does not need changes. Let me confirm:

```text
$ ls <run_dir>/lib/*.jar | wc -l
```

Good — 15 jars matching the 15 system-scope declarations in pom.xml. The pom.xml needs no changes. Now let me produce the complete strategy output.

---

#### Step 2 — Maven Layout & Scope

The existing pom.xml is correct and complete:

**Production code** (`src/main/java`): Empty. No project source is copied into the workspace ([R17b]). All target classes come from the vulnerable jars in `lib/` via `<scope>system</scope>` and `<systemPath>`.

**Test code** (`src/test/java`): All fuzzing infrastructure:
- `BlockBuilderFuzzTest.java` (frozen harness)
- `SignalSource.java` (frozen DoSGuide interface)
- Future: Guidance classes, agent classes, runner, replay

**Dependency scope correctness:**
| Artifact | Scope | Rationale |
|----------|-------|-----------|
| elasticsearch-*, x-pack-esql-compute | system (lib/) | Vulnerable artifact — NOT from Maven Central |
| lucene-* | compile | Transitive dep of ES compute module |
| log4j, hppc, joni, etc. | compile/runtime | Third-party transitive deps |
| jqf-fuzz, jqf-instrument | test | Fuzzing framework |
| junit, junit-quickcheck-core | test | Test runner |

ASM 9.8 is available transitively from `jqf-instrument` — no pom.xml change needed for the custom agent.

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

**For the frozen harness** (`BlockBuilderFuzzTest.java`):
Every import resolves to either a system-scope jar in lib/ or a test-scope dependency:
- `org.elasticsearch.common.breaker.CircuitBreaker` → `elasticsearch-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.common.breaker.CircuitBreakingException` → `elasticsearch-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.common.logging.LogConfigurator` → `elasticsearch-logging-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.common.settings.ClusterSettings` → `elasticsearch-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.common.settings.Settings` → `elasticsearch-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.common.util.BigArrays` → `elasticsearch-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.compute.data.BlockFactory` → `x-pack-esql-compute-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.compute.data.IntBlock` → `x-pack-esql-compute-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.compute.data.LongBlock` → `x-pack-esql-compute-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.indices.breaker.CircuitBreakerMetrics` → `elasticsearch-8.19.7-SNAPSHOT.jar` ✓
- `org.elasticsearch.indices.breaker.HierarchyCircuitBreakerService` → `elasticsearch-8.19.7-SNAPSHOT.jar` ✓
- `edu.berkeley.cs.jqf.fuzz.Fuzz` → `jqf-fuzz-2.1.jar` (test) ✓
- `edu.berkeley.cs.jqf.fuzz.JQF` → `jqf-fuzz-2.1.jar` (test) ✓

**For planned fuzzing infra** (Guidance, Agent, Runner):
- `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` → `jqf-fuzz-2.1.jar` (test) ✓
- `edu.berkeley.cs.jqf.fuzz.guidance.Result` → `jqf-fuzz-2.1.jar` (test) ✓
- `edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException` → `jqf-fuzz-2.1.jar` (test) ✓
- `edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing` → `jqf-fuzz-2.1.jar` (test) ✓
- `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` → `jqf-instrument-2.1.jar` (test) ✓
- `org.objectweb.asm.*` → `asm-9.8.jar` (transitive from jqf-instrument) ✓

##### 3.2 Stub Generation Rules

**No stubs are needed.** All symbols resolve to existing jars:
- Elasticsearch classes → lib/ system jars (15 jars)
- Lucene classes → Maven Central lucene-core 9.12.2
- JQF/ASM → test-scope transitive deps
- Third-party deps (log4j, hppc, etc.) → Maven Central

##### 3.3 Stub Report

**No stubs generated.** Every class referenced by the harness and planned fuzzing infrastructure is available from declared dependencies or system jars. No internal project classes are missing. Per [R21], no external library stubs are created.

#### Step 4 — GuidedFuzzing Usage

The runner will use:
```java
ClassLoader cl = Thread.currentThread().getContextClassLoader();
GuidedFuzzing.run(testClassName, testMethod, cl, guidance, System.out);
```

CLI selection:
```
java ... FuzzRunner V1 [timeSeconds]
java ... FuzzRunner V2 [timeSeconds]
```

V1 → runs `fuzzBlockFactoryNewIntBlockBuilder`
V2 → runs `fuzzBlockFactoryNewLongBlockBuilder`

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic Explanation) | Why This Strategy Wins |
|--------|------------------|------------------------------------------|------------------------|
| V1 | **VDF + CGF** (Vulnerability-Directed + Cost-Gradient) | Zest uses code coverage as its retention signal. For IntBlockBuilder, the constructor bytecode executes the SAME BRANCHES for `estimatedSize=10` and `estimatedSize=536870912`: `Math.max`, `adjustBreaker`, `new int[]`. No new branches are discovered as `estimatedSize` grows toward the overflow threshold. Zest treats all inputs that cover the same branches as equivalent and does not prioritize larger `estimatedSize`. Zest's proxy signal (coverage) is completely uncorrelated with the vulnerability's severity signal (allocation size at the array hotspot). | The custom Guidance measures `allocRequestedBytes` — the actual allocation attempted at the `NEWARRAY` bytecode in the constructor. It hill-climbs this signal: inputs that cause larger allocations are retained and prioritized. The signal correlates directly with the vulnerability mechanism (integer overflow in `initialSize * elementSize()`). The expected measurable metric: **time-to-first-OOM** is orders of magnitude faster because the guidance explores the `estimatedSize` space systematically, while Zest would only find it by lucky random mutation. |
| V2 | **VDF + CGF** (Vulnerability-Directed + Cost-Gradient) | Same as V1. Zest sees no new coverage as `estimatedSize` varies for LongBlockBuilder — the same `Math.max` → `adjustBreaker` → `new long[]` path is always taken. Coverage is flat; Zest has no reason to increase `estimatedSize`. | Same mechanism as V1 but targeting LongBlockBuilder. The lower overflow threshold (268M vs 536M) means the signal climbs faster per mutation step. The `allocRequestedBytes` signal measured at `NEWARRAY long` drives exploration toward the OOM. |

##### Zest Baseline Comparison [R18]

**Zest's failure mode**: Zest retains inputs that discover new code coverage. The IntBlockBuilder/LongBlockBuilder constructors have exactly ONE path through them for any `estimatedSize ≥ 2`: the same sequence of `Math.max → adjustBreaker → new T[]`. There are no branches based on `estimatedSize` value. Coverage is constant after the first valid input. Zest would stop retaining inputs because no new coverage is discovered, and the corpus stagnates at whatever `estimatedSize` the first seeds happen to have.

**Custom Guidance's advantage**: Uses a mechanism-aligned signal (`allocRequestedBytes`) that grows with `estimatedSize`, providing a continuous gradient to climb. Expected measurable advantage: **time-to-first-OOM** — the custom guidance should find the OOM in seconds to minutes, while Zest may never find it (or only by chance if random mutations happen to produce `estimatedSize ≥ 536870912`).

#### Step 6 — Strategy-Specific Guidance Design

##### Measurement Plan

###### Signal: `allocRequestedBytes`

**What it measures**: The number of bytes the `NEWARRAY` instruction in the block builder constructor is asked to allocate. Computed as `(long)initialSize * elementSize` using long arithmetic (avoiding the very overflow that is the vulnerability).

**Where produced**: Inside `IntBlockBuilder.<init>(int, BlockFactory)` and `LongBlockBuilder.<init>(int, BlockFactory)`, at the `NEWARRAY` bytecode instruction (bytecode offset 28 in both classes).

**Why this corresponds to the DoS mechanism**: The `NEWARRAY` instruction is the exact point where memory is consumed. The `initialSize` parameter on the stack at that point determines how much memory is requested. When this value is large enough to overflow the int product in the breaker accounting (instruction 20: `imul`), the breaker doesn't trip, and the `NEWARRAY` attempts an allocation exceeding the heap. Measuring at NEWARRAY is measuring at the consumption hotspot.

**How stored**: `ThreadLocal<long[]>` in `AllocCounter` class. The agent's inserted code calls `AllocCounter.recordAlloc(int arraySize, int elemSize)` which sets `ALLOC.get()[0] = (long)arraySize * elemSize`.

**Where reset**: In the Guidance's `getInput()` method, before returning the input stream: `AllocCounter.reset()`.

**Where consumed**: In the Guidance's `handleResult(Result, Throwable)` method: reads `AllocCounter.getAlloc()` and uses it for retention decisions.

##### Agent Instrumentation Plan [R35]

**Tier 1 (bytecode instrumentation via custom Java agent)**

**Classes/methods to instrument**:
- `org.elasticsearch.compute.data.IntBlockBuilder` — constructor `<init>(ILorg/elasticsearch/compute<data>;)V`
- `org.elasticsearch.compute.data.LongBlockBuilder` — constructor `<init>(ILorg/elasticsearch/compute<data>;)V`

**Exact instrumentation point**: Before the `NEWARRAY` bytecode instruction (offset 28 in both constructors). At this point, `initialSize` (local variable 3) is on the operand stack. The transformer inserts:
```
DUP                           // duplicate initialSize
BIPUSH/ICONST elemSize        // push 4 (for int) or 8 (for long)
INVOKESTATIC AllocCounter.recordAlloc(II)V
```
This consumes the duplicated `initialSize` and the element size, leaving the original `initialSize` on the stack for the original `NEWARRAY`.

**Required JVM flags**:
- `-javaagent:target/blockbuilder-alloc-agent.jar` — attaches the custom agent
- No `--add-opens` needed: the target classes are on the classpath (unnamed module), not in a named module

**Signal export**: `ThreadLocal<long[]>` in `AllocCounter` (shared between agent-instrumented code and Guidance via the same classloader delegation chain).

**Agent entry class**: `BlockBuilderAllocAgent` with `premain(String, Instrumentation)` that registers a `ClassFileTransformer`.

**Transformer**: `BlockBuilderAllocTransformer` using ASM `ClassVisitor`/`MethodVisitor` to find and instrument the constructors.

##### Mutation Operators [R45]

**Byte-level operators**:
- Random byte flip at random position within the 8-byte input
- Random byte overwrite at random position
- Arithmetic increment/decrement on a random 4-byte field (add/subtract random small delta)
- Random replacement of one 4-byte field with a random int value

**Structure-aware operators**:

**(a) Repetition**: Copy the `estimatedSize` field (bytes 4-7) to the `numAppends` field (bytes 0-3) or vice versa. Also: for inputs longer than 8 bytes, double a chunk and append (though the harness ignores bytes beyond 8, this ensures the Guidance CAN produce inputs as large as `input_bytes=8` trivially — any 8+ byte input suffices).

**(b) Dictionary tokens** from the code on the attack path:
| Token (4-byte big-endian) | Origin in source |
|--------------------------|-----------------|
| `[00,00,00,02]` | Literal `2` in `Math.max(estimatedSize, 2)` |
| `[00,00,00,04]` | `Integer.BYTES` = 4 (elementSize for IntBlockBuilder) |
| `[00,00,00,08]` | `Long.BYTES` = 8 (elementSize for LongBlockBuilder) |
| `[00,00,00,10]` | `RamUsageEstimator.NUM_BYTES_ARRAY_HEADER` = 16 |
| `[7F,FF,FF,FF]` | `Integer.MAX_VALUE` (mask in harness: `& Integer.MAX_VALUE`) |
| `[00,00,00,00]` | Zero (numAppends = 0 for pure constructor testing) |

Each is a single syntactic unit from the source; none is an assembled triggering input [R23].

**(c) Encoder**: Not needed — the input format is raw big-endian ints, no compression/checksum/length-prefix.

##### Retention Policy

**Primary criterion**: Retain inputs that increase the maximum observed `allocRequestedBytes` signal. This hill-climbs toward larger allocations, which approach the overflow threshold.

**Secondary criterion for flat signal** [R46]: When `allocRequestedBytes = 0` (breaker trips before NEWARRAY), or when the signal doesn't improve, retain 10% of such inputs randomly to maintain exploration diversity. The corpus is capped at ~100 entries; when full, replace the entry with the lowest signal.

**Input growth** [R46]: The target's `input_bytes` is 8. Seeds start at 8 bytes. All generated inputs are exactly 8 bytes (or longer, but only the first 8 matter). Input growth to `input_bytes=8` is immediate — no growth needed.

**Prioritization**: When selecting a parent for mutation, prefer inputs with higher `allocRequestedBytes` signal (weighted random selection proportional to signal value + 1).

##### Per-target corpus isolation [R20]
- V1 corpus: `out/V1/corpus/`
- V2 corpus: `out/V2/corpus/`

#### Step 7-10 — Planned Directory Layout

```
src/
  test/java/
    org/elasticsearch/compute<data>/
      BlockBuilderFuzzTest.java              (frozen, READ-ONLY)
      FuzzRunner.java                         (CLI runner: V1|V2 [seconds])
      agent/
        AllocCounter.java                     (ThreadLocal signal export)
        BlockBuilderAllocAgent.java           (premain, registers transformer)
        BlockBuilderAllocTransformer.java     (ASM transformer for NEWARRAY)
      guidance/
        V1Guidance.java                       (VDF+CGF for IntBlockBuilder)
        V2Guidance.java                       (VDF+CGF for LongBlockBuilder)
      replay/
        ReplayRunner.java                     (metadata replay + reproduction)
    dosguide/validate/
      SignalSource.java                       (frozen, DoSGuide interface)
```

No `src/main/java` files needed — no stubs, no source copies.

##### Agent JAR Build

Since pom.xml cannot be modified to add a plugin execution, the agent JAR is created by a post-build script or programmatically by the FuzzRunner:
1. `mvn package -DskipTests` compiles all test classes to `target/test-classes`
2. `scripts/build-agent.sh` (or FuzzRunner's static init) creates `target/blockbuilder-alloc-agent.jar` from the agent class files with a `MANIFEST.MF` containing `Premain-Class: org.elasticsearch.compute.data.fuzz.agent.BlockBuilderAllocAgent`

##### Mandatory Self-Checklist

- [YES] JDK 17+ only — all code targets Java 17
- [YES] No hallucinated APIs — Guidance interface verified from `javap` on jqf-fuzz-2.1.jar
- [YES] Guidance implements Guidance directly — no extension of existing guidances
- [YES] No existing guidance extended — custom VDF+CGF from scratch
- [YES] V* vulnerabilities identified — V1 (IntBlockBuilder), V2 (LongBlockBuilder)
- [YES] V* IDs are sequential (V1, V2) — NOT derived from version numbers [R42]
- [YES] Official vulnerability names applied — CWE-190 Integer Overflow
- [YES] PkgRisk-* identified — NONE found (vulnerability is in Elasticsearch's own arithmetic)
- [YES] Every PkgRisk-* executed or justified — no PkgRisk targets identified
- [YES] Guidance targets V* — V1Guidance targets V1, V2Guidance targets V2
- [YES] One fuzz method per V* — V1 uses `fuzzBlockFactoryNewIntBlockBuilder`, V2 uses `fuzzBlockFactoryNewLongBlockBuilder`
- [YES] CLI method selection supported — `FuzzRunner V1` / `FuzzRunner V2`
- [YES] byte[]/InputStream input model used exclusively — harness consumes InputStream
- [YES] No junit-quickcheck Generators used — no generators
- [YES] All mutation implemented inside Guidance — byte-level + dictionary + repetition
- [YES] Repetition, source dictionary, and encoder operators — repetition and dictionary from source; no encoder needed (raw bytes)
- [YES] Retention progresses while signal is flat — retains 10% of zero-signal inputs randomly
- [YES] Retention signals measured where resource is consumed — at NEWARRAY instruction, not before sink
- [YES] Logging every 1 second — structured periodic logging
- [YES] Guidance decides no failures and writes no failure files — [R6] compliant
- [YES] Corrupted inputs saved with metadata — corpus saves input bytes + signal value
- [YES] Replay/feeder implemented — ReplayRunner reads saved inputs
- [YES] Infinite + time-bounded fuzzing supported — infinite by default, optional seconds argument
- [YES] src/main vs src/test separation correct — no src/main, all fuzzing in src/test
- [YES] Maven scopes consistent — system for ES jars, test for JQF/junit
- [YES] No wildcard imports used for JQF / tracing — explicit imports only
- [YES] TraceEvent import verified — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` from jqf-instrument-2.1.jar

##### IMPORT AUDIT

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
ClassVisitor → org.objectweb.asm.ClassVisitor
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
```

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "allocRequestedBytes",
          "quantity": "bytes the NEWARRAY int instruction in IntBlockBuilder.<init> is asked to allocate, computed as (long)initialSize * Integer.BYTES using long arithmetic to avoid the very overflow that is the vulnerability",
          "aggregation": "max",
          "locations": ["IntBlockBuilder#<init>(int, BlockFactory)"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in AllocCounter (field ALLOC, index 0)",
          "reset": "AllocCounter.reset() called in V1Guidance.getInput() before returning the input stream",
          "read": "AllocCounter.getAlloc() called in V1Guidance.handleResult()"
        }
      ],
      "retention": "Primary: retain inputs whose allocRequestedBytes exceeds the current corpus maximum (hill-climb). Secondary: when allocRequestedBytes is zero or does not improve, retain 10% of inputs randomly to maintain exploration diversity and escape the breaker-trips trough (estimatedSize ~153M-536M). Corpus capped at 100 entries; on overflow, replace the lowest-signal entry. Prioritize parents for mutation proportionally to signal + 1.",
      "retention_signals": ["allocRequestedBytes"],
      "mutation": [
        "byte-level: random byte flip at random position in the 8-byte input",
        "byte-level: random byte overwrite at random position",
        "byte-level: arithmetic increment/decrement on a random 4-byte field (big-endian int add/subtract random delta 1..256)",
        "byte-level: replace one 4-byte field (bytes 0-3 or bytes 4-7) with a random int value",
        "repetition ([R45a]): copy bytes 4-7 (estimatedSize) to bytes 0-3 (numAppends) or vice versa; for longer inputs double a random chunk",
        "dictionary ([R45b]): overwrite a random 4-byte-aligned position with a token from {0x00000002 (literal 2 from Math.max), 0x00000004 (Integer.BYTES), 0x00000010 (NUM_BYTES_ARRAY_HEADER=16), 0x7FFFFFFF (Integer.MAX_VALUE), 0x00000000 (zero)}",
        "no encoder needed ([R45c]): input is raw big-endian ints, no compression or checksum"
      ]
    },
    {
      "target": "V2",
      "signals": [
        {
          "name": "allocRequestedBytes",
          "quantity": "bytes the NEWARRAY long instruction in LongBlockBuilder.<init> is asked to allocate, computed as (long)initialSize * Long.BYTES using long arithmetic",
          "aggregation": "max",
          "locations": ["LongBlockBuilder#<init>(int, BlockFactory)"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in AllocCounter (field ALLOC, index 0)",
          "reset": "AllocCounter.reset() called in V2Guidance.getInput() before returning the input stream",
          "read": "AllocCounter.getAlloc() called in V2Guidance.handleResult()"
        }
      ],
      "retention": "Primary: retain inputs whose allocRequestedBytes exceeds the current corpus maximum (hill-climb). Secondary: when allocRequestedBytes is zero or does not improve, retain 10% of inputs randomly to maintain exploration diversity and escape the breaker-trips trough (estimatedSize ~76M-268M). Corpus capped at 100 entries; on overflow, replace the lowest-signal entry. Prioritize parents for mutation proportionally to signal + 1.",
      "retention_signals": ["allocRequestedBytes"],
      "mutation": [
        "byte-level: random byte flip at random position in the 8-byte input",
        "byte-level: random byte overwrite at random position",
        "byte-level: arithmetic increment/decrement on a random 4-byte field (big-endian int add/subtract random delta 1..256)",
        "byte-level: replace one 4-byte field (bytes 0-3 or bytes 4-7) with a random int value",
        "repetition ([R45a]): copy bytes 4-7 (estimatedSize) to bytes 0-3 (numAppends) or vice versa; for longer inputs double a random chunk",
        "dictionary ([R45b]): overwrite a random 4-byte-aligned position with a token from {0x00000002 (literal 2 from Math.max), 0x00000008 (Long.BYTES), 0x00000010 (NUM_BYTES_ARRAY_HEADER=16), 0x7FFFFFFF (Integer.MAX_VALUE), 0x00000000 (zero)}",
        "no encoder needed ([R45c]): input is raw big-endian ints, no compression or checksum"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

I'll implement all files now. Let me start by reading the key source files I need to reference, then emit everything.

```text
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/src/test/java/org/elasticsearch/compute<data>/BlockBuilderFuzzTest.java
```

Now let me implement all the files. I'll start with Part A (Java Agent), then Part B (Guidance), then Part C (Runner, Replay, Scripts, Config).

**Part A — Java Agent**

```text
Write <run_dir>/src/test/java/org/elasticsearch/compute<data>/agent/AllocCounter.java
Write <run_dir>/src/test/java/org/elasticsearch/compute<data>/agent/BlockBuilderAllocAgent.java
Write <run_dir>/src/test/java/org/elasticsearch/compute<data>/agent/BlockBuilderAllocTransformer.java
```

```text
Read <run_dir>/src/test/java/org/elasticsearch/compute<data>/BlockBuilderFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/pom.xml
```

Now let me check the JQF Guidance interface to ensure the method signatures are correct:

```text
Grep <run_dir>/target/dependency interface Guidance
$ find <run_dir>/target/dependency -name "jqf-fuzz*.jar" 2>/dev/null
$ jar tf target/dependency/jqf-fuzz-2.1.jar | grep -i "Guidance.class" | head -5
$ javap -public -classpath target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1
$ javap -public -classpath target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ javap -public -classpath target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.GuidedFuzzing 2>&1
$ jar tf target/dependency/jqf-fuzz-2.1.jar | grep -i "GuidedFuzzing" | head -5
$ javap -public -classpath target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1
```

Good, now I have all the signatures. Let me also check GuidanceException:

```text
$ javap -public -classpath target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException 2>&1
```

Now I have everything needed. Let me write all remaining files in parallel:

```text
Write <run_dir>/src/test/java/org/elasticsearch/compute<data>/guidance/V1Guidance.java
Write <run_dir>/src/test/java/org/elasticsearch/compute<data>/guidance/V2Guidance.java
Write <run_dir>/src/test/java/org/elasticsearch/compute<data>/FuzzRunner.java
Write <run_dir>/src/test/java/org/elasticsearch/compute<data>/replay/ReplayRunner.java
```

Now write `run.sh` and `analysis/launch.json`:

```text
Write <run_dir>/run.sh
Write <run_dir>/analysis/launch.json
```

Now make run.sh executable and create validation inputs:

```text
$ chmod +x <run_dir>/run.sh
$ mkdir -p <run_dir>/analysis/validation_inputs/V1 <run_dir>/analysis/validation_inputs/V2
$ # Create validation inputs for V1 (IntBlockBuilder, elemSize=4) …
```

All files are written. Now compile to verify everything builds:

```text
$ mvn package -DskipTests 2>&1 | tail -30
```

Build succeeds. Now let me build the agent JAR and verify it:

```text
$ \ …
```

Good — agent JAR includes the inner class too. Now I need to update `run.sh` to also include the inner class in the agent JAR build step:

```text
Edit <run_dir>/run.sh
```

Also update the `analysis/launch.json` agent-jar build step to include the inner class:

```text
Edit <run_dir>/analysis/launch.json
```

Now let me verify the complete directory tree to confirm everything is in place:

```text
$ find src analysis run.sh -type f | sort
```

All files present. Let me do a final clean compilation to confirm everything compiles together:

```text
$ mvn clean package -DskipTests 2>&1 | tail -30
```

Clean build succeeds. Let me verify the compiled test classes contain everything:

```text
$ find target/test-classes -name "*.class" | sort
```

I see there's a `BlockBuilderAllocTransformer$1.class` (anonymous inner class from the anonymous ClassVisitor). Let me update the agent JAR build to include it too:

```text
Edit <run_dir>/run.sh
Edit <run_dir>/analysis/launch.json
```

Now rebuild the agent JAR with the complete set of inner classes:

```text
$ \ …
```

Clean build wiped the manifest directory. Let me recreate it:

```text
$ \ …
```

All compiled and packaged. Let me verify the vulnerable artifact is being used correctly (mandatory check per the rules):

```text
$ \ …
$ \ …
```

The vulnerable `IntBlockBuilder.class` and `LongBlockBuilder.class` are inside `lib/x-pack-esql-compute-8.19.7-SNAPSHOT.jar`, which is referenced via system-scope dependencies in pom.xml. The fuzz harness will compile and run against these vulnerable classes directly.

Let me do a final summary verification of all files:

```text
$ echo "=== Block 3 Implementation Files ===" && echo "" && \ …
```

All Block 3 implementation files are complete and verified. Here is the final inventory:

**Part A — Java Agent (3 files)**
- `src/test/java/org/elasticsearch/compute<data>/agent/AllocCounter.java` — ThreadLocal allocation counter with `recordAlloc(int,int)`, `getAlloc()`, `reset()`
- `src/test/java/org/elasticsearch/compute<data>/agent/BlockBuilderAllocAgent.java` — premain entry, adds JAR to bootstrap classpath, registers transformer
- `src/test/java/org/elasticsearch/compute<data>/agent/BlockBuilderAllocTransformer.java` — ASM9 ClassFileTransformer targeting IntBlockBuilder/LongBlockBuilder constructors, instruments NEWARRAY with DUP+push elemSize+INVOKESTATIC AllocCounter.recordAlloc

**Part B — Guidance (2 files)**
- `src/test/java/org/elasticsearch/compute<data>/guidance/V1Guidance.java` — VDF+CGF for IntBlockBuilder (elemSize=4). Implements `Guidance` + `SignalSource`. Tournament selection, hill-climb retention, 6 mutation operators, dictionary with `intToBytes(4)`. Signal: `allocRequestedBytes`
- `src/test/java/org/elasticsearch/compute<data>/guidance/V2Guidance.java` — VDF+CGF for LongBlockBuilder (elemSize=8). Identical to V1 except log prefix `[V2]` and dictionary uses `intToBytes(8)`

**Part C — Runner + Replay + Scripts (4 files)**
- `src/test/java/org/elasticsearch/compute<data>/FuzzRunner.java` — CLI runner with `public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log)` factory. Maps V1→fuzzBlockFactoryNewIntBlockBuilder, V2→fuzzBlockFactoryNewLongBlockBuilder
- `src/test/java/org/elasticsearch/compute<data>/replay/ReplayRunner.java` — Reads binary input, decodes fields, shows true vs overflowed allocation, analyzes overflow condition
- `run.sh` — Executable script: builds Maven, creates agent JAR, dispatches to fuzz/replay mode
- `analysis/launch.json` — Full build/run configuration with classpath, javaagent, targets, eval limits

**Part D — Validation (6 binary inputs)**
- `analysis/validation_inputs/V1/overflow_threshold.bin` — estimatedSize=0x20000000 (536870912×4 overflows)
- `analysis/validation_inputs/V1/overflow_max.bin` — estimatedSize=0x7FFFFFFF (max int ×4)
- `analysis/validation_inputs/V1/safe_1024.bin` — estimatedSize=1024 (safe)
- `analysis/validation_inputs/V2/overflow_threshold.bin` — estimatedSize=0x10000000 (268435456×8 overflows)
- `analysis/validation_inputs/V2/overflow_max.bin` — estimatedSize=0x7FFFFFFF (max int ×8)
- `analysis/validation_inputs/V2/safe_1024.bin` — estimatedSize=1024 (safe)

**Build verification**: `mvn clean package -DskipTests` → BUILD SUCCESS. Agent JAR at `target/blockbuilder-alloc-agent.jar` contains 5 class files. All 11 test classes compiled. Vulnerable artifact: `lib/x-pack-esql-compute-8.19.7-SNAPSHOT.jar` (system scope in pom.xml).

**HARD STOP — Block 3 complete.**

## Validation repair 1

```text
Read <run_dir>/analysis/launch.json
```

Now I see the issue — `"build"` must be a flat list of shell commands, `"jvm_args"` must be a list, `"targets"` entries need `"test_class"` and `"method"` only, and `"javaagent"` should only have `"jar"` and `"args"`. Let me rewrite it to match the expected format exactly:

```text
Write <run_dir>/analysis/launch.json
```

Now let me verify this is valid JSON and the build commands actually work:

```text
$ python3 -c "import json; d=json.load(open('analysis/launch.json')); print('Valid JSON'); print('build type:', type(d['build']).__name__); print('build len:', len(d['build'])); print('targets:', list(d['targets'].keys())); print('jvm_args type:', type(d['jvm_args']).__name__)"
```

Now let me verify the build commands work end-to-end:

```text
$ mvn -q package -DskipTests 2>&1 | tail -10
$ \ …
```

Build works. The only change was rewriting `analysis/launch.json` to match the expected schema:

**Summary of changes:**
- Rewrote `analysis/launch.json` to match the expected DoSGuide format:
  - `"build"`: changed from `{"steps": [{...}, ...]}` object to a flat list of shell command strings
  - `"jvm_args"`: changed from an object with `Xmx`/`Xss`/`system_properties` to an empty list `[]` (since eval limits are fixed externally)
  - `"javaagent"`: removed the extra `"description"` field, kept only `"jar"` and `"args"`
  - `"targets"`: simplified each entry to only `"test_class"` and `"method"` (removed extra metadata like `guidance_class`, `element_size`, `dictionary_tokens`, etc.)
  - Removed all extra top-level fields (`schema_version`, `project`, `description`, `eval_limits`, `runner`, `replay`, `test_class`, `guidance_factory_signature`)
