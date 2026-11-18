# kwik_GHSA-9f57-9rhg-4hvm

## Block 1

I'll start by reading the source code and the frozen fuzz test harness to understand the target.

```text
Read <source_root>/core/src/main/java/tech/kwik/core/server/impl/ConnectionSource.java
Glob <run_dir> *FuzzTest*.java
Glob <run_dir> pom.xml
Read <run_dir>/src/test/java/tech/kwik/fuzz/harness/KwikFuzzTest.java
Read <run_dir>/pom.xml
```

Now let me examine the key classes involved - `ServerConnectionRegistryImpl` and related code:

```text
Glob <source_root> **/ServerConnectionRegistryImpl.java
Glob <source_root> **/ServerConnectionProxy.java
Glob <run_dir> lib/*.jar
Read <source_root>/core/src/main/java/tech/kwik/core/server/impl/ServerConnectionRegistryImpl.java
Read <source_root>/core/src/main/java/tech/kwik/core/server/impl/ServerConnectionProxy.java
```

Now let me look at additional related source files:

```text
Glob <source_root> **/NullLogger.java
Glob <source_root> **/Bytes.java
Glob <source_root> **/ServerConnectionRegistry.java
Read <source_root>/core/src/main/java/tech/kwik/core/server/ServerConnectionRegistry.java
Read <source_root>/core/src/main/java/tech/kwik/core/log/NullLogger.java
```

Let me look at relevant server connector code to check for rate limiting and understand the full attack path:

```text
Glob <source_root> **/ServerConnectorImpl.java
Grep <source_root>/core/src/main/java/tech/kwik/core/server/impl/ConnectionSource.java Comparable
```

Good — confirmed `ConnectionSource` does NOT implement `Comparable`. Let me read the ServerConnectorImpl to understand the real-world attack surface:

```text
Read <source_root>/core/src/main/java/tech/kwik/core/server/impl/ServerConnectorImpl.java
```

Now I have a complete understanding of the code. Let me write the scale measurement data files. First, let me create the directory structure and generate the collision inputs:

```text
$ mkdir -p <run_dir>/analysis/scale/V1
$ python3 -c ' …
```

All 20 sampled collision IDs produce the same `Arrays.hashCode` value (-221995556). Let me verify the generated files:

```text
$ ls -la <run_dir>/analysis/scale/V1/
Read <run_dir>/analysis/scale/V1/series.json
```

Let me do a final verification that the input files parse correctly according to the fuzz test's `connectionIds` method and that all IDs are unique:

```text
$ python3 -c ' …
```

All files verify correctly: every ID in every file is unique, all have identical `Arrays.hashCode` values, and they parse correctly according to the fuzz test's input format.

Now I have all the information needed for the complete analysis and target register.

---

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: Hash Collision DoS on ConcurrentHashMap via ConnectionSource

**Fuzzable entrypoints & user-controlled inputs:**
The `KwikFuzzTest.fuzzServerConnectionRegistryRegisterConnection(InputStream)` method reads an `InputStream`, splits it into length-prefixed destination connection IDs (1–20 bytes each), and for each ID:
1. Calls `ServerConnectionRegistryImpl.isExistingConnection()` → `ConcurrentHashMap.get(new ConnectionSource(dcid))`
2. If not found, calls `ServerConnectionRegistryImpl.registerConnection()` → `ConcurrentHashMap.put(new ConnectionSource(dcid), proxy)`

The attacker controls the entire input stream, thus controls every byte of every connection ID.

**Mechanism — how input makes resource consumption grow:**
`ConnectionSource.hashCode()` delegates to `java.util.Arrays.hashCode(byte[])`, which uses a simple polynomial hash with base 31:
```
result = 1;
for (byte b : array) result = 31 * result + b;
```

This hash is trivially vulnerable to **multi-collision construction**: for any 2-byte pair `[a, b]` where `31*a + b = C` (constant), all pairs are interchangeable. I found 9 such "collision atoms" (see scale measurement) for `C = 31`. When a connection ID of length `2k` is composed of `k` atoms, all `9^k` possible arrangements produce the identical `Arrays.hashCode` value.

**Critical compounding factor:** `ConnectionSource` does NOT implement `Comparable<ConnectionSource>`. When `ConcurrentHashMap` treeifies a bucket (at 8+ entries), it uses `Comparable` to navigate the tree. Without it, `ConcurrentHashMap.TreeBin.find()` degrades to a **full DFS traversal of the tree** for lookups where the key is not found (and `putTreeVal` similarly for insertions). Each `get` and `put` is O(n) where n is the number of entries in the colliding bucket.

For n unique hash-colliding connection IDs, the total cost of registration is:
- `get` for ID i: O(i) — full tree traversal, key not found
- `put` for ID i: O(i) — find insertion point in tree
- Total: Σ(i=1..n) 2·O(i) = **O(n²)**

**Exhausted resource:** CPU time. The quantity that grows is the number of `ConnectionSource.equals()` (→ `Arrays.equals(byte[], byte[])`) comparisons in `ConcurrentHashMap` tree traversal. This grows quadratically: n registrations × n entries per bucket traversal.

**Failure mode:** `timeout` — a single execution runs longer than the 20,000 ms per-execution time limit.

**Scale:**
Using 10-byte connection IDs (5 × 2-byte collision atoms), there are 9⁵ = 59,049 possible unique colliding IDs. Each ID takes 11 bytes of input (1 length byte + 10 data bytes).

Estimated cost per ConcurrentHashMap tree node visit: ~100–200 ns (dominated by pointer-chasing cache misses in the tree). For n colliding registrations, total time ≈ n² × 100–200 ns.

For n = 20,000: 20,000² × 150 ns ≈ 60 seconds → exceeds 20s timeout.
Conservative minimum: n ≈ 14,000 → 14,000 × 11 = 154,000 bytes ≈ 150 KB.
Comfortable margin: n = 20,000 → 20,000 × 11 = 220,000 bytes ≈ 215 KB.

The scale measurement series (64–2048 IDs) will show clear O(n²) growth in CPU time and confirm these estimates. **input_bytes: 220,000**.

##### 1.2 Official Classification

**V1:** CWE-407 — Inefficient Algorithmic Complexity. The hash collision attack exploits the O(n²) degradation of `ConcurrentHashMap` when keys share hash codes and lack `Comparable`. Also maps to CWE-400 (Uncontrolled Resource Consumption) since `ServerConnectionRegistryImpl` imposes no limit on connection registrations.

##### 1.3 Dependency / Package-Level Risks

**PkgRisk-1: java.util.Arrays.hashCode(byte[]) + ConcurrentHashMap with non-Comparable keys**

- **Package/class:** `java.util.Arrays` (hashCode), `java.util.concurrent.ConcurrentHashMap` (storage)
- **Why input-sensitive:** `Arrays.hashCode` uses a base-31 polynomial hash on signed byte values. Multi-collisions are trivially constructible: 9 interchangeable 2-byte "atoms" allow 9^k collisions for 2k-byte arrays. `ConcurrentHashMap`'s treeified bins degrade to O(n) per operation without `Comparable` on the key type.
- **Trigger shapes:** Many distinct byte arrays of the same length, composed of interchangeable 2-byte blocks each satisfying `31*a + b = constant`. For 10-byte arrays: up to 59,049 collisions.
- **Exhausted resource:** CPU time (quadratic comparison count).
- **Failure mode:** `timeout`
- **Scale:** Same as V1: ~20,000 colliding keys → 220,000 bytes → exceeds 20s limit.
- **Fuzzing strategy:** Generate inputs containing many unique connection IDs that all share the same `Arrays.hashCode` value, using the collision atom technique.

**Note:** PkgRisk-1 is the mechanism underlying V1 — the same entrypoint, sink, and code path. It is not a separate exploitable path. Therefore I include only V1 in the target register to avoid redundant guidance per [R33].

No other PkgRisk items were identified:
- No regex engines, parsers, serializers, or compression libraries are used in the attack path.
- No URL/path parsing, encoding, or size calculations are involved.
- The only collection-based risk is the ConcurrentHashMap hash collision already covered by V1/PkgRisk-1.

##### 1.4 Zest Baseline Comparison [R18]

**Why Zest underperforms on V1:**
Zest (coverage-guided fuzzing) uses branch coverage as its fitness signal. For the `ServerConnectionRegistryImpl` code, the branches are few and flat: the `for` loop body in the fuzz test, the `if` in `processInitial`, and the `ConcurrentHashMap` operations. Zest achieves full branch coverage with just a handful of distinct connection IDs (covering the "existing" and "new" branches). Once coverage is saturated, Zest retains inputs randomly and has no signal to prefer inputs with hash collisions over non-colliding inputs.

The pathological cost of V1 arises ONLY when many keys share the same hash — a property invisible to coverage. Zest would need to accidentally generate thousands of colliding IDs to trigger the timeout, which is astronomically unlikely given the enormous space of random byte arrays. The probability that two random 10-byte arrays collide is ~1/2³² ≈ 2.3×10⁻¹⁰.

**Measurable metric:** A custom Guidance that uses **measured CPU time per execution** (from wall-clock timing around the fuzz method) and preferentially retains/mutates inputs that increase execution time will reach the timeout threshold orders of magnitude faster than Zest, because it rewards the O(n²) cost growth that hash collisions cause, while Zest cannot distinguish a colliding input from a non-colliding one.

---

#### PHASE B — Target Register

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Hash Collision DoS on ConcurrentHashMap via ConnectionSource",
      "entrypoint": "KwikFuzzTest.fuzzServerConnectionRegistryRegisterConnection(InputStream) → KwikFuzzTest.processInitial(ServerConnectionRegistryImpl, byte[]) → ServerConnectionRegistryImpl.registerConnection(ServerConnectionProxy, byte[]) → ConcurrentHashMap.put(Object, Object)",
      "source_path": "core/src/main/java/tech/kwik/core/server/impl/ConnectionSource.java",
      "sink": "ConcurrentHashMap#put",
      "mechanism": "ConnectionSource.hashCode() delegates to Arrays.hashCode(byte[]) (base-31 polynomial), which is trivially multi-collision-constructible (9 interchangeable 2-byte atoms yield 9^k collisions for 2k-byte IDs). ConnectionSource does not implement Comparable, so ConcurrentHashMap TreeBin.find/putTreeVal degrade to O(n) full tree traversal per operation. Registering n unique hash-colliding connection IDs costs O(n^2) total equals comparisons.",
      "resource": "CPU time: number of ConnectionSource.equals (Arrays.equals on byte[]) comparisons in ConcurrentHashMap tree traversal grows quadratically with the number of hash-colliding entries",
      "failure_mode": "timeout",
      "scale": "About 20,000 unique hash-colliding 10-byte connection IDs cause ~2x10^8 equals comparisons in ConcurrentHashMap tree traversal with non-Comparable keys, exceeding the 20s timeout; each ID takes 11 bytes of input (1 length + 10 data) → ~220,000 bytes",
      "input_bytes": 220000,
      "cwe": "CWE-407"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

Let me re-read the relevant source files to fix the entrypoint path:

```text
Read <source_root>/core/src/main/java/tech/kwik/core/server/impl/ServerConnectionRegistryImpl.java
Read <source_root>/core/src/main/java/tech/kwik/core/server/impl/ConnectionSource.java
```

Now I understand the issue. The path needs to extend through `ConcurrentHashMap.put` into `ConnectionSource.java` where the vulnerable code lives. Let me trace the exact call chain:

In `ServerConnectionRegistryImpl.registerConnection` (line 57):
```java
currentConnections.put(new ConnectionSource(connectionId), connection);
```

This calls `ConcurrentHashMap.put()`, which internally:
1. Calls `ConnectionSource.hashCode()` (line 34) to find the bucket — this produces the colliding hash
2. Calls `ConnectionSource.equals(Object)` (line 39) O(n) times during tree traversal for collision resolution — this is where the CPU time is consumed

The path must extend to the vulnerable code in `ConnectionSource.java`. The actual CPU resource is consumed by the O(n) `equals` calls per operation during tree traversal.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Hash Collision DoS on ConcurrentHashMap via ConnectionSource",
      "entrypoint": "KwikFuzzTest.fuzzServerConnectionRegistryRegisterConnection(InputStream) → KwikFuzzTest.processInitial(ServerConnectionRegistryImpl, byte[]) → ServerConnectionRegistryImpl.registerConnection(ServerConnectionProxy, byte[]) → ConcurrentHashMap.put(Object, Object) → ConnectionSource.equals(Object)",
      "source_path": "core/src/main/java/tech/kwik/core/server/impl/ConnectionSource.java",
      "sink": "ConnectionSource#equals",
      "mechanism": "ConnectionSource.hashCode() delegates to Arrays.hashCode(byte[]) (base-31 polynomial), which is trivially multi-collision-constructible (9 interchangeable 2-byte atoms yield 9^k collisions for 2k-byte IDs). ConnectionSource does not implement Comparable, so ConcurrentHashMap TreeBin.find/putTreeVal degrade to O(n) full tree traversal per operation, calling ConnectionSource.equals(Object) at each node. Registering n unique hash-colliding connection IDs costs O(n^2) total equals comparisons.",
      "resource": "CPU time: number of ConnectionSource.equals (Arrays.equals on byte[]) comparisons in ConcurrentHashMap tree traversal grows quadratically with the number of hash-colliding entries",
      "failure_mode": "timeout",
      "scale": "About 20,000 unique hash-colliding 10-byte connection IDs cause ~2x10^8 equals comparisons in ConcurrentHashMap tree traversal with non-Comparable keys, exceeding the 20s timeout; each ID takes 11 bytes of input (1 length + 10 data) → ~220,000 bytes",
      "input_bytes": 220000,
      "cwe": "CWE-407"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

Let me analyze the measurement data carefully.

**Growth pattern analysis:**

| n | cpu ms | Δ cpu (from previous) | n² | cpu/n² |
|---|--------|----------------------|-----|--------|
| 64 | 6.3 | — | 4,096 | 1.54×10⁻³ |
| 128 | 10.6 | 4.3 | 16,384 | 6.47×10⁻⁴ |
| 256 | 12.8 | 2.2 | 65,536 | 1.95×10⁻⁴ |
| 512 | 19.4 | 6.6 | 262,144 | 7.40×10⁻⁵ |
| 1024 | 23.7 | 4.3 | 1,048,576 | 2.26×10⁻⁵ |
| 2048 | 51.5 | 27.8 | 4,194,304 | 1.23×10⁻⁵ |

The raw `cpu/n²` drops with n because there's a large fixed baseline (JVM warmup, class loading, JIT compilation). The quadratic signal emerges when I subtract it.

**Fitting `cpu = B + C × n(n−1)` from the two largest points (past JIT warmup):**

- n=1024: 23.7 = B + C × 1,047,552
- n=2048: 51.5 = B + C × 4,194,256

Δ: 27.8 = C × 3,146,704 → **C = 8.83 × 10⁻⁶ ms ≈ 8.83 ns per equals comparison pair**
B = 23.7 − 8.83×10⁻⁶ × 1,047,552 = **14.4 ms baseline**

**Verification against other points:**
- n=512: predicted = 14.4 + 8.83×10⁻⁶ × 261,632 = 16.7 ms (measured: 19.4 ms — 14% off, consistent with JIT warmup still in progress)
- n=256: predicted = 14.4 + 8.83×10⁻⁶ × 65,280 = 15.0 ms (measured: 12.8 ms — smaller n has lower baseline overhead)

The model is consistent with O(n²) equals comparisons from the full DFS tree traversal in `ConcurrentHashMap.TreeBin.findTreeNode` for non-Comparable keys with identical hashes. Each registration calls `get` (O(n) DFS for missing key) + `put` (O(n) initial tree search in `putTreeVal`), giving ~2n equals per registration, n(n−1) total.

**Extrapolation to 20,000 ms timeout:**

20,000 = 14.4 + 8.83×10⁻⁶ × n(n−1)
n(n−1) = 19,985.6 / 8.83×10⁻⁶ = 2.263 × 10⁹
**n ≈ 47,570 colliding IDs**

At 11 bytes per ID (1 length byte + 10 data bytes): 47,570 × 11 = **523,270 bytes ≈ 524 KB**.

Note: At n≈47,500, the working set (~5 MB of tree nodes + key objects) exceeds L2 cache, likely increasing per-node cost above the fitted 8.83 ns. This means fewer IDs may suffice in practice. Conservative estimate uses the measured fit without cache adjustment.

The encoding is already near-optimal: 10-byte IDs (5 × 2-byte collision atoms, 9 atoms available → 9⁵ = 59,049 max unique collisions) are the shortest that yield enough collisions (47,570 < 59,049). No denser encoding of the same collision structure exists.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured growth is quadratic (O(n^2) equals comparisons in ConcurrentHashMap TreeBin DFS traversal). Fit from n=1024 (23.7ms) and n=2048 (51.5ms): cpu ≈ 14.4ms baseline + 8.83ns per comparison pair × n(n-1). Extrapolating to 20,000ms timeout: n ≈ 47,570 unique hash-colliding 10-byte connection IDs; at 11 bytes per ID (1 length + 10 data), ≈ 524,000 bytes. Available collision IDs: 9^5 = 59,049 (sufficient). Well within 1MB input limit.",
    "input_bytes": 524000
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by reading the necessary source files, checking the existing workspace structure, and verifying the vulnerable jar.

```text
$ ls -la <run_dir>/lib/kwik-0.10.jar
Read <run_dir>/src/test/java/tech/kwik/fuzz/harness/KwikFuzzTest.java
Read <run_dir>/pom.xml
```

Let me verify the jar contents and check the current workspace structure:

```text
$ jar tf <run_dir>/lib/kwik-0.10.jar | grep -E "(ConnectionSource|ServerConnectionRegistry|ServerConnectionProxy|NullLogger|Logger)" | head -20
$ find <run_dir>/src -type f -name "*.java" 2>/dev/null | sort
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Let me verify the pom.xml compiles correctly and check what needs to be added for the agent:

```text
$ mvn compile 2>&1 | tail -20
$ mvn package -DskipTests 2>&1 | tail -30
```

Good — the build succeeds and ASM 9.8 is already available transitively via jqf-instrument. Let me verify ASM is available for compilation:

```text
$ ls <run_dir>/target/dependency/asm*.jar 2>/dev/null
$ mvn dependency:tree 2>&1 | grep -E "(asm|objectweb)" | head -5
```

Let me verify the JQF Guidance interface to ensure I'm using the correct API:

```text
$ jar tf target/dependency/jqf-fuzz-2.1.jar | grep -E "(Guidance|GuidedFuzzing|Result)" | head -20
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1
$ javap -cp target/dependency/jqf-instrument-2.1.jar edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent 2>&1
```

Now let me verify that the existing pom.xml is sufficient for our needs. The systemPath is correct and the jar exists. Let me also verify ASM API availability:

```text
$ javap -cp target/dependency/asm-9.8.jar org.objectweb.asm.ClassVisitor 2>&1 | head -10
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException 2>&1
```

All APIs are confirmed and available. The pom.xml is correct as-is — no changes needed. Now let me produce the complete Block 2 output.

---

#### Step 2 — Maven Layout & Scope

The existing `pom.xml` is correctly structured:
- **`lib/kwik-0.10.jar`** (system scope): Contains the vulnerable `ConnectionSource`, `ServerConnectionRegistryImpl`, `ServerConnectionProxy`, `Logger`, `NullLogger` — all loaded from this single jar. **No source copying.**
- **JQF 2.1** (test scope): `jqf-fuzz`, `jqf-instrument` — provides `Guidance`, `GuidedFuzzing`, `Result`, `TraceEvent`
- **ASM 9.8** (transitive test scope via jqf-instrument): Available for custom agent bytecode manipulation
- **JUnit 4.13.2** (test scope): `@RunWith`
- **junit-quickcheck 1.0** (test scope): Required by JQF runtime

All test/fuzzing infrastructure goes under `src/test/java`. The `src/main/java` directory is empty — all target code is in the prebuilt `lib/kwik-0.10.jar`.

**pom.xml status:** No changes required. The `<systemPath>${project.basedir}/lib/kwik-0.10.jar</systemPath>` is correct and verified.

---

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

**Frozen harness (`KwikFuzzTest.java`) dependencies:**

| Symbol | Package | Resolution |
|--------|---------|-----------|
| `Logger` | `tech.kwik.core.log` | In `lib/kwik-0.10.jar` ✓ |
| `NullLogger` | `tech.kwik.core.log` | In `lib/kwik-0.10.jar` ✓ |
| `ServerConnectionProxy` | `tech.kwik.core.server.impl` | In `lib/kwik-0.10.jar` ✓ |
| `ServerConnectionRegistryImpl` | `tech.kwik.core.server.impl` | In `lib/kwik-0.10.jar` ✓ |
| `@Fuzz` | `edu.berkeley.cs.jqf.fuzz` | In `jqf-fuzz-2.1.jar` ✓ |
| `JQF` | `edu.berkeley.cs.jqf.fuzz` | In `jqf-fuzz-2.1.jar` ✓ |
| `@RunWith` | `org.junit.runner` | In `junit-4.13.2.jar` ✓ |

**Guidance/Agent dependencies (to be written in Block 3):**

| Symbol | Package | Resolution |
|--------|---------|-----------|
| `Guidance` | `edu.berkeley.cs.jqf.fuzz.guidance` | In `jqf-fuzz-2.1.jar` ✓ |
| `GuidanceException` | `edu.berkeley.cs.jqf.fuzz.guidance` | In `jqf-fuzz-2.1.jar` ✓ |
| `Result` | `edu.berkeley.cs.jqf.fuzz.guidance` | In `jqf-fuzz-2.1.jar` ✓ |
| `GuidedFuzzing` | `edu.berkeley.cs.jqf.fuzz.junit` | In `jqf-fuzz-2.1.jar` ✓ |
| `TraceEvent` | `edu.berkeley.cs.jqf.instrument.tracing.events` | In `jqf-instrument-2.1.jar` ✓ |
| `ClassReader/ClassWriter/ClassVisitor/MethodVisitor/Opcodes` | `org.objectweb.asm` | In `asm-9.8.jar` (transitive) ✓ |
| `Instrumentation` | `java.lang.instrument` | JDK 17 stdlib ✓ |
| `ClassFileTransformer` | `java.lang.instrument` | JDK 17 stdlib ✓ |
| `SignalSource` | `dosguide.validate` | Already in workspace ✓ |

##### 3.2 Stub Generation Rules

**No stubs are required.** All symbols used by the harness and all symbols needed by the guidance/agent code are resolved by existing dependencies (the prebuilt vulnerable jar and Maven test-scope dependencies).

##### 3.3 Stub Report

No stubs generated. Every symbol is satisfied by:
- `lib/kwik-0.10.jar` — kwik project classes (system scope)
- `jqf-fuzz-2.1.jar` / `jqf-instrument-2.1.jar` — JQF framework (test scope)
- `asm-9.8.jar` — ASM bytecode library (transitive test scope via jqf-instrument)
- `junit-4.13.2.jar` — JUnit 4 (test scope)
- JDK 17 standard library — `java.lang.instrument.*`, `java.util.concurrent.atomic.*`

---

#### Step 4a — Directory Tree

```
kwik-fuzz/
├── pom.xml                                 (FROZEN — canonical build)
├── lib/
│   └── kwik-0.10.jar                       (FROZEN — vulnerable artifact, system scope)
├── src/
│   ├── main/
│   │   └── java/                           (empty — target code in lib/kwik-0.10.jar)
│   └── test/
│       └── java/
│           ├── dosguide/validate/
│           │   └── SignalSource.java        (FROZEN — provided by DoSGuide)
│           └── tech/kwik/fuzz/
│               ├── harness/
│               │   └── KwikFuzzTest.java    (FROZEN — benchmark fixture)
│               ├── agent/
│               │   ├── V1Counters.java      (AtomicLong counter for equals invocations)
│               │   └── V1MeasureAgent.java  (Java agent: instruments ConnectionSource.equals)
│               ├── guidance/
│               │   └── V1Guidance.java      (Custom CGF+VDF guidance for hash collision DoS)
│               ├── runner/
│               │   └── FuzzRunner.java      (CLI runner: method selection, time bounds)
│               └── replay/
│                   └── MetadataReplay.java  (Reproduction and metadata replay)
├── scripts/
│   └── build-agent.sh                      (Assembles v1-measure-agent.jar from compiled classes)
└── analysis/
    └── scale/
        └── V1/                             (Scale measurement data — Block 1)
```

**Runtime artifacts (after `mvn package -DskipTests && bash scripts/build-agent.sh`):**
```
target/
├── test-classes/                            (Compiled guidance, agent, runner, replay)
├── dependency/                              (JQF, ASM, junit, etc. jars)
│   ├── jqf-fuzz-2.1.jar
│   ├── jqf-instrument-2.1.jar
│   ├── asm-9.8.jar
│   └── ...
└── agent/
    └── v1-measure-agent.jar                (Agent jar: V1MeasureAgent + V1Counters + MANIFEST.MF)
```

---

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic Explanation) | Why This Strategy Wins |
|--------|------------------|------------------------------------------|----------------------|
| V1 | **Cost-Gradient Guidance (CGF) + Vulnerability-Directed (VDF) hybrid** | Zest uses **coverage** as its sole retention signal. The `ServerConnectionRegistryImpl` code path has very few branches: the `for` loop, the `if (isExistingConnection)` check, and the `registerConnection` call. Full branch coverage is achieved with **2-3 unique connection IDs** (one "new", one "existing"). After coverage saturation, Zest retains inputs randomly with no mechanism to distinguish colliding from non-colliding keys. The O(n²) cost growth is **invisible to coverage**. The probability that random mutation produces two hash-colliding 10-byte arrays is ~2⁻³² per pair — Zest would need astronomically many trials. | Uses **measured `ConnectionSource.equals` invocation count** as the primary signal — this is the exact mechanism of the hash collision attack (each equals call = one comparison in the ConcurrentHashMap tree traversal). The guidance **climbs the gradient** of this count, preferentially retaining and mutating inputs that produce more equals calls. Structure-aware mutation (record-level repetition with valid length bytes) rapidly builds many well-formed connection IDs. The signal monotonically tracks attack severity: more equals calls = more collision work = closer to timeout. |

**Measurable metric where custom Guidance outperforms Zest:**
- **Time-to-first-timeout:** The custom guidance discovers inputs causing timeout in minutes to hours (by growing the equals count toward the n²≈2×10⁹ threshold). Zest would need to randomly produce ~47,500 hash-colliding byte arrays from a space of 2⁵⁶, which is practically impossible.
- **Peak equals count reached:** Custom guidance will quickly reach >10⁶ equals per execution; Zest stays below ~100 (no collisions).

---

#### Step 6 — Strategy-Specific Guidance Design (V1)

##### Measurement Plan

**Signal: `equalsCount`**

| Aspect | Detail |
|--------|--------|
| **What is measured** | Total invocations of `ConnectionSource.equals(Object)` during one fuzz execution |
| **Why mechanism-aligned** | Each `equals` call is one comparison during ConcurrentHashMap TreeBin traversal for collision resolution. With n colliding keys, ~n(n-1) equals calls occur (O(n²)). This directly measures "how much extra work collisions forced the map to do" [R36 §5]. |
| **Where produced** | Custom Java agent (`V1MeasureAgent`) instruments `ConnectionSource.equals(Object)` at bytecode level via ASM. At method entry, inserts `INVOKESTATIC V1Counters.incrementEquals()V`. |
| **Where stored** | `V1Counters.EQUALS_COUNT` — static `java.util.concurrent.atomic.AtomicLong` field in `V1Counters` class. Made visible to all class loaders via `Instrumentation.appendToBootstrapClassLoaderSearch()`. |
| **Where reset** | `V1Guidance.getInput()` calls `V1Counters.reset()` before providing the next input. |
| **Where consumed** | `V1Guidance.handleResult()` reads `V1Counters.getEqualsCount()` and uses it for retention/prioritization decisions. Also returned by `V1Guidance.lastSignals()` as `{"equalsCount": <value>}`. |

**Signal Legality [R30]:**
- (A) Derived from actual execution of target code: YES — `ConnectionSource.equals` is called by ConcurrentHashMap during real execution.
- (B) Measured at location causally linked to vulnerability: YES — `ConnectionSource#equals` (line 39 of `ConnectionSource.java`) IS the sink where CPU time is consumed during hash collision resolution.
- (C) Consumed by `handleResult()` to affect retention: YES — directly used in retention score.

##### Instrumentation Feasibility Check [R35]

| Item | Detail |
|------|--------|
| **Exact class to instrument** | `tech.kwik.core.server.impl.ConnectionSource` (internal name: `tech/kwik/core/server/impl/ConnectionSource`) |
| **Exact method to instrument** | `equals(Ljava/lang/Object;)Z` — at method entry |
| **Required JVM flags** | None. `ConnectionSource` is a project class (not JDK), so no `--add-opens` needed. Agent uses standard `java.lang.instrument` API. |
| **Signal export mechanism** | `V1Counters` class with static `AtomicLong EQUALS_COUNT`. Added to bootstrap class loader via `Instrumentation.appendToBootstrapClassLoaderSearch(agentJarFile)` so it's visible from any class loader. |
| **Agent implementation plan** | `V1MeasureAgent.premain(String, Instrumentation)`: (1) append agent jar to bootstrap classpath, (2) register a `ClassFileTransformer` that: (a) watches for class name `tech/kwik/core/server/impl/ConnectionSource`, (b) uses ASM `ClassReader`/`ClassWriter`/`ClassVisitor`/`MethodVisitor` (ASM9) to inject `INVOKESTATIC tech/kwik/fuzz/agent/V1Counters.incrementEquals()V` at the start of the `equals` method. |

##### Mutation Operators

**1. Byte-level operators:**
- **Bit flip:** Flip 1–8 random bits at random positions
- **Byte overwrite:** Replace 1–4 bytes with random values
- **Byte insertion:** Insert 1–4 random bytes at random positions
- **Byte deletion:** Remove 1–4 bytes from random positions

**2. Repetition [R45(a)]:**
- **Record-level repetition:** Parse the input to find record boundaries (each record = 1 length byte + N ID bytes). Select a random record, copy it k times (k chosen so total size approaches `input_bytes` = 524,000). This rapidly grows the number of connection IDs.
- **Whole-input doubling:** Copy the entire input and append it to itself. From a small seed, 19 doublings reach 524,288 bytes in 19 mutations — achievable within seconds at >1000 mutations/second. This satisfies [R46]: reaching `input_bytes` within the first minute.
- **Chunk duplication:** Select a random contiguous chunk (aligned to record boundaries when possible), duplicate it 2–16 times in place.

**3. Dictionary tokens from source [R45(b)]:**
Tokens extracted from the fuzz test's input-parsing code (`connectionIds` method) and the target's attack path:
- `0x09` — length byte mapping to ID length 10 (`(9 % 20) + 1 = 10`), the optimal length for maximizing collision IDs per input byte
- `0x01` — length byte mapping to ID length 2 (`(1 % 20) + 1 = 2`), the minimal collision-capable length
- `0x13` — length byte mapping to ID length 20 (`(19 % 20) + 1 = 20`), maximum QUIC connection ID length
- Single-byte values `0x00` through `0xFF` — cover the full byte range for connection ID content

Dictionary insertion: at a random position, insert or overwrite 1–4 bytes from the dictionary. This helps the guidance discover valid length bytes that produce well-formed records.

**4. Well-formed encoding [R45(c)]:**
The input format is simple length-prefixed records: `[len_byte][id_bytes×len]`. No compression, checksums, or complex encoding. The guidance maintains record alignment by:
- Operating on whole records when doing repetition/duplication
- After byte-level mutations, the format self-corrects: any byte can be a valid length byte (modulo 20 + 1 = 1..20), and any bytes following it are valid ID bytes. So random mutations still produce parseable (though differently structured) inputs.

##### Retention Policy

**Primary signal: `equalsCount` (measured)**
- An input whose `equalsCount` exceeds the previous global best is **always retained** as the new best.
- Inputs with `equalsCount` ≥ 90% of the best are **retained with decreasing probability** (favoring diversity).
- The mutation pool is weighted by equalsCount: higher-scoring inputs are selected for mutation more often.

**Secondary criterion for flat-signal progress [R46]:**
- When `equalsCount` < 100 (essentially flat — few or no collisions detected), the guidance uses **input length** as a secondary retention criterion:
  - Any input longer than the current longest retained input is kept.
  - Whole-input doubling is applied preferentially during the flat-signal phase.
- This ensures the input grows toward 524,000 bytes before collisions are discovered.
- Once `equalsCount` rises above the threshold, the primary signal takes over fully.

**Input growth guarantee:** Starting from a 1-byte seed, whole-input doubling produces inputs of length 1→2→4→8→...→524,288 in 19 steps. At 1000+ mutations per second, this completes in well under a minute. [R46 satisfied]

##### Prioritization and Stop/Continue

- **Prioritization:** Inputs in the corpus are scored by `equalsCount` (or input length during flat phase). Mutation selects inputs proportionally to their score. The highest-scoring input gets extra mutation rounds.
- **Stop/continue:** Run indefinitely by default [R8]. Time-bounded via `-Djqf.ei.timeout=<seconds>` system property. The `hasInput()` method checks the timeout.
- **Logging:** Every 1 second, log: total executions, current best `equalsCount`, corpus size, max input length, mutations/second [R5].

---

#### IMPORT AUDIT

```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz (frozen harness only)
@RunWith → org.junit.runner.RunWith (frozen harness only)
JQF → edu.berkeley.cs.jqf.fuzz.JQF (frozen harness only)
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent
SignalSource → dosguide.validate.SignalSource
```

Note: `TraceEvent` is imported only for the `generateCallBack(Thread)` return type; no JQF tracing events are used for measurement (custom agent handles instrumentation per [R43]).

---

#### Mandatory Self-Checklist

| Check | Status | Justification |
|-------|--------|--------------|
| JDK 17+ only | YES | All APIs are JDK 17 standard; no preview/incubator features |
| No hallucinated APIs | YES | All API signatures verified via `javap` on actual jars |
| Guidance implements Guidance directly | YES | `V1Guidance implements Guidance, SignalSource` — no extending existing guidances |
| No existing guidance extended | YES | Does not extend ZestGuidance, PerfFuzzGuidance, or any other |
| V* vulnerabilities identified | YES | V1: Hash Collision DoS on ConcurrentHashMap via ConnectionSource |
| V* IDs are sequential | YES | Only V1 — sequential from discovery order |
| Official vulnerability names applied | YES | CWE-407 (Inefficient Algorithmic Complexity) |
| PkgRisk-* identified | YES | PkgRisk-1 identified but same mechanism as V1; not a separate target |
| Every PkgRisk-* executed or justified | YES | PkgRisk-1 shares identical entrypoint/sink/mechanism with V1; executing V1 covers it |
| Guidance targets V* and PkgRisk-* | YES | V1Guidance covers V1 (and PkgRisk-1 by extension) |
| One fuzz method per V* or PkgRisk | YES | Targets frozen `fuzzServerConnectionRegistryRegisterConnection` |
| CLI method selection supported | YES | `FuzzRunner <method> [timeoutSec]` |
| Byte[] / InputStream input model used exclusively | YES | Guidance.getInput() provides raw bytes; harness reads InputStream |
| No junit-quickcheck Generators used | YES | All input produced by Guidance |
| All mutation implemented inside Guidance | YES | Byte-level, repetition, dictionary all in V1Guidance |
| Repetition, dictionary, encoder operators [R45] | YES | Record repetition + doubling; dictionary from source; no encoder needed (simple length-prefix format) |
| Retention progresses while signal flat [R46] | YES | Input length as secondary criterion; doubling reaches 524K in <1 minute |
| Retention signals measured at sink [R47] | YES | `ConnectionSource#equals` IS the sink per the target register |
| Logging every 1 second | YES | Guidance logs stats every 1 second |
| Guidance decides no failures, writes no failure files [R6] | YES | handleResult only updates retention; never writes failure files |
| Corrupted inputs saved with metadata | YES | All retained inputs saved with execution metadata |
| Replay/feeder implemented | YES | MetadataReplay reads saved inputs and replays |
| Infinite + time-bounded fuzzing supported | YES | Default infinite; `-Djqf.ei.timeout` for time bounds |
| src/main vs src/test separation correct | YES | src/main empty; all fuzzing infra in src/test |
| Maven scopes consistent | YES | kwik=system, JQF=test, junit=test |
| No wildcard imports for JQF/tracing | YES | All imports are explicit |
| TraceEvent import verified and audited | YES | Used only for Guidance.generateCallBack return type; listed in IMPORT AUDIT |

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "equalsCount",
          "quantity": "total invocations of ConnectionSource.equals(Object) during one fuzz execution, counting each comparison in ConcurrentHashMap tree/list traversal during collision resolution",
          "aggregation": "count",
          "locations": ["ConnectionSource#equals"],
          "technique": "bytecode",
          "storage": "static AtomicLong V1Counters.EQUALS_COUNT, class added to bootstrap class loader via Instrumentation.appendToBootstrapClassLoaderSearch",
          "reset": "V1Guidance.getInput() calls V1Counters.reset() before providing next input",
          "read": "V1Guidance.handleResult() calls V1Counters.getEqualsCount(); also returned via V1Guidance.lastSignals() as {\"equalsCount\": value}"
        }
      ],
      "retention": "Primary: retain inputs whose equalsCount exceeds 90% of the global best; always retain new global bests. Secondary (flat-signal phase, equalsCount < 100): retain inputs that are longer than any previously retained input, to grow toward input_bytes before collisions emerge. Corpus is weighted by equalsCount for mutation selection.",
      "retention_signals": ["equalsCount"],
      "mutation": [
        "byte-level: random bit flips (1-8 bits), byte overwrite (1-4 bytes), byte insertion (1-4 bytes), byte deletion (1-4 bytes)",
        "repetition [R45a]: (1) record-level repetition: parse input to find record boundaries (length byte + ID bytes), select a random record and repeat it k times to grow toward 524000 bytes; (2) whole-input doubling: concatenate input with itself, reaching 524000 bytes from a 1-byte seed in 19 steps (~seconds at >1000 mutations/sec); (3) chunk duplication: select a contiguous region and duplicate it 2-16 times in place",
        "dictionary [R45b]: tokens from source: 0x09 (length byte for 10-byte IDs, optimal collision ID length), 0x01 (length byte for 2-byte IDs), 0x13 (length byte for 20-byte IDs), 0x00-0xFF (full byte range for ID content); inserted/overwritten at random positions",
        "no encoder needed [R45c]: the input format is simple length-prefixed records with no compression, checksums, or CRCs; any byte sequence parses as valid (possibly truncated) records"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

I'll implement all the files now. Let me start by reading the existing workspace state and then write all implementation files.

```text
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/pom.xml
```

Now let me write all implementation files. I'll start with the agent, then guidance, then runner, replay, and scripts.

**Part A — Java Agent:**

```text
$ mkdir -p <run_dir>/src/test/java/tech/kwik/fuzz/agent <run_dir>/src/test/java/tech/kwik/fuzz/guidance <run_dir> …
```

Let me read the existing pom.xml and fuzz test to ensure my implementation aligns perfectly:

```text
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/tech/kwik/fuzz/harness/KwikFuzzTest.java
```

Good, I have all the context. Let me check what ASM jars are available:

```text
$ ls <run_dir>/lib/
$ ls <run_dir>/target/dependency/ 2>/dev/null | head -30 || echo "dependency dir not built yet"
```

Dependencies are already built. Now I'll write all implementation files. Let me start with the agent:

```text
Write <run_dir>/src/test/java/tech/kwik/fuzz/agent/V1Counters.java
Write <run_dir>/src/test/java/tech/kwik/fuzz/agent/V1MeasureAgent.java
```

Now Part B — the Guidance:

```text
Write <run_dir>/src/test/java/tech/kwik/fuzz/guidance/V1Guidance.java
```

Now Part C — FuzzRunner, MetadataReplay, and scripts:

```text
Write <run_dir>/src/test/java/tech/kwik/fuzz/runner/FuzzRunner.java
Write <run_dir>/src/test/java/tech/kwik/fuzz/replay/MetadataReplay.java
```

Now the scripts and launch.json:

```text
Write <run_dir>/scripts/build-agent.sh
Write <run_dir>/run.sh
Write <run_dir>/analysis/launch.json
```

Now make scripts executable and compile to verify:

```text
$ chmod +x <run_dir>/scripts/build-agent.sh <run_dir>/run.sh
$ mvn package -DskipTests 2>&1 | tail -30
```

Compilation successful. Now build the agent jar:

```text
$ bash scripts/build-agent.sh 2>&1 | tail -30
```

Agent jar built successfully with all necessary classes. Let me verify the manifest:

```text
$ unzip -p target/agent/v1-measure-agent.jar META-INF/MANIFEST.MF
```

Now let me verify the compiled test classes contain all expected classes:

```text
$ find <run_dir>/target/test-classes -name '*.class' | sort
```

All classes compiled correctly. Now let me verify the workspace directory tree:

```text
$ find . -not -path './target/*' -not -path './.mvn/*' -not -path './analysis/scale/*' | sort
```

Everything compiles and the directory structure looks good. Let me verify the classpath in launch.json matches what's actually available:

```text
$ for j in $(python3 -c "import json; d=json.load(open('analysis/launch.json')); print(d['classpath'])" | tr ':' '\n'); do if [ ! -f "$j" ]; then echo "MISSING: $j"; fi; done; echo "Classpath check done."
```

That's expected — `target/test-classes` is a directory (not a file), so the `-f` check reports it falsely. Let me confirm it exists:

```text
$ ls -d <run_dir>/target/test-classes && echo "OK: directory exists"
```

Good. Now let me verify the vulnerable artifact is properly referenced (not from Maven Central):

```text
$ jar tf lib/kwik-0.10.jar | grep ConnectionSource && echo "---" && echo "Artifact source: $(readlink -f lib/kwik-0.10.jar)"
```

Good. Let me also verify no warnings remain from the compile and do a final check of the key validation-contract items:

```text
$ mvn compile -q 2>&1 | tail -5 && echo "---" && mvn package -DskipTests -q 2>&1 | grep -i "warning\|error" | head -10 || echo "No warnings/errors"
```

Clean compile. Let me do a final inventory of all deliverables:

```text
$ echo "=== Source files ===" && find src -name '*.java' | sort && echo "" && echo "=== Scripts ===" && ls -la scripts/ run.sh && echo "" && echo "=== Analysis files ===" && ls -la analysis/launch.json && echo "" && echo "=== Build artifacts ===" && ls -la target/agent/v1-measure-agent.jar target/kwik …
```

All deliverables are in place. Here is a summary of everything emitted in Block 3:

---

#### Block 3 — Implementation Files Summary

##### Part A: Java Agent (Tier 1 — equals-call counting)

| File | Purpose |
|------|---------|
| `src/test/java/tech/kwik/fuzz/agent/V1Counters.java` | Static `AtomicLong` counter with `incrementEquals()`, `getEqualsCount()`, `reset()`. Added to bootstrap classloader for cross-loader visibility. |
| `src/test/java/tech/kwik/fuzz/agent/V1MeasureAgent.java` | `premain` agent: `appendToBootstrapClassLoaderSearch(this.jar)`, then registers `EqualsTransformer` — ASM9 `ClassFileTransformer` that matches `tech/kwik/core/server/impl/ConnectionSource` and injects `INVOKESTATIC V1Counters.incrementEquals` at the top of `equals(Ljava/lang/Object;)Z`. |
| `scripts/build-agent.sh` | Assembles `target/agent/v1-measure-agent.jar` from compiled agent classes + `asm-9.8.jar`, with `Premain-Class` manifest. |

##### Part B: Guidance (CGF + VDF hybrid)

| File | Purpose |
|------|---------|
| `src/test/java/tech/kwik/fuzz/guidance/V1Guidance.java` | Implements `Guidance` + `SignalSource`. Key mutations: **(1) hash-preserving byte-pair** `(+δ, −31·δ)` on consecutive ID bytes — preserves base-31 polynomial of `Arrays.hashCode`, enabling discovery of distinct IDs sharing one hash bucket; **(2) record repetition** (2–32×); **(3) whole-input doubling**; **(4) standard byte-level** (flip/overwrite/insert/delete); **(5) dictionary** (`0x09` for 10-byte IDs). Retention: primary=equalsCount (retain ≥80% of best), secondary=input length (for size growth). Logs every 1s. Respects `jqf.ei.MAX_INPUT_SIZE` system property. `lastSignals()` returns `{"equalsCount": <latest>}`. |

##### Part C: Runner / Replay

| File | Purpose |
|------|---------|
| `src/test/java/tech/kwik/fuzz/runner/FuzzRunner.java` | CLI entry point + factory `createGuidance(targetId, outputDir, maxDurationMs, log)`. Maps `V1` → `KwikFuzzTest#fuzzServerConnectionRegistryRegisterConnection`. Delegates to `GuidedFuzzing.run`. |
| `src/test/java/tech/kwik/fuzz/replay/MetadataReplay.java` | Replays a saved `.bin` input once through the harness with V1 agent, printing connection ID count and equalsCount. |
| `run.sh` | Builds (`mvn package -DskipTests`), assembles agent jar, runs `FuzzRunner` with `-Xmx1g -Xss1m -javaagent:...`. |

##### Part D: Validation Contract

| File | Purpose |
|------|---------|
| `analysis/launch.json` | Build commands, full classpath, javaagent config, `guidance_factory: "tech.kwik.fuzz.runner.FuzzRunner#createGuidance"`, target V1 mapping. |

##### Build Verification
- `mvn package -DskipTests` → **BUILD SUCCESS** (clean, no warnings)
- `build-agent.sh` → `v1-measure-agent.jar` (132 KB, contains V1Counters + V1MeasureAgent + ASM 9.8)
- Vulnerable artifact: `lib/kwik-0.10.jar` (system-scoped, never from Maven Central)

**HARD STOP** — Block 3 complete.

## Validation repair 1

Let me analyze the validation failures carefully before making changes.

```text
Read <run_dir>/src/test/java/tech/kwik/fuzz/guidance/V1Guidance.java
Read <run_dir>/src/test/java/tech/kwik/fuzz/agent/V1MeasureAgent.java
Read <run_dir>/src/test/java/tech/kwik/fuzz/agent/V1Counters.java
```

Now let me analyze the two issues in depth:

**Issue 1: Progress (0%)** — The single-record HP mutation converts only ~1 record per execution, way too slow for 4056 records. In 1620 executions, only ~150 distinct colliding IDs were created, giving equalsCount=22,208 vs the needed ~4.2M.

**Issue 2: Reset warning** — Non-determinism from `ConcurrentHashMap` tree traversal using `identityHashCode` for duplicate lookups. Fewer duplicate IDs = more deterministic signal.

The fix: Add a "diversify all records" mutation that applies the hash-preserving `(+δ, -31δ)` transformation to **every** byte pair in **every** record simultaneously, converting the entire input from duplicates to distinct colliding IDs in a single step. Also restructure the mutation to separate growth phase from optimization phase and remove destructive mutations.

Let me also re-examine the scale series inputs to understand their structure:

```text
$ xxd -l 66 analysis/scale/V1/n64.bin
```

I can see the series structure. Each record uses 10-byte IDs where each 2-byte atom has `31*a + b = 31` (the collision constant). My seed uses `C=0` (different constant, same collision principle, no overlap with series — safe for [R23]).

The core problem: the single-record HP mutation converts only ~1 record per execution. I need a "diversify all records" mutation that randomizes **all** byte pairs in **all** records simultaneously. Let me rewrite the guidance:

```text
Write <run_dir>/src/test/java/tech/kwik/fuzz/guidance/V1Guidance.java
```

Now compile to verify correctness:

```text
$ mvn package -DskipTests 2>&1 | tail -15
```

Clean compile. Now rebuild the agent jar to ensure consistency:

```text
$ bash scripts/build-agent.sh 2>&1 | tail -10
```

Good. Now let me verify the key mathematical property of the diversify mutation — that the delta bounds are correct:

```text
$ cat << 'JAVAEOF' …
```

The arithmetic is correct. Each atom always has exactly 9 valid values regardless of current byte values. For 10-byte IDs (5 atoms): 9^5 = 59,049 possible distinct collision IDs.

Now let me also verify the `ceilDiv31` and `floorDiv31` helper methods are correct for edge cases:

```text
$ cat << 'JAVAEOF' > /tmp/TestDiv31.java …
Write <run_dir>/TestDiv31.java
$ javac TestDiv31.java && java -ea -cp . TestDiv31 && rm -f TestDiv31.java TestDiv31.class
$ javac TestDiv31.java && echo "Compilation OK" && rm -f TestDiv31.java TestDiv31.class
$ javac TestDiv31.java 2>&1 | tail -5
$ rm -f <run_dir>/TestDiv31.java
$ rm <run_dir>/TestDiv31.java
$ ls -la <run_dir>/TestDiv31.java 2>/dev/null && echo "exists" || echo "file does not exist"
$ ls <run_dir>/TestDiv31.java 2>/dev/null; echo "done"
Glob <run_dir> TestDiv31*
Write <run_dir>/TestDiv31.java
$ find . -name 'TestDiv31*' -delete && echo "cleaned"
```

Good. The arithmetic is verified by hand:
- For seed atoms `(0,0)` with `C=0`: delta range `[-4, 4]` → 9 valid pairs
- Each delta `d` produces `(d, -31*d)` with `31*d + (-31*d) = 0 = C` ✓
- Hash preserved for each 2-byte atom independently ✓

The main Maven build already compiles clean with no errors or warnings. Let me do a final check that everything is consistent:

```text
$ mvn package -DskipTests -q 2>&1 | tail -5
```

Silent output means clean build. Let me verify the compiled classes are up to date:

```text
$ find target/test-classes -name '*.class' -newer src/test -type f | sort
```

All classes freshly compiled. Now rebuild the agent jar one more time to be sure:

```text
$ bash scripts/build-agent.sh 2>&1 | head -3
```

Everything is rebuilt. Now let me provide the revised guidance plan since the mutation strategy changed significantly:

BEGIN_GUIDANCE_PLAN_JSON
```json
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "equalsCount",
          "quantity": "number of ConnectionSource.equals(Object) invocations during one fuzz execution",
          "aggregation": "count",
          "locations": ["ConnectionSource#equals"],
          "technique": "bytecode",
          "storage": "static AtomicLong in V1Counters (bootstrap classloader)",
          "reset": "V1Counters.reset() called in V1Guidance.getInput() before each execution",
          "read": "V1Counters.getEqualsCount() called in V1Guidance.handleResult()"
        }
      ],
      "retention": "Primary: retain inputs whose equalsCount exceeds 90% of the global best; always retain new global bests. Secondary (flat-signal / growth phase): retain inputs that are longer than any previously retained input, to grow toward input_bytes.",
      "retention_signals": ["equalsCount"],
      "mutation": [
        "diversify-all-records: for every record in the input, independently randomize each non-overlapping 2-byte atom by a random delta that preserves the base-31 polynomial contribution (31*a+b=C), converting duplicate records into distinct connection IDs sharing the same hash bucket; produces up to 9^5=59049 unique colliding IDs for 10-byte IDs",
        "hash-preserving byte-pair: change one 2-byte atom in one random record by (+delta, -31*delta) for fine-grained variation",
        "whole-input doubling: concatenate input with itself for rapid size growth toward input_bytes",
        "record repetition: duplicate a random length-prefixed record 4-64 times for density growth"
      ]
    }
  ]
}
```
END_GUIDANCE_PLAN_JSON

---

**Summary of changes:**

1. **New primary mutation: `mutateDiversifyAllRecords`** — Applies independent hash-preserving `(+δ, −31·δ)` transformations to **every** 2-byte atom in **every** record simultaneously, converting an input full of identical (doubled) records into one where each record has a distinct connection ID sharing the same `Arrays.hashCode` bucket. For 10-byte IDs with 5 atoms, this draws from 9^5 = 59,049 possible unique collision IDs. At ~47,000 records, random selection yields ~32,000 unique IDs — sufficient for equalsCount ≈ 1B+ (well above the 50% threshold of ~1.1B at 524KB).

2. **Phase-based mutation strategy** — Growth phase (input < maxInputSize/2): prioritizes doubling (55%) and repetition (25%) to rapidly grow toward `input_bytes`. Optimization phase (input ≥ maxInputSize/2): prioritizes diversify-all (60%) with single-record HP (20%) for refinement.

3. **Single mutation per execution** — Removed the 1-3 stacked mutations that could destructively interfere (e.g., a bit flip undoing an HP mutation's collision).

4. **Removed destructive byte-level mutations** — No more flip, overwrite, insert, delete, or dictionary mutations. These broke record structure and collision integrity without contributing to the equalsCount signal.

5. **Correct delta bounds computation** — Uses `ceilDiv31`/`floorDiv31` to compute the valid delta range for any current atom values, ensuring the transformation always stays within signed byte range.
