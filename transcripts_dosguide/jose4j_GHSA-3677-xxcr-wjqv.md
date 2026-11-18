# jose4j_GHSA-3677-xxcr-wjqv

## Block 1

I'll start by reading the source code and the frozen fuzz test to understand the attack surface.

```text
Read <source_root>/src/main/java/org/jose4j/zip/DeflateRFC1951CompressionAlgorithm.java
Glob <run_dir> *FuzzTest*
Glob <run_dir> **/*FuzzTest*
Read <run_dir>/src/test/java/org/jose4j/fuzz/JsonWebEncryptionFuzzTest.java
Glob <run_dir> **/pom.xml
Read <run_dir>/pom.xml
Read <source_root>/pom.xml
```

Now let me trace the call path through `JsonWebEncryption.getPlaintextBytes()` to understand how decompression is triggered.

```text
Glob <source_root>/src/main/java/org/jose4j **/jwe/JsonWebEncryption.java
Glob <source_root>/src/main/java/org/jose4j **/zip/CompressionAlgorithm.java
Read <source_root>/src/main/java/org/jose4j/jwe/JsonWebEncryption.java
Read <source_root>/src/main/java/org/jose4j/zip/CompressionAlgorithm.java
```

Now let me look at how the decompression is invoked through the full call chain and check for any other potential DoS vectors:

```text
Glob <source_root>/src/main/java/org/jose4j **/base64url/Base64Url.java
Glob <source_root>/src/main/java/org/jose4j **/jwx/JsonWebStructure.java
Glob <source_root>/src/main/java/org/jose4j **/jwx/Headers.java
Read <source_root>/src/main/java/org/jose4j/base64url/Base64Url.java
```

Now let me verify the lib jar exists and check the directory structure:

```text
$ ls -la <run_dir>/lib/ 2>&1
Glob <source_root>/src/main/java/org/jose4j **/zip/CompressionAlgorithmIdentifiers.java
```

Good, the lib jar exists. Now let me create the scale measurement data. I need to create raw DEFLATE streams at various decompression sizes.

```text
$ mkdir -p <run_dir>/analysis/scale/V1
```

Now let me generate the raw DEFLATE scale measurement inputs using Python:

```text
$ python3 -c " …
```

Let me verify the series.json and file listing:

```text
Read <run_dir>/analysis/scale/V1/series.json
$ ls -la <run_dir>/analysis/scale/V1/
```

All scale measurement files are created and verified. Now let me complete the full analysis and emit the target register.

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

**V1: Unbounded Decompression Output (Decompression Bomb / Zip Bomb)**

**Fuzzable Entrypoint & User-Controlled Input:**
The fuzz test `JsonWebEncryptionFuzzTest.fuzzJsonWebEncryptionGetPlaintextBytes(InputStream)` receives arbitrary bytes from the fuzzer. These bytes serve as the raw DEFLATE-compressed payload of a JWE token. The harness wraps them in a valid `"alg":"dir","enc":"A128GCM","zip":"DEF"` JWE token via `produceToken()`, encrypts with a constant AES key, then passes the token to `JsonWebEncryption.getPlaintextBytes()`. This decrypts the token (recovering the original bytes losslessly), and then calls `decompress()` because the header says `"zip":"DEF"`.

**Mechanism:**
`DeflateRFC1951CompressionAlgorithm.decompress(byte[])` (lines 55-79) creates an `Inflater(true)` for raw DEFLATE and reads into a `ByteArrayOutputStream` in a loop (`while ((bytesRead = iis.read(buff)) != -1)`) with **no limit on the total output size**. A carefully structured DEFLATE stream achieves very high compression ratios (e.g., ~160:1 with fixed Huffman, length-258/distance-1 back-references). With 10KB input, up to ~1.6MB of decompressed output is produced.

**Exhausted Resource:**
Heap memory — the bytes accumulated in the `ByteArrayOutputStream` internal array during decompression. The array doubles when full, so allocation grows geometrically.

**Failure Mode:**
`out_of_memory` — The harness throws `AssertionError` (an undeclared `Error`) when `plaintext.length > 204800`. In a production scenario without this check, the `ByteArrayOutputStream` grows until it exhausts heap memory (OutOfMemoryError). Both are undeclared throwables that constitute failures.

**Scale Estimation:**
Using optimal raw DEFLATE encoding (fixed Huffman, length-258 distance-1 back-reference pairs at 13 bits each):
- Each 13-bit pair produces 258 bytes of output → ratio ~159:1 per pair
- To exceed 204,800 bytes: need ~794 pairs → 794 × 13 + 11 bits overhead ≈ 1292 bytes of input (~1.3 KB)
- With 10KB input: ~6300 pairs → ~1.6MB output

The critical threshold is 204,800 bytes of decompressed output (triggers harness AssertionError). This requires approximately **1,300 bytes** of crafted DEFLATE input.

The all-zeros compression test confirms:
- 8 bytes DEFLATE → 512 bytes (64:1)
- 11 bytes → 1,024 (93:1)
- 33 bytes → 16,384 (496:1)

The ratio increases as the DEFLATE stream can use more efficient back-references for longer runs. Even a small input easily exceeds 204,800 bytes.

##### 1.2 Official Classification

**V1:**
- **CWE-409**: Improper Handling of Highly Compressed Data (Data Amplification)
- Also classified under CWE-400: Uncontrolled Resource Consumption
- **GHSA-3677-xxcr-wjqv**: The specific advisory for jose4j decompression bomb vulnerability

##### 1.3 Dependency / Package-Level Risks

**PkgRisk-1: `java.util.zip.Inflater` / `java.util.zip.InflaterInputStream` — JDK DEFLATE Decompression**

- **Package/Class:** `java.util.zip.Inflater`, `java.util.zip.InflaterInputStream`
- **Why input-sensitive:** The Inflater faithfully decompresses any valid DEFLATE stream with no output limit. The JDK decompressor is designed for correctness, not security — it has no built-in guard against decompression bombs. The output size is determined entirely by the input stream's structure.
- **Trigger shapes:** A valid raw DEFLATE stream that encodes highly repetitive data (e.g., repeated zeros). Fixed Huffman blocks with length-258 distance-1 pairs maximize the output-to-input ratio.
- **Exhausted resource:** Heap memory — bytes written to the consuming `ByteArrayOutputStream`.
- **Failure mode:** `out_of_memory`
- **Scale:** Same as V1 — ~1,300 bytes input → >204,800 bytes output. The Inflater itself is the mechanism V1 uses.
- **Fuzzing strategy:** This IS the same mechanism as V1. The Inflater loop is the sink where the amplification occurs. Instrumentation should measure `Inflater.inflate()` output bytes. Combined with V1 because they share the identical signal and mutation logic ([R33] exception: mechanistic proof that they are the same dominant signal).

**Assessment:** PkgRisk-1 is the exact same mechanism as V1 (the Inflater IS V1's sink). Per [R33], combining is justified because they share the identical dominant signal (decompressed bytes emitted by `Inflater.inflate()`) and the identical mutation logic (valid DEFLATE streams). There is no separate PkgRisk distinct from V1 to target.

No other PkgRisks are identified in the reachable code path:
- `Base64Url`: Linear O(n) encoding/decoding, no amplification
- `AES/GCM` cipher: Bounded by ciphertext size, no amplification
- JSON parsing of header: The header is constant in this test (set by `ENCODED_HEADER`), not attacker-controlled

##### PHASE B — Target Selection

Only one true target: V1 (the decompression bomb vulnerability), which subsumes PkgRisk-1.

---

##### IMPORT AUDIT
(No fuzzing imports generated in Block 1 — this section applies to the frozen fuzz test)
```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
```

---

##### Zest Baseline Comparison (for V1, per [R18])

**Closest Zest configuration:** Standard Zest (coverage-guided) running `fuzzJsonWebEncryptionGetPlaintextBytes`.

**Why Zest underperforms:**
Zest uses **code coverage** as its primary retention signal. The decompression code path in `DeflateRFC1951CompressionAlgorithm.decompress()` has very low structural complexity — it is a single `while` loop with a `read()` call. Whether the loop iterates 2 times or 2000 times, the same basic blocks are covered. Zest will not retain an input that decompresses to 100KB over one that decompresses to 1KB because both achieve the same branch coverage. Zest treats the loop body as "already covered" after the first iteration.

A custom Guidance uses **mechanism-aligned signals**: specifically, the number of bytes emitted by `Inflater.inflate()` (the decompression output volume). This signal directly measures the amplification that leads to resource exhaustion. The Guidance retains inputs that produce MORE decompressed output, steering the search toward the decompression bomb.

**Measurable metric where custom Guidance outperforms:**
- **Time-to-first-failure**: Custom Guidance should reach the 204,800-byte threshold much faster because it preferentially retains and mutates inputs that maximize decompressed output. Zest explores all code paths equally, most of which don't increase decompression volume.
- **Cost amplification rate**: The custom Guidance's best-so-far decompressed output grows monotonically across generations; Zest's grows only accidentally.

---

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unbounded DEFLATE Decompression Output (Decompression Bomb)",
      "entrypoint": "JsonWebEncryptionFuzzTest.fuzzJsonWebEncryptionGetPlaintextBytes(InputStream) → JsonWebEncryption.getPlaintextBytes() → JsonWebEncryption.decrypt() → JsonWebEncryption.decompress(Headers, byte[]) → DeflateRFC1951CompressionAlgorithm.decompress(byte[])",
      "source_path": "src/main/java/org/jose4j/zip/DeflateRFC1951CompressionAlgorithm.java",
      "sink": "DeflateRFC1951CompressionAlgorithm#decompress",
      "mechanism": "The decompress() method inflates a raw DEFLATE stream into a ByteArrayOutputStream with no limit on output size. A crafted DEFLATE stream using maximum-length back-references (length-258, distance-1) achieves ~159:1 compression ratio per back-reference pair, causing small inputs to expand into output many orders of magnitude larger.",
      "resource": "heap memory: bytes accumulated in ByteArrayOutputStream during Inflater.inflate() loop iterations; the internal array doubles when full, so allocation is geometric",
      "failure_mode": "out_of_memory",
      "scale": "The harness throws AssertionError (undeclared Error) when decompressed output exceeds 204,800 bytes. Using fixed Huffman deflate with length-258 distance-1 pairs (13 bits each producing 258 output bytes), approximately 794 pairs = ~1,300 bytes of input cross this threshold. Compression test confirms: 33 bytes raw DEFLATE decompresses to 16,384 bytes (496:1 ratio). Extrapolating, ~130 bytes of optimal DEFLATE produces ~204,800 bytes of output. Well within the 10,240-byte input size limit.",
      "input_bytes": 1300,
      "cwe": "CWE-409"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

#### Scale Measurement Analysis for V1

##### Measured Data Review

| decompressed_output_bytes | input_bytes | cpu ms | wall ms | allocated | peak heap | ratio |
|---|---|---|---|---|---|---|
| 512 | 8 | 87.8 | 115.3 | 5.5 MB | 6.0 MB | 64:1 |
| 1,024 | 11 | 90.2 | 119.3 | 5.5 MB | 6.0 MB | 93:1 |
| 2,048 | 17 | 85.5 | 108.0 | 5.5 MB | 6.0 MB | 120:1 |
| 4,096 | 20 | 87.5 | 109.5 | 5.6 MB | 6.0 MB | 205:1 |
| 8,192 | 25 | 84.0 | 101.2 | 5.6 MB | 7.0 MB | 328:1 |
| 16,384 | 33 | 95.3 | 106.7 | 5.5 MB | 6.0 MB | 496:1 |

##### Observations

1. **CPU and wall time are flat** (~85–120 ms) across all sizes. The JWE processing overhead (token parsing, AES-GCM decrypt) completely dominates; inflating 16 KB of zeros adds negligible time.

2. **Allocated memory and peak heap are flat** (~5.5 MB / ~6 MB). The decompressed output (up to 16 KB) is tiny relative to baseline JVM and JWE allocations.

3. **The compression ratio increases** with output size: 64:1 → 496:1. This is because Python's `zlib` level-9 uses dynamic Huffman tables; for all-zeros data, the back-reference pair (length-258, distance-1) is encoded in as few as ~3–4 bits, and the fixed overhead (block header, Huffman table definition, initial literal) is amortized over more pairs as the stream grows.

##### Extrapolation to Failure Threshold

The input grows roughly logarithmically with decompressed output. Fitting the measured input bytes to log₂(output_bytes):

- log₂(512)=9 → 8 bytes; log₂(16384)=14 → 33 bytes
- Slope: (33−8)/(14−9) = **5 bytes per doubling of output**

For 204,800 bytes decompressed (log₂ ≈ 17.6):
- Predicted input: 8 + 5 × (17.6 − 9) = **~51 bytes**

At 10,240 bytes input (the limit), the marginal rate of ~0.001 bytes input per byte output means decompressed output could reach several million bytes—well beyond the 204,800-byte threshold.

**Resource costs at the failure threshold (204,800 bytes decompressed from ~50–65 bytes input):**
- CPU time: ~90 ms (flat; no measurable growth)
- Allocated: ~5.7 MB (the 200 KB BAOS array is negligible on top of baseline 5.5 MB)
- Peak heap: ~6 MB (nowhere near 1 GB limit)

**The failure is the harness's AssertionError** when `plaintext.length > 204800`, not an actual JVM OOM—the decompressed output from a 10 KB input (~1.6 MB maximum) fits trivially in 1 GB heap. The mechanism (unbounded decompression amplification) is confirmed by the measurements: tiny input → large output with no application-level limit.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: DEFLATE input grows ~5 bytes per doubling of decompressed output (8 bytes input→512 bytes output at 64:1 up to 33 bytes→16,384 bytes at 496:1). CPU (~85-95 ms), allocated (~5.5 MB) and peak heap (~6 MB) are flat — JWE overhead dominates, decompression cost is negligible. Extrapolating at 5 bytes per doubling: ~51 bytes of optimal dynamic-Huffman DEFLATE input produces >204,800 bytes of decompressed output, triggering the harness AssertionError (undeclared throwable). At 10,240-byte input limit, decompressed output reaches millions of bytes. Failure is not JVM OOM (decompressed output fits in 1 GB heap) but the harness's explicit 204,800-byte size check. Conservative estimate: 100 bytes accounts for encoding variation.",
    "input_bytes": 100
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by reading the necessary source files to understand the full picture, then build the strategy and measurement plan.

```text
Read <run_dir>/src/test/java/org/jose4j/fuzz/JsonWebEncryptionFuzzTest.java
Read <source_root>/src/main/java/org/jose4j/zip/DeflateRFC1951CompressionAlgorithm.java
Read <run_dir>/pom.xml
```

Let me verify the existing pom.xml compiles correctly with the frozen test:

```text
$ mvn compile test-compile 2>&1 | tail -30
$ mvn compile 2>&1 | tail -30
```

Good, the pom.xml works. Let me check what ASM version is transitively available through JQF for the agent:

```text
$ mvn dependency:tree 2>&1 | tail -40
```

ASM is available transitively (asm 9.8 via jqf-instrument, asm-commons 9.5 via jacoco). The pom.xml needs no changes. Let me create the directory structure:

```text
$ mkdir -p src/test/java/org/jose4j/fuzz/agent src/test/java/org/jose4j/fuzz/guidance src/test/java/org/jose4j/fuzz/runner src/test/java/org/jose4j/fuzz/replay src/test/resources/META-INF scripts out/V1/corpus
$ find . -type f -o -type d | sort | head -60
```

Let me check the SignalSource file that's already present:

```text
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me verify the vulnerable jar contains the expected classes:

```text
$ jar tf <run_dir>/lib/jose4j-0.9.6-SNAPSHOT.jar | grep -E "(DeflateRFC|Inflat|JsonWebEncryption|CompressionAlg)" | head -10
```

All target classes are in the vulnerable jar. The pom.xml is correct as-is — no changes needed.

Now let me produce the complete strategy output.

---

#### Step 2 — Maven Layout & Scope

The existing `pom.xml` is correctly configured per [R4]:
- **jose4j 0.9.6-SNAPSHOT** (`system` scope, `systemPath` → `lib/jose4j-0.9.6-SNAPSHOT.jar`): vulnerable artifact, READ-ONLY
- **slf4j-api 1.7.36** (`compile` scope): jose4j's transitive dependency
- **slf4j-simple 1.7.36** (`test` scope): logging backend
- **jqf-fuzz 2.1** (`test` scope): provides `Guidance`, `GuidedFuzzing`, `@Fuzz`, `@JQF`
- **jqf-instrument 2.1** (`test` scope): transitively provides **ASM 9.8** (needed for the agent transformer)
- **junit 4.13.2** (`test` scope): JQF runner requirement
- **junit-quickcheck-core 1.0** (`test` scope): JQF requirement
- **junit-quickcheck-generators 1.0** (`test` scope): JQF requirement

ASM 9.8 (`asm`) and ASM 9.5 (`asm-commons`, `asm-tree`) are available transitively — no additional dependencies needed. **No pom.xml changes required.**

FORBIDDEN dependency `org.bitbucket.b_c:jose4j` is NOT present as a normal Maven dependency. It is referenced only via `<scope>system</scope>` pointing to the local vulnerable jar. ✓

---

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

All unresolved symbols in the frozen fuzz test:

| Symbol | Package | Classification | Resolution |
|--------|---------|----------------|------------|
| `@Fuzz` | `edu.berkeley.cs.jqf.fuzz` | A) External library | jqf-fuzz (test) |
| `@RunWith` | `org.junit.runner` | A) External library | junit (test) |
| `JQF` | `edu.berkeley.cs.jqf.fuzz` | A) External library | jqf-fuzz (test) |
| `Base64Url` | `org.jose4j.base64url` | In vulnerable jar | system dep |
| `JsonWebEncryption` | `org.jose4j.jwe` | In vulnerable jar | system dep |
| `JoseException` | `org.jose4j.lang` | In vulnerable jar | system dep |
| `Cipher`, `GCMParameterSpec`, `SecretKeySpec` | `javax.crypto.*` | JDK | built-in |

For fuzzing infrastructure (Block 3):

| Symbol | Package | Classification | Resolution |
|--------|---------|----------------|------------|
| `Guidance` | `edu.berkeley.cs.jqf.fuzz.guidance` | A) External library | jqf-fuzz (test) |
| `GuidedFuzzing` | `edu.berkeley.cs.jqf.fuzz.junit` | A) External library | jqf-fuzz (test) |
| `SignalSource` | `dosguide.validate` | Already present | evaluation framework |
| `ClassReader`, `ClassWriter`, `MethodVisitor` | `org.objectweb.asm` | A) External library | ASM (transitive via jqf-instrument) |
| `AdviceAdapter` | `org.objectweb.asm.commons` | A) External library | ASM commons (transitive via jacoco) |

##### 3.2 Stub Generation

**No stubs required.** All jose4j classes are resolved from the vulnerable jar (`lib/jose4j-0.9.6-SNAPSHOT.jar`). All external libraries are resolved from Maven dependencies (declared or transitive). No internal project classes are missing.

##### 3.3 Stub Report

**Empty.** No stubs were generated. All symbols are resolved by:
1. The vulnerable jose4j jar (system scope)
2. JQF/JUnit Maven dependencies (test scope)
3. ASM (transitive through jqf-instrument and jacoco)
4. JDK built-in classes

---

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|------------------|-------------------------------|------------------------|
| V1 | **CGF + DAG Hybrid** (Cost-Gradient + Dependency-Aware) | Zest's coverage signal saturates after ONE iteration of the decompression loop (`while ((bytesRead = iis.read(buff)) != -1) { baos.write(...); }`). Whether the loop runs 2 times or 2,000 times, the same branches are covered. This is a **proxy signal failure**: code coverage does not correlate with decompression amplification. Zest retains no further inputs based on decompression volume. | Hill-climbs on `inflatedBytes` — total decompressed bytes emitted by `Inflater.inflate()`, measured via custom bytecode agent inside the JDK decompressor. Every input producing more decompressed output is retained. Mutation operates at the plaintext level with DEFLATE encoding [R45(c)] and uses repetition [R45(a)] to maximize compression ratio. The signal is directly proportional to the resource being exhausted. |

**Method-specific optimization [R19]**: The Guidance's mutation is specific to `fuzzJsonWebEncryptionGetPlaintextBytes`:
- It knows the input is a raw DEFLATE stream (because the JWE header says `"zip":"DEF"`)
- It mutates at the plaintext level and encodes via `Deflater(Deflater.DEFLATED, true)` matching the `Inflater(true)` used in the vulnerable code
- Repetition is tuned to DEFLATE's back-reference mechanics: repeated byte patterns produce the highest compression ratios

---

#### Step 6 — Measurement Plan

##### Signal 1: `inflatedBytes`

| Aspect | Detail |
|--------|--------|
| **What** | Total bytes of decompressed output emitted by `Inflater.inflate()` in one execution |
| **Code region** | `java.util.zip.Inflater.inflate(byte[], int, int)` — the JDK method called by `InflaterInputStream.read()` inside `DeflateRFC1951CompressionAlgorithm.decompress()` (line 64) |
| **Why mechanism-aligned** | Each byte returned by `inflate()` is a byte written to the `ByteArrayOutputStream`. This IS the resource being exhausted — heap memory from unbounded decompression output. |
| **Stored** | `ThreadLocal<long[]>` in `InflateCounters` class (index [0]). The class is placed on the bootstrap classloader so the instrumented JDK `Inflater` can see it. |
| **Reset** | `InflateCounters.reset()` called in `V1Guidance.getInput()` before returning the input stream |
| **Read** | `InflateCounters.get()[0]` called in `V1Guidance.handleResult()` |
| **Satisfies [R30]** | (A) Derived from actual execution ✓; (B) Measured inside `Inflater.inflate()` — the exact decompressor causing the amplification ✓; (C) Consumed by `handleResult()` to affect retention ✓ |

##### Signal 2: `inflateCallCount`

| Aspect | Detail |
|--------|--------|
| **What** | Number of times `Inflater.inflate()` was invoked (decompression loop iterations) |
| **Code region** | Same as above: `java.util.zip.Inflater.inflate(byte[], int, int)` |
| **Why** | Each call represents one loop iteration in the decompress method. More calls = more decompressed chunks. |
| **Stored** | `ThreadLocal<long[]>` in `InflateCounters` (index [1]) |
| **Reset/Read** | Same lifecycle as `inflatedBytes` |

##### Instrumentation Feasibility [R35]

1. **Exact class/method**: `java.util.zip.Inflater`, method `inflate(byte[], int, int)I` (descriptor `([BII)I`)
2. **JVM flags**: `-javaagent:target/v1-measure-agent.jar` — no `--add-opens` needed (agent transforms class bytes, not reflection)
3. **Signal export**: `InflateCounters` class with `ThreadLocal<long[]>`:
   - Put on bootstrap classloader via `Instrumentation.appendToBootstrapClassLoaderSearch(agentJar)` in premain
   - Visible to both the instrumented JDK `Inflater` class and the app-classloader `V1Guidance`
4. **Agent implementation**:
   - **`V1MeasureAgent.premain(String, Instrumentation)`**: appends self to bootstrap CP, registers `InflaterTransformer`, retransforms `Inflater.class` if already loaded
   - **`InflaterTransformer`**: `ClassFileTransformer` using ASM `AdviceAdapter`
     - Matches class `java/util/zip/Inflater`, method `inflate`, descriptor `([BII)I`
     - In `onMethodExit(IRETURN)`: `DUP` the return value (int), `INVOKESTATIC InflateCounters.addBytes(I)V`
   - **`InflateCounters`**: static utility with `ThreadLocal<long[]>`, methods `addBytes(int)`, `get()`, `reset()`

---

#### Step 7 — V1Guidance Design

**Class**: `org.jose4j.fuzz.guidance.V1Guidance implements Guidance, SignalSource`

**Corpus**: `out/V1/corpus/` — independent per [R20]

**Signals tracked** (via `lastSignals()`):
- `"inflatedBytes"` → `Double` value from last execution
- `"inflateCallCount"` → `Double` value from last execution

**Failure policy [R6]**: V1Guidance NEVER decides an execution failed and NEVER writes failure files. It only saves corpus entries. JQF reports results; the evaluation framework records failures.

**Logging [R5]**: Every 1 second, log: executions/sec, total executions, best inflatedBytes, corpus size, current input length.

##### Mutation Operators

1. **Byte-level** (on plaintext representation):
   - Bit flip at random position
   - Insert 1-4 random bytes
   - Delete 1-4 bytes
   - Replace 1-4 bytes with random values

2. **Repetition [R45(a)]**:
   - **Whole-input doubling**: append plaintext to itself (doubles length)
   - **Chunk repeat**: select random chunk [1..len/2], repeat k times (k ∈ {2..32}), insert/replace at random position
   - Growth: starting from 1-byte plaintext, doubling ~17 times → 128KB+ plaintext → ~100 bytes DEFLATE → >204,800 bytes decompressed
   - This reaches `input_bytes` (100) within seconds (17 executions × ~100ms = ~1.7s)

3. **Dictionary [R45(b)]** — tokens from attack path source code:
   - `\x00` — zero byte (from `new byte[12]` IV initialization, maximally compressible)
   - `\x01` — DEFLATE BFINAL bit marker
   - `\x03` — DEFLATE fixed Huffman block header (BFINAL=1, BTYPE=01)
   - `"DEF"` bytes — DEFLATE algorithm identifier from `CompressionAlgorithmIdentifiers.DEFLATE`
   - `"zip"` bytes — header parameter name from `HeaderParameterNames.ZIP`
   - `0x78` — zlib header magic byte (common deflate signature)

4. **Encoder [R45(c)]** — DEFLATE:
   - After mutating plaintext, compress via `new Deflater(Deflater.DEFLATED, true)` (raw deflate, level 9)
   - Output: valid raw DEFLATE bytes, accepted by the vulnerable `Inflater(true)`
   - If compressed > `MAX_INPUT_SIZE` (10240): truncate plaintext, recompress
   - All inputs are guaranteed valid DEFLATE → always reach the decompression sink

##### Retention & Prioritization [R46]

- **Primary**: retain if `inflatedBytes` > best seen so far (new maximum)
- **Secondary** (flat signal handling): when `inflatedBytes` hasn't improved for 10 executions, retain inputs where plaintext length is a new maximum (growth toward more output)
- **Corpus cap**: 32 entries, oldest/lowest-signal evicted
- **Parent selection**: weighted random from corpus, probability proportional to rank by `inflatedBytes`
- **input_growth guarantee**: plaintext doubles per repetition mutation → 128KB plaintext from 1 byte in 17 steps → ~100 bytes DEFLATE in <2 seconds. Well within the 1-minute requirement.

##### Stop/Continue

- `hasInput()`: returns `true` if no time limit or within limit
- Default: infinite
- Time-bounded: `-Djqf.ei.MAX_DURATION=<seconds>` system property

---

#### Step 8 — Fuzz Test

The **frozen** `JsonWebEncryptionFuzzTest.fuzzJsonWebEncryptionGetPlaintextBytes(InputStream)` is the fuzz method. It:
- Covers: **V1** (Decompression Bomb)
- Consumes: `InputStream` (bytes) — the raw DEFLATE payload
- Declares: `throws IOException, JoseException`
- Oracle: `AssertionError` (undeclared throwable) if decompressed output > 204,800 bytes

No additional fuzz tests are needed. The frozen harness is the sole entry point.

---

#### Step 9 — Replay / Feeder

`ReplayRunner` loads saved corpus entries from `out/V1/corpus/`:
- Each entry: `input_NNNN.bin` (raw DEFLATE bytes) + `input_NNNN.json` (metadata)
- Metadata: `{ "index": N, "inflatedBytes": X, "inflateCallCount": Y, "plaintextLen": Z, "timestamp": T }`
- Replay: reads input bytes, runs through `JsonWebEncryptionFuzzTest.fuzzJsonWebEncryptionGetPlaintextBytes()` via `GuidedFuzzing.run()` with a one-shot replay guidance
- Prints: input hex (first 64 bytes), decompressed size, exception type/message, signal values

---

#### Step 10 — Maven Configuration & Commands

**Directory layout**: as shown above.

**Commands**:
```bash
### 1. Compile
mvn compile package -DskipTests

### 2. Build agent JAR
bash scripts/build-agent.sh

### 3. Fuzz V1 (infinite)
java -Xmx1g -Xss1m -javaagent:target/v1-measure-agent.jar \
  -cp "target/test-classes:target/dependency/*:lib/jose4j-0.9.6-SNAPSHOT.jar" \
  org.jose4j.fuzz.runner.FuzzRunner fuzzJsonWebEncryptionGetPlaintextBytes

### 4. Fuzz V1 (time-bounded, 300 seconds)
java -Xmx1g -Xss1m -javaagent:target/v1-measure-agent.jar \
  -Djqf.ei.MAX_DURATION=300 \
  -cp "target/test-classes:target/dependency/*:lib/jose4j-0.9.6-SNAPSHOT.jar" \
  org.jose4j.fuzz.runner.FuzzRunner fuzzJsonWebEncryptionGetPlaintextBytes

### 5. Replay
java -Xmx1g -Xss1m -javaagent:target/v1-measure-agent.jar \
  -cp "target/test-classes:target/dependency/*:lib/jose4j-0.9.6-SNAPSHOT.jar" \
  org.jose4j.fuzz.replay.ReplayRunner out/V1/corpus/input_0001.bin
```

---

#### IMPORT AUDIT

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
SignalSource → dosguide.validate.SignalSource
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
ClassVisitor → org.objectweb.asm.ClassVisitor
MethodVisitor → org.objectweb.asm.MethodVisitor
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter
Opcodes → org.objectweb.asm.Opcodes
```

TraceEvent (`edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent`) is NOT used — custom agent uses ASM directly per [R43].

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — `<maven.compiler.source>17</maven.compiler.source>`
- [YES] No hallucinated APIs — all APIs verified from dependency tree and JDK 17 javadoc
- [YES] Guidance implements Guidance directly — `V1Guidance implements Guidance, SignalSource`
- [YES] No existing guidance extended — fresh implementation, no Zest/PerfFuzz delegation
- [YES] V* vulnerabilities identified — V1: Decompression Bomb (CWE-409)
- [YES] V* IDs are sequential — V1 is index 1 (only target)
- [YES] Official vulnerability names applied — CWE-409, GHSA-3677-xxcr-wjqv
- [YES] PkgRisk-* identified — PkgRisk-1 (Inflater) subsumed by V1, justified per [R33]
- [YES] Every PkgRisk-* executed or justified — PkgRisk-1 shares V1's mechanism/signal/mutation
- [YES] Guidance targets V* — V1Guidance targets V1 exclusively
- [YES] One fuzz method per V* — `fuzzJsonWebEncryptionGetPlaintextBytes` for V1 (frozen)
- [YES] CLI method selection supported — `FuzzRunner <methodName> [duration]`
- [YES] byte[]/InputStream input model used exclusively — Guidance provides DEFLATE bytes via InputStream
- [YES] No junit-quickcheck Generators used — all mutation inside V1Guidance
- [YES] All mutation implemented inside Guidance — byte-level + repetition + dictionary + encoder
- [YES] Repetition, source dictionary and encoder operators implemented — plaintext doubling, token dictionary from source, Deflater encoding
- [YES] Retention progresses while signal flat — secondary criterion: plaintext length growth [R46]
- [YES] Retention signals measured where resource consumed — at `Inflater.inflate()` inside decompression [R47]
- [YES] Logging every 1 second — structured stats in V1Guidance
- [YES] Guidance decides no failures and writes no failure files — per [R6]
- [YES] Corrupted inputs saved with metadata — JSON sidecar files in `out/V1/corpus/`
- [YES] Replay/feeder implemented — `ReplayRunner` reads corpus + metadata
- [YES] Infinite + time-bounded fuzzing supported — default infinite, `-Djqf.ei.MAX_DURATION`
- [YES] src/main vs src/test separation correct — all fuzzing infra in `src/test/java`
- [YES] Maven scopes consistent — jose4j=system, JQF/JUnit=test, slf4j-api=compile
- [YES] No wildcard imports for JQF/tracing — all explicit imports
- [YES] TraceEvent import verified — NOT used; custom agent via ASM per [R43]

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "inflatedBytes",
          "quantity": "total decompressed bytes emitted by the DEFLATE inflater during one execution",
          "aggregation": "sum",
          "locations": ["Inflater#inflate"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in InflateCounters (index 0), on bootstrap classloader",
          "reset": "InflateCounters.reset() called in V1Guidance.getInput() before returning the input stream",
          "read": "InflateCounters.get()[0] called in V1Guidance.handleResult()"
        },
        {
          "name": "inflateCallCount",
          "quantity": "number of Inflater.inflate() invocations (decompression loop iterations)",
          "aggregation": "count",
          "locations": ["Inflater#inflate"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in InflateCounters (index 1), on bootstrap classloader",
          "reset": "InflateCounters.reset() called in V1Guidance.getInput() before returning the input stream",
          "read": "InflateCounters.get()[1] called in V1Guidance.handleResult()"
        }
      ],
      "retention": "Primary: retain inputs whose inflatedBytes exceeds the current corpus maximum — these are the highest-amplification inputs. Secondary (flat-signal progress per R46): when inflatedBytes has not improved for 10 consecutive executions, retain inputs with a new maximum plaintext length, growing the search toward more decompressible content. Corpus capped at 32 entries; lowest-signal entries evicted. Parent selection weighted by inflatedBytes rank.",
      "retention_signals": ["inflatedBytes"],
      "mutation": [
        "Byte-level on plaintext: random bit flips, 1-4 byte insert/delete/replace",
        "Repetition (R45a): whole-plaintext doubling (append plaintext to itself) and chunk-repeat (select random chunk 1..len/2, repeat k=2..32 times). Doubling from 1 byte reaches 128KB+ plaintext in 17 steps — compresses to ~100 bytes DEFLATE — well within input_bytes=100 and within the first minute.",
        "Dictionary (R45b): tokens from attack path source — \\x00 (zero byte, maximally compressible, from IV init), \\x01 and \\x03 (DEFLATE block headers), 'DEF' bytes (CompressionAlgorithmIdentifiers.DEFLATE), 'zip' bytes (HeaderParameterNames.ZIP), 0x78 (zlib magic). Inserted/overwritten at random plaintext positions.",
        "Encoder (R45c): after every plaintext mutation, compress via Deflater(Deflater.DEFLATED, true) at level 9 (raw DEFLATE matching the vulnerable Inflater(true)). All fuzz inputs are valid DEFLATE streams guaranteed to reach the decompression sink. If compressed output exceeds MAX_INPUT_SIZE (10240), truncate plaintext and recompress."
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

I'll implement all files for the V1 decompression bomb target. Let me start by reading the existing files to understand the exact structure.

```text
Read <run_dir>/src/test/java/org/jose4j/fuzz/JsonWebEncryptionFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/pom.xml
```

Let me check the JQF Guidance interface and GuidedFuzzing API to verify correct method signatures:

```text
$ mvn dependency:resolve 2>&1 | tail -10
$ find ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/ -name "*.jar" | head -3
$ jar tf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar | grep -E "(Guidance|GuidedFuzzing)" | head -20
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class 2>&1
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Result.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/Result.class 2>&1
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class && javap -public edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/GuidanceException.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/GuidanceException.class 2>&1
```

Good, now I have all the API details. Let me also verify the ASM AdviceAdapter signature:

```text
$ find ~/.m2/repository/org/ow2/asm/ -name "asm-commons-*.jar" | head -3
$ cd /tmp && jar xf ~/.m2/repository/org/ow2/asm/asm-commons/9.5/asm-commons-9.5.jar org/objectweb/asm/commons/AdviceAdapter.class && javap -p org/objectweb/asm/commons/AdviceAdapter.class 2>&1 | head -20
$ cd /tmp && javap -p org/objectweb/asm/commons/AdviceAdapter.class 2>&1 | grep -E "(onMethod|visitInsn|protected)" | head -10
```

Now I have all API details. Let me write all the implementation files.

**Part A — Java Agent:**

```text
Write <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflateCounters.java
Write <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflaterTransformer.java
Write <run_dir>/src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java
```

**Part B — Guidance:**

```text
Write <run_dir>/src/test/java/org/jose4j/fuzz/guidance/V1Guidance.java
```

**Part C — FuzzRunner, ReplayRunner, scripts:**

```text
Write <run_dir>/src/test/java/org/jose4j/fuzz/runner/FuzzRunner.java
Write <run_dir>/src/test/java/org/jose4j/fuzz/replay/ReplayRunner.java
```

Now let me write the agent build script and the agent manifest:

```text
Write <run_dir>/src/test/resources/META-INF/MANIFEST.MF
Write <run_dir>/scripts/build-agent.sh
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh <run_dir>/scripts/build-agent.sh
```

Now write the launch.json:

```text
Write <run_dir>/analysis/launch.json
```

Now let me create validation inputs — up to 10 well-formed example inputs (valid DEFLATE streams, not failure-inducing):

```text
$ mkdir -p <run_dir>/analysis/validation_inputs && python3 -c " …
```

Good. Now let me verify the build compiles:

```text
$ mvn package -DskipTests 2>&1 | tail -30
```

Build succeeds. Now build the agent JAR:

```text
$ bash scripts/build-agent.sh 2>&1 | tail -20
```

Agent JAR built with all required classes including ASM's AdviceAdapter. Let me verify the agent jar manifest:

```text
$ jar xf target/v1-measure-agent.jar META-INF/MANIFEST.MF && cat META-INF/MANIFEST.MF && rm -rf META-INF
```

Let me now verify the complete file listing:

```text
$ find src/test/java -name "*.java" -type f | sort
Glob <run_dir> src/test/java/**/*.java
```

Let me verify the compilation still succeeds with all the new files:

```text
$ mvn package -DskipTests 2>&1 | tail -15
```

All compiles successfully. Let me also rebuild the agent to include the freshly compiled classes:

```text
$ bash scripts/build-agent.sh 2>&1 | tail -10
```

Everything builds cleanly. Now let me verify the test-classes directory has all expected classes:

```text
$ ls -la <run_dir>/target/test-classes/org/jose4j/fuzz/agent/ <run_dir>/target/test-classes/org/jose4j/fuzz/guidance/ <data>/workspaces/jose4j_GHSA-3677-xxcr-wjqv …
```

All classes compile cleanly. Let me verify the complete workspace state:

```text
$ ls -la <run_dir>/analysis/validation_inputs/
```

Everything is in order. Now let me produce the complete summary documentation.

---

#### Part A — Java Agent

##### Files emitted:

1. **`src/test/java/org/jose4j/fuzz/agent/InflateCounters.java`** — Shared counter class using `ThreadLocal<long[]>`. Placed on bootstrap classloader by the agent so both the instrumented JDK `Inflater` and the app-classloader `V1Guidance` can access it. Tracks `totalInflatedBytes` (index 0) and `inflateCallCount` (index 1).

2. **`src/test/java/org/jose4j/fuzz/agent/InflaterTransformer.java`** — ASM `ClassFileTransformer` that targets exactly `java.util.zip.Inflater.inflate([BII)I`. Uses `AdviceAdapter.onMethodExit(IRETURN)` to `DUP` the return value and call `InflateCounters.addBytes(int)`. Only transforms the Inflater class — all other classes pass through untouched.

3. **`src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java`** — Agent entry point (`premain`). Appends the agent JAR to the bootstrap classloader via `Instrumentation.appendToBootstrapClassLoaderSearch()`, registers the `InflaterTransformer` with retransform support, and retransforms `Inflater.class` if already loaded.

4. **`src/test/resources/META-INF/MANIFEST.MF`** — Agent manifest with `Premain-Class`, `Can-Retransform-Classes: true`.

5. **`scripts/build-agent.sh`** — Packages agent classes + ASM into `target/v1-measure-agent.jar`.

#### Part B — Guidance

6. **`src/test/java/org/jose4j/fuzz/guidance/V1Guidance.java`** — Implements `Guidance` directly + `SignalSource`. Hill-climbs on `inflatedBytes` from agent counters. Mutation operates on plaintext, compresses to valid raw DEFLATE via `Deflater(BEST_COMPRESSION, true)` per [R45c]. Repetition via whole-input doubling and chunk repeat [R45a]. Dictionary of tokens from attack path [R45b]. Never writes failure files [R6]. Logs every 1 second [R5]. Reads `MAX_INPUT_SIZE` from system property [R41].

#### Part C — Runner / Replay

7. **`src/test/java/org/jose4j/fuzz/runner/FuzzRunner.java`** — CLI runner with `public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log)`. Uses `GuidedFuzzing.run(testClassName, testMethod, cl, guidance, out)`. Includes class origin verification.

8. **`src/test/java/org/jose4j/fuzz/replay/ReplayRunner.java`** — Replays saved inputs through the fuzz test, prints signals and exceptions.

9. **`run.sh`** — Builds workspace, builds agent, runs V1 for 60s.

10. **`analysis/launch.json`** — Build and run descriptor for DoSGuide.

---

#### Strategy Table

| Target | Selected Strategy | Why Zest Fails | Why This Strategy Wins |
|--------|------------------|----------------|----------------------|
| V1 | CGF + DAG Hybrid | Coverage saturates after one loop iteration in `decompress()`. No new branches regardless of decompression volume. Proxy signal failure. | Hill-climbs `inflatedBytes` (total bytes from `Inflater.inflate()`) — directly measures decompression amplification. DEFLATE encoding ensures all inputs reach the sink. Repetition mutation maximizes compression ratio. |

---

#### IMPORT AUDIT

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz (in frozen FuzzTest)
@RunWith → org.junit.runner.RunWith (in frozen FuzzTest)
JQF → edu.berkeley.cs.jqf.fuzz.JQF (in frozen FuzzTest)
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance (in V1Guidance, ReplayRunner)
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException (in V1Guidance, ReplayRunner)
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result (in V1Guidance, ReplayRunner)
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing (in FuzzRunner, ReplayRunner)
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent (in V1Guidance, ReplayRunner — for generateCallBack signature)
SignalSource → dosguide.validate.SignalSource (in V1Guidance)
ClassReader → org.objectweb.asm.ClassReader (in InflaterTransformer)
ClassWriter → org.objectweb.asm.ClassWriter (in InflaterTransformer)
ClassVisitor → org.objectweb.asm.ClassVisitor (in InflaterTransformer)
MethodVisitor → org.objectweb.asm.MethodVisitor (in InflaterTransformer)
Opcodes → org.objectweb.asm.Opcodes (in InflaterTransformer)
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter (in InflaterTransformer)
```

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — `maven.compiler.source=17`, switch expressions, no preview APIs
- [YES] No hallucinated APIs — all verified via `javap` on actual JARs
- [YES] Guidance implements Guidance directly — `V1Guidance implements Guidance, SignalSource`
- [YES] No existing guidance extended — fresh implementation from interface
- [YES] V* vulnerabilities identified — V1: Decompression Bomb (CWE-409)
- [YES] V* IDs are sequential — V1 is discovery-order index 1
- [YES] Official vulnerability names applied — CWE-409, GHSA-3677-xxcr-wjqv
- [YES] PkgRisk-* identified — PkgRisk-1 (Inflater) subsumed by V1
- [YES] Every PkgRisk-* executed or justified — same mechanism, combined per [R33]
- [YES] Guidance targets V* — V1Guidance exclusively targets V1
- [YES] One fuzz method per V* — `fuzzJsonWebEncryptionGetPlaintextBytes` (frozen)
- [YES] CLI method selection supported — `FuzzRunner V1 [seconds]`
- [YES] byte[]/InputStream input model used exclusively — `getInput()` returns `ByteArrayInputStream`
- [YES] No junit-quickcheck Generators used — all mutation in V1Guidance
- [YES] All mutation implemented inside Guidance — byte-level + repetition + dictionary + encoder
- [YES] Repetition, source dictionary and encoder operators implemented — doubling/chunk-repeat, 9 tokens, Deflater encoding
- [YES] Retention progresses while signal flat — secondary: max plaintext length growth [R46]
- [YES] Retention signals measured where resource consumed — `Inflater.inflate()` inside decompress loop [R47]
- [YES] Logging every 1 second — structured stats in `handleResult()`
- [YES] Guidance decides no failures and writes no failure files — per [R6]
- [YES] Corrupted inputs saved with metadata — JSON sidecar files in `out/V1/corpus/`
- [YES] Replay/feeder implemented — `ReplayRunner`
- [YES] Infinite + time-bounded fuzzing supported — default infinite, `-Djqf.ei.MAX_DURATION`
- [YES] src/main vs src/test separation correct — all fuzzing infra in `src/test/java`
- [YES] Maven scopes consistent — jose4j=system, JQF/JUnit=test, slf4j-api=compile
- [YES] No wildcard imports used for JQF/tracing — all explicit
- [YES] TraceEvent import verified and audited — used only for `generateCallBack` signature, not for measurement

## Validation repair 1

The error is `NoClassDefFoundError: org/jose4j/fuzz/agent/InflateCounters`. This happens because when the agent instruments `java.util.zip.Inflater` (a bootstrap class), the instrumented code calls `InflateCounters.addBytes()`, but `InflateCounters` isn't on the bootstrap classpath yet when `Inflater` is first used.

The issue is in `V1MeasureAgent.premain()`: `appendToBootstrapClassLoaderSearch()` uses `getProtectionDomain().getCodeSource()` to find the agent jar, but when running from test-classes (not from the agent jar), this can fail or point to the wrong location. Let me also check that the agent jar path resolution is robust.

Let me diagnose and fix:

```text
Read <run_dir>/src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java
Read <run_dir>/scripts/build-agent.sh
Read <run_dir>/analysis/launch.json
```

The root cause is clear: the instrumented `Inflater` tries to call `InflateCounters.addBytes()` at the bootstrap level, but `InflateCounters` isn't on the bootstrap classpath. The `appendToBootstrapClassLoaderSearch()` call in premain either fails silently (the CodeSource resolution produces a directory instead of a JAR) or runs too late.

The fix is two-fold:
1. Use the `Boot-Class-Path` manifest attribute — the JVM resolves it before premain runs
2. Pass the agent jar path as the agent argument in launch.json as a fallback

```text
Read <run_dir>/src/test/resources/META-INF/MANIFEST.MF
Write <run_dir>/src/test/resources/META-INF/MANIFEST.MF
```

Now make the premain more robust — also try to programmatically add to bootstrap as a belt-and-suspenders approach:

```text
Write <run_dir>/src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java
```

Now update `launch.json` to pass the agent jar path as the agent args:

```text
Edit <run_dir>/analysis/launch.json
```

Now rebuild:

```text
$ mvn package -DskipTests -q 2>&1 | tail -10
$ bash scripts/build-agent.sh 2>&1 | tail -15
```

Verify the new manifest has Boot-Class-Path:

```text
$ unzip -p target/v1-measure-agent.jar META-INF/MANIFEST.MF
```

The manifest now has `Boot-Class-Path: v1-measure-agent.jar`. This tells the JVM to add the agent jar to the bootstrap classloader search path before premain even runs, ensuring `InflateCounters` is visible to the instrumented `Inflater`.

Let me also verify the launch.json is correct:

```text
Read <run_dir>/analysis/launch.json
```

Good. Now let me also update `run.sh` to pass the agent jar path as the agent argument:

```text
Read <run_dir>/run.sh
Edit <run_dir>/run.sh
```

**Summary of changes:**

1. **`src/test/resources/META-INF/MANIFEST.MF`** — Added `Boot-Class-Path: v1-measure-agent.jar`. This is the critical fix: it tells the JVM to add the agent jar's classes to the bootstrap classloader *before* `premain` runs and before any class transformation. This ensures `InflateCounters` is visible to the instrumented `java.util.zip.Inflater` (which is loaded by the bootstrap classloader).

2. **`src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java`** — Made `premain` more robust with a `resolveAgentJar()` method that tries multiple fallback strategies: agent args, CodeSource (both JAR and directory cases), and common relative paths. The `appendToBootstrapClassLoaderSearch()` is now a belt-and-suspenders fallback; the `Boot-Class-Path` manifest attribute is the primary mechanism.

3. **`analysis/launch.json`** — Changed agent args from `""` to `"target/v1-measure-agent.jar"` so the agent can find its own JAR via the args parameter as well.

4. **`run.sh`** — Updated the `-javaagent` flag to pass the jar path as the agent argument: `-javaagent:jar=jar`.

## Validation repair 2

Let me analyze the two issues:

1. **"javaagent rewrote no class while the test ran"** — The agent's `InflaterTransformer` transforms `java/util/zip/Inflater` but DoSGuide doesn't see it as a rewrite during the test. The `Inflater` class is likely loaded before the test runs (during JVM startup), so the transformer never fires for it during the test. The retransform in premain should handle this, but the check might specifically track transformations during test execution. The signals DO vary (0..638963), meaning the counters ARE working via Boot-Class-Path, but the transformer may have been applied at premain time, not "while the test ran."

2. **"re-running the same input gave different values (638963 then 2)"** — The first run produces a huge value, then the same input produces 2. This means the counters accumulate across executions — the `InflateCounters.reset()` in `getInput()` is not properly resetting. The problem: `InflateCounters` loaded from Boot-Class-Path vs from the app classloader are **different class instances** (different classloaders = different static fields). The `V1Guidance` calls `InflateCounters.reset()` on the app-classloader version, but the instrumented `Inflater` increments the bootstrap-classloader version.

This is the classic dual-class-loading problem. Let me fix both issues by changing the approach: instead of instrumenting `Inflater` (a JDK bootstrap class), I'll instrument `DeflateRFC1951CompressionAlgorithm.decompress()` in the jose4j jar — this runs on the app classloader, same as the Guidance.

```text
Read <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflateCounters.java
Read <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflaterTransformer.java
Read <run_dir>/src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java
Read <run_dir>/src/test/java/org/jose4j/fuzz/guidance/V1Guidance.java
```

Let me first check the jose4j source to understand the exact class and method signatures.

```text
Grep <source_root> class DeflateRFC1951CompressionAlgorithm
Read <run_dir>/src/test/java/org/jose4j/fuzz/runner/FuzzRunner.java
Read <source_root>/src/main/java/org/jose4j/zip/DeflateRFC1951CompressionAlgorithm.java
```

Now I have a clear picture. The `decompress([B)[B` method in `DeflateRFC1951CompressionAlgorithm` returns the decompressed `byte[]`. I'll instrument it to call `InflateCounters.addBytes(result.length)` on return. This fixes both validation issues:

1. The jose4j class loads **during** the test (not at JVM startup) → transformer fires during test
2. Only captures jose4j decompression (not JVM-internal inflate calls) → deterministic signals

Let me implement all the fixes:

```text
Write <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflaterTransformer.java
Write <run_dir>/src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java
Write <run_dir>/src/test/resources/META-INF/MANIFEST.MF
```

The files were read in the summary context. Let me use Edit instead for the files that need rewriting:

```text
Edit <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflaterTransformer.java
Edit <run_dir>/src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java
```

The read tracking was lost in the context compaction. Let me re-read and then edit:

```text
Read <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflaterTransformer.java
Read <run_dir>/src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java
Read <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflateCounters.java
Read <run_dir>/scripts/build-agent.sh
Read <run_dir>/analysis/launch.json
```

Good, now I have read all files. Let me apply the edits:

```text
Write <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflaterTransformer.java
Write <run_dir>/src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java
Edit <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflateCounters.java
```

Good. Now update the comment in InflateCounters for the `addBytes` method, and update the `launch.json` javaagent args (we can simplify since we no longer need to pass the jar path as args):

```text
Edit <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflateCounters.java
```

Now let me also read and update the V1Guidance comments (it references "Inflater.inflate" in several places):

```text
Read <run_dir>/src/test/java/org/jose4j/fuzz/guidance/V1Guidance.java
Edit <run_dir>/src/test/java/org/jose4j/fuzz/guidance/V1Guidance.java
```

Now let me update the `run.sh` to remove the agent args (no longer needed — we don't need to pass the jar path for bootstrap classpath resolution):

```text
Read <run_dir>/run.sh
Edit <run_dir>/run.sh
```

Now update `launch.json` — simplify the javaagent args:

```text
Edit <run_dir>/analysis/launch.json
```

Now let's compile to verify everything works:

```text
$ mvn package -DskipTests -q 2>&1 | tail -30
```

Clean compile. Now build the agent jar:

```text
$ bash scripts/build-agent.sh 2>&1 | tail -20
```

The agent JAR is built with all the correct classes. Let me verify the manifest:

```text
$ jar xf target/v1-measure-agent.jar META-INF/MANIFEST.MF -d /tmp/agent-check && cat /tmp/agent-check/META-INF/MANIFEST.MF
$ unzip -p target/v1-measure-agent.jar META-INF/MANIFEST.MF
```

The manifest is correct — no `Boot-Class-Path` attribute (which is what we want). The agent will transform the jose4j class during test execution, not a JDK bootstrap class.

Let me verify the compiled bytecode of the transformer to make sure the class names are correct:

```text
$ javap -c -p target/test-classes/org/jose4j/fuzz/agent/InflaterTransformer.class 2>&1 | head -30
```

The compiled class correctly targets `org/jose4j/zip/DeflateRFC1951CompressionAlgorithm`.

Let me also verify the DecompressAdvice inner class has the correct ARETURN / DUP / ARRAYLENGTH / INVOKESTATIC sequence:

```text
$ javap -c -p 'target/test-classes/org/jose4j/fuzz/agent/InflaterTransformer$DecompressAdvice.class' 2>&1 | tail -30
```

The bytecode is exactly right:
- `sipush 176` = `ARETURN` opcode (0xB0 = 176) — correctly checking for `ARETURN`
- `dup()` — duplicates the byte[] reference on the stack
- `arrayLength()` — gets the array length (decompressed byte count)  
- `sipush 184` = `INVOKESTATIC` opcode (0xB8 = 184)
- Calls `org/jose4j/fuzz/agent/InflateCounters.addBytes(I)V`

Now let me also verify the V1MeasureAgent has no retransform logic:

```text
$ javap -c -p target/test-classes/org/jose4j/fuzz/agent/V1MeasureAgent.class 2>&1
```

Clean and simple. The agent just:
1. Creates `InflaterTransformer`
2. Calls `inst.addTransformer(transformer, false)` — registers without retransform
3. Prints a diagnostic message

No retransform logic, no bootstrap classloader manipulation. The transformer will fire when `DeflateRFC1951CompressionAlgorithm` is first loaded during the test.

Let me also quickly verify the final state of all modified files for correctness:

```text
Read <run_dir>/analysis/launch.json
Read <run_dir>/src/test/resources/META-INF/MANIFEST.MF
```

Everything looks correct. Let me do a final clean compile to make sure the whole project still builds end-to-end:

```text
$ mvn clean package -DskipTests -q 2>&1 | tail -20
$ bash scripts/build-agent.sh 2>&1 | tail -20
```

Everything builds cleanly. Let me verify the complete set of compiled test classes:

```text
$ find <run_dir>/target/test-classes -name '*.class' | sort
```

All classes present and correct. Here's a summary of every change and why it fixes the two validation failures:

#### Changes Made

##### 1. `InflaterTransformer.java` — Retargeted from JDK to jose4j class

**Before:** Targeted `java/util/zip/Inflater.inflate([BII)I` — a JDK bootstrap class  
**After:** Targets `org/jose4j/zip/DeflateRFC1951CompressionAlgorithm.decompress([B)[B` — the jose4j class

Key differences in the instrumentation:
- **Class target:** `org/jose4j/zip/DeflateRFC1951CompressionAlgorithm` (loaded during test, not at JVM startup)
- **Method:** `decompress([B)[B` (returns `byte[]` not `int`)
- **Exit hook:** On `ARETURN` (not `IRETURN`), does `DUP → ARRAYLENGTH → addBytes(int)` to get the decompressed array length
- **ClassWriter:** Uses `COMPUTE_MAXS` only (not `COMPUTE_MAXS | COMPUTE_FRAMES`) — safer
- Added `transformed` flag and diagnostic `System.err` logging

**Fixes "javaagent rewrote no class while the test ran":** The jose4j class is first loaded when the fuzz test calls JWE decryption. The transformer fires at that point — during the test, not during JVM bootstrap.

##### 2. `V1MeasureAgent.java` — Simplified (no retransform, no bootstrap)

**Before:** Complex logic: resolve agent jar, `appendToBootstrapClassLoaderSearch`, register transformer with retransform=true, iterate loaded classes to retransform Inflater  
**After:** Just `inst.addTransformer(transformer, false)` — register and done

No retransform needed because the target class hasn't been loaded at premain time. No bootstrap classloader manipulation needed because both the instrumented class and the Guidance run on the same app classloader.

**Fixes "re-running same input gave different values":** 
- Old approach: Instrumenting `Inflater` captured ALL inflate calls (JVM jar-reading, class-loading), which vary between runs. Also, the dual-classloader problem meant `InflateCounters.reset()` in Guidance touched a different class instance than the one instrumented code incremented.
- New approach: Only jose4j's `decompress()` is instrumented. Single classloader for both InflateCounters users. Signals are deterministic.

##### 3. `MANIFEST.MF` — Removed `Boot-Class-Path`

No longer needed since we're not instrumenting JDK classes. `InflateCounters` lives on the app classloader, visible to both the instrumented jose4j class and the Guidance.

##### 4. `launch.json` — Removed agent args

`"args": "target/v1-measure-agent.jar"` was needed for the old `resolveAgentJar()` bootstrap logic. No longer needed.

##### 5. `run.sh` — Simplified `-javaagent` flag

Changed from `-javaagent:"${AGENT_JAR}=${AGENT_JAR}"` to `-javaagent:"${AGENT_JAR}"`.

##### 6. Comment updates in `InflateCounters.java` and `V1Guidance.java`

Updated documentation to reflect the new instrumentation target.

## Validation repair 3

The issue is clear: the guidance plan still references `[Inflater]` as the instrumented class, but the agent now rewrites `DeflateRFC1951CompressionAlgorithm`. I need to update the guidance plan to match the actual instrumentation.

Let me verify the current state of everything to make sure the code itself is correct (signals are working - 28 distinct values for inflatedBytes is good):

```text
Read <run_dir>/src/test/java/org/jose4j/fuzz/agent/InflaterTransformer.java
Read <run_dir>/src/test/java/org/jose4j/fuzz/agent/V1MeasureAgent.java
Read <run_dir>/src/test/java/org/jose4j/fuzz/guidance/V1Guidance.java
Read <run_dir>/analysis/launch.json
```

The code is all correct — the agent instruments `DeflateRFC1951CompressionAlgorithm.decompress`, and the validation confirms it works (28 distinct inflatedBytes values, deterministic). The only failing check is the **plan mismatch**: the plan says `[Inflater]` but the agent rewrites `DeflateRFC1951CompressionAlgorithm`.

No code changes needed — just a corrected guidance plan:

#### Summary

The only failure is `instrumentation: the plan instruments [Inflater], but the javaagent rewrote [org.jose4j.zip.DeflateRFC1951CompressionAlgorithm] and none of them`. The code is working correctly (28 distinct signal values, deterministic). The guidance plan needs to be updated to match the actual instrumentation target.

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "inflatedBytes",
          "quantity": "total decompressed output bytes from DeflateRFC1951CompressionAlgorithm.decompress()",
          "aggregation": "sum",
          "locations": ["DeflateRFC1951CompressionAlgorithm#decompress"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in InflateCounters (index 0)",
          "reset": "InflateCounters.reset() called in V1Guidance.getInput() before each execution",
          "read": "InflateCounters.get() called in V1Guidance.handleResult()"
        },
        {
          "name": "inflateCallCount",
          "quantity": "number of decompress() calls per execution",
          "aggregation": "count",
          "locations": ["DeflateRFC1951CompressionAlgorithm#decompress"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in InflateCounters (index 1)",
          "reset": "InflateCounters.reset() called in V1Guidance.getInput() before each execution",
          "read": "InflateCounters.get() called in V1Guidance.handleResult()"
        }
      ],
      "retention": "Hill-climbing: retain inputs that achieve a new best inflatedBytes or a new maximum plaintext length; corpus capped at 32 entries, evicting the lowest-signal entry when full",
      "retention_signals": ["inflatedBytes"],
      "mutation": [
        "whole-input doubling (repetition [R45a]): doubles the plaintext to maximize compressibility and decompression output growth",
        "chunk repeat (repetition [R45a]): selects a random chunk and repeats it k times (k in 2..32)",
        "dictionary token insertion ([R45b]): inserts tokens from the attack path (0x00, 0x01, 0x03, 0x78, 0xFF, DEF, zip, alg, enc)",
        "byte-level random insert: inserts 1-4 random bytes at a random position",
        "byte-level bit flip: flips a random bit",
        "byte-level random replace: replaces 1-4 bytes at a random position",
        "DEFLATE encoder ([R45c]): all mutations operate on plaintext, then compress via Deflater(BEST_COMPRESSION, true) to produce valid raw DEFLATE streams that jose4j will accept"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON
