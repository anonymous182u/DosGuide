# bc-java_GHSA-m44j-cfrm-g8qc

## Block 1

I'll start by reading the fuzz test harness and the main source file to understand the entry points and potential vulnerabilities.

```text
Read <run_dir>
Glob <run_dir> **/FuzzTest*.java
Glob <run_dir> **/*
Read <run_dir>/src/test/java/com/fuzzer/harness/Ed25519FuzzTest.java
Read <run_dir>/pom.xml
Read <run_dir>/analysis/run_config.json
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me read the Ed25519 source code to understand the vulnerability:

```text
Read <source_root>/core/src/main/java/org/bouncycastle/math/ec/rfc8032/Ed25519.java
```

Let me explore the supporting classes to understand the full verification path:

```text
Glob <source_root> **/Scalar25519.java
Glob <source_root> **/Wnaf.java
Glob <source_root> **/X25519Field.java
Read <source_root>/core/src/main/java/org/bouncycastle/math/ec/rfc8032/Scalar25519.java
Read <source_root>/core/src/main/java/org/bouncycastle/math/ec/rfc8032/Wnaf.java
```

Let me look at ScalarUtil since `reduceBasisVar` calls it in a while loop:

```text
Glob <source_root> **/ScalarUtil.java
Read <source_root>/core/src/main/java/org/bouncycastle/math/ec/rfc8032/ScalarUtil.java
```

Now let me examine X25519Field for the key field operations called during verification:

```text
Read <source_root>/core/src/main/java/org/bouncycastle/math/ec/rfc7748/X25519Field.java
```

Let me look at the SHA512Digest and Mod classes:

```text
Glob <source_root> **/SHA512Digest.java
Glob <source_root> **/raw/Mod.java
Glob <source_root> **/raw/Nat256.java
Read <source_root>/core/src/main/java/org/bouncycastle/math/raw/Mod.java
```

Now I have a thorough understanding of the code. Let me look at the Nat256 class for the square operation used in `reduceBasisVar`:

```text
Read <source_root>/core/src/main/java/org/bouncycastle/math/raw/Nat256.java
```

Now I have a comprehensive understanding of the code. Let me create the scale measurement inputs. First, let me set up the directories:

```text
$ mkdir -p <run_dir>/analysis/scale/V1
```

Now let me create the scale measurement inputs using a Python script. The inputs need to be valid enough to pass the early checks and reach `reduceBasisVar`. I'll use the Ed25519 base point encoding for both R and A, with S=1 as the scalar, and varying message lengths:

```text
$ python3 -I -c ' …
```

Let me verify the files were created correctly:

```text
$ ls -la <run_dir>/analysis/scale/V1/
Read <run_dir>/analysis/scale/V1/series.json
```

Good. Now let me complete the full analysis.

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

**V1: `Scalar25519.reduceBasisVar` Unbounded Loop (CVE-2024-29857)**

**Entrypoint & user-controlled inputs:**
- `Ed25519.verify(sig, 0, pk, 0, msg, 0, msg.length)` is the public API.
- The fuzz test provides the full input as `InputStream`: bytes 0–63 = signature (R ‖ S), bytes 64–95 = public key (A), bytes 96+ = message (m).
- All three components (sig, pk, msg) are fully attacker-controlled.

**Call path to sink:**
1. `Ed25519.verify(byte[], int, byte[], int, byte[], int, int)` delegates to `implVerify`
2. `implVerify` validates R, S, A encodings, decodes points, computes `k = reduce512(SHA512(R ‖ A ‖ m))`
3. `Scalar25519.decode(k, nA)` converts to integer array
4. **`Scalar25519.reduceBasisVar(nA, v0, v1)`** — the sink

**Mechanism:**
The `reduceBasisVar` method implements a lattice basis reduction (Pornin's algorithm from https://ia.cr/2020/454). It has a while loop `while (len_Nv > TARGET_LENGTH)` where `TARGET_LENGTH = 254`. The algorithm operates on 16-word arrays (`Nu`, `Nv`, `p`), but the `last` variable that controls the processing range of `addShifted_NP`/`subShifted_NP`/`lessThan` is only updated when a swap occurs: `last = len_Nv >>> 5`. If the arithmetic operations (`addShifted_NP`/`subShifted_NP`) produce carries that propagate beyond index `last`, those carries are silently dropped. This corrupts the mathematical invariants of the reduction, causing the algorithm to either:
- Oscillate without making progress (never reducing `Nv` below 254 bits)
- Make extremely slow progress (one bit at a time or less)

The scalar `nA` is derived from `SHA-512(R ‖ A ‖ m)` reduced modulo L. For most scalars, the algorithm converges in ~300 iterations. For pathological scalars where the carry truncation bug is triggered, the loop runs indefinitely until the per-execution time limit is reached.

**Exhausted resource:** CPU time — the number of loop iterations in `reduceBasisVar` grows unboundedly for pathological scalar values.

**Failure mode:** `timeout` — a single `Ed25519.verify` call runs longer than the 20,000 ms per-execution time limit.

**Scale:** For normal scalars, `reduceBasisVar` converges in ~300 iterations (microseconds). For pathological scalars, the loop runs indefinitely. The pathological scalars are determined by the hash output `SHA-512(R ‖ A ‖ m)`, not by input size. Any input ≥97 bytes (64 sig + 32 pk + 1 msg) that passes the early validation checks and produces a pathological hash will trigger the timeout. The input must pass: `checkPointVar(R)`, `checkVar(S)`, `checkPointFullVar(A)`, `decodePointVar(R)`, `decodePointVar(A)` — which requires R and A to encode valid Ed25519 curve points and S < L. For random bytes, roughly 25% of inputs pass all checks (50% for each of R and A decoding). The minimum input is 97 bytes; the issue is finding the specific byte combination that produces a pathological hash, not reaching a large input size.

**`input_bytes`:** 97 (minimum valid input that reaches the vulnerability). The fuzzer must explore different sig/pk/msg combinations to find one whose hash triggers the non-converging reduction.

##### 1.2 Official Classification

**V1:** CWE-400 (Uncontrolled Resource Consumption) — specifically, the `reduceBasisVar` loop lacks a proper convergence guarantee for all scalar values, leading to unbounded CPU consumption. Also related to CWE-835 (Loop with Unreachable Exit Condition) since the while loop's exit condition `len_Nv <= TARGET_LENGTH` may never be satisfied for certain inputs. The primary classification is **CWE-835**.

##### 1.3 Dependency / Package-Level Risks

**PkgRisk-1: SHA-512 Digest (`SHA512Digest`)**
- **Package/class:** `org.bouncycastle.crypto.digests.SHA512Digest`
- **Why input-sensitive:** The hash computation is O(message_length). A very long message (up to 10144 bytes = 10240 - 96) requires ~80 SHA-512 blocks.
- **Trigger shapes:** Long messages.
- **Exhausted resource:** CPU time for hashing.
- **Failure mode:** Not a realistic DoS — even 10KB of hashing completes in microseconds.
- **Scale:** ~80 blocks × ~100ns/block ≈ 8µs. Far below the 20s timeout.
- **Fuzzing strategy:** EXCLUDED — CPU cost is negligible and cannot cause timeout within evaluation limits.

**PkgRisk-2: `Mod.modOddInverseVar` (field inversion)**
- **Package/class:** `org.bouncycastle.math.raw.Mod.modOddInverseVar`
- **Why input-sensitive:** Called by `X25519Field.invVar` during point operations. Uses a bounded GCD algorithm with `maxDivsteps = getMaximumDivsteps(bits)` which caps iterations.
- **Trigger shapes:** Any input that reaches point decoding.
- **Exhausted resource:** CPU time.
- **Failure mode:** The iteration count is bounded by `maxDivsteps` (for 255 bits: (49*255+47)/17 ≈ 737). Always terminates quickly.
- **Scale:** ~737 iterations × O(9 words) ≈ microseconds. Cannot cause timeout.
- **Fuzzing strategy:** EXCLUDED — properly bounded, cannot cause DoS.

No other dependency-level risks were identified. The field arithmetic operations (add, mul, sqr, etc.) are all constant-time with no loops dependent on input values. The WNAF computation (`Wnaf.getSignedVar`) operates on fixed-size arrays (256 or 128 bytes). The `scalarMultStraus128Var` loop iterates exactly 128 times. All other loops in the verification path are bounded by constants.

##### IMPORT AUDIT
```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent
```

#### PHASE B — Target Selection

Only V1 qualifies as a DoS target. PkgRisk-1 and PkgRisk-2 are excluded because they cannot cause timeout/OOM/stack overflow within the evaluation limits (both are bounded and complete in microseconds).

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Scalar25519.reduceBasisVar unbounded loop via crafted Ed25519 verification input",
      "entrypoint": "Ed25519FuzzTest.fuzzEd25519Verify(InputStream) → Ed25519.verify(byte[], int, byte[], int, byte[], int, int) → Ed25519.implVerify(byte[], int, byte[], int, byte[], byte, byte[], int, int) → Scalar25519.reduceBasisVar(int[], int[], int[])",
      "source_path": "core/src/main/java/org/bouncycastle/math/ec/rfc8032/Scalar25519.java",
      "sink": "Scalar25519#reduceBasisVar",
      "mechanism": "The while loop 'while (len_Nv > TARGET_LENGTH)' in reduceBasisVar performs lattice basis reduction on a scalar nA derived from SHA-512(R||A||m). The 'last' index variable controls array processing bounds but is only updated on swaps. When addShifted_NP/subShifted_NP produce carries beyond index 'last', carries are silently dropped, corrupting the reduction invariants. For pathological scalar values, this causes the loop to oscillate without converging, running indefinitely.",
      "resource": "CPU time: number of iterations of the while loop in reduceBasisVar; for pathological scalars the iteration count is unbounded",
      "failure_mode": "timeout",
      "scale": "For normal scalars, ~300 loop iterations (microseconds). For pathological scalars where carry truncation corrupts the reduction, the loop runs indefinitely until the 20s timeout. The pathological scalar is determined by SHA-512(R||A||m) mod L, not by input size. Any input ≥97 bytes with valid R,A point encodings and S<L that hashes to a pathological scalar triggers the timeout.",
      "input_bytes": 97,
      "cwe": "CWE-835"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

#### Analysis of Scale Measurements

The measurements confirm that CPU time is **flat at ~14 ms** across all message lengths (1–32 bytes). There is **no growth** with the `message_length` parameter. This is expected: the parameter I varied (message length) does not control the vulnerability mechanism.

**Key observations:**
1. **Base verification cost:** ~14 ms, dominated by elliptic curve point operations (precomputation, point decoding via `sqrtRatioVar`/`invVar`, `scalarMultStraus128Var` with 128 iterations of point additions/doublings).
2. **`reduceBasisVar` contribution for normal scalars:** negligible (a few hundred iterations of lightweight integer ops = microseconds).
3. **No input produced a pathological scalar:** All 6 inputs' hashes yielded scalars where `reduceBasisVar` converges normally.
4. **The vulnerability is binary, not gradual:** Either the scalar triggers the carry-truncation bug (loop runs until timeout = 20,000 ms) or it doesn't (~14 ms). There is no intermediate cost regime that scales with a tunable input parameter.
5. **Message length has no bearing on the mechanism.** The hash is pseudorandom regardless of message size; what matters is the specific bytes of `R || A || m` that produce a pathological scalar mod L.

**Extrapolation:** Since CPU time is constant (~14 ms) regardless of input size, extrapolation to larger inputs is trivial: it stays ~14 ms. The timeout failure requires finding specific byte combinations where `SHA-512(R || A || m) mod L` hits the carry-truncation non-convergence condition — this is a search problem for the fuzzer, not a scaling problem. `input_bytes` = 97 remains the minimum viable input. No denser encoding exists (64 bytes sig + 32 bytes pk + ≥1 byte msg are all structurally required).

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured base verification cost is ~14 ms constant for all input sizes (no growth with message_length; the parameter does not control the mechanism). The vulnerability is binary: the hash SHA-512(R||A||m) mod L either produces a scalar that triggers the carry-truncation bug in reduceBasisVar (loop oscillates indefinitely → timeout at 20,000 ms) or it does not (~14 ms, ~300 loop iterations). The loop cost per iteration is negligible (nanoseconds); the pathology is non-convergence, not per-iteration expense. The fuzzer must search across different sig/pk/msg byte combinations to find one whose hash yields a pathological scalar; any input ≥97 bytes that passes point-validity checks can potentially trigger it.",
    "input_bytes": 97
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by verifying the existing pom.xml and vulnerable jar, then develop the complete measurement strategy.

```text
$ ls -la <run_dir>/lib/
Read <run_dir>/pom.xml
```

Let me verify the vulnerable jar contains the target class and test compilation:

```text
$ jar tf <run_dir>/lib/bcprov-jdk18on-1.75.jar | grep -E "(Scalar25519|Ed25519|ScalarUtil)" | head -10
$ mvn compile 2>&1 | tail -20
$ jar tf <run_dir>/lib/bcprov-jdk18on-1.75.jar | grep -E "rfc8032/(Scalar25519|Ed25519|ScalarUtil)" | head -10
```

Good — all target classes are in the jar. Now let me check the ASM transitive dependency from JQF:

```text
$ mvn dependency:tree -Dscope=test 2>&1 | grep -i asm | head -10
$ mvn dependency:tree 2>&1 | tail -40
```

The pom.xml already correctly references the vulnerable jar. Let me verify the full workspace state:

```text
$ find src -type f 2>/dev/null | sort
```

Good. Now let me re-read the key source files to confirm the exact method signatures for instrumentation:

```text
Read <source_root>/core/src/main/java/org/bouncycastle/math/ec/rfc8032/ScalarUtil.java
Read <source_root>/core/src/main/java/org/bouncycastle/math/ec/rfc8032/Scalar25519.java
```

Now let me verify the exact descriptor of the methods to instrument:

```text
$ javap -p -c -cp <run_dir>/lib/bcprov-jdk18on-1.75.jar org.bouncycastle.math.ec.rfc8032.ScalarUtil 2>&1 | head -30
$ javap -p -cp <run_dir>/lib/bcprov-jdk18on-1.75.jar org.bouncycastle.math.ec.rfc8032.ScalarUtil 2>&1 | grep -E "void (add|sub)Shifted"
```

Now I have all the information needed. The pom.xml is correct as-is — let me verify once more it compiles cleanly:

```text
$ mvn package -DskipTests 2>&1 | tail -15
```

Build succeeds. ASM jars are copied to target/deps. Let me confirm:

```text
$ ls <run_dir>/target/deps/asm*.jar 2>/dev/null
```

The pom.xml is correct as-is — no changes needed. The systemPath resolves to the existing vulnerable jar, all dependencies are present, and ASM (9.8 via jqf-instrument, 9.5 via jacoco) is transitively available for the custom agent. Now I'll produce the complete measurement strategy.

---

#### Step 2 — Maven Layout & Scope

**Production code (src/main/java):** Empty — all target classes come from the system-scoped BC jar (`lib/bcprov-jdk18on-1.75.jar`). No stubs needed.

**Test code (src/test/java):** All fuzzing infrastructure:
- `com.fuzzer.harness.Ed25519FuzzTest` (FROZEN)
- `dosguide.validate.SignalSource` (already present)
- `com.fuzzer.V1Counters` — shared iteration counter (ThreadLocal)
- `com.fuzzer.V1MeasureAgent` — custom Java agent using ASM to instrument ScalarUtil
- `com.fuzzer.V1Guidance` — custom Guidance implementing `Guidance` + `SignalSource`
- `com.fuzzer.FuzzRunner` — CLI runner
- `com.fuzzer.FuzzReplay` — metadata replay feeder

**Scope correctness:** JQF (`jqf-fuzz`, `jqf-instrument`) = test scope. BC jar = system scope. JUnit = test scope. ASM = transitively available via jqf-instrument (test scope).

#### Step 3 — Compilation Closure & Missing Symbol Audit

##### 3.1 Missing Symbol Audit

All symbols used by the fuzz test (`Ed25519FuzzTest`) resolve:
- `org.bouncycastle.math.ec.rfc8032.Ed25519` → in `lib/bcprov-jdk18on-1.75.jar` (system scope)
- `edu.berkeley.cs.jqf.fuzz.Fuzz` → in `jqf-fuzz:2.1` (test scope)
- `edu.berkeley.cs.jqf.fuzz.JQF` → in `jqf-fuzz:2.1` (test scope)
- `org.junit.runner.RunWith` → in `junit:4.13.2` (test scope)

All symbols used by the Guidance/Agent:
- `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` → in `jqf-fuzz:2.1` (test scope) ✓
- `edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException` → in `jqf-fuzz:2.1` (test scope) ✓
- `edu.berkeley.cs.jqf.fuzz.guidance.Result` → in `jqf-fuzz:2.1` (test scope) ✓
- `edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing` → in `jqf-fuzz:2.1` (test scope) ✓
- `org.objectweb.asm.ClassReader` → in `asm:9.8` (transitive via jqf-instrument, test scope) ✓
- `org.objectweb.asm.ClassVisitor` → same ✓
- `org.objectweb.asm.ClassWriter` → same ✓
- `org.objectweb.asm.MethodVisitor` → same ✓
- `org.objectweb.asm.Opcodes` → same ✓
- `dosguide.validate.SignalSource` → in workspace `src/test/java` ✓

**Classification:** All symbols are Category A (external library, resolved via Maven). No Category B (missing internal stubs) needed.

##### 3.2 Stub Generation Rules

**No stubs required.** All symbols resolve from either the vulnerable jar (system scope) or Maven dependencies (test scope).

##### 3.3 Stub Report

No stubs generated. All compilation dependencies are satisfied by:
1. `lib/bcprov-jdk18on-1.75.jar` — Bouncy Castle target classes
2. JQF framework (test scope) — fuzzing infrastructure
3. JUnit 4.13.2 (test scope) — test runner
4. ASM 9.8 (transitive, test scope) — bytecode manipulation for custom agent

#### Step 4 — GuidedFuzzing Usage

```java
ClassLoader cl = Thread.currentThread().getContextClassLoader();
GuidedFuzzing.run("com.fuzzer.Ed25519FuzzTest", methodName, cl, guidance, System.out);
```

The runner (`FuzzRunner`) supports CLI method selection:
```
java ... FuzzRunner V1 [durationSeconds]
```
This selects the `fuzzEd25519Verify` method with V1Guidance.

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|------------------|-------------------------------|------------------------|
| V1     | **Cost-Gradient Guidance (CGF)** | Zest maximizes code coverage. Ed25519.verify executes the same branches for all valid inputs—the while loop in `reduceBasisVar` takes the same branch on every iteration (either `addShifted_NP` or `subShifted_NP`). Coverage cannot distinguish 300 iterations from 300,000,000 iterations because the same code is executed in both cases. Coverage is a **proxy signal** that is orthogonal to the vulnerability. | CGF directly measures the **loop iteration count** inside `reduceBasisVar` via bytecode instrumentation of `ScalarUtil.addShifted_NP`/`subShifted_NP`. It hill-climbs this count, retaining inputs that cause more iterations. This is the **mechanism-aligned signal** (iteration count == vulnerability severity). Expected measurable advantage: **time-to-first-timeout** — CGF finds it by actively optimizing iteration count, while Zest's coverage-guided random walk has no directional pressure toward pathological scalars. |

#### Step 6 — Strategy-Specific Guidance Design

##### Measurement Plan for V1

**Primary Signal: `loopIterations`**

| Aspect | Detail |
|--------|--------|
| **What is measured** | Number of iterations of the `while (len_Nv > TARGET_LENGTH)` loop in `Scalar25519.reduceBasisVar` |
| **Code region** | `ScalarUtil.addShifted_NP(int, int, int[], int[], int[])` and `ScalarUtil.subShifted_NP(int, int, int[], int[], int[])` — each is called exactly once per loop iteration (mutually exclusively) |
| **Why this region** | These two methods constitute the core work of each reduction step. One is called per iteration based on the sign of `p[last]`. Their call count equals the loop iteration count exactly. |
| **Storage** | `V1Counters.ITERATIONS` — a `public static ThreadLocal<long[]>` where `get()[0]` holds the count |
| **Reset** | At the start of `V1Guidance.getInput()`, before each execution: `V1Counters.ITERATIONS.get()[0] = 0` |
| **Read** | In `V1Guidance.handleResult()`: reads `V1Counters.ITERATIONS.get()[0]` and uses it for retention/prioritization |
| **Technique** | Tier 1 (bytecode instrumentation via custom Java agent) |

##### Instrumentation Feasibility Check [R35]

1. **Exact classes/methods to instrument:**
   - Class: `org.bouncycastle.math.ec.rfc8032.ScalarUtil` (internal name: `org/bouncycastle/math/ec/rfc8032/ScalarUtil`)
   - Methods:
     - `addShifted_NP` — descriptor: `(II[I[I[I)V`
     - `subShifted_NP` — descriptor: `(II[I[I[I)V`
   - Confirmed from `javap` output and source code.

2. **Required JVM flags:** None specific. The agent is attached via `-javaagent:target/v1-agent.jar`. The ScalarUtil class is in the system-scope BC jar, which is loaded by the app classloader. No `--add-opens` needed since we're transforming a non-JDK class.

3. **Signal export path (ThreadLocal):**
   - `V1Counters` class has a `public static final ThreadLocal<long[]> ITERATIONS`
   - The agent's `premain` calls `inst.appendToBootstrapClassLoaderSearch(jarFile)` to put `V1Counters` on the bootstrap classpath
   - Both the transformed ScalarUtil (system classloader → delegates to bootstrap) and V1Guidance (test classloader → delegates to bootstrap) reference the same `V1Counters` class instance
   - Thread-safe since JQF runs `getInput()` → test execution → `handleResult()` sequentially in one thread

4. **Minimal agent implementation plan:**
   - `V1MeasureAgent.premain(String, Instrumentation)`:
     1. Resolves the agent jar path via `V1MeasureAgent.class.getProtectionDomain().getCodeSource()`
     2. Calls `inst.appendToBootstrapClassLoaderSearch(new JarFile(path))`
     3. Registers a `ClassFileTransformer`
   - Transformer intercepts `ScalarUtil` class loading
   - Uses ASM `ClassReader` → `ClassVisitor` → `MethodVisitor`
   - For `addShifted_NP` and `subShifted_NP`, injects at method entry:
     ```
     INVOKESTATIC com/fuzzer/V1Counters.increment ()V
     ```
   - `V1Counters.increment()` does: `ITERATIONS.get()[0]++`

##### Signal Legality Contract [R30]

| Criterion | Satisfied? | Justification |
|-----------|-----------|---------------|
| (A) Derived from actual execution | ✅ | The counter increments only when `addShifted_NP`/`subShifted_NP` actually execute inside the JVM |
| (B) Causally linked to vulnerability mechanism | ✅ | These methods are the body of the `reduceBasisVar` while loop — each call = one loop iteration = one unit of the pathological CPU consumption |
| (C) Consumed by `handleResult()` to affect retention | ✅ | `V1Guidance.handleResult()` reads the count and retains inputs with higher iteration counts |

##### Mutation Operators

1. **Byte-level operators:**
   - Random byte flip (1-4 bits in a random byte)
   - Random byte replacement (replace 1-8 bytes with random values)
   - Random byte insertion (insert 1-16 random bytes at a random position)
   - Random byte deletion (delete 1-8 bytes)

2. **Repetition [R45(a)]:**
   - Select a random chunk of the input (4-64 bytes)
   - Repeat it k times (k = 1..64), up to the input size limit (10240)
   - Also: whole-input doubling (copy entire input and append)
   - This grows inputs from the initial 97 bytes toward 10240 within the first minute

3. **Dictionary [R45(b)]:** Single syntactic tokens from the Ed25519 verification code path:
   - `0x58` — first byte of base point y-coordinate encoding
   - `0x66` — repeated byte in base point y-coordinate
   - `0xED` — low byte of prime p = 2^255 − 19 (LE)
   - `0xFF` — max byte, common in field elements near p
   - `0x7F` — mask for last byte in checkPointVar
   - `0x80` — sign bit in point encoding's last byte
   - `0x00` — zero byte, important for valid scalar S upper bytes
   - `0x10` — boundary value for S[31] (L ≈ 2^252.7)
   - `0x01` — one, identity/base values

4. **No encoder needed [R45(c)]:** Ed25519.verify accepts raw bytes directly — no compression, checksums, or length-prefixed encoding. Inputs are split mechanically (bytes 0-63=sig, 64-95=pk, 96+=msg) with no format validation beyond curve-point decoding.

##### Retention Policy

**Primary signal: `loopIterations`**
- Retain any input whose iteration count exceeds the current best seen
- Maintain a corpus of top-k inputs by iteration count (k=64)

**Secondary criteria when signal is flat [R46]:**
- All initial inputs produce ~300 iterations (normal convergence). The Guidance must still make progress:
  - **Diversity:** Keep inputs with distinct iteration counts (even 295 vs 310 vs 330 — small differences may indicate proximity to pathological values)
  - **Validity:** Prefer inputs where `loopIterations > 0` (meaning the input reached `reduceBasisVar`). Inputs with 0 iterations failed early checks; keep a few to mutate toward validity
  - **Length growth:** Keep growing inputs (growing the message portion) to explore more hash space. The repetition operator grows inputs from 97 to 10240 bytes, with the Guidance accepting longer inputs even if the signal is flat

**Stop/continue:** Infinite by default; time-bounded via `jqf.ei.TIMEOUT` system property or CLI argument.

#### Step 7 — Custom Guidance (V1Guidance, design only)

`V1Guidance` implements `Guidance` and `SignalSource` directly (not extending/delegating any existing guidance). It:
- Provides inputs via `getInput()` returning a `ByteArrayInputStream`
- Receives results via `handleResult(Result)`
- Returns `true` from `hasInput()` until time budget exhausted
- Returns signal map from `lastSignals()`: `{"loopIterations": <count>}`
- Logs stats every 1 second: executions, max iterations seen, corpus size
- Never writes failure files or decides execution failed [R6]
- Corpus directory: `out/V1/corpus`

#### Step 8 — Fuzz Test

The FROZEN harness `Ed25519FuzzTest.fuzzEd25519Verify(InputStream)` is the sole fuzz method. It consumes `InputStream`, splits bytes into sig/pk/msg, and calls `Ed25519.verify`. No generators needed. No new fuzz test class needed.

#### Step 9 — Metadata Replay / Feeder

`FuzzReplay` reads saved input files from `out/V1/corpus/`, replays each through `Ed25519FuzzTest.fuzzEd25519Verify()` deterministically, and prints:
- Input file path
- Input length
- Hex dump of sig, pk, msg portions
- Whether `verify` returned true/false or threw

#### Step 10 — Maven Configuration

**pom.xml:** No changes needed — the existing pom.xml is correct. Verified:
- System-scoped BC jar resolves ✓
- JQF 2.1 + junit-quickcheck 1.0 versions match ✓
- ASM 9.8 available transitively ✓
- maven-dependency-plugin copies all deps to `target/deps/` ✓

**Directory layout:**
```
src/test/java/
  com/fuzzer/
    harness/Ed25519FuzzTest.java   (FROZEN)
    V1Counters.java                (shared counter, ThreadLocal)
    V1MeasureAgent.java            (premain + ASM transformer)
    V1Guidance.java                (custom Guidance + SignalSource)
    FuzzRunner.java                (CLI runner)
    FuzzReplay.java                (replay feeder)
  dosguide/validate/
    SignalSource.java              (already present)
lib/
  bcprov-jdk18on-1.75.jar         (vulnerable BC jar)
pom.xml                            (no changes)
build-agent.sh                     (builds agent jar after mvn package)
```

**Build commands:**
```bash
### Compile everything
mvn package -DskipTests

### Build the agent jar (merges agent classes + ASM into self-contained jar)
bash build-agent.sh

### Fuzz (V1, time-bounded 300 seconds)
java -Xmx1g -Xss1m -javaagent:target/v1-agent.jar \
  -Djqf.ei.MAX_INPUT_SIZE=10240 \
  -cp target/test-classes:target/deps/*:lib/bcprov-jdk18on-1.75.jar \
  com.fuzzer.FuzzRunner V1 300

### Replay
java -Xmx1g -Xss1m \
  -cp target/test-classes:target/deps/*:lib/bcprov-jdk18on-1.75.jar \
  com.fuzzer.FuzzReplay out/V1/corpus
```

#### Zest Baseline Comparison [R18]

| Aspect | Zest | V1Guidance (CGF) |
|--------|------|------------------|
| **Signal** | Branch coverage (proxy) | Loop iteration count in `reduceBasisVar` (mechanism-aligned) |
| **Why it works/fails** | Ed25519.verify has ~10 branches total; coverage saturates in <100 executions. After saturation, Zest retains random inputs with no directional pressure toward pathological scalars. The vulnerability is entirely invisible to coverage. | Measures the exact quantity that grows unboundedly for the vulnerability. Small increases (310 vs 300 iterations) indicate the scalar is "closer" to pathological. Hill-climbing this signal provides directional pressure. |
| **Expected metric advantage** | Baseline: may never find timeout within campaign | Time-to-first-bug: expected orders of magnitude faster via directed search |

#### IMPORT AUDIT

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
SignalSource → dosguide.validate.SignalSource
ClassReader → org.objectweb.asm.ClassReader
ClassVisitor → org.objectweb.asm.ClassVisitor
ClassWriter → org.objectweb.asm.ClassWriter
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
```

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — all code targets Java 17
- [YES] No hallucinated APIs — all JQF/ASM APIs verified against dependency tree
- [YES] Guidance implements Guidance directly — V1Guidance implements `Guidance` + `SignalSource`
- [YES] No existing guidance extended — no Zest/PerfFuzz delegation
- [YES] V* vulnerabilities identified — V1 (reduceBasisVar unbounded loop)
- [YES] V* IDs are sequential — V1 only, sequential
- [YES] Official vulnerability names — CWE-835 (Loop with Unreachable Exit Condition)
- [YES] PkgRisk-* identified — PkgRisk-1 (SHA-512), PkgRisk-2 (modular inverse), both excluded as non-DoS
- [YES] Every PkgRisk-* justified — both complete in microseconds, cannot cause timeout/OOM/SOE
- [YES] Guidance targets V1 — V1Guidance targets reduceBasisVar loop
- [YES] One fuzz method per target — `fuzzEd25519Verify` for V1
- [YES] CLI method selection — FuzzRunner accepts target ID
- [YES] byte[]/InputStream input model — harness reads InputStream, Guidance provides ByteArrayInputStream
- [YES] No junit-quickcheck Generators — all mutation in Guidance
- [YES] All mutation inside Guidance — byte-level + repetition + dictionary
- [YES] Repetition, dictionary, encoder per [R45] — repetition grows to 10240; dictionary of 9 tokens from source; no encoder needed (raw bytes)
- [YES] Retention progresses while flat [R46] — diversity + length growth + validity preference
- [YES] Signals measured at sink [R47] — ScalarUtil.addShifted_NP/subShifted_NP inside reduceBasisVar loop
- [YES] Logging every 1 second — V1Guidance logs stats per second
- [YES] Guidance decides no failures, writes no failure files [R6] — handleResult only updates corpus/stats
- [YES] Corrupted inputs saved with metadata — corpus saves input bytes + iteration count
- [YES] Replay/feeder implemented — FuzzReplay class
- [YES] Infinite + time-bounded supported — default infinite, CLI/sysprop for duration
- [YES] src/main vs src/test separation — all fuzzing infra in src/test/java
- [YES] Maven scopes consistent — BC=system, JQF/JUnit=test
- [YES] No wildcard imports for JQF/tracing — explicit imports only
- [YES] TraceEvent import audited — not used (custom agent instead)

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "loopIterations",
          "quantity": "number of iterations of the while loop in Scalar25519.reduceBasisVar, counted as calls to ScalarUtil.addShifted_NP plus ScalarUtil.subShifted_NP (exactly one per iteration)",
          "aggregation": "sum",
          "locations": ["ScalarUtil#addShifted_NP", "ScalarUtil#subShifted_NP"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in V1Counters.ITERATIONS, index 0 holds the count",
          "reset": "V1Guidance.getInput() sets V1Counters.ITERATIONS.get()[0] = 0 before each execution",
          "read": "V1Guidance.handleResult() reads V1Counters.ITERATIONS.get()[0] and uses it for retention and prioritization"
        }
      ],
      "retention": "Primary: retain inputs with loopIterations exceeding any previously seen value (hill-climb). Secondary (flat signal): retain inputs that reach reduceBasisVar (iterations > 0) with diverse iteration counts, and growing inputs that approach 10240 bytes to explore more hash space. Keep a corpus of top-64 inputs by iteration count.",
      "retention_signals": ["loopIterations"],
      "mutation": [
        "byte-level: random byte flip (1-4 bits), random byte replacement (1-8 bytes), random byte insertion (1-16 bytes), random byte deletion (1-8 bytes)",
        "repetition [R45(a)]: copy a random 4-64 byte chunk and repeat it k times (k up to input_size_limit / chunk_size), also whole-input doubling; grows from 97 to 10240 bytes within first minute",
        "dictionary [R45(b)]: single-byte tokens from Ed25519 verification code path: 0x58 (base point y[0]), 0x66 (base point y repeated byte), 0xED (low byte of prime p LE), 0xFF (max byte, near-p values), 0x7F (high-bit mask in checkPointVar), 0x80 (sign bit in point encoding), 0x00 (zero, valid scalar high bytes), 0x10 (boundary for S[31] near group order), 0x01 (identity/one values); inserted or overwritten at random positions",
        "no encoder needed [R45(c)]: Ed25519.verify accepts raw bytes with no compression/checksum/length-prefix format; inputs are split mechanically by fixed offsets"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

I'll implement all files now. Let me start by verifying the existing workspace state and then emit all implementation files.

```text
$ ls -la <run_dir>/src/test/java/com/fuzzer/harness/
$ ls -la <run_dir>/lib/
Read <run_dir>/src/test/java/com/fuzzer/harness/Ed25519FuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Let me check the JQF Guidance interface and Result class:

```text
$ jar tf <run_dir>/target/deps/jqf-fuzz-2.1.jar | grep -E "(Guidance|Result|GuidedFuzzing)" | head -20
$ javap -public -cp target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1
$ javap -public -cp target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ javap -public -cp target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1
$ javap -public -cp target/deps/jqf-instrument-2.1.jar edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent 2>&1
```

Good. Now I have all the API signatures. Let me create all the files. I'll start with the agent components:

```text
Write <run_dir>/src/test/java/com/fuzzer/V1Counters.java
Write <run_dir>/src/test/java/com/fuzzer/V1MeasureAgent.java
```

Now the V1Guidance class:

```text
Write <run_dir>/src/test/java/com/fuzzer/V1Guidance.java
```

Let me check current state of the workspace and then continue writing the remaining files.

```text
$ find <run_dir> -type f | sort
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/com/fuzzer/harness/Ed25519FuzzTest.java
Read <run_dir>/analysis/run_config.json
Read <run_dir>/analysis/guidance_plan.json
Read <run_dir>/analysis/target_register.json
```

Now I'll write all remaining files. Let me emit FuzzRunner.java, FuzzReplay.java, build-agent.sh, run.sh, and analysis/launch.json.

```text
Write <run_dir>/src/test/java/com/fuzzer/FuzzRunner.java
Write <run_dir>/src/test/java/com/fuzzer/FuzzReplay.java
Write <run_dir>/build-agent.sh
Write <run_dir>/run.sh
```

Now let me fix the FuzzRunner - I need to verify the GuidedFuzzing API signature:

```text
$ jar tf target/deps/jqf-fuzz-2.1.jar | grep GuidedFuzzing
$ javap -classpath target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1 | head -40
```

Good - it returns `org.junit.runner.Result`, not `edu.berkeley.cs.jqf.fuzz.guidance.Result`. Let me fix both FuzzRunner and FuzzReplay:

```text
Edit <run_dir>/src/test/java/com/fuzzer/FuzzRunner.java
Edit <run_dir>/src/test/java/com/fuzzer/FuzzRunner.java
Edit <run_dir>/src/test/java/com/fuzzer/FuzzReplay.java
Edit <run_dir>/src/test/java/com/fuzzer/FuzzReplay.java
```

Good - already removed. Now fix the `Result` usage in FuzzReplay:

```text
Edit <run_dir>/src/test/java/com/fuzzer/FuzzReplay.java
Edit <run_dir>/src/test/java/com/fuzzer/FuzzReplay.java
```

Now I also need to fix the handleResult in V1Guidance to use the correct Result type. Let me check:

```text
$ javap -classpath target/deps/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1 | head -20
$ jar tf target/deps/jqf-fuzz-2.1.jar | grep "guidance/Result"
```

Good - the `Guidance.handleResult()` does use `edu.berkeley.cs.jqf.fuzz.guidance.Result`. V1Guidance is correct. For FuzzReplay, I used the fully qualified name which works. Now let me make the shell scripts executable and write the launch.json:

```text
$ chmod +x <run_dir>/build-agent.sh <run_dir>/run.sh
Write <run_dir>/analysis/launch.json
```

Now let me compile to verify everything is correct:

```text
$ mvn package -DskipTests 2>&1 | tail -30
```

BUILD SUCCESS. Now let me verify the compiled classes exist and build the agent jar:

```text
$ ls -la target/test-classes/com/fuzzer/
$ bash build-agent.sh 2>&1 | tail -20
```

All classes compiled and the agent jar is built. Let me verify the agent jar is complete:

```text
$ jar tf target/v1-measure-agent.jar | grep -E "(V1|MANIFEST|fuzzer)" | sort
```

Now let me verify artifact provenance — confirming the BC jar is from the vulnerable local copy, not from Maven Central:

```text
$ ls -la lib/bcprov-jdk18on-1.75.jar && unzip -p lib/bcprov-jdk18on-1.75.jar META-INF/MANIFEST.MF | head -10
$ jar tf lib/bcprov-jdk18on-1.75.jar | grep -c "Scalar25519" && jar tf lib/bcprov-jdk18on-1.75.jar | grep "ScalarUtil"
```

Good. The vulnerable jar contains both `Scalar25519` and `ScalarUtil` classes. Let me also verify that the classpath setup in run.sh will use this local jar rather than one from Maven Central. Let me also create a small validation input directory:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
```

Now let me create a small Java helper that prints the code source of the key classes, to be used for artifact verification during the validation phase:

```text
Write <run_dir>/src/test/java/com/fuzzer/VerifyArtifact.java
$ mvn package -DskipTests 2>&1 | tail -5
```

Let me do a final listing of all files to confirm completeness:

```text
$ echo "=== Source Files ===" && find src -name "*.java" -type f | sort && echo "" && echo "=== Shell Scripts ===" && ls -la *.sh && echo "" && echo "=== Analysis Files ===" && find analysis -name "*.json" -type f | sort && echo "" && echo "=== Build Artifacts ===" && ls -la target/v1-measure-agent.ja …
```

All files are compiled and the agent jar is built. Let me do a final review of each key file's contents to confirm correctness:

```text
Read <run_dir>/src/test/java/com/fuzzer/FuzzRunner.java
Read <run_dir>/src/test/java/com/fuzzer/FuzzReplay.java
```

All Block 3 implementation files are complete. Here's the summary of what was delivered:

##### Block 3 — Implementation Files

**Part A — Agent (bytecode instrumentation):**
| File | Description |
|---|---|
| `src/test/java/com/fuzzer/V1Counters.java` | ThreadLocal iteration counter shared via bootstrap classpath |
| `src/test/java/com/fuzzer/V1MeasureAgent.java` | ASM 9.8 Java agent that instruments `ScalarUtil.addShifted_NP` and `subShifted_NP` at method entry |

**Part B — Guidance:**
| File | Description |
|---|---|
| `src/test/java/com/fuzzer/V1Guidance.java` | Custom `Guidance` + `SignalSource` implementing Cost-Gradient Fuzzing. Signal: `loopIterations`. Mutation: byte flip/replace/insert/delete + chunk repetition [R45(a)] + dictionary tokens [R45(b)]. Retention: hill-climb on max iterations + diversity. Never marks failures [R6]. Logs every 1s [R5]. |

**Part C — Runner / Replay / Scripts:**
| File | Description |
|---|---|
| `src/test/java/com/fuzzer/FuzzRunner.java` | CLI runner with `createGuidance(String, File, long, PrintStream)` factory. Dispatches by targetId to JQF `GuidedFuzzing.run()`. |
| `src/test/java/com/fuzzer/FuzzReplay.java` | Single-input replay feeder implementing `Guidance` + `SignalSource`. Prints `loopIterations`, elapsed time, and signal map. |
| `src/test/java/com/fuzzer/VerifyArtifact.java` | Prints `CodeSource` location of BC classes to verify vulnerable jar provenance. |
| `build-agent.sh` | Builds `target/v1-measure-agent.jar` containing V1MeasureAgent + V1Counters + ASM classes + Premain-Class manifest. |
| `run.sh` | End-to-end: `mvn package -DskipTests` → `build-agent.sh` → launch with `-javaagent`, `-Xmx1g -Xss1m`, `MAX_INPUT_SIZE=10240`. |

**Part D — Validation contract:**
| File | Description |
|---|---|
| `analysis/launch.json` | Build commands, classpath layout, agent flag, factory class/method, per-target config (signal names, instrumented methods, limits, corpus dir). |

**Build verification:** `mvn package -DskipTests` → **BUILD SUCCESS**. Agent jar built (131 KB) with all required classes. All 10 `.class` files present in `target/test-classes/com/fuzzer/`.

## Validation repair 1

Let me first read the current launch.json and understand the exact format needed, then fix it.

```text
Read <run_dir>/analysis/launch.json
```

Now let me build the correct classpath string by listing all dependencies:

```text
$ CP="target/test-classes:lib/bcprov-jdk18on-1.75.jar"; for jar in target/deps/*.jar; do base=$(basename "$jar"); case "$base" in bcprov-*) continue ;; esac; CP="$CP:$jar"; done; echo "$CP"
```

Now rewrite launch.json in the correct format:

```text
Write <run_dir>/analysis/launch.json
```

Now let me verify the build still succeeds after no code changes:

```text
$ mvn package -DskipTests -q 2>&1 | tail -10
```

Clean build (no output = success with `-q`). Let me also verify the agent jar rebuild works:

```text
$ bash build-agent.sh 2>&1 | tail -10
```

Good. Let me also do a final check on the launch.json to make sure it's valid JSON:

```text
$ python3 -m json.tool analysis/launch.json > /dev/null && echo "Valid JSON"
```

**Summary of changes:**

Fixed `analysis/launch.json` to match the expected schema:

1. **`classpath`**: Changed from a dict (`{"test_classes": ..., "vulnerable_jar": ..., "deps_dir": ...}`) to a single colon-separated string with all classpath entries listed explicitly.

2. **`guidance_factory`**: Changed from a dict (`{"class": ..., "method": ..., "signature": ...}`) to the simple string format `"com.fuzzer.FuzzRunner#createGuidance"`.

3. **`targets`**: Changed from an array of objects to a map keyed by target ID: `{"V1": {"test_class": "com.fuzzer.Ed25519FuzzTest", "method": "fuzzEd25519Verify"}}`.

4. **`javaagent`**: Renamed from `"agent"` to `"javaagent"` with the expected `{"jar": "...", "args": "..."}` structure.

No code changes were needed — the Java files (V1Counters, V1MeasureAgent, V1Guidance, FuzzRunner, FuzzReplay, Ed25519FuzzTest) and build scripts were already correct. The guidance plan does not need revision.
