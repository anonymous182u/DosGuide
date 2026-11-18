# xnio_GHSA-7f88-5hhx-67m2

## Block 1

I'll start by reading the frozen fuzz test harness and the target source file to understand the vulnerability surface.

```text
Read <run_dir>
Glob <run_dir> **/*FuzzTest*.java
Read <source_root>/api/src/main/java/org/xnio/AbstractIoFuture.java
```

Now let me read the fuzz test harness and the existing pom.xml, and explore the source code more deeply.

```text
Read <run_dir>/src/test/java/org/xnio/fuzz/XnioFuzzTest.java
Glob <run_dir> pom.xml
Glob <source_root>/api/src/main/java/org/xnio **/*.java
```

Now let me read the pom.xml and the RegistrationInput helper class referenced by the fuzz test.

```text
Read <run_dir>/pom.xml
Glob <run_dir> **/RegistrationInput.java
Read <source_root>/api/src/main/java/org/xnio/FutureResult.java
Read <run_dir>/src/test/java/org/xnio/fuzz/RegistrationInput.java
Read <source_root>/api/src/main/java/org/xnio/IoFuture.java
```

Let me check the lib directory and explore more of the critical paths.

```text
$ ls -la <run_dir>/lib/ 2>&1
Glob <run_dir> **/*.java
Read <source_root>/api/src/main/java/org/xnio/IoUtils.java
```

Let me check the SignalSource file and verify the directExecutor method:

```text
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Grep <source_root>/api/src/main/java/org/xnio/IoUtils.java directExecutor
```

Now I have a complete understanding of the vulnerability. Let me also check the `Xnio.checkBlockingAllowed()` to make sure it doesn't interfere:

```text
Grep <source_root>/api/src/main/java/org/xnio/Xnio.java checkBlockingAllowed
```

Good. The `checkBlockingAllowed` is only on the `await()` path, not on `setResult()` or `cancel()`, so it doesn't interfere. Now let me create the scale measurement data files.

```text
$ mkdir -p <run_dir>/analysis/scale/V1 <run_dir>/analysis/scale/V2
```

Now let me generate the binary scale measurement inputs. Each input is N bytes of 0xFF (every byte has the high bit set, so each byte triggers one registration).

```text
$ cd <run_dir> …
```

Now write the series.json files:

```text
Write <run_dir>/analysis/scale/V1/series.json
Write <run_dir>/analysis/scale/V2/series.json
```

Now let me verify the workspace structure is correct:

```text
$ find <run_dir>/analysis -type f | sort
```

Good. All files are in place. Now let me compile the complete analysis.

---

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: Recursive notifyDone chain in AbstractIoFuture (addNotifier + setResult path)

**Fuzzable entrypoint**: `XnioFuzzTest.fuzzIoFutureAddNotifier(InputStream)` — the input stream controls how many notifiers are registered on the future via `RegistrationInput.addNotifiers()`. Each byte with its high bit set (value ≥ 128) triggers one call to `IoFuture.addNotifier()`.

**User-controlled input**: The byte stream length and content. Each registration byte adds one `NotifierState` wrapper around the current state, forming a singly-linked list chain.

**Mechanism**: 
1. `addNotifier()` (AbstractIoFuture line 566–572) wraps the current state in a new `NotifierState` via `State.withNotifier()`, creating a linked chain: `NotifierState(NotifierState(...NotifierState(InitialState)...))`.
2. When `FutureResult.setResult("done")` is called, `AbstractIoFuture.setResult()` (line 605–621) CAS-replaces the state with `CompleteState`, then calls `oldState.notifyDone(this, result)` on the old chain head.
3. `NotifierState.notifyDone()` (line 247–249) calls `doNotify(future)` (which invokes the notifier inline via `directExecutor`), then calls `next.notifyDone(future, result)` — a recursive call to the next state in the chain.
4. The recursion depth equals the number of registered notifiers.

**Exhausted resource**: Stack depth — one `notifyDone` stack frame per `NotifierState` in the chain, plus temporary frames from `doNotify → runNotifier → directExecutor.execute → NotifierRunnable.run → notifier.notify` at each level (these unwind before the next recursive call).

**Failure mode**: `stack_overflow` — `StackOverflowError` when the recursive chain walk exhausts the thread stack.

**Scale estimate**: With `-Xss1m` (1,048,576 bytes), each `notifyDone` frame holds `this` + `future` + `result` (3 references = 24 bytes) plus JVM frame overhead (return address, frame pointer, locals table metadata). Conservatively ~200 bytes per frame. ~5,000 recursion levels would overflow the stack. Each registration byte adds one level; densest encoding is all-0xFF bytes, so ~5,000 bytes of input. Well within the 65,536-byte input size limit.

###### V2: Recursive cancel chain in AbstractIoFuture (addCancelHandler + cancel path)

**Fuzzable entrypoint**: `XnioFuzzTest.fuzzFutureResultAddCancelHandler(InputStream)` — same byte encoding; each registration byte calls `FutureResult.addCancelHandler()`.

**User-controlled input**: Same as V1 — byte stream length and content.

**Mechanism**:
1. `addCancelHandler()` (AbstractIoFuture line 670–684) wraps the current state in a new `CancellableState` via `State.withCancelHandler()`, forming a chain: `CancellableState(CancellableState(...CancellableState(InitialState)...))`.
2. When `cancel()` is called (AbstractIoFuture line 654–662), it CAS-replaces the state with `CancelRequestedState(state)` and then calls `state.cancel()` on the old chain head.
3. `CancellableState.cancel()` (line 337–342) calls `cancellable.cancel()` (no-op in the fuzz test), then `next.cancel()` — a recursive call.
4. The recursion depth equals the number of registered cancel handlers.

**Exhausted resource**: Stack depth — one `cancel` stack frame per `CancellableState` in the chain. Each frame holds `this` plus try-catch overhead.

**Failure mode**: `stack_overflow` — `StackOverflowError`.

**Scale estimate**: Each `cancel()` frame is slightly smaller (fewer parameters) — ~150–200 bytes. ~5,000–7,000 recursion levels to overflow. Dense encoding: all-0xFF bytes, so ~5,000–7,000 bytes of input.

##### 1.2 Official Classification

- **V1**: CWE-674 (Uncontrolled Recursion). The `notifyDone()` method recurses through the state chain without depth control. This is also categorized under GHSA-7f88-5hhx-67m2.
- **V2**: CWE-674 (Uncontrolled Recursion). The `cancel()` method recurses through the state chain without depth control. Same advisory.

##### 1.3 Dependency / Package-Level Risks

The attack paths use only:
- `IoUtils.directExecutor()` — a trivial inline executor (JDK `Executor` interface)
- `LockSupport.unpark()` — JDK standard
- `AtomicReference.compareAndSet()` — JDK standard
- `org.xnio._private.Messages` — XNIO internal logging

None of these dependencies exhibit input-sensitive resource consumption on the attack path. The vulnerability is entirely in AbstractIoFuture's own recursive state-chain walking pattern.

**No PkgRisk items identified.** All relevant amplification is internal to the project's own code.

##### 1.4 Zest Baseline Comparison (R18)

**V1 (notifyDone recursion)**: Zest uses coverage as its proxy signal. Since `addNotifier()` exercises the same code path (same branch in the CAS loop) regardless of how many notifiers are registered, coverage saturates after just 1–2 registrations. Zest has no reason to retain inputs with more notifiers — it sees no new coverage from registering the 100th notifier versus the 2nd. A custom guidance measuring stack depth (recursion depth) at the `notifyDone` sink will retain inputs that push the recursion deeper, reaching the ~5,000-level threshold that triggers StackOverflowError.

**V2 (cancel recursion)**: Same reasoning. Coverage saturates immediately; Zest cannot discover that 5,000 cancel handlers causes a stack overflow. A guidance measuring the recursion depth of `cancel()` will retain and grow inputs toward the failure threshold.

**Measurable metric**: Time-to-first-StackOverflowError. Custom guidance is expected to find the SOE within seconds (linearly growing all-registration-byte inputs), while Zest may never find it because coverage offers no gradient toward deeper chains.

---

#### PHASE B — Target Selection

Both V1 and V2 are DoS-relevant stack overflow vulnerabilities exercised through the frozen fuzz harness. Both are selected.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Recursive notifyDone chain overflow in AbstractIoFuture (addNotifier + setResult path)",
      "entrypoint": "XnioFuzzTest.fuzzIoFutureAddNotifier(InputStream) → RegistrationInput.addNotifiers(InputStream, IoFuture, Notifier) → AbstractIoFuture.addNotifier(Notifier, Object) → AbstractIoFuture.setResult(Object) → NotifierState.notifyDone(AbstractIoFuture, Object)",
      "source_path": "api/src/main/java/org/xnio/AbstractIoFuture.java",
      "sink": "AbstractIoFuture$NotifierState#notifyDone",
      "mechanism": "Each addNotifier call wraps the current state in a new NotifierState, forming a singly-linked chain. When setResult is called, notifyDone walks the chain recursively via next.notifyDone(future, result), with recursion depth equal to the number of registered notifiers.",
      "resource": "stack depth: one notifyDone stack frame per NotifierState in the chain (~200 bytes per frame)",
      "failure_mode": "stack_overflow",
      "scale": "About 5,000 notifiers overflow the 1 MB stack at ~200 bytes per frame; one input byte per notifier (all bytes 0xFF), so about 5,000 bytes of input",
      "input_bytes": 5000,
      "cwe": "CWE-674"
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "Recursive cancel chain overflow in AbstractIoFuture (addCancelHandler + cancel path)",
      "entrypoint": "XnioFuzzTest.fuzzFutureResultAddCancelHandler(InputStream) → RegistrationInput.addCancelHandlers(InputStream, FutureResult, Cancellable) → AbstractIoFuture.addCancelHandler(Cancellable) → AbstractIoFuture.cancel() → CancellableState.cancel()",
      "source_path": "api/src/main/java/org/xnio/AbstractIoFuture.java",
      "sink": "AbstractIoFuture$CancellableState#cancel",
      "mechanism": "Each addCancelHandler call wraps the current state in a new CancellableState, forming a singly-linked chain. When cancel is called, CancellableState.cancel walks the chain recursively via next.cancel(), with recursion depth equal to the number of registered cancel handlers.",
      "resource": "stack depth: one cancel stack frame per CancellableState in the chain (~150-200 bytes per frame)",
      "failure_mode": "stack_overflow",
      "scale": "About 5,000-7,000 cancel handlers overflow the 1 MB stack at ~150-200 bytes per frame; one input byte per handler (all bytes 0xFF), so about 5,000-7,000 bytes of input",
      "input_bytes": 7000,
      "cwe": "CWE-674"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

Let me re-read the fuzz test to trace the exact call flow carefully.

```text
Read <run_dir>/src/test/java/org/xnio/fuzz/XnioFuzzTest.java
Read <run_dir>/src/test/java/org/xnio/fuzz/RegistrationInput.java
```

Now let me re-read the key source methods to trace exact call connections:

```text
Read <source_root>/api/src/main/java/org/xnio/AbstractIoFuture.java
Read <source_root>/api/src/main/java/org/xnio/FutureResult.java
```

Now I understand the issue. The problem with V1 was that `addNotifier` does not call `setResult` — they're sequential calls from the fuzz test, not a call chain. The crash path goes from the fuzz test through `setResult` to `notifyDone`. Let me also re-read the cancel path:

```text
Read <source_root>/api/src/main/java/org/xnio/AbstractIoFuture.java
Read <source_root>/api/src/main/java/org/xnio/FutureResult.java
```

Now I have the correct call chains traced through the source. Here's the corrected target register:

**V1 corrected path**: The crash path goes from the fuzz test through `FutureResult.setResult()` → `AbstractIoFuture.setResult()` → `NotifierState.notifyDone()`. The `addNotifier` calls are the setup phase (building the chain), but `setResult` is what walks it recursively. The fuzz test calls `setResult` directly (line 43), not via `addNotifier`.

**V2 path**: Already correct structurally — `fuzzFutureResultAddCancelHandler` calls `futureResult.getIoFuture()` then `.cancel()` on the returned object, which walks the `CancellableState` chain.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Recursive notifyDone chain overflow in AbstractIoFuture (addNotifier + setResult path)",
      "entrypoint": "XnioFuzzTest.fuzzIoFutureAddNotifier(InputStream) → FutureResult.setResult(String) → AbstractIoFuture.setResult(Object) → NotifierState.notifyDone(AbstractIoFuture, Object)",
      "source_path": "api/src/main/java/org/xnio/AbstractIoFuture.java",
      "sink": "AbstractIoFuture.NotifierState#notifyDone",
      "mechanism": "Each addNotifier call wraps the current state in a new NotifierState, forming a singly-linked chain. When setResult is called, notifyDone walks the chain recursively via next.notifyDone(future, result), with recursion depth equal to the number of registered notifiers.",
      "resource": "stack depth: one notifyDone stack frame per NotifierState in the chain (~200 bytes per frame)",
      "failure_mode": "stack_overflow",
      "scale": "About 5,000 notifiers overflow the 1 MB stack at ~200 bytes per frame; one input byte per notifier (all bytes 0xFF), so about 5,000 bytes of input",
      "input_bytes": 5000,
      "cwe": "CWE-674"
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "Recursive cancel chain overflow in AbstractIoFuture (addCancelHandler + cancel path)",
      "entrypoint": "XnioFuzzTest.fuzzFutureResultAddCancelHandler(InputStream) → FutureResult.getIoFuture() → AbstractIoFuture.cancel() → CancellableState.cancel()",
      "source_path": "api/src/main/java/org/xnio/AbstractIoFuture.java",
      "sink": "AbstractIoFuture.CancellableState#cancel",
      "mechanism": "Each addCancelHandler call wraps the current state in a new CancellableState, forming a singly-linked chain. When cancel is called, CancellableState.cancel walks the chain recursively via next.cancel(), with recursion depth equal to the number of registered cancel handlers.",
      "resource": "stack depth: one cancel stack frame per CancellableState in the chain (~150-200 bytes per frame)",
      "failure_mode": "stack_overflow",
      "scale": "About 5,000-7,000 cancel handlers overflow the 1 MB stack at ~150-200 bytes per frame; one input byte per handler (all bytes 0xFF), so about 5,000-7,000 bytes of input",
      "input_bytes": 7000,
      "cwe": "CWE-674"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

**Analysis of measurements:**

**V1 (notifyDone chain):** At the 256 KB probe stack cap, 1000 notifiers completed and 2000 overflowed. The overflow threshold at 256 KB is between 1000–2000 notifiers. Subtracting ~30 KB of base stack overhead (JVM thread setup + fuzz test + setResult frames), the available recursion space is ~226 KB. This gives a per-frame cost of ~113–226 bytes (226,000/2000 to 226,000/1000). At 1 MB (4× the probe cap), available recursion space is ~994 KB. Threshold: 994,000/226 ≈ 4,400 to 994,000/113 ≈ 8,800 notifiers. Conservatively ~5,000 notifiers.

**V2 (cancel chain):** Identical measurement pattern — 1000 completed, 2000 overflowed at 256 KB. Same per-frame cost range (~113–226 bytes). Same extrapolation to 1 MB: threshold ~4,400–8,800 cancel handlers. Conservatively ~5,000. My original estimate of 7,000 was slightly high; both targets have very similar frame sizes.

Both targets use the densest encoding possible: one byte (≥ 0x80) per registration. No denser encoding exists since the fuzz test reads one byte per iteration.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "At the 256 KB probe stack cap, 1000 notifiers (1000 bytes) completed and 2000 (2000 bytes) overflowed, giving a per-frame cost of ~130-230 bytes. Extrapolating linearly to the 1 MB evaluation stack (4x the probe cap, minus ~30 KB base overhead): overflow threshold is approximately 4,400-8,800 notifiers; conservatively about 5,000 notifiers overflow the 1 MB stack. One input byte per notifier (all bytes >= 0x80), so about 5,000 bytes of input. This is the densest encoding: the fuzz test reads one byte per loop iteration.",
    "input_bytes": 5000
  },
  "V2": {
    "scale": "At the 256 KB probe stack cap, 1000 cancel handlers (1000 bytes) completed and 2000 (2000 bytes) overflowed, giving a per-frame cost of ~130-230 bytes (same as V1). Extrapolating linearly to the 1 MB evaluation stack (4x the probe cap, minus ~30 KB base overhead): overflow threshold is approximately 4,400-8,800 cancel handlers; conservatively about 5,000 cancel handlers overflow the 1 MB stack. One input byte per handler (all bytes >= 0x80), so about 5,000 bytes of input. This is the densest encoding: the fuzz test reads one byte per loop iteration.",
    "input_bytes": 5000
  }
}
END_SCALE_REVISION_JSON

## Block 2

Let me start by reading the existing workspace files and understanding the build setup.

```text
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/org/xnio/fuzz/XnioFuzzTest.java
Read <run_dir>/src/test/java/org/xnio/fuzz/RegistrationInput.java
```

Now let me re-read the vulnerable source to identify exact instrumentation points:

```text
Read <source_root>/api/src/main/java/org/xnio/AbstractIoFuture.java
Read <source_root>/api/src/main/java/org/xnio/AbstractIoFuture.java
```

Let me verify the lib jar and check if the existing pom.xml compiles:

```text
$ ls -la <run_dir>/lib/
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Good. The lib jar exists. Let me verify compilation works with the current pom.xml:

```text
$ mvn compile 2>&1 | tail -20
$ mvn test-compile 2>&1 | tail -20
$ mvn compile -Dmaven.test.skip=true 2>&1 | tail -20
$ mvn package -DskipTests 2>&1 | tail -30
```

Good, the build succeeds. Now let me verify all dependencies resolve correctly and check what ASM version is available for the agent:

```text
$ ls <run_dir>/target/dependency/ | sort
```

Let me verify the JQF Guidance API to ensure accuracy:

```text
$ jar tf target/dependency/jqf-fuzz-2.1.jar | grep -E "(Guidance|Result|GuidedFuzzing)" | head -20
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1
$ javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException 2>&1
$ jar tf target/dependency/jqf-instrument-2.1.jar | grep TraceEvent | head -5
```

Let me verify the ASM API details:

```text
$ jar tf target/dependency/asm-9.8.jar | grep -E "^org/objectweb/asm/[^/]+\.class$" | head -20
```

Good — ASM 9.8 with all needed classes (ClassReader, ClassWriter, ClassVisitor, MethodVisitor). Now let me create the directory structure:

```text
$ mkdir -p <run_dir>/src/test/java/org/xnio/fuzz/agent
```

Let me verify the full directory tree:

```text
$ find <run_dir>/src -type f | sort
```

Now I have everything I need. The pom.xml does not require any modifications — the vulnerable jar is correctly referenced at `lib/xnio-api-3.8.14.Final-SNAPSHOT.jar`, and ASM 9.8 is transitively available from `jqf-instrument`. Let me now produce the complete Block 2 output.

---

#### Step 2 — Maven Layout & Scope

The existing `pom.xml` is correctly configured:

| Artifact | Scope | Purpose |
|----------|-------|---------|
| `xnio-api-3.8.14.Final-SNAPSHOT.jar` | system (lib/) | Vulnerable target — NOT from Maven Central |
| `jboss-logging:3.4.3.Final` | compile | Runtime dep of xnio-api |
| `jboss-threads:2.3.6.Final` | compile | Runtime dep of xnio-api |
| `wildfly-common:1.5.4.Final` | compile | Runtime dep of xnio-api |
| `wildfly-client-config:1.0.1.Final` | compile | Runtime dep of xnio-api |
| `jqf-fuzz:2.1` | test | Guidance, GuidedFuzzing, Result |
| `jqf-instrument:2.1` | test | TraceEvent; brings ASM 9.8 transitively |
| `junit:4.13.2` | test | JUnit 4 runner |
| `junit-quickcheck-core:1.0` | test | Required by JQF at runtime |
| `junit-quickcheck-generators:1.0` | test | Required by JQF at runtime |

**No changes needed to pom.xml.** The vulnerable jar path resolves, all dependencies are present, and ASM 9.8 is available transitively from `jqf-instrument` for the custom agent's bytecode transformation.

**FORBIDDEN coordinates verified**: `org.jboss.xnio:xnio-api` is NOT listed as a normal Maven dependency; it's referenced only via system scope with the local vulnerable jar.

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

Symbols needed by the frozen fuzz test:
| Symbol | Package | Source | Resolution |
|--------|---------|--------|------------|
| `FutureResult` | `org.xnio` | lib/xnio-api jar | ✓ Resolved |
| `IoFuture` | `org.xnio` | lib/xnio-api jar | ✓ Resolved |
| `Cancellable` | `org.xnio` | lib/xnio-api jar | ✓ Resolved |
| `@Fuzz` | `edu.berkeley.cs.jqf.fuzz` | jqf-fuzz | ✓ Resolved |
| `JQF` | `edu.berkeley.cs.jqf.fuzz` | jqf-fuzz | ✓ Resolved |
| `@RunWith` | `org.junit.runner` | junit | ✓ Resolved |

Symbols needed by Guidance classes (planned for Block 3):
| Symbol | Package | Source | Resolution |
|--------|---------|--------|------------|
| `Guidance` | `edu.berkeley.cs.jqf.fuzz.guidance` | jqf-fuzz | ✓ Resolved |
| `Result` | `edu.berkeley.cs.jqf.fuzz.guidance` | jqf-fuzz | ✓ Resolved |
| `GuidanceException` | `edu.berkeley.cs.jqf.fuzz.guidance` | jqf-fuzz | ✓ Resolved |
| `GuidedFuzzing` | `edu.berkeley.cs.jqf.fuzz.junit` | jqf-fuzz | ✓ Resolved |
| `TraceEvent` | `edu.berkeley.cs.jqf.instrument.tracing.events` | jqf-instrument | ✓ Resolved |
| `SignalSource` | `dosguide.validate` | Already in workspace | ✓ Resolved |

Symbols needed by custom agent (planned for Block 3):
| Symbol | Package | Source | Resolution |
|--------|---------|--------|------------|
| `ClassReader` | `org.objectweb.asm` | asm-9.8 (transitive from jqf-instrument) | ✓ Resolved |
| `ClassWriter` | `org.objectweb.asm` | asm-9.8 | ✓ Resolved |
| `ClassVisitor` | `org.objectweb.asm` | asm-9.8 | ✓ Resolved |
| `MethodVisitor` | `org.objectweb.asm` | asm-9.8 | ✓ Resolved |
| `Opcodes` | `org.objectweb.asm` | asm-9.8 | ✓ Resolved |
| `Instrumentation` | `java.lang.instrument` | JDK | ✓ Resolved |
| `ClassFileTransformer` | `java.lang.instrument` | JDK | ✓ Resolved |

##### 3.2 Stub Generation

**No stubs needed.** Every symbol resolves via:
- The vulnerable jar (`lib/xnio-api-3.8.14.Final-SNAPSHOT.jar`)
- Maven dependencies (jqf-fuzz, jqf-instrument, junit)
- Transitive dependencies (ASM 9.8 from jqf-instrument)
- JDK standard library

##### 3.3 Stub Report

**NONE.** All required types are available from the existing vulnerable jar or declared Maven dependencies. No internal project classes are missing. No stubs required.

#### Step 4a — Directory Tree

```
<run>/
├── pom.xml                                         (EXISTING, UNCHANGED)
├── lib/
│   └── xnio-api-3.8.14.Final-SNAPSHOT.jar          (EXISTING, vulnerable jar)
├── src/
│   └── test/
│       └── java/
│           ├── org/xnio/fuzz/
│           │   ├── XnioFuzzTest.java                (FROZEN)
│           │   ├── RegistrationInput.java           (FROZEN)
│           │   ├── V1Guidance.java                  (Block 3)
│           │   ├── V2Guidance.java                  (Block 3)
│           │   ├── FuzzRunner.java                  (Block 3)
│           │   ├── ReplayRunner.java                (Block 3)
│           │   └── agent/
│           │       ├── RecursionCounters.java       (Block 3)
│           │       ├── RecursionDepthAgent.java     (Block 3)
│           │       └── RecursionTransformer.java    (Block 3)
│           └── dosguide/validate/
│               └── SignalSource.java                (EXISTING)
└── analysis/
    └── scale/
        ├── V1/  (measurement files)
        └── V2/  (measurement files)
```

#### Step 5 — Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|-------------------|------------------------------|------------------------|
| V1 | CGF (Cost-Gradient Guidance) | Coverage saturates after 1–2 `addNotifier` calls — the same CAS-loop branches execute whether there are 2 or 5,000 notifiers. Zest retains inputs by new coverage, which provides zero gradient toward deeper chains. It is a **proxy signal** (coverage) that is **not correlated** with the mechanism (recursion depth). | Instruments recursion depth inside `NotifierState#notifyDone` (the actual sink). Hill-climbs this **mechanism-aligned signal**, retaining inputs that push the measured recursion depth higher. This directly drives toward the StackOverflowError threshold. |
| V2 | CGF (Cost-Gradient Guidance) | Identical: coverage in `addCancelHandler` and `cancel()` is constant regardless of chain length. Zest/PerfFuzz's generic cost counters don't track stack depth. | Instruments recursion depth inside `CancellableState#cancel` (the actual sink). Same hill-climbing mechanism, directly targeting the cancel-chain stack overflow. |

**Measurable metric**: Time-to-first-StackOverflowError. Custom guidance should find the SOE within seconds (linear growth via doubling operator + measured depth signal), while Zest has no gradient to guide growth.

#### Step 6 — Measurement Plans (Per-Target)

##### V1: Recursion Depth of notifyDone Chain

**Primary mechanism**: Uncontrolled recursion (CWE-674). `NotifierState.notifyDone()` calls `next.notifyDone()` at each chain node.

**Signal: `maxDepth`**
- **What**: Maximum recursion depth of `notifyDone` invocations during one fuzz execution.
- **Where produced**: Inside `AbstractIoFuture$NotifierState#notifyDone` (AbstractIoFuture.java:247). The agent injects depth-counting bytecode at method entry/exit.
- **Why this region**: This is the exact method where the recursive call happens (`next.notifyDone(future, result)` at line 249). Each frame of this method consumes stack. The resource (stack depth) is consumed here.
- **How stored**: `ThreadLocal<long[]>` in `RecursionCounters.NOTIFY_DEPTH` where `[0]` = current depth, `[1]` = max depth seen this execution.
- **Reset**: Before each execution, in `V1Guidance.getInput()`, call `RecursionCounters.resetNotify()`.
- **Read**: In `V1Guidance.handleResult()`, read `RecursionCounters.NOTIFY_DEPTH.get()[1]`.

**Instrumentation feasibility [R35]:**
- **Classes/methods to instrument**: `org/xnio/AbstractIoFuture$NotifierState`, method `notifyDone(Lorg/xnio/AbstractIoFuture;Ljava/lang/Object;)V`
- **JVM flags**: None required (instrumenting application class, not JDK class)
- **Signal export**: Static `ThreadLocal<long[]>` in `RecursionCounters` (on the same classpath)
- **Agent implementation**: Custom `RecursionDepthAgent` with ASM-based `ClassFileTransformer`. At `notifyDone` entry: `NOTIFY_DEPTH.get()[0]++; if ([0] > [1]) [1] = [0]`. At normal/exceptional return: `NOTIFY_DEPTH.get()[0]--`.

**Mutation operators [R45]:**
- **Byte-level**: Flip bits, replace random bytes, insert/delete chunks (1–16 bytes)
- **Repetition [R45(a)]**: Full-input doubling (append a copy) and chunk-repeat (copy a slice k times). From an 8-byte seed, 10 doublings reach 8192 bytes (>>5000 needed). Selected ~15% of mutations.
- **Dictionary [R45(b)]**: Tokens from the attack path code:
  - `{(byte)0xFF}` — all bits set, guaranteed registration byte
  - `{(byte)0x80}` — minimum registration byte (threshold in `isRegistrationByte`)
  - `{(byte)0x00}` — non-registration byte
  - `{(byte)0x7F}` — maximum non-registration byte
  These are the boundary values of `(value & 0x80) != 0`.
- **Encoding [R45(c)]**: Not needed — raw bytes, no format checks.

**Retention policy [R46]:**
- **Primary**: Retain if `maxDepth > bestMaxDepth` (hill-climb recursion depth).
- **Secondary (flat signal)**: When `maxDepth` is zero or unchanged, retain inputs where `input.length > bestLength` (and ≤ `MAX_INPUT_SIZE`). This ensures growth toward `input_bytes` = 5000 even before any notifiers fire. Random bytes have ~50% chance of high bit = 1, so a 10,000-byte input has ~5,000 registrations, triggering the overflow.
- **Growth guarantee**: Doubling at ~15% rate from 8-byte seed. At 100 exec/sec: ~15 doublings/sec. Reach 8192 bytes in <1 second. At 10 exec/sec: reach 8192 bytes in ~7 seconds. Well within the 1-minute requirement.

##### V2: Recursion Depth of cancel Chain

**Primary mechanism**: Uncontrolled recursion (CWE-674). `CancellableState.cancel()` calls `next.cancel()` at each chain node.

**Signal: `maxDepth`**
- **What**: Maximum recursion depth of `cancel` invocations during one fuzz execution.
- **Where produced**: Inside `AbstractIoFuture$CancellableState#cancel` (AbstractIoFuture.java:337). The agent injects depth-counting bytecode at method entry/exit.
- **Why this region**: This is the exact method where the recursive call happens (`next.cancel()` at line 341). Each frame consumes stack.
- **How stored**: `ThreadLocal<long[]>` in `RecursionCounters.CANCEL_DEPTH` where `[0]` = current depth, `[1]` = max depth.
- **Reset**: Before each execution, in `V2Guidance.getInput()`, call `RecursionCounters.resetCancel()`.
- **Read**: In `V2Guidance.handleResult()`, read `RecursionCounters.CANCEL_DEPTH.get()[1]`.

**Instrumentation feasibility [R35]:**
- **Classes/methods**: `org/xnio/AbstractIoFuture$CancellableState`, method `cancel()V`
- **JVM flags**: None required
- **Signal export**: Same `ThreadLocal<long[]>` pattern
- **Agent implementation**: Same agent, second transformation target. At `cancel` entry: `CANCEL_DEPTH.get()[0]++; if ([0] > [1]) [1] = [0]`. At return: `CANCEL_DEPTH.get()[0]--`.

**Mutation operators**: Identical to V1 (same input encoding, same byte semantics).

**Retention policy**: Identical to V1 (same hill-climbing on `maxDepth`, same flat-signal growth by length).

#### Steps 7–10 — Implementation Plans (for Block 3)

##### Step 7 — Guidance Classes

**V1Guidance**: Implements `Guidance` directly and `SignalSource`. Dedicated corpus at `out/V1/corpus`. Logs stats every 1 second. Does NOT decide failures or write failure files. Uses `RecursionCounters.NOTIFY_DEPTH` signal. Input model: `getInput()` returns `ByteArrayInputStream` wrapping mutated byte array.

**V2Guidance**: Identical structure, dedicated corpus at `out/V2/corpus`. Uses `RecursionCounters.CANCEL_DEPTH` signal.

##### Step 8 — Fuzz Tests

The frozen `XnioFuzzTest` already has the two `@Fuzz` methods:
- `fuzzIoFutureAddNotifier(InputStream)` — drives V1
- `fuzzFutureResultAddCancelHandler(InputStream)` — drives V2

Both consume `InputStream` directly. No generators needed.

##### Step 9 — Replay

**ReplayRunner**: Reads saved corpus/metadata, loads the input bytes, replays into the target method via `GuidedFuzzing.run()` with a replay guidance that feeds the saved bytes. Prints input size, hex dump, and observed exception.

##### Step 10 — CLI Commands

```bash
### Build (compile only)
mvn package -DskipTests

### Create agent JAR
mkdir -p target/agent-meta/META-INF
echo "Premain-Class: org.xnio.fuzz.agent.RecursionDepthAgent" > target/agent-meta/META-INF/MANIFEST.MF
echo "Can-Retransform-Classes: true" >> target/agent-meta/META-INF/MANIFEST.MF
jar cfm target/recursion-agent.jar target/agent-meta/META-INF/MANIFEST.MF \
    -C target/test-classes org/xnio/fuzz/agent

### Fuzz V1 (time-bounded, 5 minutes)
java -Xmx1g -Xss1m -javaagent:target/recursion-agent.jar \
    -cp target/test-classes:target/classes:lib/*:target/dependency/* \
    org.xnio.fuzz.FuzzRunner V1 300

### Fuzz V2 (time-bounded, 5 minutes)  
java -Xmx1g -Xss1m -javaagent:target/recursion-agent.jar \
    -cp target/test-classes:target/classes:lib/*:target/dependency/* \
    org.xnio.fuzz.FuzzRunner V2 300

### Replay a saved input
java -Xmx1g -Xss1m \
    -cp target/test-classes:target/classes:lib/*:target/dependency/* \
    org.xnio.fuzz.ReplayRunner V1 out/V1/corpus/input_0042.bin
```

#### Class Origin Check Plan (for Block 3)

Will verify that `org.xnio.AbstractIoFuture` is loaded from `lib/xnio-api-3.8.14.Final-SNAPSHOT.jar` and NOT from `target/classes` by printing:
```java
System.out.println(AbstractIoFuture.class.getProtectionDomain().getCodeSource().getLocation());
```

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — pom.xml targets Java 17, no preview APIs
- [YES] No hallucinated APIs — all JQF APIs verified via `javap` on actual jars
- [YES] Guidance implements Guidance directly — V1Guidance/V2Guidance will `implements Guidance`
- [YES] No existing guidance extended — no Zest/PerfFuzz inheritance
- [YES] V* vulnerabilities identified — V1 (notifyDone recursion), V2 (cancel recursion)
- [YES] V* IDs are sequential — V1, V2 (not derived from any version numbers)
- [YES] Official vulnerability names — CWE-674 (Uncontrolled Recursion) for both
- [YES] PkgRisk-* identified — NONE found (no dependency-level risks on attack path)
- [YES] Every PkgRisk-* executed or justified — N/A (none identified)
- [YES] Guidance targets V* — V1Guidance targets V1, V2Guidance targets V2
- [YES] One fuzz method per V* — `fuzzIoFutureAddNotifier` for V1, `fuzzFutureResultAddCancelHandler` for V2
- [YES] CLI method selection supported — FuzzRunner takes target ID as CLI arg
- [YES] Byte[]/InputStream input model exclusively — both @Fuzz methods take InputStream
- [YES] No junit-quickcheck Generators — none used
- [YES] All mutation inside Guidance — Guidance handles all mutation (byte-level + repetition + dictionary)
- [YES] Repetition, dictionary, encoder operators — repetition (doubling/chunk-repeat), dictionary ({0xFF,0x80,0x00,0x7F}), no encoder needed (raw bytes)
- [YES] Retention progresses while signal flat; inputs reach input_bytes within minute — secondary length criterion; doubling reaches 8192 bytes in <7 seconds
- [YES] Retention signals measured at sink — `NotifierState#notifyDone` and `CancellableState#cancel` are the sinks
- [YES] Logging every 1 second — planned for both Guidance classes
- [YES] Guidance decides no failures, writes no failure files — per [R6]
- [YES] Corrupted inputs saved with metadata — corpus saves input bytes + metadata (depth, length, timestamp)
- [YES] Replay/feeder implemented — ReplayRunner planned
- [YES] Infinite + time-bounded supported — default infinite, CLI accepts seconds arg
- [YES] src/main vs src/test separation — all fuzzing infra in src/test/java, no src/main/java needed
- [YES] Maven scopes consistent — JQF=test, vulnerable jar=system, third-party=compile
- [YES] No wildcard imports for JQF/tracing — explicit imports only
- [YES] TraceEvent import verified — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` confirmed in jqf-instrument-2.1.jar

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
Instrumentation → java.lang.instrument.Instrumentation
ClassFileTransformer → java.lang.instrument.ClassFileTransformer
```

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "maxDepth",
          "quantity": "maximum recursion depth of NotifierState.notifyDone chain walk during one execution",
          "aggregation": "max",
          "locations": ["AbstractIoFuture$NotifierState#notifyDone"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in RecursionCounters.NOTIFY_DEPTH; [0]=current depth, [1]=max depth this execution",
          "reset": "V1Guidance.getInput() calls RecursionCounters.resetNotify() before returning the input stream",
          "read": "V1Guidance.handleResult() reads RecursionCounters.NOTIFY_DEPTH.get()[1]"
        }
      ],
      "retention": "Primary: retain input if maxDepth > bestMaxDepth (hill-climb recursion depth toward stack overflow). Secondary (flat signal): when maxDepth is zero or unchanged, retain inputs with greater length (up to MAX_INPUT_SIZE) to grow toward the 5000-byte threshold where ~2500 registrations trigger overflow. Inputs are prioritized by maxDepth first, then by length.",
      "retention_signals": ["maxDepth"],
      "mutation": [
        "Byte-level: bit flips (1-3 bits), byte replacement (random value), chunk insert (1-16 random bytes), chunk delete (1-16 bytes)",
        "Repetition [R45(a)]: full-input doubling (append copy of entire input) and chunk-repeat (copy random slice k times, k up to MAX_INPUT_SIZE / slice.length). From 8-byte seed, ~10 doublings reach 8192 bytes in <1 second at 100 exec/sec. Selected ~15% of mutations.",
        "Dictionary [R45(b)]: tokens from attack path code — {(byte)0xFF} (all-bits-set registration byte), {(byte)0x80} (minimum registration byte, threshold of isRegistrationByte), {(byte)0x00} (non-registration byte), {(byte)0x7F} (maximum non-registration byte). Inserted or overwritten at random positions. Selected ~15% of mutations.",
        "No encoding operator needed [R45(c)] — input is raw bytes with no format checks or checksums."
      ]
    },
    {
      "target": "V2",
      "signals": [
        {
          "name": "maxDepth",
          "quantity": "maximum recursion depth of CancellableState.cancel chain walk during one execution",
          "aggregation": "max",
          "locations": ["AbstractIoFuture$CancellableState#cancel"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in RecursionCounters.CANCEL_DEPTH; [0]=current depth, [1]=max depth this execution",
          "reset": "V2Guidance.getInput() calls RecursionCounters.resetCancel() before returning the input stream",
          "read": "V2Guidance.handleResult() reads RecursionCounters.CANCEL_DEPTH.get()[1]"
        }
      ],
      "retention": "Primary: retain input if maxDepth > bestMaxDepth (hill-climb recursion depth toward stack overflow). Secondary (flat signal): when maxDepth is zero or unchanged, retain inputs with greater length (up to MAX_INPUT_SIZE) to grow toward the 5000-byte threshold where ~2500 registrations trigger overflow. Inputs are prioritized by maxDepth first, then by length.",
      "retention_signals": ["maxDepth"],
      "mutation": [
        "Byte-level: bit flips (1-3 bits), byte replacement (random value), chunk insert (1-16 random bytes), chunk delete (1-16 bytes)",
        "Repetition [R45(a)]: full-input doubling (append copy of entire input) and chunk-repeat (copy random slice k times, k up to MAX_INPUT_SIZE / slice.length). From 8-byte seed, ~10 doublings reach 8192 bytes in <1 second at 100 exec/sec. Selected ~15% of mutations.",
        "Dictionary [R45(b)]: tokens from attack path code — {(byte)0xFF} (all-bits-set registration byte), {(byte)0x80} (minimum registration byte, threshold of isRegistrationByte), {(byte)0x00} (non-registration byte), {(byte)0x7F} (maximum non-registration byte). Inserted or overwritten at random positions. Selected ~15% of mutations.",
        "No encoding operator needed [R45(c)] — input is raw bytes with no format checks or checksums."
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

Let me start by reading all the files I need to reference for the implementation.

```text
Read <run_dir>/src/test/java/org/xnio/fuzz/XnioFuzzTest.java
Read <run_dir>/src/test/java/org/xnio/fuzz/RegistrationInput.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/pom.xml
```

Let me check the available ASM API and verify internal class names:

```text
$ jar tf lib/xnio-api-3.8.14.Final-SNAPSHOT.jar | grep -E "AbstractIoFuture\\\$" | head -10
$ javap -cp lib/xnio-api-3.8.14.Final-SNAPSHOT.jar 'org.xnio.AbstractIoFuture$NotifierState' 2>&1 | head -20
$ javap -cp lib/xnio-api-3.8.14.Final-SNAPSHOT.jar 'org.xnio.AbstractIoFuture$CancellableState' 2>&1 | head -20
```

I have all the bytecode details I need. Now let me write all implementation files.

```text
Write <run_dir>/src/test/java/org/xnio/fuzz/agent/RecursionCounters.java
Write <run_dir>/src/test/java/org/xnio/fuzz/agent/RecursionDepthAgent.java
Write <run_dir>/src/test/java/org/xnio/fuzz/agent/RecursionTransformer.java
```

Let me check the current state of the workspace and the frozen test files before writing the remaining implementation files.

```text
$ find <run_dir> -type f | sort
Read <run_dir>/src/test/java/org/xnio/fuzz/XnioFuzzTest.java
Read <run_dir>/src/test/java/org/xnio/fuzz/RegistrationInput.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Good, I have the full context. Let me read the guidance plan and pom.xml to ensure alignment:

```text
Read <run_dir>/analysis/guidance_plan.json
Read <run_dir>/pom.xml
Read <run_dir>/analysis/run_config.json
```

Let me check the JQF GuidedFuzzing API to ensure I use the right entry point:

```text
$ jar tf <run_dir>/target/dependency/jqf-fuzz-2.1.jar | grep -i "GuidedFuzzing" 2>&1
$ javap -p -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1 | tail -30
```

Now let me also check the Guidance interface imports needed:

```text
$ javap -p -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1 | tail -20
$ javap -p -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1 | tail -15
```

Good. Now I have all the API details. Let me write all remaining files. I'll start with V1Guidance and V2Guidance:

```text
Write <run_dir>/src/test/java/org/xnio/fuzz/Mutator.java
Write <run_dir>/src/test/java/org/xnio/fuzz/V1Guidance.java
Write <run_dir>/src/test/java/org/xnio/fuzz/V2Guidance.java
```

Now write FuzzRunner.java:

```text
Write <run_dir>/src/test/java/org/xnio/fuzz/FuzzRunner.java
Write <run_dir>/src/test/java/org/xnio/fuzz/ReplayRunner.java
```

Now write `run.sh`:

```text
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh
```

Now write `analysis/launch.json`:

```text
Write <run_dir>/analysis/launch.json
```

Now create the validation inputs. These are well-formed inputs that can be replayed to demonstrate signal measurement:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
$ cd <run_dir>/analysis/validation_inputs …
```

All files are written. Now let me compile to verify correctness:

```text
$ cd <run_dir> && mvn package -DskipTests 2>&1 | tail -30
```

BUILD SUCCESS. Let me also verify the agent JAR can be built, and confirm all expected classes are compiled:

```text
$ \ …
$ \ …
```

All 11 source files compile cleanly. Let me now verify the vulnerable artifact is used correctly by checking that the vulnerable jar is on the classpath (not some Maven Central version):

```text
$ \ …
```

The vulnerable artifact is correctly wired. The `xnio-api-3.8.14.Final-SNAPSHOT.jar` in both `lib/` and `target/dependency/` (copied by maven-dependency-plugin) contains `AbstractIoFuture$NotifierState` and `AbstractIoFuture$CancellableState`.

Let me do a final inventory check of all deliverables:

```text
$ \ …
$ \ …
$ \ …
```

All Block 3 deliverables are complete and compile successfully. Here is the summary:

---

#### Block 3 — Implementation Complete

##### Part A: Java Agent (bytecode instrumentation)
| File | Purpose |
|------|---------|
| `agent/RecursionCounters.java` | ThreadLocal `long[]` depth counters (`NOTIFY_DEPTH`, `CANCEL_DEPTH`) with enter/exit/get/reset methods |
| `agent/RecursionDepthAgent.java` | `premain()` entry point that registers the `RecursionTransformer` |
| `agent/RecursionTransformer.java` | ASM 9 `ClassFileTransformer` — instruments `NotifierState.notifyDone` and `CancellableState.cancel` with `INVOKESTATIC` enter/exit calls at method entry and before each `RETURN` opcode. Uses `COMPUTE_MAXS` (not `COMPUTE_FRAMES`) to avoid classloading issues. |

##### Part B: Guidance (cost-gradient hill-climbing)
| File | Purpose |
|------|---------|
| `Mutator.java` | Shared mutation engine: 15% doubling, 15% chunk repeat, 15% dictionary `{0xFF,0x80,0x00,0x7F}`, 20% bit flip, 20% byte replace, 10% chunk insert, 5% chunk delete |
| `V1Guidance.java` | `implements Guidance, SignalSource` — resets `NOTIFY_DEPTH`, reads `getNotifyMaxDepth()`, retains on depth improvement or length growth (flat signal [R46]) |
| `V2Guidance.java` | `implements Guidance, SignalSource` — resets `CANCEL_DEPTH`, reads `getCancelMaxDepth()`, same retention strategy |

##### Part C: Runners & Scripts
| File | Purpose |
|------|---------|
| `FuzzRunner.java` | `createGuidance(targetId, outputDir, maxDurationMs, log)` factory + `main()` with class-origin check |
| `ReplayRunner.java` | Single-shot replay of saved inputs, prints depth signals |
| `run.sh` | Build, agent JAR assembly, classpath assembly, launch with `-Xmx1g -Xss1m -javaagent:...` |

##### Part D: Validation Contract
| File | Purpose |
|------|---------|
| `analysis/launch.json` | Build commands, classpath, javaagent config, `guidance_factory`, target→method map |
| `analysis/validation_inputs/` | 10 inputs: `v1_depth{10,100,500,1000}`, `v1_mixed100`, `v1_min_reg200`, `v2_depth{10,500,1000}`, `zero_signal` |

##### Compilation: **BUILD SUCCESS** — 11 source files → 16 class files + agent JAR (5.7KB)

## Validation repair 1

The issue is clear: both `V1Guidance` and `V2Guidance` hardcode `MAX_INPUT_SIZE = 65_536` instead of reading it from the `jqf.ei.MAX_INPUT_SIZE` system property. Let me fix this.

```text
Read <run_dir>/src/test/java/org/xnio/fuzz/V1Guidance.java
Read <run_dir>/src/test/java/org/xnio/fuzz/V2Guidance.java
Read <run_dir>/src/test/java/org/xnio/fuzz/Mutator.java
```

Now I can see the problem clearly. Both guidance classes hardcode `MAX_INPUT_SIZE = 65_536` instead of reading it from the `jqf.ei.MAX_INPUT_SIZE` system property. I also need to:

1. Read `maxInputSize` from the system property in both guidance constructors
2. Cap the initial seed to respect the limit
3. Add a safety truncation in `Mutator.mutate()` to guarantee no output exceeds the limit
4. Handle the case where the parent is already at or above the limit (doubleInput could return parent-sized data unchanged, which is fine, but the parent from corpus could have been added before the limit was known)

Let me fix all three files:

```text
Edit <run_dir>/src/test/java/org/xnio/fuzz/V1Guidance.java
Edit <run_dir>/src/test/java/org/xnio/fuzz/V1Guidance.java
```

Now fix V2Guidance the same way:

```text
Edit <run_dir>/src/test/java/org/xnio/fuzz/V2Guidance.java
Edit <run_dir>/src/test/java/org/xnio/fuzz/V2Guidance.java
```

Now add a safety truncation to `Mutator.mutate()` to guarantee the output never exceeds `maxInputSize`, even if a parent from the corpus was added before the limit was known, and also fix the empty-parent seed case:

```text
Edit <run_dir>/src/test/java/org/xnio/fuzz/Mutator.java
```

Now compile to verify correctness:

```text
$ mvn package -DskipTests 2>&1 | tail -15
```

BUILD SUCCESS. The fix is clean and compiles. Let me verify the final state of the changed files to confirm correctness:

```text
Grep <run_dir>/src/test/java/org/xnio/fuzz maxInputSize|MAX_INPUT_SIZE|jqf\.ei\.MAX_INPUT_SIZE
```

All references are consistent — no hardcoded `65_536` remains in the guidance classes; `maxInputSize` is always read from the `jqf.ei.MAX_INPUT_SIZE` system property. The Mutator has both per-operator capping and a final safety truncation.

#### Summary of changes

**Problem:** Both `V1Guidance` and `V2Guidance` hardcoded `MAX_INPUT_SIZE = 65_536` instead of reading from the `jqf.ei.MAX_INPUT_SIZE` system property. When the evaluation set `jqf.ei.MAX_INPUT_SIZE=16`, the guidance still generated inputs up to 65KB.

**Fixes (3 files):**

1. **`V1Guidance.java`** — Replaced `private static final int MAX_INPUT_SIZE = 65_536` with a `readMaxInputSize()` method that reads `System.getProperty("jqf.ei.MAX_INPUT_SIZE")` (defaulting to 65536 if not set). The initial seed is also capped to `maxInputSize`.

2. **`V2Guidance.java`** — Same fix as V1Guidance.

3. **`Mutator.java`** — Added three safety measures:
   - Truncates the parent to `maxInputSize` if it already exceeds it (guards against stale corpus entries)
   - Caps the empty-parent seed to `Math.min(16, maxInputSize)`
   - Added a final hard-cap `Arrays.copyOf(result, maxInputSize)` after every mutation, guaranteeing no output ever exceeds the limit regardless of which operator ran
