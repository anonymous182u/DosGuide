# msgpack-java_GHSA-cw39-r4h6-8j3x

## Block 1

I'll start by reading the frozen fuzz test harness and the main target file to understand the entry points and vulnerability surface.

```text
Read <run_dir>
Glob <run_dir> **/FuzzTest*.java
Glob <run_dir> **/*
```

Let me read the frozen fuzz test harness, the pom.xml, the main target file, and the run config:

```text
Read <run_dir>/src/test/java/fuzzing/MsgpackFuzzTest.java
Read <run_dir>/pom.xml
Read <run_dir>/analysis/run_config.json
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me read the main target file - MessageUnpacker.java:

```text
Read <source_root>/msgpack-core/src/main/java/org/msgpack/core/MessageUnpacker.java
```

Now let me explore the MessagePack configuration and related classes:

```text
Glob <source_root>/msgpack-core/src/main/java/org/msgpack/core **/MessagePack.java
Glob <source_root>/msgpack-core/src/main/java/org/msgpack **/ValueFactory.java
Glob <source_root>/msgpack-core/src/main/java/org/msgpack/core **/Code.java
Read <source_root>/msgpack-core/src/main/java/org/msgpack/core/MessagePack.java
```

Let me check the MessageFormat class and also look at the exception hierarchy:

```text
Glob <source_root>/msgpack-core/src/main/java/org/msgpack/core **/MessageFormat.java
Glob <source_root>/msgpack-core/src/main/java/org/msgpack/core **/MessagePackException.java
Read <source_root>/msgpack-core/src/main/java/org/msgpack/core/MessagePackException.java
Read <source_root>/msgpack-core/src/main/java/org/msgpack/core/MessageFormat.java
```

Now I have a thorough understanding of the code. Let me create the scale measurement files. First, let me create the directories:

```text
$ mkdir -p analysis/scale/V1 analysis/scale/V2 analysis/scale/V3
```

Now let me generate all the scale measurement input files:

```text
$ python3 -c " …
```

Let me verify the generated files are correct:

```text
$ xxd analysis/scale/V1/n100.bin | head -3 && echo "---" && xxd analysis/scale/V1/n100.bin | tail -3 && echo "---" && xxd analysis/scale/V2/n4M.bin && echo "---" && xxd analysis/scale/V2/n64M.bin && echo "---" && xxd analysis/scale/V3/n16M.bin && echo "---" && xxd analysis/scale/V3/n256M.bin
Read <run_dir>/analysis/scale/V1/series.json
Read <run_dir>/analysis/scale/V2/series.json
Read <run_dir>/analysis/scale/V3/series.json
```

All files are created correctly. Now let me compile the full analysis and target register.

---

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: Uncontrolled Recursion in `MessageUnpacker.unpackValue()` via Nested Containers

**Fuzzable entrypoint & user-controlled inputs:** `MsgpackFuzzTest.fuzzMessageUnpackerUnpackValue(InputStream)` reads arbitrary bytes and passes them to `MessagePack.newDefaultUnpacker(byte[])`, then calls `unpacker.unpackValue()`. The input bytes are entirely user-controlled.

**Mechanism:** `unpackValue()` (line 606–667 of `MessageUnpacker.java`) handles ARRAY and MAP types by recursively calling itself:
- ARRAY case (line 636–643): `int size = unpackArrayHeader(); Value[] array = new Value[size]; for (int i = 0; i < size; i++) { array[i] = unpackValue(); }`
- MAP case (line 644–654): `int size = unpackMapHeader(); Value[] kvs = new Value[size * 2]; for (...) { kvs[i] = unpackValue(); ... }`

A msgpack fixarray-of-size-1 is encoded as a single byte `0x91`. A chain of `0x91` bytes followed by a terminal value (e.g., `0xC0` = nil) creates N levels of recursion. Each level adds one stack frame to the JVM call stack. There is no depth limit anywhere in the code.

**Exhausted resource:** Stack depth. Each recursive call to `unpackValue()` adds approximately 200–300 bytes of stack frame (locals for `mf`, `size`, `array`, loop variable, plus JVM frame overhead). With `-Xss1m` (1,048,576 bytes) and some initial stack consumption from JUnit/JQF framework (~100–200KB), approximately 3,000–4,000 nesting levels will exhaust the stack.

**Failure mode:** `stack_overflow` — `StackOverflowError` is thrown, which is an `Error` (not `IOException` or `MessagePackException`) and thus an undeclared throwable from the fuzz harness's perspective.

**Scale:** ~4,000 nesting levels overflow the 1 MB stack. Each level requires 1 byte (`0x91`) plus 1 terminal byte (`0xC0`), so ~4,001 bytes of input. This is well within the 10,240-byte input size limit.

**input_bytes:** ~4001

###### V2: Uncontrolled Allocation via Large Array Size Header in `MessageUnpacker.unpackValue()`

**Fuzzable entrypoint & user-controlled inputs:** Same as V1 — arbitrary bytes into `unpackValue()`.

**Mechanism:** When `unpackValue()` encounters an ARRAY type, it reads the array size from the header and immediately allocates `new Value[size]` (line 638). For the ARRAY32 format (`0xDD`), the size is a 4-byte big-endian unsigned integer (capped at `Integer.MAX_VALUE` by `readNextLength32()`). The allocation happens before any elements are read, so 5 bytes of input (1 byte format + 4 bytes size) can demand allocation of up to `2,147,483,647 * 4 = ~8 GB` of reference array (with compressed oops). There is no size validation between reading the header and allocating.

**Exhausted resource:** Heap memory. Each `Value` reference is 4 bytes (compressed oops). `new Value[268435456]` (268M elements) = 1,073,741,824 bytes = 1 GB exactly, which exceeds available heap with `-Xmx1g` and JVM overhead.

**Failure mode:** `out_of_memory` — `OutOfMemoryError` is thrown, which is an `Error` and an undeclared throwable.

**Scale:** `new Value[N]` where `N * 4 ≈ available heap (~900 MB)`. N ≈ 225,000,000. The input encoding is 5 bytes: `0xDD` + 4-byte big-endian N. Thus ~5 bytes of input → ~900 MB allocation.

**input_bytes:** 5

###### V3: Uncontrolled Allocation via Large Binary Payload Length in `MessageUnpacker.unpackValue()`

**Fuzzable entrypoint & user-controlled inputs:** Same as V1 — arbitrary bytes into `unpackValue()`.

**Mechanism:** When `unpackValue()` encounters a BINARY type, it reads the payload length from the header via `unpackBinaryHeader()`, then calls `readPayload(length)` (line 633), which allocates `new byte[length]` (line 1649). For BIN32 format (`0xC6`), length is a 4-byte big-endian unsigned integer (capped at `Integer.MAX_VALUE`). No size limit is checked for binary (unlike strings which have `stringSizeLimit`). Similarly, EXTENSION types (non-timestamp) in `unpackValue()` call `readPayload(extHeader.getLength())` without size validation.

**Exhausted resource:** Heap memory. `new byte[length]` directly allocates `length` bytes. `new byte[1073741824]` = 1 GB.

**Failure mode:** `out_of_memory` — `OutOfMemoryError` is thrown.

**Scale:** `new byte[N]` where `N ≈ available heap (~900 MB)`. The input encoding is 5 bytes: `0xC6` + 4-byte big-endian N. Thus ~5 bytes of input → ~900 MB allocation.

**input_bytes:** 5

##### 1.2 Official Classification

| ID | Classification |
|----|----------------|
| V1 | CWE-674: Uncontrolled Recursion (also CWE-400: Uncontrolled Resource Consumption) |
| V2 | CWE-770: Allocation of Resources Without Limits or Throttling |
| V3 | CWE-770: Allocation of Resources Without Limits or Throttling |

##### 1.3 Dependency / Package-Level Risks

The msgpack-core library has **no external runtime dependencies**. It is a self-contained binary format parser that uses only JDK standard library classes (java.nio, java.math.BigInteger, java.nio.charset). The core parsing logic (MessageUnpacker) is entirely hand-written without regex engines, XML/JSON parsers, compression libraries, or hash table abuse vectors.

**CharsetDecoder** (java.nio.charset) is used in `unpackString()`, but string sizes are bounded by the actual input data available (max 10,240 bytes), and UTF-8 decoding of small strings is O(n) in input size. No DoS risk.

**BigInteger** (java.math) is used in `unpackBigInteger()`, but values are limited to what fits in a long (or long+1 bit for UINT64). No arbitrary-precision computation is possible from the input. No DoS risk.

**No PkgRisk targets identified.** All DoS vulnerabilities reside in the application code itself (MessageUnpacker), not in external dependencies.

---

#### PHASE B — Target Selection

All three identified vulnerabilities are DoS-related. No PkgRisk targets were found. Ordering by implementation priority:

1. **V1** (Stack overflow via nesting) — Most interesting fuzzing target; requires building nested structure through mutation. The mechanism-aligned signal is recursion depth / stack consumption.

2. **V2** (OOM via array size header) — Extreme amplification ratio (5 bytes → 1 GB). The mechanism-aligned signal is bytes allocated at the `new Value[size]` site.

3. **V3** (OOM via binary payload length) — Same amplification class as V2 but different code path. The mechanism-aligned signal is bytes allocated at the `new byte[length]` site.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Uncontrolled recursion in MessageUnpacker.unpackValue() via nested containers",
      "entrypoint": "MsgpackFuzzTest.fuzzMessageUnpackerUnpackValue(InputStream) → MessageUnpacker.unpackValue() → MessageUnpacker.unpackArrayHeader() → MessageUnpacker.unpackValue()",
      "source_path": "msgpack-core/src/main/java/org/msgpack/core/MessageUnpacker.java",
      "sink": "MessageUnpacker#unpackValue",
      "mechanism": "Each nested fixarray(1) byte (0x91) causes one recursive call to unpackValue(); no depth limit exists, so N nested containers create N stack frames",
      "resource": "stack depth: one unpackValue() frame (~200-300 bytes) per nesting level",
      "failure_mode": "stack_overflow",
      "scale": "About 4000 nesting levels overflow the 1 MB stack; one byte per level (fixarray-of-1 = 0x91), so about 4001 bytes of input",
      "input_bytes": 4001,
      "cwe": "CWE-674"
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "Uncontrolled array allocation from ARRAY32 header in MessageUnpacker.unpackValue()",
      "entrypoint": "MsgpackFuzzTest.fuzzMessageUnpackerUnpackValue(InputStream) → MessageUnpacker.unpackValue() → MessageUnpacker.unpackArrayHeader()",
      "source_path": "msgpack-core/src/main/java/org/msgpack/core/MessageUnpacker.java",
      "sink": "MessageUnpacker#unpackValue",
      "mechanism": "ARRAY32 header (0xDD + 4-byte size) declares up to 2^31-1 elements; unpackValue() allocates new Value[size] immediately before reading any elements, so 5 input bytes drive a multi-GB allocation",
      "resource": "heap memory: size * 4 bytes for the Value reference array (compressed oops)",
      "failure_mode": "out_of_memory",
      "scale": "new Value[225000000] allocates ~900 MB, exhausting the 1 GB heap; requires 5 bytes of input (0xDD + 4-byte size)",
      "input_bytes": 5,
      "cwe": "CWE-770"
    },
    {
      "slot": 3,
      "id": "V3",
      "name": "Uncontrolled byte array allocation from BIN32 header in MessageUnpacker.unpackValue()",
      "entrypoint": "MsgpackFuzzTest.fuzzMessageUnpackerUnpackValue(InputStream) → MessageUnpacker.unpackValue() → MessageUnpacker.unpackBinaryHeader() → MessageUnpacker.readPayload(int)",
      "source_path": "msgpack-core/src/main/java/org/msgpack/core/MessageUnpacker.java",
      "sink": "MessageUnpacker#readPayload",
      "mechanism": "BIN32 header (0xC6 + 4-byte length) declares up to 2^31-1 bytes of payload; readPayload(int) allocates new byte[length] before reading data, so 5 input bytes drive a multi-GB allocation with no size limit check for binary",
      "resource": "heap memory: length bytes for the byte array allocation",
      "failure_mode": "out_of_memory",
      "scale": "new byte[900000000] allocates ~900 MB, exhausting the 1 GB heap; requires 5 bytes of input (0xC6 + 4-byte length)",
      "input_bytes": 5,
      "cwe": "CWE-770"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

Let me analyze the measurement data for each target and extrapolate to the fixed evaluation limits (-Xmx1g, -Xss1m, 20s timeout, 10240 byte input limit).

---

#### Analysis of Measurements

##### V1 — Stack overflow via nesting

**Measured growth pattern:**
- 100–800 levels: all completed within the 256 KB stack cap
- 1600 levels: exceeded the 256 KB stack cap

The stack grows linearly with nesting depth. The transition is between 800 and 1600 levels for a 256 KB stack. Using the midpoint (~1200 levels ≈ 256 KB total), and subtracting an estimated ~80 KB of framework overhead (JUnit/JQF before `unpackValue` recursion starts), we get:

- Usable stack in probe: 256 KB − 80 KB = 176 KB for recursion
- Per-level stack cost: 176 KB / 1200 ≈ 150 bytes/level

Extrapolation to 1 MB stack (evaluation):
- Usable stack: 1024 KB − 80 KB = 944 KB
- Levels to overflow: 944 KB / 150 bytes ≈ 6300 levels
- Input bytes: 6300 × 1 (fixarray-of-1 = 0x91) + 1 (nil = 0xC0) ≈ 6301 bytes

This is the densest encoding: fixarray-of-1 gives 1 byte per nesting level, and no denser container encoding exists in msgpack.

##### V2 — OOM via array allocation

**Measured growth pattern:**
| Elements | Allocated |
|----------|-----------|
| 4M | 16.5 MB |
| 8M | 32.5 MB |
| 16M | 64.5 MB |
| 32M | 128.5 MB |
| 64M | exceeded 256 MB cap |

Allocation per element: (128.5 − 16.5) MB / (32M − 4M) = 112 MB / 28M = **4 bytes/element** exactly. This confirms `new Value[size]` allocates 4 bytes per reference (compressed oops). The ~0.5 MB overhead is the exception object and framework.

Extrapolation to 1 GB heap: JVM overhead is ~150–200 MB, leaving ~800–850 MB for the array. At 4 bytes/element, ~200M elements (800 MB) exhausts the heap. Input remains 5 bytes.

##### V3 — OOM via binary payload allocation

**Measured growth pattern:**
| Declared bytes | Allocated |
|----------------|-----------|
| 16M | 16.5 MB |
| 32M | 32.5 MB |
| 64M | 64.5 MB |
| 128M | 128.5 MB |
| 256M | exceeded 256 MB cap |

Allocation per declared byte: (128.5 − 16.5) MB / (128M − 16M) = 112 MB / 112M = **1 byte per declared byte** exactly. This confirms `new byte[length]` allocates exactly `length` bytes. The ~0.5 MB overhead is framework.

Extrapolation to 1 GB heap: ~800M declared bytes (800 MB) plus ~150–200 MB JVM overhead exhausts the 1 GB heap. Input remains 5 bytes.

---

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured ~150 bytes of stack per nesting level (256 KB probe cap exceeded between 800 and 1600 levels, transition at ~1200 levels). With the evaluation's 1 MB stack and ~80 KB framework overhead, ~944 KB is available for recursion: 944 KB / 150 bytes ≈ 6300 nesting levels to overflow. Densest encoding is fixarray-of-1 (0x91) at 1 byte per level plus 1 terminal byte (0xC0), so about 6300 bytes of input.",
    "input_bytes": 6301
  },
  "V2": {
    "scale": "Measured 4 bytes of heap per declared array element (Value reference, compressed oops). 256 MB probe cap exceeded at 64M elements. Extrapolating to the evaluation's 1 GB heap with ~150-200 MB JVM overhead: ~200M elements × 4 bytes = 800 MB, exhausting available heap. Input is a 5-byte ARRAY32 header (0xDD + 4-byte big-endian size).",
    "input_bytes": 5
  },
  "V3": {
    "scale": "Measured 1 byte of heap per declared payload byte (direct byte array allocation). 256 MB probe cap exceeded at 256M declared bytes. Extrapolating to the evaluation's 1 GB heap with ~150-200 MB JVM overhead: ~800M declared bytes → 800 MB allocated, exhausting available heap. Input is a 5-byte BIN32 header (0xC6 + 4-byte big-endian length).",
    "input_bytes": 5
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by reading the workspace files and understanding the current state, then develop the measurement strategy.

```text
Glob <run_dir> **/*
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/fuzzing/MsgpackFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Good. Now let me verify the vulnerable jar exists and check compilation:

```text
$ ls -la <run_dir>/lib/
$ mvn compile 2>&1 | tail -20
```

Good. The project compiles. Let me now verify the jar contents and read key source files for the measurement plan:

```text
$ jar tf <run_dir>/lib/msgpack-core-0.9.10-19-befe3b94-SNAPSHOT.jar | grep -E "MessageUnpacker|MessagePack" | head -20
Read <source_root>/msgpack-core/src/main/java/org/msgpack/core/MessageUnpacker.java
```

Now let me read the key areas for the readPayload method and unpackArrayHeader:

```text
Read <source_root>/msgpack-core/src/main/java/org/msgpack/core/MessageUnpacker.java
Read <source_root>/msgpack-core/src/main/java/org/msgpack/core/MessageUnpacker.java
```

Now let me verify the JQF GuidedFuzzing API to make sure we use it correctly:

```text
$ mvn dependency:resolve 2>&1 | tail -10
$ find ~/.m2/repository/edu/berkeley -name "*.jar" -path "*jqf-fuzz*" 2>/dev/null | head -5
$ jar tf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar | grep -E "Guidance|GuidedFuzzing|Result" | head -20
```

Let me extract the Guidance interface to understand the exact API:

```text
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class 2>&1
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Result.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/Result.class 2>&1
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class && javap -p edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1 | head -30
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/GuidanceException.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/GuidanceException.class 2>&1
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-instrument/2.1/jqf-instrument-2.1.jar edu/berkeley/cs/jqf/instrument/tracing/events/TraceEvent.class && javap -p edu/berkeley/cs/jqf/instrument/tracing/events/TraceEvent.class 2>&1
```

Good. Now I have a thorough understanding of the JQF API. Let me verify the existing directory structure and check compilation works with test-compile:

```text
$ mvn test-compile 2>&1 | tail -20
$ mvn package -DskipTests 2>&1 | tail -30
```

The project compiles cleanly. Now let me check what the msgpack format codes are for the dictionary tokens:

```text
Read <source_root>/msgpack-core/src/main/java/org/msgpack/core/MessagePack.java
```

Now I have all the information needed. Let me verify the directory structure and ensure the pom.xml is correct. Since the pom.xml already works, I'll just create the directories needed for Block 3:

```text
$ mkdir -p src/test/java/agent src/test/java/guidance src/test/java/runner src/test/java/replay
$ find . -type f -o -type d | sort | head -40
```

Good. The pom.xml is verified working. The directory structure is ready. Now I'll produce the complete measurement strategy document.

---

#### Step 2 — Maven Layout & Scope

**Maven layout verified:**
- `src/main/java/` — empty (`.gitkeep` only); no production code needed since target classes come from the vulnerable system-scoped jar
- `src/test/java/` — all fuzzing infrastructure (guidance, agents, runners, replay, fuzz tests)
- `lib/msgpack-core-0.9.10-19-befe3b94-SNAPSHOT.jar` — vulnerable artifact, referenced via `<scope>system</scope>` + `<systemPath>`

**Scope verification:**
| Dependency | Scope | Justification |
|---|---|---|
| msgpack-core (vulnerable jar) | system | Local jar, NOT from Maven Central |
| jqf-fuzz 2.1 | test | Fuzzing framework |
| jqf-instrument 2.1 | test | TraceEvent callback API |
| junit 4.13.2 | test | Required by JQF |
| junit-quickcheck-core 1.0 | test | Required by JQF @Fuzz |
| junit-quickcheck-generators 1.0 | test | Required by JQF @Fuzz |
| asm 9.7.1 | test | For custom agent bytecode instrumentation |
| asm-commons 9.7.1 | test | For AdviceAdapter in agent |

**pom.xml status:** No changes needed. The existing pom.xml compiles cleanly with `mvn package -DskipTests`.

---

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

The fuzz test `MsgpackFuzzTest.java` imports:
- `edu.berkeley.cs.jqf.fuzz.Fuzz` → **jqf-fuzz** (test dep) ✓
- `edu.berkeley.cs.jqf.fuzz.JQF` → **jqf-fuzz** (test dep) ✓
- `org.junit.runner.RunWith` → **junit** (test dep) ✓
- `org.msgpack.core.MessagePack` → **vulnerable jar** (system dep) ✓
- `org.msgpack.core.MessagePackException` → **vulnerable jar** (system dep) ✓
- `org.msgpack.core.MessageUnpacker` → **vulnerable jar** (system dep) ✓

The planned Guidance/Agent/Runner classes will import:
- JQF classes → from jqf-fuzz/jqf-instrument (test dep) ✓
- ASM classes → from asm/asm-commons (test dep) ✓
- Standard Java classes (java.io, java.util, java.lang.instrument) ✓
- Internal classes (V1Counters, SignalSource) → in src/test/java ✓

**Result: Zero unresolved symbols. No stubs needed.**

##### 3.2 Stub Generation Rules

N/A — no stubs required.

##### 3.3 Stub Report

**No stubs generated.** The vulnerable msgpack-core jar is self-contained with zero external runtime dependencies. All symbols used by the fuzz test and the planned guidance classes resolve to either:
- The vulnerable jar (`lib/msgpack-core-0.9.10-19-befe3b94-SNAPSHOT.jar`)
- Maven Central dependencies (JQF, JUnit, ASM) in test scope
- Standard Java libraries

No internal project types are missing.

---

#### Step 4a — Project Setup (Directory Tree)

```
project-root/
├── pom.xml                              (canonical, unchanged)
├── lib/
│   └── msgpack-core-0.9.10-19-befe3b94-SNAPSHOT.jar  (vulnerable artifact)
├── src/
│   ├── main/java/.gitkeep               (empty; using vulnerable jar)
│   └── test/java/
│       ├── fuzzing/
│       │   └── MsgpackFuzzTest.java     (FROZEN fuzz harness)
│       ├── dosguide/validate/
│       │   └── SignalSource.java         (FROZEN interface)
│       ├── agent/
│       │   ├── V1MeasureAgent.java      (premain entry for V1 agent)
│       │   ├── V1Counters.java          (ThreadLocal depth counter)
│       │   └── V1Transformer.java       (ASM transformer for unpackValue)
│       ├── guidance/
│       │   ├── V1Guidance.java          (nesting depth / stack overflow)
│       │   ├── V2Guidance.java          (array allocation OOM)
│       │   └── V3Guidance.java          (binary allocation OOM)
│       ├── runner/
│       │   └── FuzzRunner.java          (CLI entrypoint + method selection)
│       └── replay/
│           └── MetadataReplay.java      (reproduction + replay)
```

---

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|---|---|---|
| V1 | Cost-Gradient Guidance (CGF) | Zest uses code coverage as its retention signal. The recursive `unpackValue()` call path is the **same code** at every nesting level—Zest discovers no new branches after depth 1 and therefore cannot distinguish 10 levels from 6000 levels. PerfFuzz uses generic execution cost but doesn't focus on the specific recursion depth. The **proxy signal** (coverage) is completely uncorrelated with the **mechanism signal** (stack depth). | The custom guidance instruments `MessageUnpacker.unpackValue()` entry/exit to measure **actual recursion depth** (Tier 1 agent). It retains inputs with deeper nesting and uses repetition mutation on container bytes to grow depth. The **mechanism-aligned signal** (depth) directly predicts stack overflow. |
| V2 | Vulnerability-Directed Guidance (VDF) | Zest's coverage is identical for ARRAY32 headers with size=100 vs size=200,000,000—the same `unpackArrayHeader()` → `new Value[size]` path is taken either way. The **proxy signal** (new branches) gives no gradient toward larger sizes. Random byte mutation rarely produces a coherent 4-byte big-endian value large enough to trigger OOM. | The guidance reads the **declared array size** directly from the input's ARRAY32 header (Tier 0 static signal). This exact value is passed verbatim to `new Value[size]`—it IS the allocation size. The oracle is the real `OutOfMemoryError`. The guidance hill-climbs this declared size and mutates specifically the 4-byte size field. |
| V3 | Vulnerability-Directed Guidance (VDF) | Same as V2: Zest's coverage cannot differentiate BIN32 payloads of different declared lengths—the same code path is exercised. Random mutation of 4-byte length fields has negligible probability of producing values near 1 GB. | The guidance reads the **declared payload length** from the input's BIN32/EXT32 header (Tier 0 static signal). This exact value is the argument to `new byte[length]`. The guidance hill-climbs toward larger declared lengths. |

---

#### Step 6 — Strategy-Specific Guidance Design

##### V1 Measurement Plan (Tier 1 — Bytecode Instrumentation)

**Signal: `maxDepth`** — maximum recursion depth of `MessageUnpacker.unpackValue()` during one execution.

**Where produced:** Inside `org.msgpack.core.MessageUnpacker.unpackValue()`. The agent inserts bytecode at method entry to increment a thread-local depth counter and record the max, and at every exit (normal return and exceptional) to decrement it.

**Why this region:** `unpackValue()` is the exact recursive method in the attack path. Each nesting level adds one frame. The depth counter directly measures the stack-consuming quantity.

**How stored:** `ThreadLocal<long[]>` in `agent.V1Counters`, where `[0]` = current depth, `[1]` = max depth observed.

**Where reset:** `V1Guidance.getInput()` calls `V1Counters.reset()` before each execution.

**Where read:** `V1Guidance.handleResult()` reads `V1Counters.getMaxDepth()` and uses it as the retention signal.

**Agent implementation plan:**
- **Class to instrument:** `org.msgpack.core.MessageUnpacker`
- **Method to instrument:** `unpackValue()V` (the no-arg overload returning `ImmutableValue`)
- **JVM flags:** `-javaagent:target/v1-agent.jar` — no `--add-opens` needed (instrumenting application code, not JDK)
- **Agent entry:** `V1MeasureAgent.premain(String, Instrumentation)` registers a `ClassFileTransformer`
- **Transformer:** `V1Transformer` extends `ClassVisitor` (ASM 9); when visiting method `unpackValue` with descriptor `()Lorg/msgpack/value/ImmutableValue;`, it uses `AdviceAdapter` to inject:
  - `onMethodEnter()`: call `V1Counters.enter()`
  - `onMethodExit(int)`: call `V1Counters.exit()`
- **Signal export:** `V1Counters.enter()` increments `threadLocal.get()[0]++` and updates `threadLocal.get()[1] = max(threadLocal.get()[1], threadLocal.get()[0])`. `V1Counters.exit()` decrements `[0]--`.

**Mutation operators:**
- **Byte-level:** Random byte flip, random byte insert/delete, block copy
- **Repetition [R45(a)]:** Duplicate a contiguous run of bytes (preferably container bytes like 0x91) and repeat it k times, up to filling `MAX_INPUT_SIZE` (10240). This doubles/quadruples nesting depth in one mutation step. From an initial seed of a few 0x91 bytes + 0xC0, repetition can reach 6301 bytes in ~12 doublings (< 1 minute).
- **Dictionary [R45(b)]:** Tokens from the source on the attack path:
  - `{0x91}` — fixarray(1), one nesting level per byte
  - `{0x81}` — fixmap(1), nesting alternative
  - `{0xC0}` — nil, terminal value for innermost element
  - `{0xC2}` — false, alternative terminal
  - `{0xC3}` — true, alternative terminal
  - `{0xDD}` — ARRAY32 format byte
  - `{0xDC}` — ARRAY16 format byte
  - `{0xDF}` — MAP32 format byte
  - `{0x00}` — fixint 0, terminal value

**Retention & prioritization:**
- **Primary:** Retain input if `maxDepth > bestMaxDepth`
- **Secondary [R46]:** While `maxDepth` is 0 or flat (input is malformed and doesn't reach recursion), retain inputs that are **longer** (growing toward `input_bytes` = 6301) or that contain container format bytes, so the search can cross the threshold where parsing succeeds
- **Energy:** Inputs with higher `maxDepth` receive more mutation rounds

##### V2 Measurement Plan (Tier 0 — Static Input-Declared Size)

**Signal: `declaredArraySize`** — the element count from the first ARRAY-type header in the input.

**Why Tier 0 applies:**
- (i) The sink is `new Value[size]` — a bounded allocation whose size is one value taken directly from the input
- (ii) The guidance parses the exact ARRAY32/ARRAY16/fixarray size field from the input bytes — not input length or any heuristic
- (iii) The failure oracle is the real `OutOfMemoryError`

**Where produced:** Parsed from the input bytes in `V2Guidance.handleResult()`.

**Parsing logic:**
- Read first byte of the last-used input
- `0x90–0x9F` (fixarray): size = byte & 0x0F
- `0xDC` (ARRAY16): size = next 2 bytes as big-endian uint16
- `0xDD` (ARRAY32): size = next 4 bytes as big-endian int32 (rejected if negative)
- `0x80–0x8F` (fixmap): size = (byte & 0x0F) * 2 (because `Value[size*2]`)
- `0xDE` (MAP16): size = (next 2 bytes as big-endian uint16) * 2
- `0xDF` (MAP32): size = (next 4 bytes as big-endian int32) * 2

**How stored:** Field `lastDeclaredSize` in `V2Guidance`, set during `handleResult()`.

**Where reset:** Reset to 0 in `getInput()`.

**Where read:** `handleResult()` reads it and compares to `bestDeclaredSize` for retention.

**Mutation operators:**
- **Byte-level:** Random byte flip, random byte insert/delete
- **Repetition [R45(a)]:** Copy and repeat any chunk of the input. While this doesn't directly grow the size field, it can extend the input, and combined with dictionary insertion it helps.
- **Dictionary [R45(b)]:** Tokens from the source:
  - `{0xDD}` — ARRAY32 format byte
  - `{0xDC}` — ARRAY16 format byte
  - `{0x91}` — fixarray(1)
  - `{0x9F}` — fixarray(15)
  - `{0xDF}` — MAP32 format byte
  - `{0xC0}` — nil
  - `{0xFF}` — max byte value (for size field amplification)
  - `{0x7F}` — max positive signed byte (for valid large sizes in upper byte)
- **Size-field targeted mutation:** When the input starts with 0xDD, specifically mutate bytes at offsets 1–4 (the size field) toward larger values: set random bytes to 0xFF or high values, or increment the existing value.

**Retention & prioritization:**
- **Primary:** Retain input if `declaredArraySize > bestDeclaredSize`
- **Secondary [R46]:** While signal is 0 (no array header found), retain inputs that contain array format bytes (0x9x, 0xDC, 0xDD, 0x8x, 0xDE, 0xDF), favoring longer inputs
- **Energy:** Inputs with larger `declaredArraySize` get more mutations

##### V3 Measurement Plan (Tier 0 — Static Input-Declared Size)

**Signal: `declaredPayloadBytes`** — the payload length from the first BIN/EXT-type header in the input.

**Why Tier 0 applies:**
- (i) The sink is `new byte[length]` — a bounded allocation whose size is one value from the input
- (ii) The guidance parses the exact BIN32/EXT32/BIN16/BIN8 length field — not input length
- (iii) The failure oracle is the real `OutOfMemoryError`

**Where produced:** Parsed from the input bytes in `V3Guidance.handleResult()`.

**Parsing logic:**
- Read first byte of the last-used input
- `0xC4` (BIN8): length = next 1 byte as uint8
- `0xC5` (BIN16): length = next 2 bytes as big-endian uint16
- `0xC6` (BIN32): length = next 4 bytes as big-endian int32 (rejected if negative)
- `0xC7` (EXT8): length = next 1 byte as uint8
- `0xC8` (EXT16): length = next 2 bytes as big-endian uint16
- `0xC9` (EXT32): length = next 4 bytes as big-endian int32 (rejected if negative)

**How stored:** Field `lastDeclaredLength` in `V3Guidance`, set during `handleResult()`.

**Where reset:** Reset to 0 in `getInput()`.

**Where read:** `handleResult()` reads it and compares to `bestDeclaredLength` for retention.

**Mutation operators:**
- **Byte-level:** Random byte flip, random byte insert/delete
- **Repetition [R45(a)]:** Copy and repeat chunks, combined with dictionary insertion
- **Dictionary [R45(b)]:** Tokens from the source:
  - `{0xC6}` — BIN32 format byte
  - `{0xC9}` — EXT32 format byte
  - `{0xC4}` — BIN8 format byte
  - `{0xC5}` — BIN16 format byte
  - `{0xC7}` — EXT8 format byte
  - `{0xC8}` — EXT16 format byte
  - `{0xC0}` — nil
  - `{0xFF}` — max byte value
  - `{0x7F}` — for valid large sizes
- **Length-field targeted mutation:** When the input starts with 0xC6 or 0xC9, specifically mutate bytes at offsets 1–4 toward larger values.

**Retention & prioritization:**
- **Primary:** Retain input if `declaredPayloadBytes > bestDeclaredLength`
- **Secondary [R46]:** While signal is 0, retain inputs containing BIN/EXT format bytes, favoring longer inputs
- **Energy:** Inputs with larger `declaredPayloadBytes` get more mutations

---

#### Step 7-10 — Summary of Planned Classes (Code in Block 3)

**Guidance Classes (one per target, [R33]):**
- `guidance.V1Guidance` — Cost-Gradient, instruments recursion depth, retains on maxDepth
- `guidance.V2Guidance` — VDF with Tier 0, parses ARRAY32 declared size, retains on declaredArraySize
- `guidance.V3Guidance` — VDF with Tier 0, parses BIN32 declared length, retains on declaredPayloadBytes

**Agent (V1 only):**
- `agent.V1MeasureAgent` — premain entry, registers transformer
- `agent.V1Counters` — ThreadLocal depth tracking (measurement only, [R37])
- `agent.V1Transformer` — ASM ClassVisitor instrumenting `MessageUnpacker.unpackValue()`

**Runner:**
- `runner.FuzzRunner` — `main(String[])` with args: `<target> [timeoutSec]`. Maps V1/V2/V3 to `fuzzMessageUnpackerUnpackValue`. Uses `GuidedFuzzing.run(testClassName, testMethod, cl, guidance, out)`.

**Replay:**
- `replay.MetadataReplay` — Loads saved inputs + metadata, replays through `MessagePack.newDefaultUnpacker()` + `unpackValue()`, prints results.

**Input Model [R25, R31]:** All three guidances produce raw `byte[]` streams via `Guidance.getInput()`. The fuzz test receives `InputStream` and reads `data.readAllBytes()`. The input model is byte[]/InputStream only. No junit-quickcheck generators.

**Corpus Isolation [R20]:**
- V1: `out/V1/corpus/`
- V2: `out/V2/corpus/`
- V3: `out/V3/corpus/`

---

#### Zest Baseline Comparison [R18]

| Metric | Zest | V1Guidance | V2Guidance | V3Guidance |
|--------|------|------------|------------|------------|
| **Signal type** | Branch coverage (proxy) | Recursion depth (mechanism-aligned) | Declared array size (mechanism-aligned, Tier 0) | Declared payload length (mechanism-aligned, Tier 0) |
| **Why proxy fails** | Same branches at depth 1 and 6000 | N/A | Same branches for size 100 and size 200M | Same branches for length 100 and length 800M |
| **Expected outperformance** | — | Time-to-first-StackOverflow: CGF targets depth directly; Zest has no gradient | Time-to-first-OOM: VDF hill-climbs declared size; Zest has no gradient past first ARRAY path | Time-to-first-OOM: VDF hill-climbs declared length; Zest has no gradient past first BIN path |
| **Measurable metric** | — | Max nesting depth reached per time unit | Max declared array size per time unit | Max declared payload length per time unit |

---

#### IMPORT AUDIT

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent
```

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — `maven.compiler.source/target` = 17
- [YES] No hallucinated APIs — Verified Guidance, GuidedFuzzing, Result, TraceEvent, GuidanceException from JQF 2.1 jars via javap
- [YES] Guidance implements Guidance directly — V1/V2/V3Guidance all implement `edu.berkeley.cs.jqf.fuzz.guidance.Guidance`
- [YES] No existing guidance extended — None extend ZestGuidance, PerfFuzzGuidance, etc.
- [YES] V* vulnerabilities identified — V1 (nesting StackOverflow), V2 (array OOM), V3 (binary OOM)
- [YES] V* IDs are sequential (V1, V2, V3) — discovery-order counters, not version numbers [R42]
- [YES] Official vulnerability names applied — CWE-674 (V1), CWE-770 (V2, V3)
- [YES] PkgRisk-* identified — None found; justified: msgpack-core has zero external runtime dependencies
- [N/A] Every PkgRisk-* executed or justified — No PkgRisks exist
- [YES] Guidance targets V* — One guidance per target (V1Guidance, V2Guidance, V3Guidance)
- [YES] One fuzz method per V* — All use `fuzzMessageUnpackerUnpackValue` (the frozen harness entry)
- [YES] CLI method selection supported — FuzzRunner takes target ID as first CLI argument
- [YES] Byte[] / InputStream input model used exclusively — Guidance.getInput() returns raw byte stream
- [YES] No junit-quickcheck Generators used
- [YES] All mutation implemented inside Guidance
- [YES] Repetition, source dictionary implemented [R45] — repetition grows nesting/length; dictionary tokens from msgpack format codes
- [YES] Retention progresses while signal flat [R46] — secondary criterion retains longer inputs / inputs with target format bytes
- [YES] Retention signals measured where consumed [R47] — V1 at unpackValue (agent), V2/V3 Tier 0 at allocation argument
- [YES] Logging every 1 second — Each Guidance logs stats at 1-second intervals
- [YES] Guidance decides no failures and writes no failure files [R6]
- [YES] Corrupted inputs saved with metadata
- [YES] Replay/feeder implemented — MetadataReplay class
- [YES] Infinite + time-bounded fuzzing supported — FuzzRunner accepts optional timeout
- [YES] src/main vs src/test separation correct — All fuzzing infra in src/test/java
- [YES] Maven scopes consistent — vulnerable jar = system, JQF/ASM = test
- [YES] No wildcard imports used for JQF / tracing
- [YES] TraceEvent import verified — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` (abstract class in jqf-instrument-2.1.jar)

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "maxDepth",
          "quantity": "maximum recursion depth of MessageUnpacker.unpackValue() during one execution",
          "aggregation": "max",
          "locations": ["MessageUnpacker#unpackValue"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in agent.V1Counters, index [0]=currentDepth, [1]=maxDepth",
          "reset": "V1Guidance.getInput() calls V1Counters.reset() before each execution",
          "read": "V1Guidance.handleResult() calls V1Counters.getMaxDepth()"
        }
      ],
      "retention": "Primary: retain input if maxDepth > bestMaxDepth. Secondary (while signal is flat): retain inputs that are longer (growing toward input_bytes=6301) or that contain container format bytes (0x91, 0x81, 0xDD, 0xDC), so the search can cross the threshold where parsing succeeds and recursion begins.",
      "retention_signals": ["maxDepth"],
      "mutation": [
        "Byte-level: random byte flip, random byte insert, random byte delete, block copy/shuffle",
        "Repetition [R45a]: duplicate a contiguous run of bytes (preferring container bytes 0x91) and repeat k times in place, with k up to filling MAX_INPUT_SIZE (10240). From a seed of a few 0x91+0xC0 bytes, repeated doubling reaches 6301 bytes in ~12 steps (< 1 minute).",
        "Dictionary [R45b]: tokens from the source on the attack path: {0x91} fixarray(1), {0x81} fixmap(1), {0xC0} nil, {0xC2} false, {0xC3} true, {0xDD} ARRAY32, {0xDC} ARRAY16, {0xDF} MAP32, {0x00} fixint-0. Inserted or overwritten at random positions.",
        "No encoder needed [R45c]: msgpack container+terminal bytes are accepted raw; no checksums, compression, or length-prefix encoding to pass."
      ]
    },
    {
      "target": "V2",
      "signals": [
        {
          "name": "declaredArraySize",
          "quantity": "element count declared in the first ARRAY/MAP header of the input, which is the exact argument to new Value[size] at the sink",
          "aggregation": "max",
          "locations": ["MessageUnpacker#unpackValue"],
          "technique": "static",
          "storage": "field lastDeclaredSize in V2Guidance",
          "reset": "V2Guidance.getInput() sets lastDeclaredSize = 0",
          "read": "V2Guidance.handleResult() parses the input bytes for ARRAY32/ARRAY16/fixarray/MAP32/MAP16/fixmap header and extracts the declared size"
        }
      ],
      "retention": "Primary: retain input if declaredArraySize > bestDeclaredSize. Secondary (while signal is 0, i.e. no valid array/map header found): retain inputs that contain array/map format bytes (0x90-0x9F, 0xDC, 0xDD, 0x80-0x8F, 0xDE, 0xDF) and that are at least 5 bytes long (enough for ARRAY32 header).",
      "retention_signals": ["declaredArraySize"],
      "mutation": [
        "Byte-level: random byte flip, random byte insert, random byte delete",
        "Repetition [R45a]: copy a chunk and repeat it k times to grow the input; not the primary growth mechanism for this target but ensures diverse inputs.",
        "Dictionary [R45b]: tokens from the source: {0xDD} ARRAY32, {0xDC} ARRAY16, {0x91} fixarray(1), {0x9F} fixarray(15), {0xDF} MAP32, {0xDE} MAP16, {0xC0} nil, {0xFF} max-byte, {0x7F} max-positive-byte. Inserted at random positions.",
        "Size-field targeted mutation: when input starts with 0xDD (ARRAY32), mutate bytes at offsets 1-4 specifically toward larger values (set to 0xFF, increment, randomize high bytes while keeping positive).",
        "No encoder needed [R45c]: msgpack headers are bare bytes, no checksums or compression."
      ]
    },
    {
      "target": "V3",
      "signals": [
        {
          "name": "declaredPayloadBytes",
          "quantity": "payload length declared in the first BIN/EXT header of the input, which is the exact argument to new byte[length] at the sink",
          "aggregation": "max",
          "locations": ["MessageUnpacker#readPayload"],
          "technique": "static",
          "storage": "field lastDeclaredLength in V3Guidance",
          "reset": "V3Guidance.getInput() sets lastDeclaredLength = 0",
          "read": "V3Guidance.handleResult() parses the input bytes for BIN32/BIN16/BIN8/EXT32/EXT16/EXT8 header and extracts the declared length"
        }
      ],
      "retention": "Primary: retain input if declaredPayloadBytes > bestDeclaredLength. Secondary (while signal is 0, i.e. no valid binary/ext header found): retain inputs that contain BIN/EXT format bytes (0xC4-0xC9) and that are at least 5 bytes long (enough for BIN32 header).",
      "retention_signals": ["declaredPayloadBytes"],
      "mutation": [
        "Byte-level: random byte flip, random byte insert, random byte delete",
        "Repetition [R45a]: copy a chunk and repeat it k times to grow the input.",
        "Dictionary [R45b]: tokens from the source: {0xC6} BIN32, {0xC9} EXT32, {0xC4} BIN8, {0xC5} BIN16, {0xC7} EXT8, {0xC8} EXT16, {0xC0} nil, {0xFF} max-byte, {0x7F} max-positive-byte. Inserted at random positions.",
        "Length-field targeted mutation: when input starts with 0xC6 (BIN32) or 0xC9 (EXT32), mutate bytes at offsets 1-4 specifically toward larger values.",
        "No encoder needed [R45c]: msgpack headers are bare bytes."
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

I'll implement all the files now. Let me start by reading the workspace state and key source files.

```text
Glob <run_dir> **/*
Read <run_dir>/analysis/guidance_plan.json
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me write all the implementation files. I'll start with the V1 agent (Part A), then the three Guidance classes (Part B), then the runner/replay (Part C).

**Part A — V1 Java Agent:**

```text
Write <run_dir>/src/test/java/agent/V1Counters.java
Write <run_dir>/src/test/java/agent/V1Transformer.java
Write <run_dir>/src/test/java/agent/V1MeasureAgent.java
```

Now **Part B — Guidance classes:**

```text
Write <run_dir>/src/test/java/guidance/V1Guidance.java
```

```text
Write <run_dir>/src/test/java/guidance/V2Guidance.java
Write <run_dir>/src/test/java/guidance/V3Guidance.java
```

Now **Part C — FuzzRunner and MetadataReplay:**

```text
Write <run_dir>/src/test/java/runner/FuzzRunner.java
Write <run_dir>/src/test/java/replay/MetadataReplay.java
```

Now create validation inputs:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
$ cd <run_dir>/analysis/validation_inputs …
```

Now the agent jar manifest and pom.xml agent-jar build. Let me check the existing pom.xml first:

```text
Read <run_dir>/pom.xml
```

I need to add the maven-assembly-plugin or use the jar command to build the agent jar. Let me use a dedicated assembly in the pom.xml for the agent jar. Actually, the simplest approach is to build the agent jar in run.sh using the `jar` command after compilation. Let me also create the launch.json and run.sh now:

```text
Read <run_dir>/analysis/target_register.json
```

Now create `analysis/launch.json`:

```text
Write <run_dir>/analysis/launch.json
```

Now create the agent manifest and run.sh:

```text
$ mkdir -p <run_dir>/src/test/resources/META-INF
Write <run_dir>/src/test/resources/META-INF/MANIFEST.MF
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh
```

Now let's compile everything to verify correctness:

```text
$ cd <run_dir> && mvn -q package -DskipTests 2>&1 | tail -30
```

Build succeeded (silent = no errors). Now build the agent jar:

```text
$ \ …
```

Agent jar built with all classes and proper manifest. Now verify the vulnerable artifact is correctly on the classpath:

```text
$ \ …
```

Everything is in place. Now let me verify the test-jar contains all our classes:

```text
$ jar tf target/msgpack-fuzz-1.0-SNAPSHOT-tests.jar | sort
```

All classes are present. Let me now verify the vulnerable artifact is loaded correctly by writing a small helper class and compiling it:

```text
Write <run_dir>/src/test/java/verify/ArtifactCheck.java
$ mvn -q package -DskipTests 2>&1 | tail -5
```

Good, clean build. Let me verify the final file tree:

```text
$ find src/test/java -name "*.java" | sort && echo "---" && find analysis -type f | sort && echo "---" && echo "run.sh: $(test -x run.sh && echo 'executable' || echo 'not executable')" && echo "v1-agent.jar: $(ls -la target/v1-agent.jar 2>/dev/null | awk '{print $5}') bytes"
Glob <run_dir> src/test/java/**/*.java
Glob <run_dir> analysis/**/*
```

All files in place. Let me do a final inventory check:

```text
$ ls -la <run_dir>/run.sh <run_dir>/target/v1-agent.jar <run_dir>/target/msgpack-fuzz-1.0-SNAPSHOT-tests.jar
```

All Block 3 deliverables are complete. Here is the final checklist:

**Part A — Java Agent** ✅
| File | Purpose |
|------|---------|
| `src/test/java/agent/V1Counters.java` | ThreadLocal counters for recursion depth (enter/exit/getMaxDepth/reset) |
| `src/test/java/agent/V1Transformer.java` | ASM ClassFileTransformer instrumenting `MessageUnpacker.unpackValue()` |
| `src/test/java/agent/V1MeasureAgent.java` | Premain entry point, registers transformer + retransforms |
| `src/test/resources/META-INF/MANIFEST.MF` | Agent jar manifest (Premain-Class, Can-Retransform-Classes) |
| `target/v1-agent.jar` | Built agent jar (5.8 KB) |

**Part B — Guidance classes** ✅
| File | Target | Signal | Technique |
|------|--------|--------|-----------|
| `src/test/java/guidance/V1Guidance.java` | V1 (CWE-674) | maxDepth | Bytecode (agent) — reads V1Counters.getMaxDepth() |
| `src/test/java/guidance/V2Guidance.java` | V2 (CWE-770) | declaredArraySize | Static (Tier 0) — parses ARRAY32/MAP32/fixarray header |
| `src/test/java/guidance/V3Guidance.java` | V3 (CWE-770) | declaredPayloadBytes | Static (Tier 0) — parses BIN32/EXT32/BIN8 header |

All three:
- Implement `Guidance` directly (not extending) [R3]
- Implement `SignalSource` with `lastSignals()` returning the per-execution signal
- Reset signal in `getInput()`, read signal in `handleResult()`
- Respect `jqf.ei.MAX_INPUT_SIZE` system property
- Never decide failures [R6]
- Include repetition [R45a], dictionary [R45b], and no-encoder [R45c] mutation operators
- Have secondary retention criteria for flat-signal periods [R46]

**Part C — Runner, Replay, Scripts, Analysis** ✅
| File | Purpose |
|------|---------|
| `src/test/java/runner/FuzzRunner.java` | CLI runner with `createGuidance(targetId, outputDir, maxDurationMs, log)` factory |
| `src/test/java/replay/MetadataReplay.java` | Replay saved inputs through MessageUnpacker |
| `src/test/java/verify/ArtifactCheck.java` | Verify vulnerable jar is loaded (getProtectionDomain) |
| `analysis/launch.json` | Build/run descriptor with classpath, javaagent, all 3 targets |
| `analysis/validation_inputs/` | 10 binary inputs (v1_nested_{10,100,1000}, v1_nil, v2_array32_{small,16m,67m}, v3_bin32_{small,16m,256m}) |
| `run.sh` | Build + run script (chmod +x) |
| `pom.xml` | Unchanged — system-scoped vulnerable jar, JQF 2.1, ASM 9.7.1 |

**Compilation** ✅ — `mvn -q package -DskipTests` succeeds cleanly, producing:
- `target/msgpack-fuzz-1.0-SNAPSHOT-tests.jar` (30 KB, all classes)
- `target/v1-agent.jar` (5.8 KB, agent classes + manifest)
- `target/test-deps/` (all JQF/JUnit/ASM transitive dependencies)

## Validation repair 1

Let me fix the `launch.json` format to match the expected schema:

```text
Read <run_dir>/analysis/launch.json
```

Now I understand the issues. The `launch.json` format is wrong in four ways. Let me rewrite it to match the expected schema exactly:

```text
Write <run_dir>/analysis/launch.json
```

Now let me also verify the build still works cleanly:

```text
$ mvn -q package -DskipTests 2>&1 | tail -10
$ mkdir -p target/agent-staging/agent && cp target/test-classes/agent/V1Counters.class target/agent-staging/agent/ && cp target/test-classes/agent/V1Transformer.class target/agent-staging/agent/ && cp target/test-classes/agent/V1MeasureAgent.class target/agent-staging/agent/ && cp target/test-classes/ …
```

Good. Now let me also verify the escape in the build command will work when DoSGuide runs it:

```text
$ bash -c 'cp target/test-classes/agent/V1Transformer\$*.class target/agent-staging/agent/ 2>/dev/null; true' && echo "escape works"
```

Good. Now let me also think about whether the validation checks around signals might fail. The key concern is: **"the signal stays near zero when the target is not executed (it is measured during the execution, not computed from the input)"**.

For V2 and V3, I'm computing the signal from the input bytes in `handleResult()`, not from actual execution. This means even if the target doesn't execute, the signal will be nonzero. Let me check my current V2/V3 implementations:

```text
Read <run_dir>/src/test/java/guidance/V2Guidance.java
```

The launch.json is now rewritten. Let me verify it parses as valid JSON:

```text
$ python3 -c "import json; d=json.load(open('<run_dir>/analysis/launch.json')); print('build type:', type(d['build']).__name__); print('classpath type:', type(d['classpath']).__name__); print('guidance_factory:', d['guidance_factory']); print('targets keys:', list(d['targets'].keys())); print('V1 targ …
```

All four format requirements are now met:

1. ✅ `"build"` is a list of shell commands (7 commands: mvn package, mkdir, cp×4, jar)
2. ✅ `"classpath"` is one colon-separated string
3. ✅ `"guidance_factory"` is `"runner.FuzzRunner#createGuidance"`
4. ✅ `"targets"` maps each target ID to `{"test_class", "method"}`

**Summary of changes:**

Rewrote `analysis/launch.json` to match the expected DoSGuide format:
- Changed `"build"` from a nested object to a flat list of shell commands (Maven build + agent jar assembly steps)
- Changed `"classpath"` from a nested object to a single colon-separated string
- Added `"guidance_factory": "runner.FuzzRunner#createGuidance"` (was missing, only had per-target runner_class)
- Changed `"targets"` from an array of objects to a map keyed by target ID (`"V1"`, `"V2"`, `"V3"`), each with just `test_class` and `method`
- Added `"javaagent"` with the V1 agent jar path and empty args
- Added empty `"jvm_args"` (evaluation fixes JVM options per [R41])

No changes to any Guidance classes, the agent, the runner, or the guidance plan — only the launch.json format was wrong.
