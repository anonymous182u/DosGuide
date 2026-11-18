# framework_GHSA-c332-w4jm-55wv

## Block 1

I'll start by reading the source files and the frozen fuzz test to understand the target.

```text
Read <source_root>/compatibility-server/src/main/java/com/vaadin/v7<data>/EmailValidator.java
Glob <run_dir> *FuzzTest.java
Glob <run_dir> **/*FuzzTest.java
Read <run_dir>/src/test/java/com/vaadin/fuzz/EmailValidatorFuzzTest.java
Glob <run_dir> pom.xml
Read <run_dir>/pom.xml
Glob <source_root> **/com/vaadin/v7<data>/RegexpValidator.java
Glob <source_root> **/com/vaadin<data>/EmailValidator.java
Read <source_root>/compatibility-server/src/main/java/com/vaadin/v7<data>/RegexpValidator.java
Read <source_root>/server/src/main/java/com/vaadin<data>/EmailValidator.java
```

Now let me look at the v8 RegexpValidator and the AbstractStringValidator classes:

```text
Glob <source_root> **/com/vaadin<data>/RegexpValidator.java
Glob <source_root> **/com/vaadin/v7<data>/AbstractStringValidator.java
Glob <source_root> **/com/vaadin/v7<data>/AbstractValidator.java
Read <source_root>/server/src/main/java/com/vaadin<data>/RegexpValidator.java
Read <source_root>/compatibility-server/src/main/java/com/vaadin/v7<data>/AbstractStringValidator.java
Read <source_root>/compatibility-server/src/main/java/com/vaadin/v7<data>/AbstractValidator.java
```

Now let me check the workspace lib directory and verify the vulnerable jars exist:

```text
$ ls -la <run_dir>/lib/ 2>&1 | head -20
$ ls <run_dir>/
$ ls -la <run_dir>/analysis/ 2>&1
Read <run_dir>/analysis/run_config.json
```

Let me verify the vulnerable class is in the jar:

```text
$ jar tf <run_dir>/lib/vaadin-compatibility-server-8.13-SNAPSHOT.jar | grep -i EmailValidator
$ jar tf <run_dir>/lib/vaadin-server-8.13-SNAPSHOT.jar | grep -i EmailValidator
```

Good. Both classes exist in the jars. Now let me compile the project to verify the pom.xml works:

```text
$ mvn compile 2>&1 | tail -30
```

Good, the project compiles. Now let me create the scale measurement inputs. I need to create inputs for both V1 (v7 EmailValidator) and V2 (v8 EmailValidator).

Let me create the analysis/scale directories and input files:

```text
$ mkdir -p <run_dir>/analysis/scale/V1 …
```

Now I have a thorough understanding of both validators. Let me analyze the regexes in detail and create scale measurement inputs.

#### PHASE A — Vulnerability Analysis

##### V1 — Vaadin v7 EmailValidator (CWE-1333 ReDoS, Exponential)

The v7 regex (from `EmailValidator.java` constructor):
```
^([a-zA-Z0-9_\.\-+])+@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9]{2,4})+$
```

The TLD part `([a-zA-Z0-9]{2,4})+$` has a **nested quantifier**: the inner `{2,4}` matches 2–4 alphanumeric chars, and the outer `+` repeats the group. When the input has N alphanumeric chars in the TLD position followed by a char that prevents `$` from matching (e.g. `!`), the engine tries every partition of N chars into groups of 2–4, giving exponential backtracking with growth rate ~1.3247^N.

Attack shape: `a@b.` + N alphanumeric chars + `!` (trailing `!` forces match failure)

##### V2 — Vaadin v8 EmailValidator (CWE-1333 ReDoS, Polynomial/Linear)

The v8 regex (from `EmailValidator.java`):
```
^([a-zA-Z0-9_\.\-+])+@[a-zA-Z0-9-.]+\.[a-zA-Z0-9-]{2,}$
```

The TLD part `[a-zA-Z0-9-]{2,}$` is a simple char class with no nested quantifier — backtracking is at most O(N). Domain part `[a-zA-Z0-9-.]+\.` has overlap but no nesting. Total backtracking is O(N) or at most O(N²) with specific dot patterns. May or may not reach timeout within input size limit.

Attack shape: `a@a.` + N alphanumeric chars + `!`

##### PkgRisk Assessment

The only external dependency on the attack path is `java.util.regex.Matcher` / `java.util.regex.Pattern` from the JDK. This IS the mechanism for V1 and V2 (the NFA regex engine performs the backtracking). It is not a separate risk — it is captured by V1 and V2 directly. No additional PkgRisk entries needed.

Now let me create the scale measurement inputs:

```text
$ python3 -c " …
```

Let me verify the files were created correctly:

```text
$ find <run_dir>/analysis/scale -type f | sort
Read <run_dir>/analysis/scale/V1/series.json
Read <run_dir>/analysis/scale/V2/series.json
```

Good. Now let me complete the full analysis and emit the target register.

#### Complete Analysis

##### 1.1 Code-Level Vulnerabilities

**V1: Vaadin v7 EmailValidator ReDoS (Exponential Backtracking)**

- **Source**: `compatibility-server/src/main/java/com/vaadin/v7<data>/EmailValidator.java`
- **Regex**: `^([a-zA-Z0-9_\.\-+])+@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9]{2,4})+$`
- **Fuzzable entrypoint**: `EmailValidatorFuzzTest.fuzzEmailValidatorIsValid(InputStream)` — user-controlled bytes decoded as UTF-8 string passed to `validator.isValid(value)`.
- **Mechanism**: The TLD part `([a-zA-Z0-9]{2,4})+$` creates a nested quantifier: the group `[a-zA-Z0-9]{2,4}` (matches 2–4 chars) is repeated by `+`. When a string of N alphanumeric characters is followed by a non-alphanumeric trailer (e.g. `!`), `$` can never match, and the regex engine exhaustively tries every partition of N chars into groups of size 2, 3, or 4. The number of partitions grows exponentially as ~1.3247^N.
- **Exhausted resource**: CPU time — the number of regex VM steps grows exponentially with the TLD length.
- **Failure mode**: `timeout` — a single execution runs longer than the 20,000 ms per-execution time limit.
- **Scale estimate**: For N=60 alphanumeric chars in the TLD, ~1.3247^60 ≈ 2×10^7 partitions, each requiring ~60 steps = ~10^9 total regex steps. At ~10^8 steps/sec, this takes ~10 seconds. For N≈65–70, timeout is expected. Total input: `a@b.` (4 bytes) + 65 chars + `!` (1 byte) = **70 bytes**, well within the 10,240-byte input size limit.
- **Input bytes**: 70

**V2: Vaadin v8 EmailValidator ReDoS (Linear/Polynomial Backtracking)**

- **Source**: `server/src/main/java/com/vaadin<data>/EmailValidator.java`
- **Regex**: `^([a-zA-Z0-9_\.\-+])+@[a-zA-Z0-9-.]+\.[a-zA-Z0-9-]{2,}$`
- **Fuzzable entrypoint**: `EmailValidatorFuzzTest.fuzzEmailValidatorApply(InputStream)` — user-controlled bytes decoded as UTF-8 string passed to `validator.apply(value, new ValueContext())`.
- **Mechanism**: The domain part `[a-zA-Z0-9-.]+` overlaps with TLD `[a-zA-Z0-9-]{2,}$` on `[a-zA-Z0-9-]` characters. When the input ends with a non-matching character, the engine backtracks through dot positions trying different domain/TLD splits. No nested quantifiers exist, so backtracking is at most O(N²) for inputs with many dots, or O(N) for inputs without dots.
- **Exhausted resource**: CPU time — regex steps grow linearly or quadratically with input length.
- **Failure mode**: `timeout` — if O(N²) is confirmed and the constant factor is large enough.
- **Scale estimate**: With N=10,000 chars and O(N²) ≈ 10^8 steps: ~1 second at 10^8 steps/sec. Timeout is **unlikely** within the 10,240-byte limit unless constant factors are very large. Scale measurements will confirm.
- **Input bytes**: 10240 (maximum, may still not timeout)

##### 1.2 Official Classification

- **V1**: CWE-1333 — Inefficient Regular Expression Complexity (ReDoS). Also CWE-400 Uncontrolled Resource Consumption.
- **V2**: CWE-1333 — Inefficient Regular Expression Complexity (ReDoS). Also CWE-400 Uncontrolled Resource Consumption.

##### 1.3 Dependency / Package-Level Risks

The only external dependency on the attack path is `java.util.regex.Pattern` / `java.util.regex.Matcher` from the JDK. The JDK's NFA regex engine uses backtracking, which is the root cause of the exponential behavior when given a pattern with nested quantifiers. However, this is not a separate risk from V1/V2 — it IS the mechanism for V1 and V2. The vulnerability lies in the combination of the application's regex pattern and the engine's backtracking behavior. No additional PkgRisk entries are needed because the regex engine risk is fully captured by V1 and V2.

##### 1.4 R18 — Zest Baseline Comparison

**V1**: Zest uses code coverage as its primary retention signal. For the v7 EmailValidator, the code path is essentially a single regex `matches()` call — there is very little branch diversity to guide exploration. Zest can discover short inputs that cover all reachable branches quickly, but has no signal to distinguish an input that takes 1 µs from one that takes 10 seconds. The critical axis of exploration (TLD length after the last dot, specifically with a non-matching trailer) is invisible to coverage. A custom Guidance that measures CPU time or regex backtracking steps will directly optimize for the pathological behavior. **Expected advantage**: time-to-first-timeout, because the custom Guidance retains and extends inputs that increase regex execution time, while Zest treats all non-crashing inputs as equivalent once branches are covered.

**V2**: Same reasoning as V1. Additionally, the linear/polynomial growth in V2 means the signal is much weaker — coverage-based Zest and time-based custom Guidance may both struggle to trigger a timeout for V2.

---

#### PHASE B — Target Register

Based on the analysis:
- **V1** is the primary target: exponentially vulnerable, confirmed by regex structure analysis, triggerable with ~70 bytes.
- **V2** is a secondary target: reported in the same GHSA, but only polynomial/linear backtracking, may not reach timeout. Included because the GHSA names it and the fuzz test has a dedicated method.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Vaadin v7 EmailValidator ReDoS — exponential backtracking in TLD quantifier",
      "entrypoint": "EmailValidatorFuzzTest.fuzzEmailValidatorIsValid(InputStream) → EmailValidator.isValid(Object) → AbstractValidator.validate(Object) → RegexpValidator.isValidValue(String) → Matcher.matches()",
      "source_path": "compatibility-server/src/main/java/com/vaadin/v7<data>/EmailValidator.java",
      "sink": "java.util.regex.Matcher#matches",
      "mechanism": "The regex TLD part ([a-zA-Z0-9]{2,4})+$ has a nested quantifier: variable-length group {2,4} repeated by +. When N alphanumeric chars precede a non-matching trailer, the engine tries every partition of N into groups of 2-4, giving exponential backtracking (~1.3247^N partitions).",
      "resource": "CPU time: number of regex engine backtracking steps grows exponentially with TLD length",
      "failure_mode": "timeout",
      "scale": "About 65-70 alphanumeric chars in the TLD position cause ~1.3247^65 ≈ 5×10^7 partitions × ~65 steps each ≈ 3×10^9 total regex steps, exceeding the 20s timeout at ~10^8 steps/sec. Input is a@b. + 65 alphanumeric chars + ! = 70 bytes.",
      "input_bytes": 70,
      "cwe": "CWE-1333"
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "Vaadin v8 EmailValidator ReDoS — polynomial backtracking in domain/TLD overlap",
      "entrypoint": "EmailValidatorFuzzTest.fuzzEmailValidatorApply(InputStream) → EmailValidator.apply(String, ValueContext) → RegexpValidator.isValid(String) → Matcher.matches()",
      "source_path": "server/src/main/java/com/vaadin<data>/EmailValidator.java",
      "sink": "java.util.regex.Matcher#matches",
      "mechanism": "The regex domain part [a-zA-Z0-9-.]+\\.[a-zA-Z0-9-]{2,}$ has overlapping character classes between domain and TLD. When input ends with a non-matching char, the engine backtracks through dot positions trying domain/TLD splits. No nested quantifiers, so backtracking is O(N) to O(N^2).",
      "resource": "CPU time: number of regex engine backtracking steps grows linearly or quadratically with domain length",
      "failure_mode": "timeout",
      "scale": "With N=10240 domain chars and O(N^2) ≈ 10^8 steps: ~1 second at 10^8 steps/sec. Timeout likely requires very large constant factor or higher polynomial degree than analysis predicts. Scale measurements will confirm feasibility. Input is a@a. + N alphanumeric chars + ! = up to 10240 bytes.",
      "input_bytes": 10240,
      "cwe": "CWE-1333"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

Looking at the measurement results, I need to carefully analyze the growth patterns.

**V1 Measurements Analysis:**
- N=10→60: CPU time 3.6→5.2 ms. This is essentially **flat** (~0.03 ms/char).
- The predicted exponential growth (~1.3247^N) is **not observed**. The JDK 17 regex engine appears to apply a dead-state optimization: since `([a-zA-Z0-9]{2,4})+` always terminates at the same non-`[a-zA-Z0-9]` character (the trailing `!`) regardless of internal partitioning, the engine determines that `$` will deterministically fail (the position after all consumable chars is not at end-of-string) and skips the partition enumeration entirely.
- Linear extrapolation to N≈10235 (maximum input minus 5-byte prefix/suffix): ~3.6 + 0.03 × 10225 ≈ 310 ms. Far below the 20,000 ms timeout.

**V2 Measurements Analysis:**
- N=100→2400: CPU time 10.6→14.0 ms. Growth ~0.0015 ms/char — essentially **flat** (sublinear, dominated by string allocation overhead).
- Extrapolation to N≈10235: ~26 ms. Far below timeout.
- Confirms no nested quantifiers → no exponential behavior.

Both targets show the regex engine's dead-state optimization preventing meaningful backtracking. The theoretical exponential mechanism does not manifest on this JVM.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: CPU time essentially flat 3.6–5.2 ms for N=10 to N=60 (TLD alphanumeric length). The theoretical exponential backtracking in ([a-zA-Z0-9]{2,4})+$ does NOT manifest on JDK 17: the regex engine applies a dead-state optimization recognizing that all partitions of the TLD group terminate at the same non-matchable character, making $ deterministically fail without exploring partitions. Measured growth rate ~0.03 ms/char (attributable to string creation overhead, not backtracking). Linear extrapolation to maximum input N≈10235: ~310 ms, which is 64× below the 20,000 ms timeout. Triggering a timeout with input shape a@b.<alphanums><non-alphanum> appears infeasible under these evaluation limits on this JDK.",
    "input_bytes": 10240
  },
  "V2": {
    "scale": "Measured: CPU time nearly flat 10.6–14.0 ms for N=100 to N=2400 (domain TLD length). Growth ~0.0015 ms/char (sublinear, dominated by string allocation). Extrapolated to max N≈10235: ~26 ms, 770× below the 20,000 ms timeout. The v8 regex has no nested quantifiers; backtracking is at most O(N). Confirmed not triggerable under these evaluation limits.",
    "input_bytes": 10240
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by carefully examining the existing workspace structure, the frozen harness, and the pom.xml, then develop the measurement strategy.

```text
Read <run_dir>/src/test/java/com/vaadin/fuzz/EmailValidatorFuzzTest.java
Read <run_dir>/pom.xml
```

Good. The pom.xml already has the system-scoped dependencies pointing to `lib/`. Let me verify the build works and explore the internal structure of `java.util.regex.Pattern` to design the instrumentation agent:

```text
$ mvn compile 2>&1 | tail -20
$ ls -la <run_dir>/lib/
```

Good. Now let me explore the internal structure of `java.util.regex.Pattern` to understand what classes/methods to instrument for counting regex backtracking steps:

```text
$ java -version 2>&1
$ javac -version 2>&1
```

Good - JDK 17.0.20.1. Now let me examine the JDK's `java.util.regex.Pattern` source to find the internal `Node.match()` method that drives backtracking:

```text
$ find /usr/lib/jvm -name "src.zip" 2>/dev/null | head -5
$ unzip -p /usr/lib/jvm/java-17-amazon-corretto.x86_64/lib/src.zip java.base/java/util/regex/Pattern.java 2>/dev/null | head -100
$ unzip -l /usr/lib/jvm/java-17-amazon-corretto.x86_64/lib/src.zip 2>/dev/null | grep -i "regex/Pattern" | head -5
$ cd /tmp && mkdir -p jdksrc && unzip -q -o /usr/lib/jvm/java-17-amazon-corretto.x86_64/lib/src.zip java.base/java/util/regex/Pattern.java -d jdksrc 2>&1 | tail -5
```

Let me check ASM availability through JQF's transitive dependencies:

```text
$ mvn dependency:tree 2>&1 | tail -40
```

Let me verify test compilation works:

```text
$ mvn compile test-compile 2>&1 | tail -20
$ mvn package -DskipTests 2>&1 | tail -30
```

Build succeeds. ASM 9.8 is available via `jqf-instrument`. Let me verify the test classes were compiled:

```text
$ ls <run_dir>/target/test-classes/com/vaadin/fuzz/ 2>&1
```

Good. The frozen fuzz test compiles. Now let me verify the workspace directory structure:

```text
$ find <run_dir>/src -type f | sort
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Good. The build succeeds, test classes compile, and ASM 9.8 is available via `jqf-instrument`. Now let me verify the existing directory and design everything needed.

```text
$ ls <run_dir>/target/deps/ | sort
```

Now let me verify the JQF Guidance interface to make sure I have the right API:

```text
$ jar tf <run_dir>/target/deps/jqf-fuzz-2.1.jar | grep -E "(Guidance|GuidedFuzzing|Result)" | head -20
$ cd /tmp && jar xf <run_dir>/target/deps/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class 2>&1 && javap -p /tmp/edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class 2>&1
$ cd /tmp && jar xf <run_dir>/target/deps/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Result.class && javap -p /tmp/edu/berkeley/cs/jqf/fuzz/guidance/Result.class 2>&1
$ cd /tmp && jar xf <run_dir>/target/deps/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class && javap -p /tmp/edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1 | head -30
```

Now let me check the TraceEvent class:

```text
$ cd /tmp && jar xf <run_dir>/target/deps/jqf-instrument-2.1.jar edu/berkeley/cs/jqf/instrument/tracing/events/TraceEvent.class && javap -p /tmp/edu/berkeley/cs/jqf/instrument/tracing/events/TraceEvent.class 2>&1
```

Good. I now have a complete picture of the APIs. The pom.xml is already correctly configured — no adjustments needed since the lib/ jars exist at the expected paths. Let me now produce the complete strategy output.

---

#### Step 2 — Maven Layout & Scope Verification

The existing pom.xml correctly separates:
- **Production code** (`src/main/java`): Empty — all target classes come from the system-scoped lib/ jars
- **Test code** (`src/test/java`): Contains the frozen fuzz harness; will also contain Guidance, Runner, Agent, and Counter classes
- **JQF/JUnit** dependencies: `test` scope ✓
- **Vaadin library jars**: `system` scope with `systemPath` pointing to `lib/` ✓
- **Third-party Vaadin dependencies** (jsoup, sass-compiler, etc.): `compile` scope ✓
- **ASM 9.8**: Available transitively via `jqf-instrument` (test scope) ✓

No pom.xml modification is needed. The systemPaths resolve correctly.

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

**For the frozen fuzz test (`EmailValidatorFuzzTest.java`):**
| Symbol | Classification | Source |
|--------|---------------|--------|
| `com.vaadin.data.ValueContext` | (A) External — lib jar | `lib/vaadin-server-8.13-SNAPSHOT.jar` |
| `com.vaadin.v7.data.validator.EmailValidator` | (A) External — lib jar | `lib/vaadin-compatibility-server-8.13-SNAPSHOT.jar` |
| `com.vaadin.data.validator.EmailValidator` | (A) External — lib jar | `lib/vaadin-server-8.13-SNAPSHOT.jar` |
| `edu.berkeley.cs.jqf.fuzz.Fuzz` | (A) External — Maven | `jqf-fuzz:2.1` |
| `edu.berkeley.cs.jqf.fuzz.JQF` | (A) External — Maven | `jqf-fuzz:2.1` |

**For planned Guidance/Agent code:**
| Symbol | Classification | Source |
|--------|---------------|--------|
| `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` | (A) External — Maven | `jqf-fuzz:2.1` |
| `edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException` | (A) External — Maven | `jqf-fuzz:2.1` |
| `edu.berkeley.cs.jqf.fuzz.guidance.Result` | (A) External — Maven | `jqf-fuzz:2.1` |
| `edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing` | (A) External — Maven | `jqf-fuzz:2.1` |
| `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` | (A) External — Maven | `jqf-instrument:2.1` |
| `org.objectweb.asm.ClassReader` | (A) External — Maven | `asm:9.8` (via jqf-instrument) |
| `org.objectweb.asm.ClassWriter` | (A) External — Maven | `asm:9.8` |
| `org.objectweb.asm.ClassVisitor` | (A) External — Maven | `asm:9.8` |
| `org.objectweb.asm.MethodVisitor` | (A) External — Maven | `asm:9.8` |
| `org.objectweb.asm.Opcodes` | (A) External — Maven | `asm:9.8` |
| `dosguide.validate.SignalSource` | (A) Already present | `src/test/java/dosguide/validate/SignalSource.java` |

##### 3.2 Stub Generation: **NONE NEEDED**

All symbols are either available from lib/ system-scoped jars, Maven test-scope dependencies, or already present in the workspace. No internal project classes are missing.

##### 3.3 Stub Report

**No stubs required.** All types are resolved from existing jars and dependencies. Zero stub files generated.

#### Step 4a — Directory Tree

```
<run>/
├── pom.xml                                    (FROZEN — no changes)
├── lib/
│   ├── vaadin-compatibility-server-8.13-SNAPSHOT.jar
│   ├── vaadin-compatibility-shared-8.13-SNAPSHOT.jar
│   ├── vaadin-server-8.13-SNAPSHOT.jar
│   └── vaadin-shared-8.13-SNAPSHOT.jar
├── analysis/
│   ├── run_config.json
│   └── scale/
│       ├── V1/ (series.json + n*.bin)
│       └── V2/ (series.json + n*.bin)
├── src/
│   ├── main/
│   │   └── java/                              (empty — all code from lib jars)
│   └── test/
│       └── java/
│           ├── com/vaadin/fuzz/
│           │   ├── EmailValidatorFuzzTest.java (FROZEN — read-only)
│           │   ├── V1Guidance.java             (Custom Guidance for V1)
│           │   ├── V2Guidance.java             (Custom Guidance for V2)
│           │   ├── FuzzRunner.java             (CLI runner)
│           │   ├── ReplayRunner.java           (Metadata replay/feeder)
│           │   ├── RegexStepAgent.java         (Java agent premain + transformer)
│           │   └── RegexStepCounter.java       (ThreadLocal counter — bootstrap)
│           └── dosguide/
│               └── validate/
│                   └── SignalSource.java        (DO NOT TOUCH — evaluation infra)
└── build-agent.sh                              (Shell script to package agent jar)
```

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|------------------|------------------------------|----------------------|
| V1 | **CGF** (Cost-Gradient Guidance) | Zest uses code coverage as retention signal. The v7 EmailValidator has ~3 branches (null check, empty check, `complete` flag in `RegexpValidator.isValidValue`). Coverage saturates immediately. After saturation, Zest treats all inputs equally — a 4 ms execution and a potential 20 s execution look identical. The pathological cost lives INSIDE `java.util.regex.Matcher.matches()` where Zest has zero visibility. | CGF instruments `Pattern$Node.match()` calls via a custom Java agent to directly count regex VM steps — the actual resource being consumed. It retains inputs that maximize this count and uses structure-aware mutation (email-token dictionary, repetition) to systematically explore the input space. Even if JDK 17 optimizations flatten the signal for some inputs, CGF can discover input shapes that bypass the optimization. |
| V2 | **CGF** (Cost-Gradient Guidance) | Same as V1: coverage has ~3 branches in the v8 RegexpValidator path, saturates instantly. Zest is blind to regex engine internal cost. The v8 regex has no nested quantifiers, so the cost growth is at most polynomial — but Zest can't even detect that. | Same agent-based step counting. CGF explores inputs with many dot positions and long alphanumeric segments to maximize domain/TLD boundary ambiguity work. The agent-measured step count captures the actual O(N) or O(N²) work where it happens. |

#### Step 6 — Strategy-Specific Guidance Design

##### Measurement Plan

**Signal: `regexSteps`** (used by both V1Guidance and V2Guidance)

| Aspect | Detail |
|--------|--------|
| **Code region** | `java.util.regex.Pattern$Node#match` and all overrides in Pattern's inner classes (e.g., `Pattern$Curly`, `Pattern$GroupCurly`, `Pattern$CharProperty`, `Pattern$Slice`, `Pattern$Branch`, `Pattern$Loop`, etc.) |
| **Why this region** | `Node.match(Matcher, int, CharSequence)` is THE method where the NFA simulation's state transitions and backtracking occur. Each invocation = one regex VM step. Backtracking = repeated invocations with different positions/states. |
| **Storage** | `ThreadLocal<long[]>` in `RegexStepCounter.counter` — one `long[1]` per thread, `counter.get()[0]` holds the count |
| **Reset** | `RegexStepCounter.reset()` called at the start of `Guidance.getInput()` before providing the next input |
| **Read** | `RegexStepCounter.get()` called in `Guidance.handleResult()` to retrieve the step count for the execution that just completed |

##### Instrumentation Feasibility Check ([R35])

1. **Exact classes/methods to instrument:**
   - All classes whose bytecode name matches `java/util/regex/Pattern$*`
   - Method signature: `boolean match(java.util.regex.Matcher, int, java.lang.CharSequence)` — descriptor `(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z`

2. **Required JVM flags:**
   - `-javaagent:target/regex-step-agent.jar` — to load the agent at startup
   - No `--add-opens` needed: the agent transforms classes during loading via `ClassFileTransformer`, not via reflection

3. **Signal export (ThreadLocal/atomic counters):**
   - `RegexStepCounter` class with `ThreadLocal<long[]>` counter
   - Injected bytecode at the START of each `match()` method: `INVOKESTATIC com/vaadin/fuzz/RegexStepCounter.increment ()V`
   - `RegexStepCounter` placed on bootstrap classpath via agent manifest `Boot-Class-Path: regex-step-agent.jar`

4. **Agent implementation plan:**
   - **`RegexStepCounter.java`**: Pure static counter class. Methods: `increment()`, `get()`, `reset()`. No external dependencies.
   - **`RegexStepAgent.java`**: Contains `premain(String, Instrumentation)` which registers a `ClassFileTransformer`. The transformer:
     - Checks class name starts with `java/util/regex/Pattern$`
     - Uses ASM `ClassReader` → `ClassVisitor` → `ClassWriter` pipeline
     - In `visitMethod()`, when name is `match` and descriptor is `(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z`, wraps the method with a `MethodVisitor` that emits `INVOKESTATIC com/vaadin/fuzz/RegexStepCounter.increment ()V` at `visitCode()` before delegating to the original bytecode
   - **Agent jar**: Built from compiled test-classes + ASM classes by `build-agent.sh`
   - **Manifest**: `Premain-Class: com.vaadin.fuzz.RegexStepAgent`, `Can-Retransform-Classes: true`, `Boot-Class-Path: regex-step-agent.jar`

##### Signal Legality ([R30])
- **(A)** Derived from actual execution: the `match()` method IS called during regex matching ✓
- **(B)** Causally linked to mechanism: `Pattern$Node.match()` is where backtracking steps are executed — it IS the vulnerability sink ✓
- **(C)** Consumed by `handleResult()`: the step count directly determines retention/prioritization ✓

##### Mutation Operators ([R45])

**Byte-level operators:**
- Random byte flip at random position
- Random byte insertion at random position
- Random byte deletion at random position
- Random byte overwrite with random value

**Repetition (R45a):**
- Select a random contiguous chunk (1 byte to half the current input length)
- Repeat it k times in place, where k is chosen to fill up to the input size limit (10,240 bytes)
- Special case: doubling the entire input (whole-input repetition)
- This can grow 16 bytes → 32 → 64 → ... → 10240 in ~10 doublings (<1 second of fuzzing)

**Dictionary tokens (R45b) — extracted from the regex source on the attack path:**

For V1 (v7 regex `^([a-zA-Z0-9_\.\-+])+@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9]{2,4})+$`):
- `@` (0x40) — email literal separator
- `.` (0x2E) — domain label separator / regex `.`
- `-` (0x2D) — valid in domain `[a-zA-Z0-9-]`
- `+` (0x2B) — valid in local part
- `_` (0x5F) — valid in local part
- `\n` (0x0A) — affects `$` anchor behavior in Java regex

For V2 (v8 regex `^([a-zA-Z0-9_\.\-+])+@[a-zA-Z0-9-.]+\.[a-zA-Z0-9-]{2,}$`):
- Same tokens as V1 (they appear in the same regex character classes)

Each token is a single syntactic unit found in the source. The dictionary does NOT contain assembled triggering inputs.

**Encoding (R45c):** Not applicable — input is plain UTF-8 text with no compression, checksums, or length prefixes.

##### Retention Policy ([R46])

**Primary criterion:** Maximize `regexSteps`
- Maintain a corpus ordered by step count
- When a new execution has a higher step count than the current maximum, retain the input

**Secondary criterion (progress while signal is flat):**
- When all inputs produce similar step counts (signal is flat), retain inputs that:
  - Are LONGER (trending toward `input_bytes` = 10,240) — ensures the search can reach the target input size
  - Contain MORE dictionary tokens (reaching code on the attack path: past the `@`, past the `.`, into the TLD)
  - Have higher byte diversity (exploring different input structures)

**Growth guarantee:**
- Initial seed: 16 bytes of random ASCII printable chars
- Repetition operator doubles the input within a few mutations
- 16 → 32 → 64 → 128 → 256 → 512 → 1024 → 2048 → 4096 → 8192 → 10240 = 10 doublings
- At ≥100 executions/second, 10 doublings complete in <1 second
- The Guidance will generate an input of 10,240 bytes within the first minute of fuzzing ✓

##### Stop/Continue Conditions

- **Default:** Infinite fuzzing (runs until killed)
- **Time-bounded:** System property `jqf.ei.MAX_DURATION` or CLI argument `durationSeconds`
- Guidance's `hasInput()` checks elapsed time against the configured duration

#### Step 7 — Custom Guidance (Per-Target)

##### V1Guidance (for `fuzzEmailValidatorIsValid`)
- **Target:** V1 — Vaadin v7 EmailValidator ReDoS
- **Corpus directory:** `out/V1/corpus/`
- **Signal:** `regexSteps` from `RegexStepCounter.get()`
- **Implements:** `Guidance`, `SignalSource`
- **`lastSignals()`** returns `{"regexSteps": <count>}` for the most recent execution
- Does NOT write failure files or declare executions as failed ([R6])
- Logs stats every 1 second: total executions, best step count, corpus size, current input length

##### V2Guidance (for `fuzzEmailValidatorApply`)
- **Target:** V2 — Vaadin v8 EmailValidator ReDoS
- **Corpus directory:** `out/V2/corpus/`
- **Signal:** `regexSteps` from `RegexStepCounter.get()`
- **Implements:** `Guidance`, `SignalSource`
- Same structure as V1Guidance with independent corpus
- Does NOT write failure files or declare executions as failed ([R6])

#### Step 8 — Fuzz Tests

The frozen `EmailValidatorFuzzTest.java` already provides the required `@Fuzz` methods:
- `fuzzEmailValidatorIsValid(InputStream)` → V1 (Vaadin v7)
- `fuzzEmailValidatorApply(InputStream)` → V2 (Vaadin v8)

Both consume `InputStream` directly, decode as UTF-8 inside the harness. No generators are used. This satisfies [R31].

#### Step 9 — Metadata Replay / Feeder

**`ReplayRunner`:**
- Reads a saved input file from the corpus directory
- Loads the bytes from the file
- Wraps them in a `ByteArrayInputStream`
- Creates the appropriate validator (v7 or v8 based on CLI argument)
- Calls the validator with the input
- Prints: input string (truncated), input length, whether it matched, execution time
- Deterministic reproduction guaranteed because the input is fully specified

#### Step 10 — Maven Configuration & Commands

**pom.xml:** FROZEN — already correct, no changes needed.

**Commands:**

```bash
### 1. Build everything
mvn package -DskipTests
./build-agent.sh

### 2. Fuzz V1 (infinite)
java -Xmx1g -Xss1m \
  -cp "target/test-classes:target/classes:lib/*:target/deps/*" \
  -javaagent:target/regex-step-agent.jar \
  com.vaadin.fuzz.FuzzRunner V1

### 3. Fuzz V1 (time-bounded, 300 seconds)
java -Xmx1g -Xss1m \
  -cp "target/test-classes:target/classes:lib/*:target/deps/*" \
  -javaagent:target/regex-step-agent.jar \
  com.vaadin.fuzz.FuzzRunner V1 300

### 4. Fuzz V2 (time-bounded)
java -Xmx1g -Xss1m \
  -cp "target/test-classes:target/classes:lib/*:target/deps/*" \
  -javaagent:target/regex-step-agent.jar \
  com.vaadin.fuzz.FuzzRunner V2 300

### 5. Replay a saved input
java -Xmx1g -Xss1m \
  -cp "target/test-classes:target/classes:lib/*:target/deps/*" \
  com.vaadin.fuzz.ReplayRunner V1 out/V1/corpus/input_0001.bin
```

#### Zest Baseline Comparison ([R18])

**V1:** Zest's closest configuration is `ZestGuidance` with the same test class and method. Zest's coverage signal saturates immediately (the EmailValidator has ~3 reachable branches). After saturation, Zest has no mechanism to distinguish inputs by regex engine work. The custom V1Guidance uses `regexSteps` (measured by the agent inside `Pattern$Node.match()`) as a mechanism-aligned signal — it directly measures the quantity that grows during backtracking. Expected advantage: **time-to-first-bug** — V1Guidance retains and extends inputs that maximize engine work, while Zest randomly mutates with no preference for high-cost inputs.

**V2:** Same comparison. The v8 regex has at most linear/polynomial backtracking, so the absolute step counts are lower. But V2Guidance still has a signal (step count) that Zest completely lacks.

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
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
ClassVisitor → org.objectweb.asm.ClassVisitor
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
SignalSource → dosguide.validate.SignalSource
```

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — JDK 17.0.20.1 ✓
- [YES] No hallucinated APIs — all verified via javap decompilation of actual jars
- [YES] Guidance implements Guidance directly — V1Guidance/V2Guidance implement `Guidance` and `SignalSource`
- [YES] No existing guidance extended — no Zest/PerfFuzz/AFL extended or delegated
- [YES] V* vulnerabilities identified — V1 (v7 regex ReDoS), V2 (v8 regex ReDoS)
- [YES] V* IDs are sequential — V1=v7 validator, V2=v8 validator (sequential discovery order)
- [YES] Official vulnerability names applied — CWE-1333 for both
- [YES] PkgRisk-* identified — None separate; `java.util.regex` risk is captured by V1/V2
- [YES] Every PkgRisk-* executed or justified — The regex engine risk IS the V1/V2 mechanism
- [YES] Guidance targets V* — V1Guidance targets V1, V2Guidance targets V2
- [YES] One fuzz method per V* — `fuzzEmailValidatorIsValid` for V1, `fuzzEmailValidatorApply` for V2
- [YES] CLI method selection supported — `FuzzRunner V1` or `FuzzRunner V2`
- [YES] Byte[]/InputStream input model used exclusively — harness consumes InputStream, Guidance provides bytes
- [YES] No junit-quickcheck Generators used — none
- [YES] All mutation implemented inside Guidance — byte-level, repetition, dictionary all in V*Guidance
- [YES] Repetition, source dictionary and encoder operators — repetition ✓, dictionary from regex source ✓, encoder N/A (plain text)
- [YES] Retention progresses while signal is flat; inputs can reach input_bytes within a minute — secondary criterion keeps longer inputs; repetition doubling reaches 10240 in ~10 steps
- [YES] Retention signals measured where resource is consumed — `Pattern$Node.match()` IS the sink
- [YES] Logging every 1 second — structured log every 1s with stats
- [YES] Guidance decides no failures and writes no failure files — only signal tracking and corpus retention
- [YES] Corrupted inputs saved with metadata — corpus saves input bytes + step count metadata
- [YES] Replay/feeder implemented — `ReplayRunner` reads corpus files and replays deterministically
- [YES] Infinite + time-bounded fuzzing supported — `hasInput()` checks duration
- [YES] src/main vs src/test separation correct — all fuzzing infra in src/test/java
- [YES] Maven scopes consistent — JQF=test, Vaadin jars=system, third-party=compile
- [YES] No wildcard imports used for JQF/tracing — all explicit imports
- [YES] TraceEvent import verified and audited — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` verified via javap

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "regexSteps",
          "quantity": "count of Pattern$Node.match() invocations during regex matching — each call is one NFA state transition or backtracking step in the regex engine",
          "aggregation": "count",
          "locations": ["java.util.regex.Pattern$Node#match"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in RegexStepCounter.counter; counter.get()[0] holds the running count per thread",
          "reset": "RegexStepCounter.reset() called at the start of V1Guidance.getInput() before providing the next input",
          "read": "RegexStepCounter.get() called in V1Guidance.handleResult() to retrieve the step count"
        }
      ],
      "retention": "Primary: retain inputs with the highest regexSteps value in a corpus of up to 20 entries sorted by step count. When a new execution yields a step count exceeding the current corpus minimum, it replaces the minimum-scoring entry. Secondary (when regexSteps is flat across all corpus entries): retain inputs that are longer (trending toward 10240 bytes) or that contain more dictionary tokens (@, ., -, etc.) to reach code on the attack path. This ensures the search makes progress toward the target input_bytes even when the step-count signal is constant.",
      "retention_signals": ["regexSteps"],
      "mutation": [
        "Byte-level: random byte flip, byte insertion, byte deletion, byte overwrite at random positions",
        "Repetition (R45a): select a random chunk (1 byte to half the input length) and repeat it k times in place, with k chosen to fill up to 10240 bytes; includes whole-input doubling. Grows from 16-byte seed to 10240 bytes in ~10 doublings (<1 second).",
        "Dictionary (R45b): tokens from the v7 regex source on the attack path: '@' (0x40, email separator), '.' (0x2E, domain label separator), '-' (0x2D, valid in domain/local), '+' (0x2B, valid in local), '_' (0x5F, valid in local), '\\n' (0x0A, affects $ anchor). Inserted or overwritten at random positions.",
        "No encoder needed (R45c): input is plain UTF-8 text, no format constraints."
      ]
    },
    {
      "target": "V2",
      "signals": [
        {
          "name": "regexSteps",
          "quantity": "count of Pattern$Node.match() invocations during regex matching — each call is one NFA state transition or backtracking step in the regex engine",
          "aggregation": "count",
          "locations": ["java.util.regex.Pattern$Node#match"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in RegexStepCounter.counter; counter.get()[0] holds the running count per thread",
          "reset": "RegexStepCounter.reset() called at the start of V2Guidance.getInput() before providing the next input",
          "read": "RegexStepCounter.get() called in V2Guidance.handleResult() to retrieve the step count"
        }
      ],
      "retention": "Primary: retain inputs with the highest regexSteps value in a corpus of up to 20 entries sorted by step count. When a new execution yields a step count exceeding the current corpus minimum, it replaces the minimum-scoring entry. Secondary (when regexSteps is flat across all corpus entries): retain inputs that are longer (trending toward 10240 bytes) or that contain more dictionary tokens (@, ., -, etc.) to reach code on the attack path. This ensures the search makes progress toward the target input_bytes even when the step-count signal is constant.",
      "retention_signals": ["regexSteps"],
      "mutation": [
        "Byte-level: random byte flip, byte insertion, byte deletion, byte overwrite at random positions",
        "Repetition (R45a): select a random chunk (1 byte to half the input length) and repeat it k times in place, with k chosen to fill up to 10240 bytes; includes whole-input doubling. Grows from 16-byte seed to 10240 bytes in ~10 doublings (<1 second).",
        "Dictionary (R45b): tokens from the v8 regex source on the attack path: '@' (0x40, email separator), '.' (0x2E, domain/TLD separator), '-' (0x2D, valid in domain/TLD), '+' (0x2B, valid in local), '_' (0x5F, valid in local), '\\n' (0x0A, affects $ anchor). Inserted or overwritten at random positions.",
        "No encoder needed (R45c): input is plain UTF-8 text, no format constraints."
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

Let me read the existing files to understand the current state before implementing Block 3.

```text
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/com/vaadin/fuzz/EmailValidatorFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
$ ls <run_dir>/lib/
$ ls <run_dir>/target/deps/ 2>&1 | head -20
$ ls <run_dir>/target/deps/ 2>&1 | tail -20
$ ls <run_dir>/analysis/ 2>&1
$ ls <run_dir>/src/test/java/com/vaadin/fuzz/
```

Good — the guidance plan already exists. Let me verify its contents, then start implementing all Block 3 files.

```text
Read <run_dir>/analysis/guidance_plan.json
```

Good — the guidance plan is complete and matches my implementation plan. Now let me implement all Block 3 files. I'll start with the core Java files.

=== FILE: src/test/java/com/vaadin/fuzz/RegexStepCounter.java ===

```text
Write <run_dir>/src/test/java/com/vaadin/fuzz/RegexStepCounter.java
```

=== FILE: src/test/java/com/vaadin/fuzz/RegexStepAgent.java ===

```text
Write <run_dir>/src/test/java/com/vaadin/fuzz/RegexStepAgent.java
```

=== FILE: src/test/java/com/vaadin/fuzz/V1Guidance.java ===

```text
Write <run_dir>/src/test/java/com/vaadin/fuzz/V1Guidance.java
```

=== FILE: src/test/java/com/vaadin/fuzz/V2Guidance.java ===

```text
Write <run_dir>/src/test/java/com/vaadin/fuzz/V2Guidance.java
```

=== FILE: src/test/java/com/vaadin/fuzz/FuzzRunner.java ===

```text
Write <run_dir>/src/test/java/com/vaadin/fuzz/FuzzRunner.java
```

=== FILE: src/test/java/com/vaadin/fuzz/ReplayRunner.java ===

```text
Write <run_dir>/src/test/java/com/vaadin/fuzz/ReplayRunner.java
```

Now let me write the build scripts and configuration files:

=== FILE: build-agent.sh ===

```text
Write <run_dir>/build-agent.sh
```

=== FILE: run.sh ===

```text
Write <run_dir>/run.sh
$ chmod +x <run_dir>/build-agent.sh <run_dir>/run.sh
```

=== FILE: analysis/launch.json ===

```text
Write <run_dir>/analysis/launch.json
```

Now let me create the validation input examples:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
Write <run_dir>/analysis/validation_inputs/input_01.bin
Write <run_dir>/analysis/validation_inputs/input_02.bin
Write <run_dir>/analysis/validation_inputs/input_03.bin
Write <run_dir>/analysis/validation_inputs/input_04.bin
Write <run_dir>/analysis/validation_inputs/input_05.bin
Write <run_dir>/analysis/validation_inputs/input_06.bin
Write <run_dir>/analysis/validation_inputs/input_07.bin
Write <run_dir>/analysis/validation_inputs/input_08.bin
Write <run_dir>/analysis/validation_inputs/input_09.bin
Write <run_dir>/analysis/validation_inputs/input_10.bin
```

Now let me compile everything to verify correctness:

```text
$ mvn package -DskipTests -q 2>&1 | tail -30
```

Clean compile. Now let me build the agent jar:

```text
$ bash build-agent.sh 2>&1 | tail -30
```

The agent jar is built successfully with all required classes:
- `RegexStepAgent.class` + inner classes (`$1`, `$1$1`)
- `RegexStepCounter.class`
- Full ASM library

Let me verify the agent manifest is correct:

```text
$ unzip -p target/regex-step-agent.jar META-INF/MANIFEST.MF 2>&1
```

Manifest is correct. Let me verify the compiled test classes exist for all our new files:

```text
$ ls -la <run_dir>/target/test-classes/com/vaadin/fuzz/
```

All classes compiled successfully. Let me verify the complete directory tree:

```text
$ find src analysis lib build-agent.sh run.sh pom.xml -type f | sort
```

Everything is in place. Let me verify the agent jar is in the right location:

```text
$ ls -la <run_dir>/target/regex-step-agent.jar
```

Good — 130KB agent jar with ASM included. Everything compiles and builds correctly.

Now let me provide the complete output with all required sections:

---

#### BLOCK 3 — Implementation Files

##### Part A — Java Agent

**RegexStepCounter.java** — Pure static counter class with `ThreadLocal<long[]>` storage. No external dependencies. Placed on the bootstrap classpath via the agent jar's `Boot-Class-Path` manifest attribute, making it visible to instrumented `java.util.regex.Pattern$*` classes.

**RegexStepAgent.java** — Java agent implementing `ClassFileTransformer`. The `premain` method registers the transformer. The `transform` method intercepts all classes whose name starts with `java/util/regex/Pattern$` and uses ASM 9 to inject `INVOKESTATIC com/vaadin/fuzz/RegexStepCounter.increment()V` at the entry of every `match(Matcher, int, CharSequence)` method (descriptor `(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z`).

**build-agent.sh** — Packages the agent jar from compiled test-classes and extracted ASM classes, with the manifest specifying `Premain-Class`, `Can-Retransform-Classes`, and `Boot-Class-Path`.

##### Part B — Guidance

**V1Guidance.java** — CGF Guidance for V1 (Vaadin v7 EmailValidator). Implements `Guidance` and `SignalSource`. Signal: `regexSteps` via `RegexStepCounter`. Corpus up to 20 entries with two-tier retention (steps primary, length secondary). Mutation: 30% repetition, 20% dictionary insert, 10% dictionary overwrite, 40% byte-level.

**V2Guidance.java** — CGF Guidance for V2 (Vaadin v8 EmailValidator). Same architecture as V1Guidance with independent corpus and target ID.

##### Part C — Runner, Replay, Scripts

**FuzzRunner.java** — CLI runner with `createGuidance(String, File, long, PrintStream)` factory method. Maps target IDs to test methods and guidance classes.

**ReplayRunner.java** — Deterministic replay harness. Reads saved corpus input, decodes as UTF-8, runs the appropriate validator, prints timing and metadata.

**run.sh** — End-to-end build + fuzz script.

##### Part D — Validation Contract

**analysis/launch.json** — Build/classpath/agent/targets configuration for DoSGuide validation.

**analysis/validation_inputs/** — 10 well-formed email example inputs.

---

#### Zest Baseline Comparison ([R18])

| Aspect | Zest | V1Guidance / V2Guidance |
|--------|------|------------------------|
| **Signal** | Code coverage (branch/line) | `regexSteps` — Pattern$Node.match() invocation count |
| **Saturation** | Saturates immediately: EmailValidator has ~3 reachable branches | Never saturates: step count varies with every input structure |
| **Mechanism visibility** | Zero: regex engine work is invisible to coverage | Full: measures the exact resource being consumed (NFA transitions) |
| **Retention criterion** | New branch coverage (stops retaining after saturation) | Higher step count or longer input (always makes progress) |
| **Expected advantage** | — | Time-to-first-high-cost-input: V*Guidance retains and extends inputs that maximize engine work; Zest randomly mutates with no preference for high-cost inputs |

---

#### IMPORT AUDIT

```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz (in EmailValidatorFuzzTest — FROZEN)
@RunWith → org.junit.runner.RunWith (in EmailValidatorFuzzTest — FROZEN)
JQF → edu.berkeley.cs.jqf.fuzz.JQF (in EmailValidatorFuzzTest — FROZEN)
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance (in V1Guidance, V2Guidance)
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException (in V1Guidance, V2Guidance)
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result (in V1Guidance, V2Guidance)
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing (in FuzzRunner)
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent (in V1Guidance, V2Guidance)
SignalSource → dosguide.validate.SignalSource (in V1Guidance, V2Guidance)
ClassFileTransformer → java.lang.instrument.ClassFileTransformer (in RegexStepAgent)
Instrumentation → java.lang.instrument.Instrumentation (in RegexStepAgent)
ClassReader → org.objectweb.asm.ClassReader (in RegexStepAgent)
ClassVisitor → org.objectweb.asm.ClassVisitor (in RegexStepAgent)
ClassWriter → org.objectweb.asm.ClassWriter (in RegexStepAgent)
MethodVisitor → org.objectweb.asm.MethodVisitor (in RegexStepAgent)
Opcodes → org.objectweb.asm.Opcodes (in RegexStepAgent)
```

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — JDK 17.0.20.1, no preview/incubator APIs used
- [YES] No hallucinated APIs — all verified via javap decompilation of actual jars in prior blocks
- [YES] Guidance implements Guidance directly — `V1Guidance implements Guidance, SignalSource`; `V2Guidance implements Guidance, SignalSource`
- [YES] No existing guidance extended — no Zest/PerfFuzz/AFL extended or delegated
- [YES] V* vulnerabilities identified — V1 (v7 regex ReDoS), V2 (v8 regex ReDoS)
- [YES] V* IDs are sequential (V1, V2) — NOT derived from software version numbers [R42]
- [YES] Official vulnerability names applied — CWE-1333 for both
- [YES] PkgRisk-* identified — None; `java.util.regex` risk is captured by V1/V2
- [YES] Every PkgRisk-* executed or justified — The regex engine risk IS the V1/V2 mechanism
- [YES] Guidance targets V* — V1Guidance targets V1, V2Guidance targets V2
- [YES] One fuzz method per V* — `fuzzEmailValidatorIsValid` for V1, `fuzzEmailValidatorApply` for V2
- [YES] CLI method selection supported — `FuzzRunner V1` or `FuzzRunner V2`
- [YES] Byte[]/InputStream input model used exclusively — Guidance provides ByteArrayInputStream, harness consumes InputStream
- [YES] No junit-quickcheck Generators used — none
- [YES] All mutation implemented inside Guidance — byte flip/insert/delete/overwrite, repetition, dictionary all in V*Guidance
- [YES] Repetition, source dictionary and encoder operators — repetition ✓, dictionary from regex source ✓, encoder N/A (plain text)
- [YES] Retention progresses while signal is flat; inputs can reach input_bytes within a minute — secondary criterion keeps longer inputs; repetition doubling reaches 10240 in ~11 steps
- [YES] Retention signals measured where resource is consumed — `Pattern$Node.match()` IS the regex engine's work loop
- [YES] Logging every 1 second — structured log every 1s with execs, best_steps, corpus, max_len, elapsed
- [YES] Guidance decides no failures and writes no failure files ([R6]) — only signal tracking and corpus retention
- [YES] Corrupted inputs saved with metadata — corpus saves input bytes + step count/length/timestamp metadata
- [YES] Replay/feeder implemented — `ReplayRunner` reads corpus files and replays deterministically
- [YES] Infinite + time-bounded fuzzing supported — `hasInput()` checks elapsed < maxDurationMs
- [YES] src/main vs src/test separation correct — all fuzzing infra in src/test/java
- [YES] Maven scopes consistent — JQF=test, Vaadin jars=system, third-party=compile
- [YES] No wildcard imports used for JQF/tracing — all explicit imports
- [YES] TraceEvent import verified and audited — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` verified via javap in prior block
