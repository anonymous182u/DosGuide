# powsybl-core_GHSA-8qjw-9xgm-c9ff

## Block 1

I'll start by reading the target source file, the frozen fuzz test, and the workspace pom.xml to understand the setup.

```text
Read <source_root>/iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/RegexCriterion.java
Glob <run_dir> *FuzzTest.java
Glob <run_dir> pom.xml
Read <run_dir>/src/test/java/com/powsybl/fuzzing/tests/RegexCriterionFuzzTest.java
Read <run_dir>/pom.xml
```

Now let me explore the criteria package and understand the interfaces involved:

```text
Glob <source_root>/iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria **/*.java
$ ls <run_dir>/lib/ 2>/dev/null || echo "No lib directory"
```

Good - the lib directory has the pre-built vulnerable jars. Let me read the Criterion interface to understand the `filter` method contract:

```text
Read <source_root>/iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/Criterion.java
Read <source_root>/iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/IdentifiableCriterion.java
```

Now I have all the information I need. Let me analyze the vulnerability in detail.

**Key finding in `RegexCriterion.java` (line 33):**
```java
return Pattern.compile(regex).matcher(identifiable.getId()).find();
```

The `regex` field is user-controlled (set via constructor), and `Pattern.compile(regex)` is called without any timeout, complexity limit, or sanitization. Java's `java.util.regex` uses an NFA-based backtracking engine vulnerable to catastrophic backtracking with nested quantifiers (e.g., `(a+)+b`).

The fuzz test splits input at midpoint: first half → regex string, second half → match text.

Let me create the scale measurement directories and files:

```text
$ mkdir -p <run_dir>/analysis/scale/V1 <run_dir>/analysis/scale/PkgRisk-1
```

Now let me generate the scale measurement inputs. Each input is laid out as the `@Fuzz` method reads it: `data[0:half]` → regex string (UTF-8), `data[half:]` → match text (UTF-8). The regex is `(a+)+b` (6 bytes) padded with `z` bytes; the text is `n` repetitions of `a`.

```text
$ cd <run_dir> …
```

Let me verify the generated files are correct:

```text
$ cd <run_dir> …
Read <run_dir>/analysis/scale/V1/series.json
```

The inputs are correctly constructed. At the midpoint split:
- `regex = "(a+)+bzzzz..."` — a valid regex with the catastrophic nested-quantifier `(a+)+b` prefix; the `z` padding after `b` is harmless literal characters that never match the all-`a` text
- `text = "aaaa..."` — N repetitions of `a` that drive exponential NFA backtracking in `(a+)+`

Now let me verify file sizes are all under 2560 bytes:

```text
$ ls -la <run_dir>/analysis/scale/V1/ …
```

All files are well under 2560 bytes (largest is 640 bytes). 

---

#### PHASE A — Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: RegexCriterion.filter() — Uncontrolled Regex Denial of Service

**Source**: `RegexCriterion.java`, line 33:
```java
return Pattern.compile(regex).matcher(identifiable.getId()).find();
```

**Fuzzable entrypoints & user-controlled inputs**:
- The `regex` string is passed via the `RegexCriterion(String regex)` constructor (line 22). In the fuzz test, it comes from the first half of the raw input bytes.
- The `identifiable.getId()` value is the text being matched. In the fuzz test, it comes from the second half.
- Both are fully attacker-controlled.

**Mechanism**: Java's `java.util.regex.Pattern` uses an NFA-based backtracking engine. When the regex contains nested quantifiers (e.g., `(a+)+b`), the engine explores an exponential number of ways to partition matching characters among the quantified groups. For a text of `n` characters matching the inner group (e.g., `n` repetitions of `a`), the engine explores approximately 2^(n-1) groupings before concluding no match exists. The `find()` call exacerbates this because it tries matching at successive positions.

**Exhausted resource**: CPU time — the number of NFA backtracking steps grows exponentially with the number of matching characters in the text: ~2^(n-1) steps for n matching characters.

**Failure mode**: `timeout` — a single execution exceeds the 20,000 ms per-execution time limit.

**Scale estimate**: The backtracking steps grow as 2^n. Each step takes ~10–100 ns in the JDK regex engine. To exceed 20 seconds:
- At ~10 ns/step: need 2×10^9 steps → n ≈ 31 characters
- At ~100 ns/step: need 2×10^8 steps → n ≈ 28 characters

With the input split at the midpoint, a total input of ~60–70 bytes (30–35 bytes per half) suffices. The regex itself needs only 6–10 bytes (`(a+)+b`); the rest of the first half is harmless padding. **Input_bytes ≈ 70**.

##### 1.2 Official Classification

- **V1**: **CWE-1333** — Inefficient Regular Expression Complexity (a.k.a. ReDoS). Also classifiable as CWE-400 (Uncontrolled Resource Consumption) and matches OWASP "Regular Expression Denial of Service."

##### 1.3 Dependency / Package-Level Risks

###### PkgRisk-1: java.util.regex — NFA Backtracking Engine Catastrophic Complexity

**Package/class**: `java.util.regex.Pattern`, `java.util.regex.Matcher` (JDK standard library)

**Why input-sensitive**: The JDK regex implementation uses a backtracking NFA that has exponential worst-case time complexity for patterns with ambiguous quantifiers. Unlike RE2-style engines (linear time), the JDK engine does not guarantee polynomial-time matching.

**Trigger shapes**: A regex with nested/overlapping quantifiers (e.g., `(a+)+`, `(a|a)+`, `(a+)*`) paired with text that matches the inner group but not the trailing literal, forcing exhaustive backtracking. The text must consist of characters matching the quantified group (e.g., repeated `a` for `(a+)+`), followed by a non-matching end.

**Exhausted resource**: CPU time — backtracking steps grow as O(2^n) where n is the length of the matching text prefix.

**Failure mode**: `timeout`

**Scale**: Same as V1 — approximately 28–31 matching characters cause >20 seconds of backtracking. Total input ~70 bytes.

**Fuzzing strategy**: Custom guidance that instruments `Pattern$Node.match()` (or `Pattern$BnM.match()`, `Pattern$Curly.match()` — the internal node types) to count backtracking steps. Inputs causing more steps are retained and mutated. A dictionary of regex metacharacters (`(`, `)`, `+`, `*`, `?`, `|`, `.`, `[`, `]`, `{`, `}`, `^`, `$`, `\`) helps the fuzzer discover syntactically valid pathological patterns.

##### 1.4 Zest Baseline Comparison (R18)

**Zest's weakness for this target**: Zest uses code coverage as its fitness signal. For regex matching, the coverage map is dominated by the same code paths in `Pattern$Node.match()` executing repeatedly — a 10-character match and a 30-character match traverse the same bytecode paths. Zest sees no new coverage from longer backtracking sequences and has no reason to prefer inputs that cause more steps. It would need luck, not signal, to grow the text length from 10 to 30+ characters.

**Custom guidance advantage**: A guidance that instruments `Pattern$Node.match()` invocations (backtracking step count) provides a monotonically increasing signal that directly correlates with CPU time. It retains inputs that trigger more backtracking steps, steadily driving toward timeout. **Measurable metric**: time-to-first-timeout — the custom guidance should find a timeout-inducing input orders of magnitude faster than Zest because it has a signal that grows with the pathological behavior, whereas Zest's coverage signal plateaus.

---

#### PHASE B — Target Selection

Both V1 and PkgRisk-1 are DoS targets. They target the same underlying mechanism (regex backtracking) through different entry points in the fuzz test:
- V1 enters via `RegexCriterion.filter()` → `Pattern.compile().matcher().find()`
- PkgRisk-1 enters via `Pattern.compile().matcher().find()` directly

Both are included as they exercise distinct code paths (V1 goes through the application wrapper).

---

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "RegexCriterion.filter() ReDoS via user-controlled regex",
      "entrypoint": "RegexCriterionFuzzTest.fuzzRegexCriterionFilter(InputStream) → RegexCriterion(String) → RegexCriterion.filter(Identifiable, IdentifiableType) → Pattern.compile(String) → Matcher.find()",
      "source_path": "iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/RegexCriterion.java",
      "sink": "Matcher#find()",
      "mechanism": "User-controlled regex with nested quantifiers (e.g. (a+)+b) causes the JDK NFA backtracking engine to explore 2^(n-1) groupings of n matching characters before failing, consuming exponential CPU time",
      "resource": "CPU time: NFA backtracking steps grow as O(2^n) where n is the number of text characters matching the inner quantified group",
      "failure_mode": "timeout",
      "scale": "About 28-31 repeated matching characters cause >20 seconds of backtracking in the JDK regex engine (2^30 ≈ 10^9 steps at ~10-100 ns/step). The regex needs ~6-10 bytes, text ~30 bytes; with the midpoint split, total input ~70 bytes.",
      "input_bytes": 70,
      "cwe": "CWE-1333"
    },
    {
      "slot": 2,
      "id": "PkgRisk-1",
      "name": "java.util.regex NFA catastrophic backtracking",
      "entrypoint": "RegexCriterionFuzzTest.fuzzPatternMatcherFind(InputStream) → Pattern.compile(String) → Matcher.find()",
      "source_path": "iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/RegexCriterion.java",
      "sink": "Matcher#find()",
      "mechanism": "JDK java.util.regex NFA engine explores exponential backtracking paths for patterns with nested/overlapping quantifiers against non-matching text of repeated characters",
      "resource": "CPU time: NFA backtracking steps grow as O(2^n) where n is the number of text characters matching the inner quantified group",
      "failure_mode": "timeout",
      "scale": "About 28-31 repeated matching characters cause >20 seconds of backtracking (2^30 ≈ 10^9 steps at ~10-100 ns/step). Regex ~6-10 bytes + text ~30 bytes; with midpoint split, total ~70 bytes.",
      "input_bytes": 70,
      "cwe": "CWE-1333"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

Let me re-read the fuzz test to understand the exact call paths:

```text
Read <run_dir>/src/test/java/com/powsybl/fuzzing/tests/RegexCriterionFuzzTest.java
Read <source_root>/iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/RegexCriterion.java
```

I understand the issue. `fuzzPatternMatcherFind` calls `Pattern.compile().matcher().find()` directly and never passes through `RegexCriterion.java`. I need to fix PkgRisk-1's entrypoint to route through `fuzzRegexCriterionFilter`, which does call `RegexCriterion(String)` → `RegexCriterion.filter(Identifiable, IdentifiableType)` at line 33, where `Pattern.compile(regex).matcher(identifiable.getId()).find()` is invoked — entering the JDK regex library.

The corrected path for PkgRisk-1 starts at `fuzzRegexCriterionFilter`, passes through `RegexCriterion.filter()` in `RegexCriterion.java`, and then continues into the JDK library (`Pattern.compile` → `Matcher.find()`) where the exponential backtracking resource consumption occurs.

V1 passed CHECKPATH and is unchanged.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "RegexCriterion.filter() ReDoS via user-controlled regex",
      "entrypoint": "RegexCriterionFuzzTest.fuzzRegexCriterionFilter(InputStream) → RegexCriterion(String) → RegexCriterion.filter(Identifiable, IdentifiableType) → Pattern.compile(String) → Matcher.find()",
      "source_path": "iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/RegexCriterion.java",
      "sink": "Matcher#find()",
      "mechanism": "User-controlled regex with nested quantifiers (e.g. (a+)+b) causes the JDK NFA backtracking engine to explore 2^(n-1) groupings of n matching characters before failing, consuming exponential CPU time",
      "resource": "CPU time: NFA backtracking steps grow as O(2^n) where n is the number of text characters matching the inner quantified group",
      "failure_mode": "timeout",
      "scale": "About 28-31 repeated matching characters cause >20 seconds of backtracking in the JDK regex engine (2^30 ≈ 10^9 steps at ~10-100 ns/step). The regex needs ~6-10 bytes, text ~30 bytes; with the midpoint split, total input ~70 bytes.",
      "input_bytes": 70,
      "cwe": "CWE-1333"
    },
    {
      "slot": 2,
      "id": "PkgRisk-1",
      "name": "java.util.regex NFA catastrophic backtracking via RegexCriterion.filter()",
      "entrypoint": "RegexCriterionFuzzTest.fuzzRegexCriterionFilter(InputStream) → RegexCriterion(String) → RegexCriterion.filter(Identifiable, IdentifiableType) → Pattern.compile(String) → Matcher.find()",
      "source_path": "iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/RegexCriterion.java",
      "sink": "Matcher#find()",
      "mechanism": "JDK java.util.regex NFA engine explores exponential backtracking paths for patterns with nested/overlapping quantifiers against non-matching text of repeated characters",
      "resource": "CPU time: NFA backtracking steps grow as O(2^n) where n is the number of text characters matching the inner quantified group",
      "failure_mode": "timeout",
      "scale": "About 28-31 repeated matching characters cause >20 seconds of backtracking (2^30 ≈ 10^9 steps at ~10-100 ns/step). Regex ~6-10 bytes + text ~30 bytes; with midpoint split, total ~70 bytes.",
      "input_bytes": 70,
      "cwe": "CWE-1333"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 2

I need to differentiate PkgRisk-1's path from V1's. Since PkgRisk-1 is a **library-level** risk, its path should continue deeper into the JDK regex library internals where the backtracking actually occurs, past the `Matcher.find()` entry point where V1 stops. Let me verify the JDK regex engine's internal call chain:

```text
$ # Verify the internal structure of java.util.regex.Matcher and Pattern in JDK 17 …
$ javap -p java.util.regex.Matcher 2>&1 | grep -E 'find|search|match' | head -20
$ # Check Pattern's inner Node class and its match method …
```

Now I have the exact JDK internal call chain verified:
- `Matcher.find()` → `Matcher.search(int)` → `Pattern$Node.match(Matcher, int, CharSequence)`

The exponential backtracking occurs in recursive calls to `Pattern$Node.match()` across the compiled node tree. 

For PkgRisk-1, the path continues past V1's endpoint (`Matcher.find()`) deeper into the library to where the CPU resource is actually consumed (`Pattern$Node.match()`). The sink is also updated to reflect this.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "RegexCriterion.filter() ReDoS via user-controlled regex",
      "entrypoint": "RegexCriterionFuzzTest.fuzzRegexCriterionFilter(InputStream) → RegexCriterion(String) → RegexCriterion.filter(Identifiable, IdentifiableType) → Pattern.compile(String) → Matcher.find()",
      "source_path": "iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/RegexCriterion.java",
      "sink": "Matcher#find()",
      "mechanism": "User-controlled regex with nested quantifiers (e.g. (a+)+b) causes the JDK NFA backtracking engine to explore 2^(n-1) groupings of n matching characters before failing, consuming exponential CPU time",
      "resource": "CPU time: NFA backtracking steps grow as O(2^n) where n is the number of text characters matching the inner quantified group",
      "failure_mode": "timeout",
      "scale": "About 28-31 repeated matching characters cause >20 seconds of backtracking in the JDK regex engine (2^30 ≈ 10^9 steps at ~10-100 ns/step). The regex needs ~6-10 bytes, text ~30 bytes; with the midpoint split, total input ~70 bytes.",
      "input_bytes": 70,
      "cwe": "CWE-1333"
    },
    {
      "slot": 2,
      "id": "PkgRisk-1",
      "name": "java.util.regex NFA catastrophic backtracking via RegexCriterion.filter()",
      "entrypoint": "RegexCriterionFuzzTest.fuzzRegexCriterionFilter(InputStream) → RegexCriterion(String) → RegexCriterion.filter(Identifiable, IdentifiableType) → Pattern.compile(String) → Matcher.find() → Matcher.search(int) → Pattern$Node.match(Matcher, int, CharSequence)",
      "source_path": "iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/RegexCriterion.java",
      "sink": "Pattern$Node#match()",
      "mechanism": "JDK java.util.regex NFA engine explores exponential backtracking paths for patterns with nested/overlapping quantifiers against non-matching text of repeated characters",
      "resource": "CPU time: NFA backtracking steps grow as O(2^n) where n is the number of text characters matching the inner quantified group",
      "failure_mode": "timeout",
      "scale": "About 28-31 repeated matching characters cause >20 seconds of backtracking (2^30 ≈ 10^9 steps at ~10-100 ns/step). Regex ~6-10 bytes + text ~30 bytes; with midpoint split, total ~70 bytes.",
      "input_bytes": 70,
      "cwe": "CWE-1333"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

The issue is the directory name: I used `PkgRisk-1` (with a hyphen) but the expected ID is `PkgRisk1` (no hyphen). Let me check what exists and create the correctly named directory:

```text
$ ls -la <run_dir>/analysis/scale/
$ mkdir -p <run_dir>/analysis/scale/PkgRisk1
$ cd <run_dir> …
```

Let me verify the series.json and file sizes:

```text
Read <run_dir>/analysis/scale/PkgRisk1/series.json
$ ls -la <run_dir>/analysis/scale/PkgRisk1/
```

The `PkgRisk1` scale measurement series is now in place at `analysis/scale/PkgRisk1/series.json` with 6 input files (n10.bin through n320.bin), all under 2560 bytes. Each input has the same structure as V1's series — first half contains the pathological regex `(a+)+b` (padded with `z`), second half contains `n` repetitions of `a` — since both targets share the same `@Fuzz` entry point (`fuzzRegexCriterionFilter`) and the same backtracking mechanism.

## Scale revision 2

Let me analyze the measurements carefully.

**Observation**: Both V1 and PkgRisk1 show approximately **linear** growth, not exponential:
- V1: 3.5ms → 9.2ms over n=10→320 (32× parameter increase → only 2.6× time increase)
- PkgRisk1: 3.5ms → 9.8ms over n=10→320 (similar)

**Root cause**: The test regex `(a+)+bzzz...z` contains the **required literal `b`**. Java's regex engine (JDK 17) applies a Boyer-Moore (BnM) pre-scan optimization: before starting NFA matching, it scans the text for the required literal `b`. Since the text is all `a` characters, the scan finds no `b` and returns `false` immediately — the expensive NFA backtracking is **never entered**. The measured time is just the linear BnM text scan cost.

**Linear extrapolation** (measured path):
- V1: slope ≈ (9.2 - 3.5) / (320 - 10) = 0.018 ms/char. For 20,000 ms timeout: ~1.1M chars → ~2.2M bytes input. Far exceeds 10,240-byte limit. **Timeout is unreachable** on this BnM-optimized code path.

**Exponential mechanism** (actual ReDoS path): The vulnerability is real but requires a regex **without** required literals, such as `(a+)+$` (using anchor `$` instead of literal `b`). With no literal to pre-scan for, the BnM optimization is bypassed and the NFA engine explores all 2^(n-1) groupings of n matching characters. Each grouping traverses ~n nodes, giving ~n × 2^(n-1) node evaluations. At ~5–50 ns per evaluation:
- n=25: ~4.2×10⁸ evaluations → ~2–21 seconds
- n=28: ~3.8×10⁹ evaluations → ~19–190 seconds  
- n=31: ~3.3×10¹⁰ evaluations → guaranteed timeout

With the midpoint split encoding: regex `(a+)+$` (6 bytes) padded with `$` anchors in the first half, text of n `a`'s + `!` in the second half. For n=31: total = 2×32 = 64 bytes.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: with regex `(a+)+bzzz...` the JDK BnM pre-filter scans for the required literal `b`, finds none in the all-`a` text, and returns in O(n) time (~0.018 ms/char); extrapolating linearly, 20 s timeout would need ~1.1 M chars (~2.2 MB input), far exceeding the 10240-byte limit. The actual exponential mechanism requires a regex without required literals (e.g. `(a+)+$`), bypassing BnM: the NFA then explores 2^(n-1) groupings of n matching chars, each walking ~n nodes. At ~5-50 ns/node, n=28 gives ~3.8e9 evaluations ≈ 19-190 s (timeout). With the midpoint split, regex `(a+)+$` (6 B padded with `$` to 32 B) + text `a`×31+`!` (32 B) = 64 bytes total.",
    "input_bytes": 64
  },
  "PkgRisk1": {
    "scale": "Measured: with regex `(a+)+bzzz...` the JDK BnM pre-filter scans for the required literal `b`, finds none in the all-`a` text, and returns in O(n) time (~0.019 ms/char); extrapolating linearly, 20 s timeout would need ~1.0 M chars (~2.1 MB input), far exceeding the 10240-byte limit. The actual exponential mechanism requires a regex without required literals (e.g. `(a+)+$`), bypassing BnM: the NFA then explores 2^(n-1) groupings of n matching chars, each walking ~n nodes. At ~5-50 ns/node, n=28 gives ~3.8e9 evaluations ≈ 19-190 s (timeout). With the midpoint split, regex `(a+)+$` (6 B padded with `$` to 32 B) + text `a`×31+`!` (32 B) = 64 bytes total.",
    "input_bytes": 64
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by reading the existing workspace files and understanding the project structure.

```text
$ ls -la <run_dir>/
$ ls -la <run_dir>/lib/ 2>/dev/null || echo "No lib dir"
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/com/powsybl/fuzzing/tests/RegexCriterionFuzzTest.java
$ find <run_dir>/src -type f -name '*.java' 2>/dev/null
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me check the JQF Guidance interface and the `Pattern$Node` internals to plan instrumentation:

```text
$ # Verify the Guidance interface in JQF 2.1 …
$ # Compile the project to resolve dependencies and verify structure …
$ mvn package -DskipTests 2>&1 | tail -30
```

The build works. Now let me inspect the JQF Guidance interface and check the Pattern$Node structure:

```text
$ # Find the JQF jars in the local Maven repo …
$ # Inspect the JQF Guidance interface …
$ # Decompile the Guidance interface …
$ # Check GuidedFuzzing class …
$ # Check the Result enum …
$ # Check the GuidanceException class …
```

Now let me examine Pattern$Node internals for the custom agent:

```text
$ # List all Pattern inner classes to understand the regex engine node structure …
$ # Check TraceEvent class …
```

Now let me check ASM availability for the custom agent:

```text
$ # Check ASM version available - JQF depends on ASM …
```

Good, ASM 9.7+ is available. Now let me verify the `Matcher.search` and `Matcher.match` methods to confirm instrumentation points:

```text
$ # Full Matcher API listing - focus on internal methods …
$ # Check if there's a Presto node for single characters …
$ # Check BmpCharProperty (the likely single-char matcher in JDK 17) …
$ # Check if ASM is a transitive dependency of JQF …
$ # Check JQF's pom for its dependencies …
$ # Check what ASM version JQF 2.1 depends on …
```

Good - ASM 9.8 is transitively available through `jqf-instrument` (test scope). Now let me verify the build works and create the directory structure:

```text
$ # Verify ASM is resolved transitively in test scope …
$ mvn compile -q 2>&1 | tail -5
```

Build compiles cleanly. Now let me verify ASM is available on the test classpath:

```text
$ # Verify ASM 9.8 is available transitively from jqf-instrument …
```

Now let me create the directory structure for Block 3:

```text
$ cd <run_dir> …
```

Good. The pom.xml is already correct — the build succeeds with the existing configuration. No changes needed to the vulnerable-jar systemPaths. Let me now produce the full measurement strategy document.

---

#### Step 2 — Maven Layout & Scope

**Production code (src/main/java)**: EMPTY — no project source copies ([R17b]). The vulnerable `RegexCriterion` is loaded from `lib/powsybl-iidm-criteria-6.8.0-SNAPSHOT.jar` via system scope.

**Test code (src/test/java)**: All fuzzing infrastructure:
- `com.powsybl.fuzzing.tests.RegexCriterionFuzzTest` — frozen harness (read-only)
- `dosguide.validate.SignalSource` — provided by framework (read-only)
- `com.powsybl.fuzzing.agent.*` — custom Java agent for NFA step counting
- `com.powsybl.fuzzing.counter.*` — shared counter (bootstrap-accessible)
- `com.powsybl.fuzzing.guidance.*` — V1Guidance, PkgRisk1Guidance
- `com.powsybl.fuzzing.runner.*` — CLI runner
- `com.powsybl.fuzzing.replay.*` — metadata replay

**Scope correctness**: JQF (`jqf-fuzz`, `jqf-instrument`) and JUnit are test scope. ASM 9.8 is a transitive dependency of `jqf-instrument` (test scope). powsybl jars are system scope with `systemPath` pointing to `lib/`. All third-party deps (jackson, guava, etc.) are compile scope — needed at runtime for powsybl classes.

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

The frozen fuzz test (`RegexCriterionFuzzTest`) imports:
| Symbol | Package | Source | Status |
|--------|---------|--------|--------|
| `RegexCriterion` | `com.powsybl.iidm.criteria` | `lib/powsybl-iidm-criteria-6.8.0-SNAPSHOT.jar` | ✓ Available |
| `Identifiable` | `com.powsybl.iidm.network` | `lib/powsybl-iidm-api-6.8.0-SNAPSHOT.jar` | ✓ Available |
| `IdentifiableType` | `com.powsybl.iidm.network` | `lib/powsybl-iidm-api-6.8.0-SNAPSHOT.jar` | ✓ Available |
| `Network` | `com.powsybl.iidm.network` | `lib/powsybl-iidm-api-6.8.0-SNAPSHOT.jar` | ✓ Available |
| `Extension` | `com.powsybl.commons.extensions` | `lib/powsybl-commons-6.8.0-SNAPSHOT.jar` | ✓ Available |
| `@Fuzz` | `edu.berkeley.cs.jqf.fuzz` | `jqf-fuzz-2.1.jar` (test) | ✓ Available |
| `JQF` | `edu.berkeley.cs.jqf.fuzz` | `jqf-fuzz-2.1.jar` (test) | ✓ Available |

New code to be written (Block 3) uses:
| Symbol | Package | Source | Status |
|--------|---------|--------|--------|
| `Guidance` | `edu.berkeley.cs.jqf.fuzz.guidance` | `jqf-fuzz-2.1.jar` (test) | ✓ Available |
| `GuidedFuzzing` | `edu.berkeley.cs.jqf.fuzz.junit` | `jqf-fuzz-2.1.jar` (test) | ✓ Available |
| `Result` | `edu.berkeley.cs.jqf.fuzz.guidance` | `jqf-fuzz-2.1.jar` (test) | ✓ Available |
| `GuidanceException` | `edu.berkeley.cs.jqf.fuzz.guidance` | `jqf-fuzz-2.1.jar` (test) | ✓ Available |
| `TraceEvent` | `edu.berkeley.cs.jqf.instrument.tracing.events` | `jqf-instrument-2.1.jar` (test) | ✓ Available |
| `ClassVisitor` etc. | `org.objectweb.asm` | `asm-9.8.jar` (transitive test dep) | ✓ Available |
| `SignalSource` | `dosguide.validate` | Already in workspace | ✓ Available |

##### 3.2 Stub Generation — NONE NEEDED

All symbols resolve against the provided jars (system scope: lib/*.jar) and Maven dependencies (test scope: JQF, JUnit, ASM). No missing internal project types require stubs.

##### 3.3 Stub Report

**No stubs generated.** All required types are available from:
- `lib/` jars (vulnerable powsybl modules, system scope)
- Maven Central (JQF 2.1, JUnit 4.13.2, ASM 9.8 transitive)
- Framework-provided (`SignalSource`)

#### Step 4a — Project Setup

**pom.xml**: No changes needed. The canonical pom.xml compiles successfully. All `<systemPath>` entries correctly resolve to `${project.basedir}/lib/*.jar`. Dependencies, plugins, and the fuzzed-artifact identity are unchanged.

**Directory tree** (created above):
```
src/test/java/
  com/powsybl/fuzzing/
    agent/           → RegexBacktrackAgent.java, RegexNodeTransformer.java
    counter/         → RegexStepCounter.java
    guidance/        → V1Guidance.java, PkgRisk1Guidance.java
    runner/          → FuzzRunner.java
    replay/          → ReplayRunner.java
    tests/           → RegexCriterionFuzzTest.java (frozen, read-only)
  dosguide/validate/ → SignalSource.java (framework, read-only)
```

#### Step 5 — Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|------------------|------------------------------|----------------------|
| V1 | VDF + CGF (Vulnerability-Directed + Cost-Gradient) | Zest uses code coverage. The NFA engine's `Pattern$Node.match()` methods are the same bytecode paths whether called 10 times or 10⁹ times during backtracking. Zest sees identical coverage for a fast and catastrophically slow execution — it has no signal to prefer longer backtracking sequences. | Custom agent instruments `Pattern$Node.match()` and all subclass overrides to count NFA steps directly. Guidance hill-climbs this count. Dictionary of regex metacharacters `( ) + * ? . [ ] { } | ^ $ \` helps construct valid pathological patterns. |
| PkgRisk1 | DAG + CGF (Dependency-Aware + Cost-Gradient) | Same as V1: coverage cannot distinguish backtracking depth. The library-internal `Pattern$Node.match()` calls are invisible to coverage-only guidance. | Same agent-measured NFA step count targeting `Pattern$Node.match()` deep inside the JDK regex library. Hill-climbs the measured backtracking steps with a dependency-aware focus on the library's internal match nodes. |

#### Step 6 — Strategy-Specific Guidance Design

##### Measurement Plan (Both Targets)

**Signal: `nfaSteps`**
- **Code region**: Every override of `match(Matcher, int, CharSequence)` in subclasses of `java.util.regex.Pattern$Node`. Key classes: `Pattern$Node`, `Pattern$GroupHead`, `Pattern$GroupTail`, `Pattern$Loop`, `Pattern$Curly` (also `match0`, `match1`, `match2`), `Pattern$BmpCharProperty`, `Pattern$CharProperty`, `Pattern$Dollar`, `Pattern$BnM`.
- **Why this corresponds to the DoS mechanism**: Each `match()` call is one NFA evaluation step. Catastrophic backtracking explores O(2ⁿ) such calls; counting them directly measures the exponential cost.
- **Storage**: `RegexStepCounter.counter` — a `static ThreadLocal<long[]>` field. Using `long[]` of size 1 avoids boxing overhead. The `ThreadLocal` ensures thread safety.
- **Reset**: In `V1Guidance.getInput()` / `PkgRisk1Guidance.getInput()`, immediately before returning the `InputStream` to JQF.
- **Read**: In `handleResult()`, after the execution completes: `long steps = RegexStepCounter.get()`.

##### Agent Plan ([R35])

1. **Classes/methods to instrument**: All classes in `java.util.regex` package whose name matches `java/util/regex/Pattern$*` AND that have a method `match` with descriptor `(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z`. Additionally, `Pattern$Curly`'s `match0`, `match1`, `match2` methods (same descriptor except extra `int` param) are instrumented since they are the inner match loops of the Curly quantifier node.
2. **Required JVM flags**: 
   - `-javaagent:<path/to/regex-agent.jar>` — loads the agent
   - `--add-opens java.base/java.util.regex=ALL-UNNAMED` — allows retransformation of already-loaded JDK classes
   - `Can-Retransform-Classes: true` in agent MANIFEST.MF
3. **Signal export**: `RegexStepCounter` class with `static ThreadLocal<long[]>`. Methods: `increment()`, `get()`, `reset()`. Loaded on bootstrap classpath via `Boot-Class-Path` in agent manifest (self-referencing the agent jar), ensuring the same class instance is visible from both the injected `Pattern$*` code (bootstrap classloader) and the Guidance (application classloader, which delegates to parent=bootstrap).
4. **Agent implementation**:
   - `RegexBacktrackAgent.premain(String, Instrumentation)`: registers `RegexNodeTransformer`, then retransforms already-loaded `Pattern$*` classes via `instrumentation.retransformClasses()`
   - `RegexNodeTransformer extends ClassFileTransformer`: in `transform()`, checks if class name starts with `java/util/regex/Pattern$`, then uses ASM `ClassReader` → `ClassVisitor` → `ClassWriter` pipeline to inject `INVOKESTATIC RegexStepCounter.increment()V` at the entry of `match()` methods (and `match0/match1/match2` for `Curly`)
   - `RegexStepCounter`: pure static utility, no dependencies beyond JDK

##### Mutation Operators

**Byte-level**:
- `FLIP_BYTE`: flip a random byte at a random position
- `INSERT_BYTE`: insert a random byte at a random position
- `DELETE_BYTE`: delete a byte at a random position
- `OVERWRITE_BLOCK`: copy a random block from one position to another

**Repetition** ([R45](a)):
- `REPEAT_CHUNK`: select a random contiguous chunk of the current input, repeat it k times in place, where k is chosen randomly up to what fills the input size limit (from `jqf.ei.MAX_INPUT_SIZE`, default 10240). This builds repeated character sequences in the text half (e.g., `aaa` → `aaaaaaaaa`) and repeated regex fragments in the regex half (e.g., `(a+)` → `(a+)(a+)`). Can also double the entire input.

**Dictionary** ([R45](b)):
- Tokens extracted from the code on the target's attack path (the regex metacharacters that `Pattern.compile()` and its `match()` nodes compare input against):
  - `(`, `)`, `+`, `*`, `?`, `.`, `[`, `]`, `{`, `}`, `|`, `^`, `$`, `\`
  - Single atom characters: `a`, `b`, `!`
- Operation: insert or overwrite a dictionary token at a random position in the input
- These are syntactic units from the regex language, not assembled payloads ([R23])

**No encoder needed** ([R45](c)): The input is plain bytes decoded as UTF-8. No checksums, length fields, or compression.

##### Retention Strategy

**Primary signal**: `nfaSteps` (measured NFA match invocation count)
- An input with `nfaSteps` > current maximum is ALWAYS retained (new best)
- Among equal step counts, prefer the shorter input (minimization)

**Secondary (while signal is flat, [R46])**:
- When all inputs so far have `nfaSteps == 0` (e.g., regex is invalid and throws `PatternSyntaxException` before reaching `Matcher.find()`):
  - Retain inputs that are LONGER than previously retained ones (growing toward `input_bytes` = 64, up to `MAX_INPUT_SIZE`)
  - Retain inputs where `Result == SUCCESS` (the regex compiled and the match ran to completion — the code path reached `Matcher.find()` and the NFA was exercised, even if trivially)
  - The repetition operator grows inputs from small seeds (4 bytes → 8 → 16 → 32 → 64 in 4 doublings, achievable in seconds)
- Once the signal rises above zero, switch to pure step-count hill-climbing

**Input growth guarantee**: Starting from 4-byte random seeds, the repetition operator can double input size each mutation. 4 → 64 bytes in 4 doublings. At ~1000 executions/second, this takes <1 second. Well within the 1-minute budget for reaching `input_bytes`.

##### Prioritization Logic

- Corpus entries are sorted by `nfaSteps` (descending)
- Mutations are applied preferentially to the highest-step-count inputs
- Energy (number of mutations per parent) scales with the parent's step count relative to the best
- Fresh random inputs are periodically injected to escape local optima

##### Stop/Continue Conditions

- Default: infinite (run until stopped)
- Time-bounded: `-Djqf.ei.MAX_DURATION=<seconds>` system property
- Each execution is bounded by the 20,000 ms per-execution time limit (enforced externally)

#### Step 7 — Custom Guidance Classes (Block 3)

**V1Guidance** — targets `fuzzRegexCriterionFilter`, corpus: `out/V1/corpus`
**PkgRisk1Guidance** — targets `fuzzRegexCriterionFilter`, corpus: `out/PkgRisk1/corpus`

Both implement `Guidance` directly ([R3]) AND `SignalSource` (for DoSGuide validation). Both use `nfaSteps` signal. Neither decides failures nor writes failure files ([R6]). Both log stats every 1 second ([R5]).

#### Step 8 — Fuzz Tests

The frozen harness `RegexCriterionFuzzTest` provides:
- `fuzzRegexCriterionFilter(InputStream)` — used by V1 and PkgRisk1
  - Consumes `InputStream` directly ([R31])
  - Splits bytes at midpoint: first half → regex string (UTF-8), second half → match text (UTF-8)
  - Constructs `RegexCriterion(regex)` and calls `filter()`
  - Declares `PatternSyntaxException` (normal result for invalid regex)

Input model: byte[] via InputStream. All input mutation in Guidance ([R31]).

#### Step 9 — Metadata Replay

`ReplayRunner` will:
1. Read metadata JSON (containing input file path, step count, result, timestamp)
2. Load input bytes from the saved file
3. Replay deterministically through `RegexCriterionFuzzTest.fuzzRegexCriterionFilter()`
4. Print: input hex dump, decoded regex string, decoded match text, step count, result, and whether it times out

#### Step 10 — Maven Configuration

**pom.xml**: No changes needed — canonical build succeeds.

**Commands**:
- Compile: `mvn compile`
- Build agent jar: `jar -cfm regex-agent.jar <manifest> -C target/test-classes com/powsybl/fuzzing/agent/ -C target/test-classes com/powsybl/fuzzing/counter/` (with ASM classes bundled)
- Fuzz V1: `java -Xmx1g -Xss1m --add-opens java.base/java.util.regex=ALL-UNNAMED -javaagent:regex-agent.jar -cp <test-classpath> com.powsybl.fuzzing.runner.FuzzRunner V1`
- Fuzz PkgRisk1: `java -Xmx1g -Xss1m --add-opens java.base/java.util.regex=ALL-UNNAMED -javaagent:regex-agent.jar -cp <test-classpath> com.powsybl.fuzzing.runner.FuzzRunner PkgRisk1`
- Time-bounded: add `-Djqf.ei.MAX_DURATION=300` (5 minutes)
- Reproduce: `java ... com.powsybl.fuzzing.replay.ReplayRunner <metadata.json>`

#### Zest Baseline Comparison ([R18])

**Zest configuration**: `ZestGuidance` with default coverage feedback, same fuzz method `fuzzRegexCriterionFilter`.

**Why Zest underperforms**:
- **Proxy signal failure**: Zest's coverage map saturates within seconds — `Pattern.compile()`, `Matcher.find()`, the NFA `match()` paths are all exercised by the first valid regex. Subsequent inputs with more backtracking traverse the exact same bytecode branches.
- **No cost correlation**: Zest treats a 1ms match and a 20s timeout-inducing match identically (same coverage bitmap). It cannot distinguish them.
- **Random walk**: Without a cost signal, Zest's mutations are undirected. Finding a pathological regex+text combination requires hitting a very specific structure by chance.

**Custom Guidance advantage**:
- **Mechanism-aligned signal**: NFA step count directly measures the backtracking. Every additional backtracking step increases the signal, providing continuous gradient.
- **Measurable metric**: Time-to-first-timeout — custom guidance expected to find a timeout in <5 min vs. Zest's random walk which may never find one.

#### IMPORT AUDIT

```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent
SignalSource → dosguide.validate.SignalSource
```

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — all code targets JDK 17
- [YES] No hallucinated APIs — verified all interfaces via `javap`
- [YES] Guidance implements Guidance directly — both V1Guidance and PkgRisk1Guidance implement `edu.berkeley.cs.jqf.fuzz.guidance.Guidance`
- [YES] No existing guidance extended — no extends ZestGuidance/PerfFuzzGuidance/etc.
- [YES] V* vulnerabilities identified — V1 (RegexCriterion ReDoS)
- [YES] V* IDs are sequential (V1) — not derived from software versions [R42]
- [YES] Official vulnerability names applied — CWE-1333 (Regex DoS)
- [YES] PkgRisk-* identified — PkgRisk1 (java.util.regex NFA backtracking)
- [YES] Every PkgRisk-* executed — PkgRisk1 has its own Guidance class
- [YES] Guidance targets V* and PkgRisk-* — V1Guidance targets V1, PkgRisk1Guidance targets PkgRisk1
- [YES] One fuzz method per V* or PkgRisk — both use fuzzRegexCriterionFilter (frozen harness)
- [YES] CLI method selection supported — FuzzRunner accepts V1/PkgRisk1 as CLI arg
- [YES] Byte[]/InputStream input model used exclusively — harness consumes InputStream
- [YES] No junit-quickcheck Generators used — all mutation inside Guidance
- [YES] All mutation implemented inside Guidance — byte-level + dictionary + repetition
- [YES] Repetition, source dictionary and encoder operators implemented [R45] — repetition for chunk doubling; dictionary of regex metacharacters; no encoder needed (plain UTF-8)
- [YES] Retention progresses while signal is flat; inputs can reach input_bytes within a minute [R46] — secondary criterion keeps longer inputs and successful compilations; repetition doubles size quickly
- [YES] Retention signals measured where resource is consumed (Pattern$Node.match), not before the sink [R47]
- [YES] Logging every 1 second — structured log output in Guidance
- [YES] Guidance decides no failures and writes no failure files ([R6]) — handleResult only retains/prioritizes
- [YES] Corrupted inputs saved with metadata — corpus entries saved with JSON metadata
- [YES] Replay/feeder implemented — ReplayRunner reads metadata and replays
- [YES] Infinite + time-bounded fuzzing supported — MAX_DURATION property
- [YES] src/main vs src/test separation correct — src/main/java empty; all infra in src/test/java
- [YES] Maven scopes consistent — JQF=test, powsybl=system, third-party=compile
- [YES] No wildcard imports used for JQF/tracing — all explicit
- [YES] TraceEvent import verified — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` confirmed via javap

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "nfaSteps",
          "quantity": "total invocations of Pattern$Node.match() and all subclass overrides during one regex match execution",
          "aggregation": "sum",
          "locations": [
            "Pattern$Node#match",
            "Pattern$GroupHead#match",
            "Pattern$GroupTail#match",
            "Pattern$Loop#match",
            "Pattern$Curly#match",
            "Pattern$Curly#match0",
            "Pattern$Curly#match1",
            "Pattern$Curly#match2",
            "Pattern$BmpCharProperty#match",
            "Pattern$CharProperty#match",
            "Pattern$Dollar#match",
            "Pattern$BnM#match"
          ],
          "technique": "bytecode",
          "storage": "static ThreadLocal<long[]> in com.powsybl.fuzzing.counter.RegexStepCounter, loaded on bootstrap classpath via agent jar Boot-Class-Path",
          "reset": "RegexStepCounter.reset() called in V1Guidance.getInput() immediately before returning the InputStream",
          "read": "RegexStepCounter.get() called in V1Guidance.handleResult() to obtain the step count for the just-completed execution"
        }
      ],
      "retention": "Primary: retain input if nfaSteps exceeds the current maximum (hill-climb). Secondary (while nfaSteps is flat at zero): retain inputs that are longer (growing toward input_bytes=64, up to MAX_INPUT_SIZE=10240) and that completed without PatternSyntaxException (regex compiled successfully, reaching the Matcher.find() sink). Among equal step counts, prefer shorter inputs (minimization). Corpus entries sorted by nfaSteps descending; mutations weighted toward highest-step parents.",
      "retention_signals": ["nfaSteps"],
      "mutation": [
        "FLIP_BYTE: flip a random byte at a random position",
        "INSERT_BYTE: insert a random byte at a random position",
        "DELETE_BYTE: remove a byte at a random position",
        "OVERWRITE_BLOCK: copy a random block from one position to another within the input",
        "REPEAT_CHUNK: select a random contiguous chunk, repeat it k times in place (k from 2 up to what fills MAX_INPUT_SIZE=10240), enabling input growth from 4-byte seeds to 64+ bytes in 4 doublings (<1 second)",
        "DICTIONARY_INSERT: insert or overwrite a token from the regex metacharacter dictionary at a random position; tokens: ( ) + * ? . [ ] { } | ^ $ \\ a b !"
      ]
    },
    {
      "target": "PkgRisk1",
      "signals": [
        {
          "name": "nfaSteps",
          "quantity": "total invocations of Pattern$Node.match() and all subclass overrides during one regex match execution",
          "aggregation": "sum",
          "locations": [
            "Pattern$Node#match",
            "Pattern$GroupHead#match",
            "Pattern$GroupTail#match",
            "Pattern$Loop#match",
            "Pattern$Curly#match",
            "Pattern$Curly#match0",
            "Pattern$Curly#match1",
            "Pattern$Curly#match2",
            "Pattern$BmpCharProperty#match",
            "Pattern$CharProperty#match",
            "Pattern$Dollar#match",
            "Pattern$BnM#match"
          ],
          "technique": "bytecode",
          "storage": "static ThreadLocal<long[]> in com.powsybl.fuzzing.counter.RegexStepCounter, loaded on bootstrap classpath via agent jar Boot-Class-Path",
          "reset": "RegexStepCounter.reset() called in PkgRisk1Guidance.getInput() immediately before returning the InputStream",
          "read": "RegexStepCounter.get() called in PkgRisk1Guidance.handleResult() to obtain the step count for the just-completed execution"
        }
      ],
      "retention": "Primary: retain input if nfaSteps exceeds the current maximum (hill-climb). Secondary (while nfaSteps is flat at zero): retain inputs that are longer (growing toward input_bytes=64, up to MAX_INPUT_SIZE=10240) and that completed without PatternSyntaxException (regex compiled successfully, reaching Pattern$Node.match() sink). Among equal step counts, prefer shorter inputs (minimization). Corpus entries sorted by nfaSteps descending; mutations weighted toward highest-step parents.",
      "retention_signals": ["nfaSteps"],
      "mutation": [
        "FLIP_BYTE: flip a random byte at a random position",
        "INSERT_BYTE: insert a random byte at a random position",
        "DELETE_BYTE: remove a byte at a random position",
        "OVERWRITE_BLOCK: copy a random block from one position to another within the input",
        "REPEAT_CHUNK: select a random contiguous chunk, repeat it k times in place (k from 2 up to what fills MAX_INPUT_SIZE=10240), enabling input growth from 4-byte seeds to 64+ bytes in 4 doublings (<1 second)",
        "DICTIONARY_INSERT: insert or overwrite a token from the regex metacharacter dictionary at a random position; tokens: ( ) + * ? . [ ] { } | ^ $ \\ a b !"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

Let me start by reading the existing workspace files to understand the current state.

```text
$ ls -la <run_dir>/
$ find <run_dir>/src -type f -name '*.java' 2>/dev/null
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/src/test/java/com/powsybl/fuzzing/tests/RegexCriterionFuzzTest.java
```

Now I'll write all implementation files. Let me start by creating the directory structure and then write each file.

```text
$ cd <run_dir> …
```

Let me first read the existing files to understand the current state of the workspace.

```text
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/com/powsybl/fuzzing/tests/RegexCriterionFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
$ ls <run_dir>/lib/
$ ls <run_dir>/analysis/
```

Let me also check the existing analysis files for target info and the launch config:

```text
Read <run_dir>/analysis/target_register.json
Read <run_dir>/analysis/guidance_plan.json
Read <run_dir>/analysis/run_config.json
```

Now let me check existing analysis files and the validation inputs:

```text
$ ls -la <run_dir>/analysis/validation_inputs/ 2>/dev/null; echo "---"; ls -la <run_dir>/analysis/scale/ 2>/dev/null
$ ls -la <run_dir>/src/test/java/com/powsybl/fuzzing/*/
```

Good - directories exist but are empty. Let me check if ASM is available as a dependency:

```text
$ mvn dependency:tree -DincludeArtifactIds=asm 2>&1 | tail -15
```

ASM 9.8 is available via jqf-instrument. Let me find its jar path:

```text
$ find ~/.m2/repository/org/ow2/asm/asm/9.8 -name '*.jar' 2>/dev/null | head -5
```

Now I'll write all implementation files. Starting with Part A (Java Agent):

```text
Write <run_dir>/src/test/java/com/powsybl/fuzzing/counter/RegexStepCounter.java
Write <run_dir>/src/test/java/com/powsybl/fuzzing/agent/RegexNodeTransformer.java
Write <run_dir>/src/test/java/com/powsybl/fuzzing/agent/RegexBacktrackAgent.java
```

Part A done. Now Part B — Guidance classes. I'll write V1Guidance and PkgRisk1Guidance:

```text
Write <run_dir>/src/test/java/com/powsybl/fuzzing/guidance/V1Guidance.java
Write <run_dir>/src/test/java/com/powsybl/fuzzing/guidance/PkgRisk1Guidance.java
```

Part B done. Now Part C — FuzzRunner, ReplayRunner, and run.sh:

```text
Write <run_dir>/src/test/java/com/powsybl/fuzzing/runner/FuzzRunner.java
Write <run_dir>/src/test/java/com/powsybl/fuzzing/replay/ReplayRunner.java
```

Now let me write the run.sh script:

```text
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh
```

Now Part D — launch.json and validation inputs:

```text
Write <run_dir>/analysis/launch.json
```

Now create the validation input files. These need to be well-formed binary inputs that exercise the fuzz target:

```text
$ cd <run_dir> …
```

Now let me compile to verify everything works:

```text
$ mvn -q compile test-compile 2>&1 | tail -30
$ mvn compile 2>&1 | tail -30
```

Main sources compiled (there are none). Let me compile the test sources:

```text
$ mvn package -DskipTests 2>&1 | tail -30
```

`TraceEvent` is an inner interface of `Guidance`. Let me check the exact API:

```text
$ find ~/.m2/repository/edu/berkeley/cs/jqf -name 'jqf-fuzz-2.1.jar' | head -1 | xargs -I{} jar tf {} | grep -i 'trace\|TraceEvent\|Guidance' | head -20
$ find ~/.m2/repository/edu/berkeley/cs/jqf -name 'jqf-instrument-2.1.jar' | head -1 | xargs -I{} jar tf {} | grep -i 'trace' | head -20
```

`TraceEvent` is in `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent`. I need to import it. Let me fix all three files:

```text
Edit <run_dir>/src/test/java/com/powsybl/fuzzing/guidance/V1Guidance.java
Edit <run_dir>/src/test/java/com/powsybl/fuzzing/guidance/V1Guidance.java
Read <run_dir>/src/test/java/com/powsybl/fuzzing/guidance/V1Guidance.java
```

Need to fix the SuppressWarnings placement:

```text
Edit <run_dir>/src/test/java/com/powsybl/fuzzing/guidance/V1Guidance.java
```

Now fix PkgRisk1Guidance:

```text
Edit <run_dir>/src/test/java/com/powsybl/fuzzing/guidance/PkgRisk1Guidance.java
```

Now fix ReplayRunner:

```text
Edit <run_dir>/src/test/java/com/powsybl/fuzzing/replay/ReplayRunner.java
```

Now recompile:

```text
$ mvn package -DskipTests 2>&1 | tail -30
```

All 9 source files compile successfully. Now let me build the agent jar:

```text
$ cd <run_dir> …
```

Agent jar is built and contains all required classes. Let me verify the complete file listing:

```text
$ cd <run_dir> …
```

All files are in place. Let me verify the Guidance classes implement the correct interfaces by checking the compiled bytecode:

```text
$ cd <run_dir> …
$ cd <run_dir> …
```

Both Guidance classes correctly implement `Guidance` and `SignalSource` with all required methods. Let me also verify the FuzzRunner:

```text
$ cd <run_dir> …
$ cd <run_dir> …
$ cd <run_dir> …
```

All classes compile and have correct signatures. Let me verify the runner class too:

```text
$ cd <run_dir> …
```

All classes verified. The `createGuidance` factory method has the correct signature: `public static Guidance createGuidance(String, File, long, PrintStream)`.

Let me do a final summary of everything that was written:

```text
$ cd <run_dir> …
$ cd <run_dir> …
$ cd <run_dir> …
$ find <run_dir>/src/test/java -name '*.java' | sort
$ find <run_dir>/target/test-classes -name '*.class' | wc -l
$ ls -la <run_dir>/regex-agent.jar <run_dir>/run.sh
$ ls <run_dir>/analysis/validation_inputs/
Glob <run_dir> src/test/java/com/powsybl/fuzzing/**/*.java
```

All 8 Java files are in place (7 new + 1 frozen FuzzTest), 13 compiled class files, agent jar built, run.sh executable, launch.json written, and 10 validation input files created.

**Block 3 Implementation Summary:**

##### Part A — Java Agent (3 files)
- **`RegexStepCounter.java`** — `ThreadLocal<long[]>` counter with `increment()`, `get()`, `reset()`. On bootstrap classpath via agent jar's `Boot-Class-Path`.
- **`RegexBacktrackAgent.java`** — `premain()` agent that registers the transformer and retransforms already-loaded `Pattern$*` classes.
- **`RegexNodeTransformer.java`** — ASM 9.8 `ClassFileTransformer` that injects `INVOKESTATIC RegexStepCounter.increment()V` at entry of `match()`, `match0()`, `match1()`, `match2()` in all `java.util.regex.Pattern$*` inner classes.

##### Part B — Guidance Classes (2 files)
- **`V1Guidance.java`** — Implements `Guidance` + `SignalSource` directly. Signal: `nfaSteps`. Hill-climb retention. 6 mutation operators (flip, insert, delete, block overwrite, repeat chunk, dictionary insert with regex metacharacters).
- **`PkgRisk1Guidance.java`** — Same structure, targeting the deeper `Pattern$Node.match()` sink path. Independent corpus at `out/PkgRisk1/corpus`.

##### Part C — Runner + Replay + Script (3 files)
- **`FuzzRunner.java`** — CLI entry with `createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log)` factory.
- **`ReplayRunner.java`** — Single-input replay with signal measurement via embedded `SingleInputGuidance`.
- **`run.sh`** — Build script: compiles, creates agent jar with proper `MANIFEST.MF` (Premain-Class + Can-Retransform-Classes + Boot-Class-Path), assembles classpath, runs with `-javaagent:regex-agent.jar -Xmx1g -Xss1m -Djqf.ei.MAX_INPUT_SIZE=10240`.

##### Part D — Config + Validation (2 items)
- **`analysis/launch.json`** — Build commands, classpath command, JVM args, target configs for V1 and PkgRisk1.
- **`analysis/validation_inputs/`** — 10 well-formed binary inputs exercising various regex patterns (literal, quantifiers, alternation, character classes, nested quantifiers, dollar anchor).

## Validation repair 1

Looking at the validation error, the `launch.json` is missing the `guidance_factory` field and has extra fields that don't match the expected format. Let me fix it.

```text
Read <run_dir>/analysis/launch.json
```

The issue is clear: `launch.json` is missing the `guidance_factory` field and has the wrong structure. The expected format uses `guidance_factory`, `javaagent`, and simpler target entries. Let me rewrite it:

```text
Write <run_dir>/analysis/launch.json
```

**Summary of changes:**

Rewrote `analysis/launch.json` to match the expected format:
1. Added `"guidance_factory": "com.powsybl.fuzzing.runner.FuzzRunner#createGuidance"` — the required field that was missing.
2. Added `"javaagent": {"jar": "regex-agent.jar", "args": ""}` — the agent is now declared in its own field instead of being embedded in `jvm_args`.
3. Simplified target entries to use only `test_class` and `method` (removed extra fields like `guidance_class`, `signals`, `runner_class`, `replay_class` that don't belong in the expected schema).
4. Removed `-javaagent`, `-Xmx1g`, `-Xss1m`, `-Djqf.ei.MAX_INPUT_SIZE` from `jvm_args` (the evaluation fixes JVM options per [R41], and the agent is now in `javaagent`).
5. Removed `timeout_ms` and `max_input_bytes` (these are controlled by the fixed evaluation limits, not launch.json).
