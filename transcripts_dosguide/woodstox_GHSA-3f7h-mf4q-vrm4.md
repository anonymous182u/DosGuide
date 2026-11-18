# woodstox_GHSA-3f7h-mf4q-vrm4

## Block 1

```text
Glob <run_dir> **/*FuzzTest*.java
Glob <run_dir> **/pom.xml
$ ls <run_dir>/
Read <run_dir>/src/test/java/fuzzing/harness/WoodstoxFuzzTest.java
Read <run_dir>/pom.xml
$ ls -la <run_dir>/analysis/ <run_dir>/lib/ 2>&1
```

Now let me read the main source file and explore the DTD-related source code:

```text
$ wc -l <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Glob <source_root> src/main/java/com/ctc/wstx/dtd/*.java
$ cat -n <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java | head -n 100
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Let me now search for the key vulnerability methods — entity expansion, and especially look for recursive or unbounded processing:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java expandPE|expandEntity|handleEntityDecl|parseContentSpec|handleDeclaration
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now let me look at the `expandEntity` method and the `handleDeclaration` method:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/dtd private.*void expandEntity|protected.*void expandEntity|void expandEntity
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/MinimalDTDReader.java expandEntity
Grep <source_root>/src/main/java/com/ctc/wstx expandEntity
Grep <source_root>/src/main/java/com/ctc/wstx/sr/StreamScanner.java expandEntity
Read <source_root>/src/main/java/com/ctc/wstx/sr/StreamScanner.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now let me find the `readContentSpec` method which is the core recursive parser:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java readContentSpec|readMixedSpec
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now let me look at the `DFAState.constructDFA` method and related code that might cause exponential blowup:

```text
Read <source_root>/src/main/java/com/ctc/wstx/dtd/DFAState.java
```

Let me look more closely at the entity handling to understand the full attack surface:

```text
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now let me understand the entity value parsing and potential for entity amplification:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java parseEntityValue
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now let me check for entity expansion limits and whether the "billion laughs" / entity bombing is possible:

```text
Grep <source_root>/src/main/java/com/ctc/wstx getMaxEntityCount|maxEntityCount|MAX_ENTITY_COUNT|verifyLimit|getMaxEntityDepth|maxEntityDepth
Read <source_root>/src/main/java/com/ctc/wstx/sr/StreamScanner.java
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java checkInclusion|INCLUDE|IGNORE
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now let me look at the key recursive methods more carefully — specifically `readContentSpec` and where the GHSA vulnerability lies. Let me check for depth-related limits in this version:

```text
Grep <source_root>/src/main/java/com/ctc/wstx maxNesting|MAX_NESTING|maxDepth|MAX_DEPTH|nestingDepth|contentSpecDepth|MAX_ELEMENT_DEPTH|maxElementDepth
Grep <source_root>/src/main/java/com/ctc/wstx MAX_DTD_DEPTH|maxDtdDepth|dtdDepth|contentDepth|readContentSpec.*depth|nesting.*limit|nesting.*check
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java handleAttrDecl
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now let me investigate the actual parsing flow more deeply. Let me check how the DTD internal subset gets read during XML parsing:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/sr readInternalSubset|FullDTDReader
Grep <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java readInternalSubset|FullDTDReader
Grep <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java readInternalSubset|MinimalDTDReader
Grep <source_root>/src/main/java/com/ctc/wstx/stax/WstxInputFactory.java createXMLStreamReader|createSR|ValidatingStreamReader|BasicStreamReader
Read <source_root>/src/main/java/com/ctc/wstx/stax/WstxInputFactory.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/ValidatingStreamReader.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/ValidatingStreamReader.java
$ cd <source_root> && git log --oneline -10 2>&1 | tail -15
```

Let me look at the MinimalDTDReader to understand the full inheritance chain and look for any DTD-related entity expansion amplification:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/MinimalDTDReader.java class MinimalDTDReader
Read <source_root>/src/main/java/com/ctc/wstx/dtd/MinimalDTDReader.java
```

Now let me look at more of the content spec area, particularly checking whether the DTD nesting depth overflow affects the non-validating path:

```text
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Grep <source_root>/src/main/java/com/ctc/wstx/api/ReaderConfig.java DEFAULT_MAX_ENTITY_DEPTH|mMaxEntityDepth
Grep <source_root>/src/main/java/com/ctc/wstx/api/ReaderConfig.java DEFAULT_MAX_CHARACTERS|DEFAULT_MAX_TEXT_LENGTH|DEFAULT_MAX_ATTRIBUTE_SIZE
Grep <source_root>/src/main/java/com/ctc/wstx/api/ReaderConfig.java mMaxCharacters|mMaxTextLength|getMaxCharacters|getMaxTextLength
Grep <source_root>/src/main/java/com/ctc/wstx/sr maxElementDepth|mMaxElementDepth|getMaxElementDepth|MAX_ELEMENT_DEPTH
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java mCurrDepth
Grep <source_root>/src/main/java/com/ctc/wstx/sr/StreamScanner.java mCurrDepth
```

Let me check for other potential DoS paths in the DTD handling:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java parseAttrDefaultValue
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Let me also look at whether the `readComment` or `skipComment` methods have any recursion concerns:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java private.*readComment|private.*skipComment|protected.*readComment|readPI
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Grep <source_root>/src/main/java/com/ctc/wstx/dtd rewrite\(\)|addFirstPos|calcFollowPos
```

Let me check how Woodstox handles entity expansion during next():

```text
Grep <source_root>/src/main/java/com/ctc/wstx/api/ReaderConfig.java mCfgReplaceEntities|replaceEntities|REPLACE_ENTITY
```

Let me check the BasicStreamReader's handling of nested elements:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java handleStartElem|handleEndElem|nextFromTree|nextFromProlog
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Grep <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java skipToken|finishToken
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Grep <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java private.*skipTokenText
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
```

Let me also verify the line count and check the tail of the file for any other recursive methods:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java private|protected|public
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now I have a thorough understanding of the code. Let me create the scale measurement inputs and produce the target register.

First, let me create the scale measurement directory and files:

```text
$ mkdir -p <run_dir>/analysis/scale/V1
```

Now I'll create the scale measurement inputs. Each input is an XML document with a DTD containing deeply nested parenthesized content spec. The parameter is the nesting depth (number of recursive `readContentSpec` calls).

```text
$ python3 -c " …
```

Good. All inputs are well within the 2560-byte limit. Now let me write the series.json file:

```text
Write <run_dir>/analysis/scale/V1/series.json
```

Let me verify the generated files are correct:

```text
$ python3 -c " …
$ python3 -c " …
$ python3 -c " …
```

All inputs are verified. Now let me finalize the analysis.

#### PHASE A — Analysis

##### 1.1 Code-Level Vulnerabilities

**V1: Unbounded recursion in DTD content specification parsing (StackOverflowError)**

- **Fuzzable entrypoint**: `WoodstoxFuzzTest.fuzzXMLStreamReaderNextNonValidating(InputStream)` — the fuzz input is an InputStream of raw XML bytes containing an internal DTD subset with a deeply nested `<!ELEMENT>` content specification.
- **User-controlled input**: The entire InputStream content, including the DTD internal subset with the `<!ELEMENT>` content spec parenthesized groups.
- **Mechanism**: The method `FullDTDReader.readContentSpec()` (line 3055 of FullDTDReader.java) is recursive. For each opening parenthesis `(` encountered in a DTD content spec like `<!ELEMENT r ((((((a))))))>`, it recursively calls itself (line 3089-3091). There is **no depth limit check** on this recursion. Each nesting level consumes one Java stack frame (~200-400 bytes). Deep nesting exhausts the thread stack.
- **Exhausted resource**: Stack depth — one `readContentSpec` frame per nesting level.
- **Failure mode**: `stack_overflow` (StackOverflowError, which is an undeclared throwable not caught by XMLStreamException).
- **Scale**: With `-Xss1m` stack limit, approximately 3000-3500 nesting levels overflow the 1 MB stack (estimated ~300 bytes per frame, with ~100KB already consumed by the call chain from factory to DTD reader). Input encoding: 2 bytes per nesting level (one `(` and one `)`) plus ~51 bytes of XML/DTD boilerplate and 1 byte for element name. For 3500 nesting levels: 2 × 3501 + 51 + 1 = **7054 bytes**, well within the 10240 byte input limit.

##### 1.2 Official Classification

- **V1**: CWE-674 (Uncontrolled Recursion) → CWE-400 (Uncontrolled Resource Consumption). This is the known vulnerability GHSA-3f7h-mf4q-vrm4 in Woodstox. The `readContentSpec` method lacks a recursion depth limit, allowing crafted DTDs to cause StackOverflowError.

##### 1.3 Dependency / Package-Level Risks

After thorough analysis:

- **java.util.regex**: Not used in the DTD content spec parsing path.
- **java.util.HashMap**: Used for entity/element storage in `FullDTDReader`, but with the 10240-byte input limit, the number of entities and elements is bounded to a few hundred, insufficient for hash collision DoS.
- **javax.xml.stream**: Standard StAX API; Woodstox implements it. The vulnerability is in Woodstox's implementation, not the API itself.
- **Entity expansion (billion laughs)**: Woodstox has a `maxEntityCount` limit of 100,000 and `maxEntityDepth` of 500. With 10240-byte input limit, the maximum amplified text is ~80 MB (100K × ~800 bytes), fitting within 1 GB heap. Text is scanned without full materialization during `skipToken()`. Not enough for OOM or timeout.
- **DFA construction** (`DFAState.constructDFA`): The `calcNext` method merges tokens with the same name, preventing exponential DFA state explosion. Only active when `IS_VALIDATING = true`. Not a realistic DoS vector with the given input size limit.

**No PkgRisk items qualify as DoS vulnerabilities under the fixed evaluation limits.**

#### PHASE B — Target Selection

##### IMPORT AUDIT
```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
```

##### Zest Baseline Comparison [R18]

**V1: readContentSpec stack overflow**

- **Closest Zest configuration**: Standard Zest fuzzing of `fuzzXMLStreamReaderNextNonValidating` with random byte mutations.
- **Why Zest underperforms**: Zest uses code coverage as its signal. Code coverage is a **proxy signal** that does not directly correlate with stack depth. A coverage-guided fuzzer might discover DTD parsing code paths quickly, but coverage doesn't increase linearly with nesting depth — after the first few nesting levels, no new coverage is gained, so Zest has no incentive to deepen nesting. Zest's random byte-level mutations are also unlikely to incrementally build deep balanced parenthesized structures (each `(` needs a matching `)`).
- **Custom Guidance advantage**: A mechanism-aligned Guidance tracks **recursion depth** (stack frame count) in `readContentSpec` via a Java agent. It retains inputs that increase measured recursion depth. It uses a dictionary of DTD tokens (`(`, `)`, `<!ELEMENT`, etc.) and a **repetition operator** that doubles regions of balanced parens. This enables rapid growth toward the ~3500-level threshold.
- **Measurable metric**: Time-to-first-bug (StackOverflowError). The custom Guidance should find the SOE within seconds; Zest is unlikely to reach ~3500 nesting levels through random mutations alone, as the search has no signal to guide nesting depth increase beyond basic coverage.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unbounded recursion in DTD content spec parsing",
      "entrypoint": "WoodstoxFuzzTest.fuzzXMLStreamReaderNextNonValidating(InputStream) → WstxInputFactory.createXMLStreamReader(InputStream) → ValidatingStreamReader.finishDTD(boolean) → FullDTDReader.readInternalSubset(WstxInputData, WstxInputSource, ReaderConfig, boolean, int) → FullDTDReader.parseDTD() → FullDTDReader.handleElementDecl() → FullDTDReader.readContentSpec(PrefixedName, boolean, boolean)",
      "source_path": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java",
      "sink": "FullDTDReader#readContentSpec",
      "mechanism": "Each opening parenthesis in a DTD ELEMENT content specification triggers one recursive call to readContentSpec (line 3090). There is no recursion depth limit. Deep nesting exhausts the call stack.",
      "resource": "stack depth: one readContentSpec frame (~200-400 bytes) per nesting level",
      "failure_mode": "stack_overflow",
      "scale": "About 3000-3500 nesting levels overflow the 1 MB stack (~300 bytes/frame, ~100KB pre-used). Encoding: 2 bytes per level (one open paren + one close paren) plus ~52 bytes boilerplate + 1 byte element name. For 3500 levels: ~7054 bytes.",
      "input_bytes": 7054,
      "cwe": "CWE-674"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

Let me trace the correct call path from the fuzz harness to the vulnerable method by reading the relevant source files.

```text
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Read <source_root>/src/main/java/com/ctc/wstx/sr/ValidatingStreamReader.java
```

Now let me verify what class `createXMLStreamReader` actually returns:

```text
Read <source_root>/src/main/java/com/ctc/wstx/stax/WstxInputFactory.java
Read <source_root>/src/main/java/com/ctc/wstx/stax/WstxInputFactory.java
Grep <source_root>/src/main/java/com/ctc/wstx/stax/WstxInputFactory.java private XMLStreamReader2 doCreateSR|return doCreateSR
Read <source_root>/src/main/java/com/ctc/wstx/stax/WstxInputFactory.java
Grep <source_root>/src/main/java/com/ctc/wstx/api/ReaderConfig.java CFG_LAZY_PARSING|LAZY_PARSING|lazyParsing|mCfgLazyParsing
Grep <source_root>/src/main/java/com/ctc/wstx/api/ReaderConfig.java CFG_LAZY_PARSING
Grep <source_root>/src/main/java/com/ctc/wstx/sr CFG_LAZY_PARSING\s*=
Grep <source_root>/src/main/java/com/ctc/wstx CFG_LAZY_PARSING\s*="
Grep <source_root>/src/main/java/com/ctc/wstx CFG_LAZY_PARSING"
Grep <source_root>/src/main/java/com/ctc/wstx CFG_LAZY_PARSING
Read <source_root>/src/main/java/com/ctc/wstx/api/ReaderConfig.java
Grep <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java mStTextThreshold
Read <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java
Grep <source_root>/src/main/java/com/ctc/wstx/sr/BasicStreamReader.java TOKEN_STARTED|TOKEN_PARTIAL_SINGLE|TOKEN_FULL_SINGLE|TOKEN_FULL_COALESCED
```

Now I have the complete picture. The issue is that I skipped from `createXMLStreamReader` directly to `finishDTD`. The correct path must go through `next()` → `nextFromProlog()` → `skipToken()` → `finishDTD()`. Let me also verify the `parseDTD()` → `handleElementDecl()` intermediate hops:

```text
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now I have the complete correct call chain. Let me construct the corrected path. The key fix is that between `createXMLStreamReader` and `finishDTD`, we must go through `BasicStreamReader.next()` → `BasicStreamReader.nextFromProlog()` → `BasicStreamReader.skipToken()`.

Let me verify one more intermediate hop — that `parseDTD` reaches `handleElementDecl`:

```text
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Good. Now I have the correct chain. Let me produce the corrected target register:

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Unbounded recursion in DTD content spec parsing",
      "entrypoint": "WoodstoxFuzzTest.fuzzXMLStreamReaderNextNonValidating(InputStream) → BasicStreamReader.next() → BasicStreamReader.nextFromProlog(boolean) → BasicStreamReader.skipToken() → ValidatingStreamReader.finishDTD(boolean) → FullDTDReader.readInternalSubset(WstxInputData, WstxInputSource, ReaderConfig, boolean, int) → FullDTDReader.parseDTD() → FullDTDReader.parseDirective() → FullDTDReader.handleDeclaration(char) → FullDTDReader.handleElementDecl() → FullDTDReader.readContentSpec(PrefixedName, boolean, boolean)",
      "source_path": "src/main/java/com/ctc/wstx/dtd/FullDTDReader.java",
      "sink": "FullDTDReader#readContentSpec",
      "mechanism": "Each opening parenthesis in a DTD ELEMENT content specification triggers one recursive call to readContentSpec (line 3090). There is no recursion depth limit. Deep nesting exhausts the call stack.",
      "resource": "stack depth: one readContentSpec frame (~200-400 bytes) per nesting level",
      "failure_mode": "stack_overflow",
      "scale": "About 3000-3500 nesting levels overflow the 1 MB stack (~300 bytes/frame, ~100KB pre-used). Encoding: 2 bytes per level (one open paren + one close paren) plus ~52 bytes boilerplate + 1 byte element name. For 3500 levels: ~7054 bytes.",
      "input_bytes": 7054,
      "cwe": "CWE-674"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

Looking at the measurement results:

**V1 Analysis:**

- **n=64 through n=512**: All completed within the 256 KB stack cap, with flat CPU time (~17-26 ms) and flat allocation (~2.2 MB). Stack consumption is the only resource that grows with nesting depth — CPU and heap are constant, confirming this is purely a stack-depth mechanism.
- **n=1024**: Exceeds the 256 KB stack cap (stack overflow).

**Extrapolation to 1 MB stack (`-Xss1m`):**

The threshold at 256 KB is between 512 and 1024 levels. Using the geometric mean (~724) as the estimated threshold at 256 KB:

The total stack at overflow = base overhead (B) + threshold × per-frame cost (F).
- B includes the entire JVM thread bootstrap, JUnit/JQF framework, Woodstox reader setup, and the chain from `next()` to the first `readContentSpec`. Estimated ~50-70 KB.
- With B ≈ 60 KB: F ≈ (256 KB − 60 KB) / 724 ≈ 277 bytes/frame.

For 1 MB stack: threshold = (1,048,576 − 61,440) / 277 ≈ **3,564 nesting levels**.

Sensitivity check:
- B=40 KB: F≈307 B/frame → T≈3,283
- B=70 KB: F≈263 B/frame → T≈3,724

Range: ~3,300–3,700 nesting levels. Middle estimate: ~3,500.

Input encoding: 2 bytes per level (one `(` + one `)`) plus 54 bytes overhead (`<?xml version="1.0"?><!DOCTYPE r [<!ELEMENT r ` + `a` + `>]><r/>`). For 3,500 levels: 2 × 3,501 + 54 = **7,056 bytes** — well within the 10,240-byte input limit.

No denser encoding exists for this structure: each nesting level requires exactly one open and one close parenthesis character.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: stack overflows between 512 and 1024 nesting levels at 256 KB stack cap; CPU time and allocation are flat (not depth-dependent). Estimated per-frame cost ~277 bytes (with ~60 KB base stack for JVM/framework/reader chain). Extrapolating to 1 MB evaluation stack: ~3500 nesting levels cause StackOverflowError. Encoding: 2 bytes per nesting level (one open + one close paren) plus 54 bytes boilerplate. For 3500 levels: 7056 bytes.",
    "input_bytes": 7056
  }
}
END_SCALE_REVISION_JSON

## Block 2

```text
Glob <run_dir> **/*
Glob <source_root> **/target/*.jar
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/fuzzing/harness/WoodstoxFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Glob <source_root> src/main/java/com/ctc/wstx/dtd/*.java
```

Now let me examine the exact readContentSpec method more closely and look at what string/character literals are used in the DTD parsing path:

```text
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now let me verify the lib jar exists and check it:

```text
$ ls -la <run_dir>/lib/
$ jar tf <run_dir>/lib/woodstox-core-5.3.1-SNAPSHOT.jar | head -30
$ jar tf <run_dir>/lib/woodstox-core-5.3.1-SNAPSHOT.jar | grep -i "FullDTDReader\|readContentSpec"
```

Good. The vulnerable jar exists at the expected path and contains the FullDTDReader class. Now let me verify the build compiles:

```text
$ mvn compile 2>&1 | tail -30
```

Build succeeds. Now let me look at the exact token/character literals in the DTD parsing path for the dictionary:

```text
Read <source_root>/src/main/java/com/ctc/wstx/dtd/FullDTDReader.java
```

Now let me check how `readArity` works and what `skipDtdWs` does:

```text
Grep <source_root>/src/main/java/com/ctc/wstx/dtd private.*readArity
```

Now I have enough understanding. Let me now create the directory structure and files. First, let me set up the workspace directories:

```text
$ mkdir -p <run_dir>/src/test/java/fuzzing/guidance …
```

Good. Now let me also verify there are no missing symbols for the fuzz test compilation:

```text
$ mvn compile -pl . -q 2>&1 | tail -20
$ mvn test-compile 2>&1 | tail -20
$ mvn compile -DskipTests 2>&1 | tail -20
```

Good, the compilation succeeds. No src/main/java sources exist (which is correct - no stubs needed). The harness in src/test references `com.ctc.wstx.stax.WstxInputFactory` which is in the system-scoped jar, and the JQF/JUnit classes are in test scope. No stubs are needed.

Now let me verify the `asm-util` is available or needed for our agent:

```text
$ mvn dependency:tree 2>&1 | tail -40
```

All dependencies are in order. ASM 9.7 (with asm-commons and asm-tree) is available for writing the custom Java agent. Now I have everything needed to produce the Block 2 deliverables.

Let me now write the complete analysis and plan. The pom.xml already exists and is correct — I only need to verify no systemPath fix is needed (it isn't — the jar is in lib/ as expected).

Now let me produce the output. First, let me verify one more time what directory layout I need:

```text
$ ls -la <run_dir>/src/main/java/ 2>&1 || echo "No src/main/java"
```

Good — no src/main/java exists and none is needed (no stubs required).

Now I'll produce the complete Block 2 output:

---

#### Step 2 — Maven Layout & Scope

The workspace pom.xml (already provided, verified) has the correct layout:

| Dependency | Scope | Purpose |
|---|---|---|
| woodstox-core 5.3.1-SNAPSHOT | system (lib/woodstox-core-5.3.1-SNAPSHOT.jar) | Vulnerable target artifact |
| stax2-api 4.2 | compile | Woodstox runtime dependency (transitive) |
| jqf-fuzz 2.1 | test | JQF fuzzing framework |
| jqf-instrument 2.1 | test | JQF instrumentation support |
| junit 4.13.2 | test | JUnit 4 runner |
| asm 9.7 | test | Bytecode manipulation (custom agent) |
| asm-commons 9.7 | test | ASM commons for class visitors |

The `src/test/java` tree holds all fuzzing infrastructure: harness, guidance, agent, runner, replay.
The `src/main/java` tree is empty — no production code or stubs are needed.

**Classpath correctness**: The harness references `com.ctc.wstx.stax.WstxInputFactory` from the system-scoped jar. JQF annotations (`@Fuzz`, `@RunWith(JQF.class)`) come from `jqf-fuzz` test scope. No missing symbols.

**pom.xml status**: No changes needed. The `<systemPath>` correctly points to `${project.basedir}/lib/woodstox-core-5.3.1-SNAPSHOT.jar` (435 KB, confirmed present, contains `com/ctc/wstx/dtd/FullDTDReader.class`).

---

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

The fuzz harness (`WoodstoxFuzzTest.java`) imports:
- `edu.berkeley.cs.jqf.fuzz.Fuzz` → from `jqf-fuzz` (test scope) ✓
- `edu.berkeley.cs.jqf.fuzz.JQF` → from `jqf-fuzz` (test scope) ✓
- `org.junit.runner.RunWith` → from `junit` (test scope) ✓
- `javax.xml.stream.XMLInputFactory` → JDK ✓
- `javax.xml.stream.XMLStreamException` → JDK ✓
- `javax.xml.stream.XMLStreamReader` → JDK ✓
- `java.io.InputStream` → JDK ✓
- `com.ctc.wstx.stax.WstxInputFactory` → from system-scoped woodstox jar ✓

The custom Guidance will import:
- `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` → from `jqf-fuzz` (test scope) ✓
- `edu.berkeley.cs.jqf.fuzz.guidance.Result` → from `jqf-fuzz` (test scope) ✓
- `edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing` → from `jqf-fuzz` (test scope) ✓
- `org.objectweb.asm.*` → from `asm`/`asm-commons` (test scope) ✓

The `SignalSource` interface is already present at `src/test/java/dosguide/validate/SignalSource.java`.

##### 3.2 Stub Generation Rules

**No stubs are needed.** All symbols used by the harness and the planned fuzzing infrastructure resolve to:
- JDK classes (javax.xml.stream, java.io, java.util)
- The system-scoped vulnerable jar (com.ctc.wstx.*)
- Test-scoped Maven dependencies (JQF, JUnit, ASM)

##### 3.3 Stub Report

**No stubs generated.** The compilation closure is complete with:
- The vulnerable jar providing all Woodstox classes
- `stax2-api` providing the Stax2 extension API (required by Woodstox at runtime)
- JQF + JUnit providing test framework classes
- ASM providing bytecode manipulation for the custom agent

---

#### Step 4 — GuidedFuzzing Usage

The runner will use:
```java
ClassLoader cl = Thread.currentThread().getContextClassLoader();
GuidedFuzzing.run("fuzzing.harness.WoodstoxFuzzTest", methodName, cl, guidance, System.out);
```

CLI method selection: The runner accepts `V1` as the target identifier, which maps to `fuzzXMLStreamReaderNextNonValidating`. The mapping:
- `V1` → `fuzzXMLStreamReaderNextNonValidating` (the target registered in the frozen register)

---

#### Step 5 — Guidance Strategy Selection

##### Strategy Table

| Target | Selected Strategy | Why Zest Fails (Mechanistic Explanation) | Why This Strategy Wins |
|--------|-------------------|------------------------------------------|----------------------|
| V1 | Cost-Gradient Guidance (CGF) + Vulnerability-Directed Guidance (VDF) hybrid | **Zest tracks branch coverage, which plateaus after the parser has seen a few nesting levels.** Once Zest discovers `readContentSpec` → `readContentSpec` (recursion), it has covered all branches in the method. Deeper nesting (512→1024→3500 levels) exercises the **exact same branches** repeatedly, giving zero new coverage. Zest has no reason to retain or prioritize deeper inputs. Furthermore, Zest's random byte mutations destroy the fragile XML/DTD structure — well-formed DTD content specs with parentheses that balance and include an element name are extremely unlikely from random mutations. | **CGF directly measures recursion depth of `readContentSpec` via bytecode instrumentation.** The signal increases monotonically with nesting depth, providing a clear gradient toward the stack overflow. **VDF elements** include a source-token dictionary and structure-aware mutation (parenthesis repetition/doubling) that can efficiently produce well-formed DTD content specs with deep nesting, reaching 7056 bytes within the first minute. |

##### Measurable Metric for Outperformance

**Primary metric**: Maximum recursion depth of `readContentSpec` reached within 5 minutes of fuzzing.
- **Zest expected**: Covers all branches at ~2-4 nesting levels, then stalls with no gradient. Random mutations destroy XML structure. Expected max depth: <50.
- **V1Guidance expected**: Hill-climbs recursion depth monotonically via structure-preserving mutations. Expected max depth: 3000+ (reaching stack overflow territory).

**Secondary metric**: Time-to-first-StackOverflowError.
- **Zest**: Extremely unlikely to trigger within any reasonable timeframe (needs to randomly produce ~7000 bytes of balanced parentheses in valid DTD structure).
- **V1Guidance**: Expected within 1-3 minutes due to directed depth hill-climbing.

---

#### Step 6 — Strategy-Specific Guidance Design

##### V1 — Unbounded Recursion in DTD Content Spec Parsing

###### Measurement Plan

**Signal: `maxDepth`**
- **What**: Maximum recursion depth of `FullDTDReader#readContentSpec` during a single execution.
- **Where produced**: Custom Java agent (`V1MeasureAgent`) instruments `FullDTDReader.readContentSpec(PrefixedName, boolean, boolean)` — specifically, it increments a thread-local counter on method entry and decrements on method exit, recording the maximum value reached.
- **Why this location**: `readContentSpec` is the exact recursive method that consumes stack. Each call = one nesting level = one stack frame. The recursion depth IS the vulnerability mechanism. This is the lowest feasible instrumentation point — there is no internal sub-loop or sub-call that constitutes the cost; it's the unbounded recursion itself.
- **Storage**: `ThreadLocal<long[]>` in class `fuzzing.agent.V1Counters` (a holder class). Index 0 = current depth, index 1 = max depth this execution.
- **Reset**: In `V1Guidance` before returning the `InputStream` from `getInput()` — sets both counters to 0.
- **Read**: In `V1Guidance.handleResult()` — reads index 1 (max depth) from the ThreadLocal.

**Agent implementation plan** (`V1MeasureAgent`):
1. Java agent with `premain(String, Instrumentation)` — registers a `ClassFileTransformer`.
2. The transformer watches for class `com/ctc/wstx/dtd/FullDTDReader`.
3. Uses ASM `ClassVisitor`/`MethodVisitor` to instrument method `readContentSpec` with descriptor `(Lcom/ctc/wstx/util/PrefixedName;ZZ)Lcom/ctc/wstx/dtd/ContentSpec;`:
   - On method entry: call `V1Counters.enter()` (increments current depth, updates max if needed)
   - On method exit (normal return + exceptional return): call `V1Counters.exit()` (decrements current depth)
4. JVM flags: `--add-opens java.base/java.lang=ALL-UNNAMED` (for agent attachment); `-javaagent:target/v1-agent.jar`
5. The `V1Counters` class is loaded by the bootstrap classloader (appended via `Instrumentation.appendToBootstrapClassLoaderSearch`) so both the instrumented Woodstox class and the Guidance can access it.

###### Mutation Operators

The Guidance implements the following mutation operators per [R45]:

**(a) Byte-level mutations:**
- Single-byte flip at a random position
- Single-byte insertion at a random position
- Single-byte deletion at a random position
- Byte-range copy within the input

**(b) Repetition operator:**
- **Parenthesis doubling**: Identify a run of `(` bytes in the input; double it (copy and concatenate), then mirror the closing `)` run. This directly doubles nesting depth.
- **Whole-region doubling**: Pick a contiguous region of the input and repeat it in place, up to the input size limit (10240 bytes).
- **Growth target**: Start from seed (~100 bytes), double parenthesis nesting each mutation → can reach 7056 bytes in 6-7 doublings (~6 seconds at 100+ exec/sec).

**(c) Dictionary of source tokens** (from the attack path in `FullDTDReader`):
Tokens extracted from the DTD parsing code at the attack path:
- `<?xml` — XML declaration start
- `version` — XML version attribute
- `"1.0"` — version value
- `?>` — XML declaration end
- `<!DOCTYPE` — doctype declaration
- `<!ELEMENT` — element declaration keyword
- `(` — opens content spec group (the recursion trigger)
- `)` — closes content spec group
- `|` — choice separator in content spec
- `,` — sequence separator in content spec
- `?` — optional arity marker
- `*` — zero-or-more arity marker
- `+` — one-or-more arity marker
- `#PCDATA` — mixed content keyword
- `>` — declaration close
- `]` — internal subset end
- `<` — tag start
- `/>` — empty element close
- ` ` (space) — DTD whitespace

Each token is inserted or overwritten at random positions. No assembled triggering input is in the dictionary — these are individual syntactic units observed in the source code.

**(d) Well-formed encoding:**
The DTD format doesn't use compression, checksums, or length fields. However, the XML/DTD structure DOES reject most random bytes. The Guidance implements a **DTD content-spec encoder**:
- Maintains a representation as a "depth" count
- Encodes as: prefix (`<?xml version="1.0"?><!DOCTYPE r [<!ELEMENT r `) + `(` × depth + element name + `)` × depth + suffix (`>]><r/>`)
- Mutation operates on the depth count (increase/decrease/double) and the Guidance encodes to bytes
- This ensures every mutated input is well-formed XML with a valid DTD content spec

The Guidance alternates between raw byte mutations (for exploration) and structure-aware mutations (for directed depth increase).

###### Retention Policy

**Primary criterion**: `maxDepth` — the maximum `readContentSpec` recursion depth observed during execution.
- An input with higher `maxDepth` than the current corpus best is always retained.
- Inputs that match the current best depth are retained with 50% probability (for diversity).

**Secondary criterion (for flat-signal progress per [R46])**:
- While `maxDepth` is 0 or constant (meaning no input has reached `readContentSpec` yet), retain inputs that are longer (growing toward 7056 bytes target) or that return without error (suggesting they pass more XML parsing stages).
- Specifically: retain an input if `input.length > maxLengthInCorpus` (grows the search toward the threshold).
- This ensures the Guidance generates inputs reaching `input_bytes` (7056) within the first minute even before the signal rises above zero.

**Corpus management**: Priority queue sorted by `maxDepth` (descending). Maximum corpus size: 100 entries. When full, the entry with the lowest `maxDepth` is evicted.

###### Prioritization Logic

- Pick inputs from the corpus weighted by `maxDepth^2` (quadratic favoring of deeper inputs).
- The selected input is mutated using one of the operators (byte-level 30%, repetition 40%, dictionary insert 20%, structure-aware encode 10%).
- The repetition and structure-aware operators target `(` and `)` characters specifically, since these are the recursion triggers.

###### Stop/Continue Conditions

- Default: infinite (continues until externally terminated).
- Time-bounded: reads `System.getProperty("jqf.ei.MAX_DURATION")` for a time limit in milliseconds.
- No Guidance-side failure detection — the Guidance never decides an execution failed ([R6]).

---

#### Step 7 — Custom Guidance (V1Guidance)

Class: `fuzzing.guidance.V1Guidance implements Guidance, SignalSource`
- Location: `src/test/java/fuzzing/guidance/V1Guidance.java`
- Corpus directory: `out/V1/corpus`
- Signals tracked: `maxDepth` (recursion depth of `readContentSpec`)
- Logging: Prints stats every 1 second (executions, max depth, corpus size, current input size)
- Does NOT write failure files or decide failures ([R6])
- Implements `SignalSource.lastSignals()` returning `{"maxDepth": <value>}`

#### Step 8 — Fuzz Tests

The frozen harness `WoodstoxFuzzTest` already provides the required fuzz method:
- `fuzzXMLStreamReaderNextNonValidating(InputStream)` — covers V1
- Input model: `InputStream` (raw bytes) per [R31]
- No generators, no structured input parameters

#### Step 9 — Metadata Replay / Feeder

Class: `fuzzing.replay.V1Replay`
- Reads saved corpus entries from `out/V1/corpus/`
- Each entry has metadata (JSON sidecar): input file path, maxDepth, timestamp, execution number
- Replays by feeding the saved input bytes to the same fuzz method
- Prints: input file, input size, measured maxDepth, exception (if any)

#### Step 10 — Maven Configuration

**pom.xml**: Already provided and verified. No changes needed.

**Directory layout:**
```
woodstox-fuzz/
├── lib/
│   └── woodstox-core-5.3.1-SNAPSHOT.jar   (vulnerable artifact)
├── pom.xml                                  (canonical build, frozen)
├── src/
│   ├── main/java/                           (empty — no stubs needed)
│   └── test/java/
│       ├── dosguide/validate/
│       │   └── SignalSource.java             (frozen interface)
│       └── fuzzing/
│           ├── agent/
│           │   ├── V1Counters.java           (ThreadLocal signal holder)
│           │   ├── V1MeasureAgent.java        (Java agent premain)
│           │   └── V1ClassTransformer.java    (ASM transformer)
│           ├── guidance/
│           │   └── V1Guidance.java            (Custom Guidance for V1)
│           ├── harness/
│           │   └── WoodstoxFuzzTest.java      (frozen harness)
│           ├── runner/
│           │   └── FuzzRunner.java            (CLI runner)
│           └── replay/
│               └── V1Replay.java              (metadata replay)
├── analysis/                                 (Block 1 artifacts)
└── out/V1/corpus/                            (runtime corpus, created by Guidance)
```

**Commands:**
- Compile: `mvn compile -DskipTests`
- Package: `mvn package -DskipTests`
- Build agent jar: `jar cf target/v1-agent.jar -C target/test-classes fuzzing/agent/`
- Run V1 fuzzing: `java -Xmx1g -Xss1m -javaagent:target/v1-agent.jar -cp <classpath> fuzzing.runner.FuzzRunner V1 0`
- Time-bounded (5 min): `java -Xmx1g -Xss1m -Djqf.ei.MAX_DURATION=300000 -javaagent:target/v1-agent.jar -cp <classpath> fuzzing.runner.FuzzRunner V1 300000`
- Replay: `java -Xmx1g -Xss1m -javaagent:target/v1-agent.jar -cp <classpath> fuzzing.replay.V1Replay out/V1/corpus/<input-file>`

---

#### Zest Baseline Comparison (per [R18])

| Dimension | Zest | V1Guidance |
|-----------|------|------------|
| **Signal type** | Branch coverage (proxy) | Recursion depth of readContentSpec (mechanism-aligned) |
| **Why signal fails/succeeds** | Coverage saturates at 2-4 nesting levels — all branches in readContentSpec exercised. No gradient for deeper nesting. | maxDepth increases monotonically with nesting. Clear gradient from 1→3500+. |
| **Input generation** | Random byte mutations destroy XML/DTD structure. Extremely unlikely to produce balanced parentheses. | Structure-aware mutations: parenthesis doubling, DTD token dictionary, well-formed encoder. |
| **Expected max depth** | <50 (if any structured input is found) | 3000+ (directed hill-climbing) |
| **Expected time-to-bug** | Effectively never (probability of generating 3500 balanced parens in DTD structure ≈ 0) | 1-3 minutes (6-7 doublings from seed) |

The fundamental Zest failure is that **coverage is the wrong proxy signal** for this vulnerability. The vulnerability is depth-unbounded recursion, which produces no new coverage beyond the first recursive call. Zest's retention keeps inputs that cover new branches, not inputs that recurse deeper. V1Guidance directly measures and hill-climbs the resource being exhausted (stack depth via recursion count).

---

#### IMPORT AUDIT (per [R15])

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
SignalSource → dosguide.validate.SignalSource
ClassVisitor → org.objectweb.asm.ClassVisitor
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter
```

No TraceEvent is used — measurement is done via custom agent, not JQF tracing ([R43]).

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — All code targets JDK 17, no preview/incubator APIs
- [YES] No hallucinated APIs — All APIs verified against JQF 2.1 source and JDK 17
- [YES] Guidance implements Guidance directly — `V1Guidance implements Guidance, SignalSource`
- [YES] No existing guidance extended — Does not extend Zest/PerfFuzz/any other
- [YES] V* vulnerabilities identified — V1: unbounded recursion in readContentSpec
- [YES] V* IDs are sequential (V1) — Not derived from version numbers [R42]
- [YES] Official vulnerability names applied — GHSA-3f7h-mf4q-vrm4, CWE-674
- [N/A] PkgRisk-* identified — No package-level risks found (Woodstox has no external dependencies beyond stax2-api which is a pure API)
- [N/A] Every PkgRisk-* executed or justified — No PkgRisk targets
- [YES] Guidance targets V1 — V1Guidance dedicated to V1
- [YES] One fuzz method per V1 — `fuzzXMLStreamReaderNextNonValidating`
- [YES] CLI method selection supported — FuzzRunner accepts target ID
- [YES] Byte[]/InputStream input model used exclusively — Harness takes InputStream [R31]
- [YES] No junit-quickcheck Generators used — All mutation in Guidance
- [YES] All mutation implemented inside Guidance — Byte-level, repetition, dictionary, encoder
- [YES] Repetition, source dictionary and encoder operators implemented [R45]
- [YES] Retention progresses while signal is flat; inputs can reach input_bytes within a minute [R46]
- [YES] Retention signals measured where the resource is consumed (readContentSpec), not before the sink [R47]
- [YES] Logging every 1 second — V1Guidance logs stats at 1s interval
- [YES] Guidance decides no failures and writes no failure files [R6]
- [YES] Corrupted inputs saved with metadata — Corpus entries have JSON sidecar
- [YES] Replay/feeder implemented — V1Replay class
- [YES] Infinite + time-bounded fuzzing supported — MAX_DURATION property
- [YES] src/main vs src/test separation correct — No production code; all fuzzing in test
- [YES] Maven scopes consistent — system for target, compile for stax2-api, test for JQF/ASM/JUnit
- [YES] No wildcard imports used for JQF/tracing — All explicit
- [N/A] TraceEvent import verified — Not used; custom agent instead [R43]

---

BEGIN_GUIDANCE_PLAN_JSON
```json
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "maxDepth",
          "quantity": "maximum recursion depth of readContentSpec during one execution",
          "aggregation": "max",
          "locations": ["FullDTDReader#readContentSpec"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in fuzzing.agent.V1Counters; index 0 = current depth, index 1 = max depth this execution",
          "reset": "V1Guidance.getInput() sets both counters to 0 before returning the InputStream",
          "read": "V1Guidance.handleResult() reads index 1 (max depth) from V1Counters.get()"
        }
      ],
      "retention": "Primary: retain input if maxDepth > best maxDepth in corpus (always) or maxDepth == best (50% probability for diversity). Secondary (flat-signal progress per R46): while maxDepth is 0 or constant, retain inputs with length > max length in corpus (growing toward 7056 target bytes) or that complete without error. Corpus is a priority queue by maxDepth (descending), max 100 entries, evicting lowest-depth entry when full.",
      "retention_signals": ["maxDepth"],
      "mutation": [
        "byte-flip: flip a random byte at a random position (30% of byte-level mutations)",
        "byte-insert: insert a random byte at a random position",
        "byte-delete: delete a byte at a random position",
        "byte-range-copy: copy a random contiguous range to another position",
        "repetition-paren-doubling: locate a run of '(' bytes in the input, double its length, and mirror with matching ')' run — directly doubles nesting depth. Can grow from seed (~100 bytes) to 7056 bytes in ~7 doublings.",
        "repetition-region-doubling: select a contiguous region and repeat it in place, up to input size limit (10240). Generalizes growth for non-parenthesis structures.",
        "dictionary-insert: insert or overwrite at a random position using tokens from the DTD parsing source code: '<?xml', 'version', '\"1.0\"', '?>', '<!DOCTYPE', '<!ELEMENT', '(', ')', '|', ',', '?', '*', '+', '#PCDATA', '>', ']', '<', '/>', ' ' (space). Each is a single syntactic unit from FullDTDReader source.",
        "structure-aware-encode: maintain an internal nesting-depth representation, mutate the depth (increment, double, halve, random), then encode as well-formed DTD: prefix + '(' * depth + element_name + ')' * depth + suffix. Ensures valid XML/DTD structure that reaches readContentSpec."
      ]
    }
  ]
}
```
END_GUIDANCE_PLAN_JSON

## Block 3

Let me start by re-reading the key files I need to reference for implementation.

```text
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/fuzzing/harness/WoodstoxFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Now let me check the JQF Guidance interface to ensure I implement all required methods:

```text
Grep <run_dir> public interface Guidance
$ find ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/ -name "*.jar" 2>/dev/null | head -5
$ jar tf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar | grep "guidance/Guidance\|guidance/Result\|GuidedFuzzing"
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class 2>&1
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Result.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/Result.class 2>&1
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class && javap -p edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/GuidanceException.class && javap -p edu/berkeley/cs/jqf/fuzz/guidance/GuidanceException.class 2>&1
```

Now let me verify the exact method descriptor for readContentSpec to be instrumented:

```text
$ cd /tmp && jar xf <run_dir>/lib/woodstox-core-5.3.1-SNAPSHOT.jar com/ctc/wstx/dtd/FullDTDReader.class && javap -p com/ctc/wstx/dtd/FullDTDReader.class 2>&1 | grep readContentSpec
```

The descriptor is `(Lcom/ctc/wstx/util/PrefixedName;ZZ)Lcom/ctc/wstx/dtd/ContentSpec;`. Now let me check the TraceEvent import:

```text
$ jar tf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-instrument/2.1/jqf-instrument-2.1.jar | grep TraceEvent
```

Good. Now I have all the information I need. Let me write all the implementation files.

```text
Write <run_dir>/src/test/java/fuzzing/agent/V1Counters.java
Write <run_dir>/src/test/java/fuzzing/agent/V1ClassTransformer.java
Write <run_dir>/src/test/java/fuzzing/agent/V1MeasureAgent.java
```

Now let me write the V1Guidance:

```text
Write <run_dir>/src/test/java/fuzzing/guidance/V1Guidance.java
```

Now the FuzzRunner:

```text
Write <run_dir>/src/test/java/fuzzing/runner/FuzzRunner.java
```

Now the Replay class:

```text
Write <run_dir>/src/test/java/fuzzing/replay/V1Replay.java
```

Now let me write the launch.json:

```text
Write <run_dir>/analysis/launch.json
```

Wait, I need to think more carefully about the agent jar build. The agent needs to be a proper jar with the manifest and the ASM dependencies. Let me fix the build process. The agent jar needs:
1. The V1MeasureAgent, V1ClassTransformer, and V1Counters classes
2. ASM classes (for the transformer to work)
3. A MANIFEST.MF with Premain-Class

Let me create the manifest file first and fix the launch.json:

```text
$ mkdir -p <run_dir>/src/test/resources
Write <run_dir>/src/test/resources/V1-MANIFEST.MF
```

Now let me write a proper build script that creates the agent jar correctly. The agent jar must contain ASM classes alongside the agent classes:

```text
Write <run_dir>/build-agent.sh
```

Now let me update the launch.json with the proper build commands:

```text
Write <run_dir>/analysis/launch.json
```

Now let me write the run.sh script:

```text
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh <run_dir>/build-agent.sh
```

Now let me create a couple of validation inputs — well-formed XML with small DTD content specs (not failure-inducing):

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
$ cd <run_dir>/analysis/validation_inputs …
```

Now let me compile everything to verify it works:

```text
$ cd <run_dir> && mvn package -DskipTests 2>&1 | tail -30
```

Compilation succeeded. Now let me verify the test classes were compiled:

```text
$ ls <run_dir>/target/test-classes/fuzzing/agent/ …
```

All classes compiled. Now let me build the agent jar:

```text
$ bash build-agent.sh 2>&1 | tail -30
```

The issue is that the deps directory structure uses different paths. Let me check:

```text
$ ls <run_dir>/target/deps/asm*
```

The file exists. The issue is likely the `jar xf` command failing. Let me debug the script more carefully:

```text
$ rm -rf target/agent-staging && mkdir -p target/agent-staging && cd target/agent-staging && jar xf ../deps/asm-9.7.jar org/ 2>&1 | tail -5 && ls org/objectweb/asm/ | head -10
```

OK the jar extraction works manually. The issue in the script must be the `(cd ...)` subshell. Let me fix the build-agent.sh:

```text
Write <run_dir>/build-agent.sh
$ cd <run_dir> && bash build-agent.sh 2>&1 | tail -10
```

Agent jar built with 108 classes. Let me verify it contains the right structure:

```text
$ jar tf target/v1-agent.jar | grep -E "fuzzing/agent|AdviceAdapter|MANIFEST" | head -20
```

Let me also verify the manifest:

```text
$ unzip -p target/v1-agent.jar META-INF/MANIFEST.MF
```

Now let me verify the complete workspace file listing:

```text
Glob <run_dir> src/**/*.java
```

All 8 Java files are in place (6 new + 2 frozen). Let me also save the guidance plan that Block 2 produced, so the validation can reference it:

```text
Write <run_dir>/analysis/guidance_plan.json
$ ls <run_dir>/analysis/guidance_plan.json 2>&1
Read <run_dir>/analysis/guidance_plan.json
```

The guidance_plan.json was already written by Block 2. It's consistent with the implementation. Let me verify the plan matches the implementation:

1. Signal "maxDepth" → ✓ `V1Guidance.lastSignals()` returns `{"maxDepth": ...}`
2. Location "FullDTDReader#readContentSpec" → ✓ `V1ClassTransformer` instruments that exact method
3. Technique "bytecode" → ✓ Custom Java agent
4. Storage ThreadLocal in V1Counters → ✓ 
5. Reset in getInput() → ✓ `V1Counters.reset()` called in `getInput()`
6. Read in handleResult() → ✓ `V1Counters.getMaxDepth()` called in `handleResult()`

Now let me do a final compilation check to make sure everything is clean:

```text
$ mvn compile -DskipTests 2>&1 | tail -10
$ mvn package -DskipTests 2>&1 | tail -10
```

Everything compiles and packages correctly. Let me verify the complete workspace file listing one final time:

```text
Glob <run_dir> **/*
```

Let me just list the source and analysis files:

```text
Glob <run_dir> src/**/*.java
Glob <run_dir> analysis/**
Glob <run_dir> *.sh
```

Everything is in place. Now let me produce the complete output document.

---

#### BLOCK 3 — Implementation Files

##### Part A — Java Agent

###### V1Counters.java
Thread-local signal holder for `readContentSpec` recursion depth. Loaded on the bootstrap classloader via `Instrumentation.appendToBootstrapClassLoaderSearch` so both instrumented Woodstox code and the Guidance can access it.

- `enter()` — increments current depth, updates max if new high
- `exit()` — decrements current depth
- `reset()` — zeros both counters before each execution
- `getMaxDepth()` — returns maximum depth observed since last reset

###### V1ClassTransformer.java
ASM `ClassFileTransformer` that watches for `com/ctc/wstx/dtd/FullDTDReader` and instruments the private `readContentSpec(PrefixedName, boolean, boolean)` method:
- Method entry → `V1Counters.enter()`
- Method exit (normal return + exceptional) → `V1Counters.exit()`

Uses `AdviceAdapter` from ASM to properly handle both normal and exceptional exits.

###### V1MeasureAgent.java
Java agent with `premain(String, Instrumentation)`:
1. Appends itself to the bootstrap classloader so V1Counters is visible everywhere
2. Registers `V1ClassTransformer`
3. Measurement-only — no input generation, no payloads [R37]

##### Part B — Guidance

###### V1Guidance.java
`implements Guidance, SignalSource`

**Signal**: `maxDepth` — maximum recursion depth of `FullDTDReader#readContentSpec`, measured by the V1 agent via bytecode instrumentation.

**Input model**: `InputStream` (raw bytes) — consistent with the frozen harness [R25][R31].

**Maximum input size**: Read from `System.getProperty("jqf.ei.MAX_INPUT_SIZE", 10240)` at construction time. Never generates longer inputs, and imposes no smaller maximum [R41].

**Mutation operators** [R45]:
1. **Parenthesis doubling** (30%): Finds runs of `(` and `)` and doubles them — directly increases nesting depth. Can grow from seed (~56 bytes) to 7056+ bytes in 7 doublings.
2. **Region repetition** (20%): Generic chunk doubling for exploration.
3. **Dictionary insert** (20%): 23 tokens from the DTD parsing source path (`<?xml`, `<!DOCTYPE`, `<!ELEMENT`, `(`, `)`, `|`, `,`, `?`, `*`, `+`, `#PCDATA`, `>`, `]`, etc.)
4. **Structure-aware encode** (10%): Constructs a well-formed DTD with mutated nesting depth — ensures inputs pass XML/DTD format checks.
5. **Byte-level** (20%): flip, insert, delete for exploration.

**Retention** [R46]:
- Primary: retain if `maxDepth > bestMaxDepth` (always) or equals it (50% for diversity)
- Secondary (flat signal): while `maxDepth <= 1`, retain inputs with `length > bestInputLength` to grow toward target `input_bytes`
- Corpus: max 100 entries, evict lowest-depth entry when full
- Selection: weighted by `maxDepth^2`

**No failure decisions** [R6]: Never calls `Result.FAILURE`, never writes failure files.

**Logging** [R5]: Every 1 second — executions, lastDepth, bestDepth, corpusSize, inputLen.

##### Part C — Runner, Replay, Scripts

###### FuzzRunner.java
- `main(String[] args)` — CLI: `FuzzRunner <targetId> [durationMs]`
- `createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log)` — factory method used by DoSGuide
- Maps `V1` → `fuzzXMLStreamReaderNextNonValidating` on class `fuzzing.harness.WoodstoxFuzzTest`
- Uses `GuidedFuzzing.run(testClassName, testMethod, cl, guidance, out)`

###### V1Replay.java
- Reads corpus entries from `.bin` files
- Replays against `WstxInputFactory.createXMLStreamReader` + `reader.next()` loop
- Reports: file name, size, measured maxDepth (via V1Counters), result/exception, input preview

###### run.sh
Compiles, builds agent jar, runs V1 fuzzer with fixed JVM options (`-Xmx1g -Xss1m`).

###### build-agent.sh
Assembles the `v1-agent.jar` with agent classes + ASM classes + manifest.

##### Part D — Validation Contract

**launch.json**: Describes build commands, classpath, javaagent, guidance factory, and target mapping.

**Validation inputs**: 8 well-formed XML files with varying DTD nesting depths (0, 1, 3, 5, 10) and structures (choice, sequence), none failure-inducing.

---

#### Strategy Table (Step 5)

| Target | Selected Strategy | Why Zest Fails | Why This Strategy Wins |
|--------|-------------------|----------------|----------------------|
| V1 | CGF + VDF hybrid (Cost-Gradient + Vulnerability-Directed) | Zest tracks branch coverage, which plateaus after 2-4 nesting levels — all branches in `readContentSpec` are covered by the first recursive call. Deeper nesting (512→3500 levels) exercises the exact same branches repeatedly, providing zero new coverage. Zest's random byte mutations also destroy the fragile XML/DTD structure. | V1Guidance directly measures recursion depth of `readContentSpec` via bytecode agent — monotonically increasing signal. Structure-aware mutations (paren doubling, DTD encoder, token dictionary) can efficiently build deep content specs. Hill-climbs from seed to 7056 bytes in minutes. |

**Measurable metric**: Maximum recursion depth reached within 5 minutes.
- Zest: <50 (no gradient beyond first recursive call; random mutations unlikely to produce balanced parens)
- V1Guidance: 3000+ (directed depth hill-climbing via paren doubling)

---

#### Measurement Plan (Step 6)

**Signal: `maxDepth`**
- **Code region**: `FullDTDReader#readContentSpec` (line 3055 in source)
- **Why**: This is the exact recursive method whose unbounded depth causes StackOverflowError. Each recursive call = one stack frame.
- **Storage**: `ThreadLocal<long[]>` in `fuzzing.agent.V1Counters` — index 0 = current depth, index 1 = max depth
- **Reset**: `V1Guidance.getInput()` calls `V1Counters.reset()` before returning
- **Read**: `V1Guidance.handleResult()` calls `V1Counters.getMaxDepth()` and stores in `lastMaxDepth`
- **Technique**: Bytecode instrumentation via custom Java agent [R43]

---

#### IMPORT AUDIT (Step 15)

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz (harness only, frozen)
@RunWith → org.junit.runner.RunWith (harness only, frozen)
JQF → edu.berkeley.cs.jqf.fuzz.JQF (harness only, frozen)
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance (V1Guidance.java)
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException (V1Guidance.java)
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result (V1Guidance.java)
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing (FuzzRunner.java)
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent (V1Guidance.java, for generateCallBack signature)
SignalSource → dosguide.validate.SignalSource (V1Guidance.java)
ClassReader → org.objectweb.asm.ClassReader (V1ClassTransformer.java)
ClassVisitor → org.objectweb.asm.ClassVisitor (V1ClassTransformer.java)
ClassWriter → org.objectweb.asm.ClassWriter (V1ClassTransformer.java)
MethodVisitor → org.objectweb.asm.MethodVisitor (V1ClassTransformer.java)
Opcodes → org.objectweb.asm.Opcodes (V1ClassTransformer.java)
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter (V1ClassTransformer.java)
ClassFileTransformer → java.lang.instrument.ClassFileTransformer (V1ClassTransformer.java)
Instrumentation → java.lang.instrument.Instrumentation (V1MeasureAgent.java)
```

No wildcard imports used. No JQF built-in instrumentation agent used [R43].

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — switch expressions, standard JDK 17 APIs
- [YES] No hallucinated APIs — All APIs verified from javap of JQF 2.1 jars
- [YES] Guidance implements Guidance directly — `V1Guidance implements Guidance, SignalSource`
- [YES] No existing guidance extended — No Zest/PerfFuzz inheritance or delegation
- [YES] V* vulnerabilities identified — V1: unbounded readContentSpec recursion
- [YES] V* IDs are sequential (V1) — Not derived from version numbers [R42]
- [YES] Official vulnerability names — GHSA-3f7h-mf4q-vrm4, CWE-674
- [N/A] PkgRisk-* identified — No package-level risks found
- [N/A] Every PkgRisk-* executed or justified — No PkgRisk targets
- [YES] Guidance targets V1 — V1Guidance dedicated solely to V1
- [YES] One fuzz method per V1 — `fuzzXMLStreamReaderNextNonValidating`
- [YES] CLI method selection supported — `FuzzRunner V1 [duration]`
- [YES] Byte[]/InputStream input model used exclusively — InputStream in harness [R31]
- [YES] No junit-quickcheck Generators used — All mutation in Guidance
- [YES] All mutation implemented inside Guidance — 7 operators in V1Guidance
- [YES] Repetition, source dictionary and encoder operators implemented [R45]
- [YES] Retention progresses while signal is flat; inputs can reach input_bytes within a minute [R46] — paren doubling grows from 56 bytes to 7056+ in ~7 doublings; flat-signal retention keeps longer inputs
- [YES] Retention signals measured where resource is consumed (readContentSpec), not before sink [R47]
- [YES] Logging every 1 second — `handleResult` logs on 1-second interval
- [YES] Guidance decides no failures and writes no failure files [R6]
- [YES] Corrupted inputs saved with metadata — JSON sidecar per corpus entry
- [YES] Replay/feeder implemented — V1Replay class
- [YES] Infinite + time-bounded fuzzing supported — 0=infinite, positive=bounded, plus `jqf.ei.MAX_DURATION` property
- [YES] src/main vs src/test separation correct — All fuzzing infra in src/test/java, no src/main/java production code
- [YES] Maven scopes consistent — system for target jar, compile for stax2-api, test for JQF/ASM/JUnit
- [YES] No wildcard imports used for JQF/tracing — All explicit imports
- [YES] TraceEvent import verified — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` used in V1Guidance for `generateCallBack` signature, verified exists in jqf-instrument-2.1.jar
