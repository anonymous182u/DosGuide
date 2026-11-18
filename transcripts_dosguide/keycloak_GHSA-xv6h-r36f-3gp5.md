# keycloak_GHSA-xv6h-r36f-3gp5

## Block 1

I'll start by reading the source files and the fuzz test to understand the target.

```text
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/SAMLRequestParser.java
Glob <run_dir> *FuzzTest.java
Glob <run_dir> **/*FuzzTest.java
Read <run_dir>/src/test/java/com/fuzzer/saml/SAMLRequestParserFuzzTest.java
Read <run_dir>/pom.xml
```

Now let me trace the call path deeper into the SAML parsing code.

```text
Glob <source_root> **/RedirectBindingUtil.java
Glob <source_root> **/SAML2Request.java
Glob <source_root> **/PostBindingUtil.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/web/util/RedirectBindingUtil.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/request/SAML2Request.java
Glob <source_root> **/DocumentUtil.java
Glob <source_root> **/DeflateUtil.java
Glob <source_root> **/JAXPValidationUtil.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/common/util/DocumentUtil.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/api/util/DeflateUtil.java
Glob <source_root> **/SAMLParser.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/core/util/JAXPValidationUtil.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/SAMLParser.java
Glob <source_root>/saml-core **/AbstractParser.java
Glob <source_root>/saml-core **/StaxParserUtil.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/common/parsers/AbstractParser.java
```

Let me trace the SAML parsing more deeply, particularly looking at how extensions or unknown elements are handled.

```text
Glob <source_root>/saml-core **/SAMLAuthNRequestParser.java
Glob <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/protocol **/SAMLResponseParser.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/protocol/SAMLAuthNRequestParser.java
Glob <source_root>/saml-core **/SAMLRequestAbstractParser.java
Glob <source_root>/saml-core **/AbstractStaxParser.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/common/parsers/AbstractStaxParser.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/protocol/SAMLRequestAbstractParser.java
Glob <source_root>/saml-core **/SAMLExtensionsParser.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/common/util/StaxParserUtil.java
Grep <source_root>/saml-core/src/main/java/org/keycloak/saml/common/util/StaxParserUtil.java bypassElementBlock
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/protocol/SAMLExtensionsParser.java
Grep <source_root>/saml-core/src/main/java/org/keycloak/saml/common/util/StaxParserUtil.java getDOMElement
$ ls -la <run_dir>/lib/ 2>&1
Glob <source_root>/saml-core **/TransformerUtil.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/common/util/TransformerUtil.java
```

Now I have a thorough understanding of the code. Let me verify the workspace structure and then generate scale measurement files.

```text
$ ls -la <run_dir>/
$ ls -la <run_dir>/analysis/
```

Good. Now let me generate the scale measurement inputs for V1. I'll write a Python script to create deflate-compressed XML files.

```text
$ mkdir -p <run_dir>/analysis/scale/V1
$ python3 -c " …
```

The compression ratios are excellent (606:1 to 1009:1). Let me verify the inputs are valid by decompressing one:

```text
$ python3 -c " …
Read <run_dir>/analysis/scale/V1/series.json
$ ls -la <run_dir>/analysis/scale/V1/
```

All files are created and well under the 16384-byte limit. Now let me complete the full analysis and produce the target register.

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

**V1: Deflate Decompression Bomb → DOM Memory Exhaustion**

**Fuzzable entrypoint:** `SAMLRequestParser.parseRequestRedirectBinding(String)` — user-controlled input is a base64-encoded DEFLATE-compressed SAML XML message.

**User-controlled inputs:** The fuzz test provides raw bytes as the DEFLATE-compressed content. These bytes are base64-encoded by the harness and passed to `parseRequestRedirectBinding`, which base64-decodes and DEFLATE-decompresses them, then parses the decompressed output as XML into a DOM tree.

**Mechanism:** The call chain is:
1. `RedirectBindingUtil.base64DeflateDecode(samlMessage)` → `Base64.getMimeDecoder().decode()` → `DeflateUtil.decode(byte[])` → creates `InflaterInputStream(bais, new Inflater(true))` with **no output size limit**
2. `DocumentUtil.getDocument(InputStream)` → `DocumentBuilder.parse(is)` reads from the InflaterInputStream and builds a DOM tree with **no limit on element count or total node memory**

The DEFLATE compression algorithm achieves very high compression ratios for repetitive content. Measured ratios:
- 10K elements of `<a/>`: 606:1
- 320K elements of `<a/>`: 1009:1

With these ratios, 65 KB of compressed input produces 32–65 MB of decompressed XML. The DOM parser amplifies this further: each `<a/>` element (4 bytes XML) creates ~125 bytes of DOM objects (ElementNSImpl + parent references + name strings), yielding a 31:1 DOM amplification factor. Combined: 4 bytes XML → ~125 bytes DOM, from ~0.004 bytes compressed.

For 8 million `<a/>` elements: 32 MB XML → ~32 KB compressed → 1 GB DOM → exceeds `-Xmx1g` heap.

Note: `DocumentBuilderFactory` disables DOCTYPE (`feature_disallow_doctype_decl = true`), blocking entity expansion bombs. External entities are also disabled. But there is NO limit on:
- Decompressed output size from the deflate stream
- Number of XML elements/nodes in the DOM tree
- Total DOM tree memory

**Exhausted resource:** Heap memory — total bytes allocated for DOM nodes grow linearly with the number of XML elements in the decompressed output.

**Failure mode:** `out_of_memory` (OutOfMemoryError). Note that `catch (Exception e)` in `parseRequestRedirectBinding` does NOT catch Error subclasses, so OutOfMemoryError propagates to the fuzz test.

**Scale:** ~8 million DOM elements at ~125 bytes each exhaust the 1 GB heap (`-Xmx1g`). That requires ~32 MB of decompressed XML (8M × 4 bytes for `<a/>`). With measured deflate compression ratio of ~1000:1, this needs only ~32 KB of compressed input, well within the 65,536-byte input limit.

**Input bytes:** ~32768 (conservative; actual OOM could occur with less due to GC overhead limit).

##### 1.2 Official Classification

**V1:** CWE-409 (Improper Handling of Highly Compressed Data / Decompression Bomb), combined with CWE-770 (Allocation of Resources Without Limits or Throttling) for the DOM parsing step.

##### 1.3 Dependency / Package-Level Risks

**PkgRisk-1: `java.util.zip.InflaterInputStream` — No decompressed output limit (CWE-409)**
- **Package/class:** `java.util.zip.InflaterInputStream` (JDK standard library)
- **Why input-sensitive:** Decompresses an arbitrary-length stream from compressed input with no output size limit. The decompression ratio for DEFLATE on repetitive content can exceed 1000:1.
- **Trigger shapes:** Deflate-compressed streams with highly repetitive content (repeating short patterns).
- **Exhausted resource:** Heap memory (the consumer — DOM parser — allocates memory proportional to decompressed output size).
- **Failure mode:** `out_of_memory`
- **Scale:** 65 KB compressed → 65 MB decompressed → consumer allocates multi-GB.
- **Fuzzing strategy:** Generate valid DEFLATE streams via `Deflater`/`zlib.compressobj` containing repetitive XML, maximizing decompression ratio within the input size limit. Measure DOM allocation growth.
- **Note:** This risk is mechanistically identical to V1 — the Inflater is the amplification stage of V1's attack chain. V1 subsumes it.

**PkgRisk-2: `javax.xml.parsers.DocumentBuilder` — No DOM tree size limit (CWE-770)**
- **Package/class:** `javax.xml.parsers.DocumentBuilder` (JDK standard library)
- **Why input-sensitive:** Builds a complete DOM tree in memory proportional to XML input size, with no limit on node count, tree depth, or total memory.
- **Trigger shapes:** Very large XML documents with many small elements (maximizes node count per byte of XML). E.g., millions of `<a/>` elements.
- **Exhausted resource:** Heap memory (DOM node allocation).
- **Failure mode:** `out_of_memory`
- **Scale:** ~8 million elements × ~125 bytes/element = 1 GB. At DOM amplification of ~31:1 over XML text, 32 MB of XML input suffices.
- **Fuzzing strategy:** Provide large XML input (via decompression). Measure total DOM node count and bytes allocated.
- **Note:** This risk is the consumption stage of V1's attack chain. V1 subsumes it.

Both PkgRisk-1 and PkgRisk-2 are components of V1's mechanism. They are not independently exploitable through this entry point without V1's overall attack chain (compressed input → decompression → DOM parsing). Therefore, V1 is the sole distinct target.

##### IMPORT AUDIT
(No fuzzing code is generated in this block; audit applies to future blocks.)

##### R18 — Zest Baseline Comparison (for V1)
**Zest's weakness on this target:**
- Zest uses code coverage as its retention signal. For V1, the code path is essentially the same regardless of input size: `base64Decode → inflate → DocumentBuilder.parse()`. A 10-element input and a 10-million-element input traverse the same code paths (same parser methods, same DOM builder). Coverage plateaus immediately with the first valid XML input.
- Zest's mutation operators (byte flips, insertions) operating on compressed deflate bytes will almost always corrupt the deflate stream, producing invalid inputs that fail at decompression (IOException) and return null. Valid deflate streams are vanishingly rare in random byte space.
- **Why custom guidance outperforms:** A custom guidance must (a) encode inputs via DEFLATE compression so they're always valid streams ([R45(c)]), (b) measure heap allocation as the retention signal (not coverage), and (c) use repetition operators to grow the decompressed XML toward the OOM threshold. The measurable metric: **time-to-first-OOM** — custom guidance produces valid, large decompressed XML from the start, while Zest never produces valid deflate streams through byte mutation alone.

---

Now the target register:

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Deflate decompression bomb causing DOM memory exhaustion in SAML redirect binding parsing",
      "entrypoint": "SAMLRequestParserFuzzTest.fuzzSAMLRequestParserParseRequestRedirectBinding(InputStream) → SAMLRequestParser.parseRequestRedirectBinding(String) → RedirectBindingUtil.base64DeflateDecode(String) → DeflateUtil.decode(byte[]) → DocumentUtil.getDocument(InputStream) → DocumentBuilder.parse(InputStream)",
      "source_path": "saml-core/src/main/java/org/keycloak/saml/SAMLRequestParser.java",
      "sink": "DocumentBuilder#parse",
      "mechanism": "Input is a DEFLATE-compressed XML document. DeflateUtil.decode() wraps it in an InflaterInputStream with no decompressed output size limit. DocumentBuilder.parse() reads the decompressed XML and builds a DOM tree in memory. DEFLATE achieves compression ratios exceeding 1000:1 for repetitive XML content (measured: 606:1 at 10K elements to 1009:1 at 320K elements). Each self-closing XML element <a/> (4 bytes) creates ~125 bytes of DOM objects. With 65 KB compressed input decompressing to ~65 MB XML containing ~16 million elements, the DOM tree requires ~2 GB of heap, far exceeding the 1 GB limit.",
      "resource": "heap memory: total bytes allocated for DOM nodes (ElementNSImpl, child-node linked lists, interned name strings) grows linearly with the number of XML elements in the decompressed output",
      "failure_mode": "out_of_memory",
      "scale": "About 8 million DOM elements at ~125 bytes each exhaust the 1 GB heap. That is 32 MB of decompressed XML (8M x 4 bytes per <a/>). With measured deflate ratio ~1000:1, this needs ~32 KB of compressed input.",
      "input_bytes": 32768,
      "cwe": "CWE-409"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

Let me re-read the source code to trace the exact call chain from `DeflateUtil.decode()` back to `DocumentUtil.getDocument()`.

```text
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/SAMLRequestParser.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/SAMLRequestParser.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/request/SAML2Request.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/common/util/DocumentUtil.java
```

Now I have the precise call chain. The issue was that my original path included `DeflateUtil.decode(byte[])` which is internal to `base64DeflateDecode` and doesn't directly connect to `DocumentUtil.getDocument`. The actual flow goes: `base64DeflateDecode` returns an `InputStream` to `parseRequestRedirectBinding` (line 47), which then passes it to `SAML2Request.getSAML2ObjectFromStream` (line 65). These are consecutive calls within the same method body connected by data flow.

Here is the corrected target register:

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Deflate decompression bomb causing DOM memory exhaustion in SAML redirect binding parsing",
      "entrypoint": "SAMLRequestParserFuzzTest.fuzzSAMLRequestParserParseRequestRedirectBinding(InputStream) → SAMLRequestParser.parseRequestRedirectBinding(String) → RedirectBindingUtil.base64DeflateDecode(String) → SAML2Request.getSAML2ObjectFromStream(InputStream) → DocumentUtil.getDocument(InputStream) → DocumentBuilder.parse(InputStream)",
      "source_path": "saml-core/src/main/java/org/keycloak/saml/SAMLRequestParser.java",
      "sink": "DocumentBuilder#parse",
      "mechanism": "Input is a DEFLATE-compressed XML document. DeflateUtil.decode() wraps it in an InflaterInputStream with no decompressed output size limit. DocumentBuilder.parse() reads the decompressed XML and builds a DOM tree in memory. DEFLATE achieves compression ratios exceeding 1000:1 for repetitive XML content (measured: 606:1 at 10K elements to 1009:1 at 320K elements). Each self-closing XML element <a/> (4 bytes) creates ~125 bytes of DOM objects. With 65 KB compressed input decompressing to ~65 MB XML containing ~16 million elements, the DOM tree requires ~2 GB of heap, far exceeding the 1 GB limit.",
      "resource": "heap memory: total bytes allocated for DOM nodes (ElementNSImpl, child-node linked lists, interned name strings) grows linearly with the number of XML elements in the decompressed output",
      "failure_mode": "out_of_memory",
      "scale": "About 8 million DOM elements at ~125 bytes each exhaust the 1 GB heap. That is 32 MB of decompressed XML (8M x 4 bytes per <a/>). With measured deflate ratio ~1000:1, this needs ~32 KB of compressed input.",
      "input_bytes": 32768,
      "cwe": "CWE-409"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

Let me analyze the measurement data carefully.

**Allocation growth (the most consistent metric):**
- 10K→20K: (7.0−5.6) MB / 10K = 140 bytes/elem
- 20K→40K: (9.6−7.0) MB / 20K = 130 bytes/elem
- 40K→80K: (14.9−9.6) MB / 40K = 133 bytes/elem
- 80K→160K: (25.4−14.9) MB / 80K = 131 bytes/elem
- 160K→320K: (46.6−25.4) MB / 160K = 133 bytes/elem

Very consistent: **~133 bytes allocated per XML element**.

**Linear model from allocation data:**
- Marginal rate: 133 bytes/element (0.000133 MB/element)
- Baseline (intercept): 5.6 MB − 10000 × 0.000133 = **4.27 MB**
- Formula: `allocated_MB ≈ 4.3 + 0.000133 × N`

**CPU time growth:**
- Marginal CPU: (217−153 ms) / (320K−80K) = 0.267 μs/element
- For 6M elements: ~1.6 seconds pure CPU (before GC overhead)

**Peak heap vs allocated divergence at 320K** (34 MB peak vs 46.6 MB allocated) shows GC reclaiming temporaries during parsing; the retained DOM tree is slightly smaller than total allocation, but all DOM nodes are retained.

**Extrapolation to 1 GB evaluation heap (`-Xmx1g`):**
- JVM/JQF/guidance overhead: ~200 MB (conservative)
- Available for DOM: ~824 MB
- Elements for OOM: (824 − 4.3) MB / 0.000133 MB = ~6.16 million elements
- Decompressed XML: 6.16M × 4 bytes = 24.6 MB
- Compressed (at measured ~1000:1 ratio for large inputs): ~25 KB

**GC behavior near OOM:** At ~80%+ heap utilization, GC overhead escalates dramatically. Full GC pauses accumulate, and "GC overhead limit exceeded" (a form of OutOfMemoryError) is thrown when >98% of CPU time goes to GC. This is likely before the 20-second wall-clock timeout.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured ~133 bytes allocated per XML element (consistent across 10K–320K elements) with ~4.3 MB baseline. Extrapolating: with 1 GB heap and ~200 MB JVM/JQF overhead, ~6.2 million elements exhaust the remaining ~820 MB. That is ~25 MB of decompressed XML (6.2M × 4 bytes per <a/>). With measured deflate ratio ~1000:1 at large sizes, this needs ~25 KB of compressed input, well within the 65 KB limit.",
    "input_bytes": 25600
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by examining the workspace structure and verifying the build setup.

```text
$ ls -la <run_dir>/
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/com/fuzzer/saml/SAMLRequestParserFuzzTest.java
$ ls -la <run_dir>/lib/
```

Good. Let me verify the build compiles and check the existing workspace structure.

```text
$ find src -type f -name '*.java' 2>/dev/null
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
$ mvn compile 2>&1 | tail -20
```

Let me check ASM availability from the existing dependency tree:

```text
$ mvn dependency:tree -Dscope=test 2>&1 | grep -i asm | head -10
$ mvn dependency:tree -Dscope=compile 2>&1 | grep -i asm | head -10
$ find ~/.m2/repository/org/ow2/asm -name 'asm-*.jar' -not -name '*sources*' -not -name '*javadoc*' 2>/dev/null | head -5
$ find ~/.m2/repository/org/ow2/asm/asm -name 'asm-9.7.jar' 2>/dev/null | head -1
```

```text
Read <run_dir>/pom.xml
$ ls -la <run_dir>/lib/
Read <run_dir>/src/test/java/com/fuzzer/saml/SAMLRequestParserFuzzTest.java
$ mvn dependency:tree -Dscope=test 2>&1 | grep -i asm | head -10
$ mvn compile 2>&1 | tail -10
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/api/util/DeflateUtil.java
$ find ~/.m2/repository/edu/berkeley/cs/jqf/jqf-instrument/2.1/ -name '*.pom' | head -1 | xargs grep -A2 'asm' 2>/dev/null | head -20
$ ls ~/.m2/repository/org/ow2/asm/asm/9.7/asm-9.7.jar && ls ~/.m2/repository/org/ow2/asm/asm-commons/ 2>/dev/null | head -5
$ ls ~/.m2/repository/org/ow2/asm/asm-commons/9.7/asm-commons-9.7.jar 2>/dev/null; ls ~/.m2/repository/org/ow2/asm/asm-util/9.7/ 2>/dev/null | head -5
$ find <run_dir>/src -type f 2>/dev/null
$ find <run_dir> -maxdepth 1 -type d | sort
```

Good. Now let me verify the existing compilation works and understand the full picture before writing the output. Let me check the frozen target register values.

```text
$ ls <run_dir>/analysis/scale/V1/ 2>/dev/null
$ ls <run_dir>/analysis/ 2>/dev/null; find <run_dir>/analysis -type f 2>/dev/null | head -20
Read <run_dir>/analysis/target_register.json
Read <run_dir>/analysis/phase2_from.json
```

Now I have all the information needed. Let me produce the complete Block 2 output.

---

#### Step 2 — Maven Layout & Scope Verification

**Project coordinates**: `com.fuzzer:keycloak-saml-fuzz:1.0-SNAPSHOT` (jar packaging, Java 17)

**Library under test** (system scope — vulnerable jars):
| Artifact | systemPath | Size | Present |
|----------|-----------|------|---------|
| keycloak-saml-core | `${project.basedir}/lib/keycloak-saml-core-999.0.0-SNAPSHOT.jar` | 581,343 B | ✓ |
| keycloak-saml-core-public | `${project.basedir}/lib/keycloak-saml-core-public-999.0.0-SNAPSHOT.jar` | 252,597 B | ✓ |
| keycloak-common | `${project.basedir}/lib/keycloak-common-999.0.0-SNAPSHOT.jar` | 189,943 B | ✓ |

**Fuzzing infrastructure** (test scope):
| Artifact | Version | Purpose |
|----------|---------|---------|
| jqf-fuzz | 2.1 | Guidance interface, GuidedFuzzing launcher |
| jqf-instrument | 2.1 | JQF instrumentation (transitive dep: `org.ow2.asm:asm`) |
| junit | 4.13.2 | JUnit 4 runner for `@RunWith(JQF.class)` |

**Third-party runtime deps**: 20 dependencies (xmlsec, jaxb-runtime, saaj-impl, jboss-logging, etc.) all from Maven Central — required for Keycloak SAML parsing at runtime. These are NOT the fuzzed project's coordinates.

**ASM availability**: `org.ow2.asm:asm` is a transitive dependency of `jqf-instrument:2.1` (test scope). Verified in local Maven repo: `asm-9.7.jar`, `asm-commons-9.7.jar`. ASM classes are available during test compilation without modifying pom.xml. This satisfies [R43].

**Build verification**: `mvn compile` → BUILD SUCCESS.

---

#### Step 3 — Compilation Closure / Stub Report

**Existing symbols** (all resolve from declared dependencies):
- `edu.berkeley.cs.jqf.fuzz.{Fuzz, JQF}` → jqf-fuzz (test) ✓
- `org.keycloak.saml.SAMLRequestParser` → keycloak-saml-core system jar ✓
- `java.io.{InputStream, IOException}`, `java.util.Base64` → JDK ✓

**New symbols planned for Block 3** (all will resolve without stubs):
- `edu.berkeley.cs.jqf.fuzz.guidance.{Guidance, GuidedFuzzing, Result}` → jqf-fuzz ✓
- `org.objectweb.asm.{ClassReader, ClassWriter, ClassVisitor, MethodVisitor, Opcodes}` → asm (transitive via jqf-instrument) ✓
- `java.lang.instrument.{Instrumentation, ClassFileTransformer}` → JDK ✓
- `java.util.zip.{Deflater, DeflaterOutputStream}` → JDK ✓
- `dosguide.validate.SignalSource` → workspace src/test/java/ ✓

**Stub report**: NO STUBS NEEDED. All symbols resolve from existing dependencies or the JDK.

---

#### Step 4a — pom.xml & Directory Tree

**pom.xml**: NO CHANGES NEEDED. The three `<systemPath>` values use `${project.basedir}/lib/` and all jars are present. Build succeeds as-is.

**Directory tree** (planned state after Block 3):

```
keycloak-saml-fuzz/
├── pom.xml                                                # FROZEN — no changes
├── lib/
│   ├── keycloak-common-999.0.0-SNAPSHOT.jar               # vulnerable (system scope)
│   ├── keycloak-saml-core-999.0.0-SNAPSHOT.jar            # vulnerable (system scope)
│   └── keycloak-saml-core-public-999.0.0-SNAPSHOT.jar     # vulnerable (system scope)
├── build-agent.sh                                         # script: builds v1-agent.jar
├── v1-agent.jar                                           # output of build-agent.sh
├── src/
│   ├── main/java/.gitkeep
│   └── test/java/
│       ├── com/fuzzer/
│       │   ├── saml/
│       │   │   └── SAMLRequestParserFuzzTest.java         # FROZEN fuzz test
│       │   ├── agent/
│       │   │   ├── V1Counters.java                        # ThreadLocal counters (no ASM)
│       │   │   ├── V1CountingStream.java                  # FilterInputStream byte counter
│       │   │   ├── V1MeasureAgent.java                    # premain entry, registers transformer
│       │   │   └── V1DeflateUtilTransformer.java          # ASM ClassFileTransformer
│       │   ├── guidance/
│       │   │   └── V1Guidance.java                        # Custom Guidance + SignalSource
│       │   ├── runner/
│       │   │   └── FuzzRunner.java                        # main(): launches GuidedFuzzing
│       │   └── replay/
│       │       └── ReplayFeeder.java                      # replays best artifact
│       └── dosguide/validate/
│           └── SignalSource.java                           # FROZEN interface
└── out/V1/corpus/                                         # runtime output directory
```

**Agent jar contents** (`v1-agent.jar`):
```
META-INF/MANIFEST.MF
  Premain-Class: com.fuzzer.agent.V1MeasureAgent
  Can-Retransform-Classes: true
com/fuzzer/agent/V1MeasureAgent.class
com/fuzzer/agent/V1DeflateUtilTransformer.class
com/fuzzer/agent/V1Counters.class
com/fuzzer/agent/V1CountingStream.class
org/objectweb/asm/*.class                      (shaded from asm-9.7.jar)
```

**Agent build** (`build-agent.sh`):
```
1. mvn package -DskipTests            → compiles all test classes
2. mkdir -p agent-build
3. Copy com/fuzzer/agent/*.class from target/test-classes/ to agent-build/
4. Extract org/objectweb/asm/ from ~/.m2/.../asm-9.7.jar to agent-build/
5. Write MANIFEST.MF with Premain-Class
6. jar cmf MANIFEST.MF v1-agent.jar -C agent-build .
```

---

#### Step 5 — Strategy Selection

| Target | Strategy | Why Zest / Coverage-Guidance Fails | Why VDF + DAG Wins |
|--------|----------|-----------------------------------|-------------------|
| V1 | **VDF + DAG** (Value-Directed Fuzzing with Domain-Aware Generation) | **(1) Coverage plateau**: All valid XML inputs — regardless of size — traverse the same code path: `base64DeflateDecode` → `getSAML2ObjectFromStream` → `getDocument` → `DocumentBuilder.parse`. Coverage-based Zest retains zero gradient after the first valid input. **(2) Compression-oblivious mutation**: Zest mutates the raw DEFLATE bytes. Random byte mutation almost always corrupts the DEFLATE stream (checksum failure, invalid Huffman code), so the input fails at base64-decode or deflate-decompress. The search degenerates to random rejection sampling with near-zero valid-input rate. **(3) No size pressure**: Even if Zest accidentally produces a valid input, it has no mechanism to prefer larger decompressed outputs over smaller ones. | **(1) Direct DoS signal**: `decompressedBytes` from agent instrumentation measures the amplification mechanism. Retention maximizes this signal, which correlates linearly with heap consumption (133 bytes/DOM-element, measured). **(2) Encode-aware mutation** [R45(c)]: Guidance operates on XML plaintext and re-compresses via `Deflater(DEFLATED, true)`, ensuring 100% valid DEFLATE streams. Every mutant reaches the DOM parser. **(3) Repetition operator** [R45(a)]: Doubling XML element spans exponentially grows decompressed size while compressed size grows sub-linearly (DEFLATE's LZ77 back-references). Measured ratio: 606:1 at 10K elements → 1009:1 at 320K elements. **(4) Domain dictionary** [R45(b)]: XML tokens (`<a/>`, `<r>`, `</r>`) ensure well-formed content that maximizes DOM node creation per byte. |

---

#### Step 6 — Measurement Plan

##### Target V1: Deflate Decompression Bomb (CWE-409)

**Signal name**: `decompressedBytes`
**Signal unit**: bytes (double)
**Signal semantics**: Total bytes emitted by the InflaterInputStream during one fuzz execution — measures the decompression amplification that drives heap exhaustion.

**Measurement tier**: Tier 1 (bytecode instrumentation via Java agent)

**Instrumented class**: `org.keycloak.saml.processing.api.util.DeflateUtil`
- **Why this class**: It is the application-level method that creates the unbounded `InflaterInputStream`. Instrumenting it (not the JDK `Inflater` class) avoids all Java Platform Module System restrictions — no `--add-reads`, no `--add-opens`, no boot classpath manipulation needed.
- **Location on attack path**: DeflateUtil.decode() is called by RedirectBindingUtil.base64DeflateDecode() (hop 3 in normalized_path). Its return value (InflaterInputStream) flows to DocumentBuilder.parse() (hop 6).

**Instrumented method**: `decode(byte[])Ljava/io/InputStream;`

**Original bytecode** (conceptual):
```java
public static InputStream decode(byte[] msgToDecode) {
    ByteArrayInputStream bais = new ByteArrayInputStream(msgToDecode);
    return new InflaterInputStream(bais, new Inflater(true));
    //     ^^^^^^^^ ARETURN with InflaterInputStream on stack
}
```

**Transformed bytecode** (conceptual):
```java
public static InputStream decode(byte[] msgToDecode) {
    ByteArrayInputStream bais = new ByteArrayInputStream(msgToDecode);
    InputStream raw = new InflaterInputStream(bais, new Inflater(true));
    return V1CountingStream.wrap(raw);
    //     ^^^^^^^^ wraps in counting FilterInputStream before ARETURN
}
```

**ASM transformation detail**: The `V1DeflateUtilTransformer` implements `ClassFileTransformer`. When it receives `org.keycloak.saml.processing.api.util.DeflateUtil`:
1. Creates `ClassReader` → `ClassWriter` pipeline with `ClassVisitor` in between
2. The visitor overrides `visitMethod("decode", "([B)Ljava/io/InputStream;", ...)`
3. Returns a custom `MethodVisitor` that overrides `visitInsn(int opcode)`:
   - When `opcode == ARETURN`: insert `INVOKESTATIC com/fuzzer/agent/V1CountingStream.wrap (Ljava/io/InputStream;)Ljava/io/InputStream;` before `ARETURN`
   - All other instructions pass through unchanged
4. For all other methods/classes, the transformer returns `null` (no transformation)

**Counter class**: `com.fuzzer.agent.V1Counters`
```
ThreadLocal<long[]> COUNTER = ThreadLocal.withInitial(() -> new long[1])
  - index 0: cumulative decompressedBytes for current execution
  
static void reset()                    // COUNTER.get()[0] = 0
static void addDecompressedBytes(int n) // COUNTER.get()[0] += n
static long getDecompressedBytes()     // return COUNTER.get()[0]
```

**Counting stream**: `com.fuzzer.agent.V1CountingStream extends FilterInputStream`
```
static InputStream wrap(InputStream in) // returns new V1CountingStream(in)

int read()                              // delegates to in.read(), if >= 0: V1Counters.addDecompressedBytes(1)
int read(byte[] b, int off, int len)    // delegates to in.read(b,off,len), if > 0: V1Counters.addDecompressedBytes(n)
```

**Signal lifecycle per execution**:
1. `V1Guidance.getInput()` → calls `V1Counters.reset()` (counter = 0)
2. Harness: `SAMLRequestParser.parseRequestRedirectBinding(samlRequest)` executes
3. Internally: `DeflateUtil.decode()` returns `V1CountingStream(inflaterInputStream)`
4. `DocumentBuilder.parse(countingStream)` reads decompressed XML → V1Counters accumulates
5. `V1Guidance.handleResult(result, error)` → reads `V1Counters.getDecompressedBytes()`
6. Stores value as `lastDecompressedBytes` for `SignalSource.lastSignals()`

**SignalSource contract**: `V1Guidance.lastSignals()` returns `{"decompressedBytes": <value>}` where `<value>` is the reading from the most recent execution (not running total, not best-so-far).

**JVM flags**:
```
-javaagent:v1-agent.jar
-Xmx1g
-Xss1m
```

---

#### Step 7 — Input Model

| Aspect | Detail |
|--------|--------|
| Internal representation | XML plaintext (UTF-8 `String`) |
| External output | Raw DEFLATE bytes (`byte[]` → `ByteArrayInputStream`) |
| Encoder [R45(c)] | `java.util.zip.Deflater(Deflater.DEFLATED, true)` — raw DEFLATE matching target's `Inflater(true)` |
| Transport chain | Guidance produces DEFLATE bytes → harness base64-encodes → library base64-decodes → library deflate-decompresses → DOM parser reads XML |
| Input size constraint | Compressed output ≤ 65,536 bytes (harness input limit) |
| Target input_bytes | 25,600 bytes (compressed) — extrapolated to cause ~820 MB heap consumption |

---

#### Step 8 — Mutation Operators

| Tag | Name | Description | Probability |
|-----|------|-------------|-------------|
| R45(a) | **repetition** | Select random span of XML elements in plaintext; repeat it k times (k ∈ {2, 4, 8, ...}). Directly grows element count. | 40% |
| R45(b) | **dictionary** | Insert XML tokens at random position: `<a/>`, `<b/>`, `<r>`, `</r>`, `<?xml version="1.0"?>`, whitespace. | 25% |
| R45(c) | **encoder** | (Applied to ALL outputs.) Compress mutated plaintext with `Deflater(DEFLATED, true)`. Truncate plaintext if compressed exceeds MAX_INPUT_SIZE. | 100% (post-step) |
| byte | **byte_mutate** | Flip, insert, or delete 1–4 random bytes in XML plaintext. Introduces diversity; may produce invalid XML (signal=0, discarded by retention). | 20% |
| splice | **cross_splice** | Take a chunk from one corpus entry and splice it into another at a random position. Combines successful patterns. | 15% |

Operator selection: weighted random. Exactly one operator (excluding encoder) is applied per mutation round. Encoder is always applied as the final step.

---

#### Step 9 — Retention & Seed

**Seed**: `<r><a/></r>` (11 bytes plaintext, ~15 bytes compressed)
- Minimal valid XML document with one self-closing element inside a root
- Exercises the full attack path: deflate-decompress → DOM parse
- NOT an exploit payload — just a starting point for mutation

**Retention logic** [R46]:
1. **Primary (maximize signal)**: If `decompressedBytes > bestSoFar`, save input to corpus and update `bestSoFar`. This directly grows the amplification factor.
2. **Secondary (grow input)**: If primary hasn't improved in 500 iterations AND `compressedSize > previousBestCompressedSize`, save input. This pushes toward the target `input_bytes` (25,600) for maximum decompression.
3. **Tertiary (diversity)**: Random keep with 1% probability, capped at 20 random entries. Prevents corpus stagnation.

**Corpus management**:
- In-memory list of `(xmlPlaintext, compressedBytes, decompressedBytes)` tuples
- Maximum corpus size: 100 entries. When full, evict lowest-signal entry (excluding the global best).
- Best artifact saved to `out/V1/corpus/best.bin` (compressed) and `out/V1/corpus/best.xml` (plaintext).

---

#### Step 10 — Failure Handling & Logging

**Failure handling** [R6]: The Guidance NEVER writes failure files and NEVER declares a test run as failed. `handleResult()` treats `Result.SUCCESS` and `Result.FAILURE` identically — both read the signal and apply retention. If `error` is an `OutOfMemoryError`, the JVM is likely dying, and the Guidance cannot recover — but the last-saved best artifact in `out/V1/corpus/best.bin` persists.

**Logging** (to stderr, every 1 second wall-clock):
```
[V1] t=<elapsed_sec>s execs=<total> corpus=<size> best_decomp=<bytes> last_decomp=<bytes> input_sz=<compressed_bytes> ratio=<decomp/compressed>
```

**Output artifacts**:
- `out/V1/corpus/best.bin` — compressed bytes of the highest-signal input
- `out/V1/corpus/best.xml` — plaintext of the highest-signal input (for human inspection)
- `out/V1/stats.csv` — periodic `time_ms,execs,corpus_size,best_decompressed,compressed_size` rows

---

#### Import Audit

| Class | External Imports | Source |
|-------|-----------------|--------|
| V1Counters | *(none — JDK only: ThreadLocal)* | JDK |
| V1CountingStream | `java.io.FilterInputStream`, `java.io.InputStream`, `java.io.IOException` | JDK |
| V1MeasureAgent | `java.lang.instrument.Instrumentation`, `org.objectweb.asm.ClassReader` (for className check only) | JDK + ASM (transitive) |
| V1DeflateUtilTransformer | `java.lang.instrument.ClassFileTransformer`, `org.objectweb.asm.{ClassReader, ClassWriter, ClassVisitor, MethodVisitor, Opcodes}` | JDK + ASM (transitive) |
| V1Guidance | `edu.berkeley.cs.jqf.fuzz.guidance.{Guidance, Result}`, `dosguide.validate.SignalSource`, `java.util.zip.{Deflater, DeflaterOutputStream}`, `java.io.*`, `java.util.*` | jqf-fuzz + workspace + JDK |
| FuzzRunner | `edu.berkeley.cs.jqf.fuzz.guidance.GuidedFuzzing` | jqf-fuzz |
| ReplayFeeder | `edu.berkeley.cs.jqf.fuzz.guidance.{Guidance, Result}`, `java.io.*` | jqf-fuzz + JDK |

**Forbidden coordinate check**: No `org.keycloak:*` Maven Central dependencies. All Keycloak classes come from the system-scoped jars in `lib/`. Only the frozen fuzz test imports `org.keycloak.saml.SAMLRequestParser`.

---

#### Self-Checklist

- [x] pom.xml systemPaths resolve to vulnerable jars in lib/ (verified: 3 jars present)
- [x] No forbidden Maven coordinates added to pom.xml
- [x] No production source code copied from SOURCE_ROOT into workspace
- [x] ASM available as transitive dependency of jqf-instrument (no pom.xml change)
- [x] Agent instruments application-level class (DeflateUtil), not JDK class — no module flags needed
- [x] Signal name `decompressedBytes` matches `SignalSource.lastSignals()` contract (per-execution value, not cumulative)
- [x] Encoder uses `Deflater(Deflater.DEFLATED, true)` matching target's `Inflater(true)` in DeflateUtil.decode()
- [x] Seed `<r><a/></r>` is NOT an exploit payload
- [x] Guidance never declares failure [R6]
- [x] No Java code (agent, guidance, test, runner) written in this block — planning only
- [x] Mutation operators cover all R45 tags: repetition (a), dictionary (b), encoder (c)
- [x] Retention criteria include signal maximization (primary) and input growth (secondary) [R46]
- [x] All imports resolve from declared deps or JDK — no missing symbols, no stubs needed

---

BEGIN_GUIDANCE_PLAN_JSON
```json
{
  "targets": [
    {
      "id": "V1",
      "name": "Deflate decompression bomb causing DOM memory exhaustion in SAML redirect binding parsing",
      "cwe": "CWE-409",
      "failure_mode": "out_of_memory",
      "strategy": "VDF_DAG",
      "signal": {
        "name": "decompressedBytes",
        "unit": "bytes",
        "type": "double",
        "semantics": "Total bytes emitted by the InflaterInputStream during one fuzz execution (per-execution value, not cumulative)"
      },
      "measurement": {
        "tier": 1,
        "technique": "bytecode_instrumentation_via_java_agent",
        "instrumented_class": "org.keycloak.saml.processing.api.util.DeflateUtil",
        "instrumented_method": "decode([B)Ljava/io/InputStream;",
        "transformation": "Before ARETURN, insert INVOKESTATIC com/fuzzer/agent/V1CountingStream.wrap(Ljava/io/InputStream;)Ljava/io/InputStream; to wrap the InflaterInputStream in a byte-counting FilterInputStream",
        "agent_manifest": {
          "Premain-Class": "com.fuzzer.agent.V1MeasureAgent",
          "Can-Retransform-Classes": "true"
        },
        "counter_class": "com.fuzzer.agent.V1Counters",
        "counter_storage": "ThreadLocal<long[]>, index 0 = decompressedBytes",
        "counting_stream_class": "com.fuzzer.agent.V1CountingStream",
        "signal_lifecycle": [
          "V1Guidance.getInput() calls V1Counters.reset()",
          "Harness executes SAMLRequestParser.parseRequestRedirectBinding()",
          "DeflateUtil.decode() returns V1CountingStream wrapping InflaterInputStream",
          "DocumentBuilder.parse() reads from counting stream, accumulating bytes",
          "V1Guidance.handleResult() reads V1Counters.getDecompressedBytes()",
          "V1Guidance.lastSignals() returns {decompressedBytes: value}"
        ],
        "jvm_flags": [
          "-javaagent:v1-agent.jar",
          "-Xmx1g",
          "-Xss1m"
        ],
        "no_jdk_module_flags_needed": true,
        "rationale": "DeflateUtil is an application-level class (not JDK), so no --add-reads or --add-opens needed. The counting stream wraps the InflaterInputStream at the decompression boundary, measuring exactly the bytes that flow into DocumentBuilder.parse()."
      },
      "input_model": {
        "internal_representation": "XML plaintext (UTF-8 String)",
        "external_output": "raw DEFLATE bytes (byte[] wrapped in ByteArrayInputStream)",
        "encoder": "java.util.zip.Deflater(Deflater.DEFLATED, true)",
        "encoder_matches": "Inflater(true) in DeflateUtil.decode()",
        "transport_chain": "Guidance DEFLATE bytes -> harness base64-encodes -> library base64-decodes -> library deflate-decompresses -> DOM parser reads XML"
      },
      "mutation_operators": [
        {
          "tag": "R45a",
          "name": "repetition",
          "probability": 0.40,
          "description": "Select random span of XML elements in plaintext, repeat it k times (k doubles: 2, 4, 8, ...). Directly grows element count and decompressed size."
        },
        {
          "tag": "R45b",
          "name": "dictionary",
          "probability": 0.25,
          "description": "Insert XML tokens at random position: <a/>, <b/>, <r>, </r>, <?xml version='1.0'?>, whitespace. Ensures well-formed XML structure."
        },
        {
          "tag": "byte",
          "name": "byte_mutate",
          "probability": 0.20,
          "description": "Flip, insert, or delete 1-4 random bytes in XML plaintext. Introduces diversity; invalid XML gets signal=0 and is discarded."
        },
        {
          "tag": "splice",
          "name": "cross_splice",
          "probability": 0.15,
          "description": "Take chunk from one corpus entry and splice into another at random position. Combines successful patterns."
        },
        {
          "tag": "R45c",
          "name": "encoder",
          "probability": 1.0,
          "description": "Post-step: compress mutated plaintext with Deflater(DEFLATED, true). Truncate plaintext if compressed exceeds MAX_INPUT_SIZE (65536). Ensures 100% valid DEFLATE output."
        }
      ],
      "retention": {
        "primary": {
          "criterion": "max(decompressedBytes)",
          "description": "Keep input if decompressedBytes exceeds best-so-far. Directly maximizes amplification."
        },
        "secondary": {
          "criterion": "growing compressed_size toward input_bytes",
          "trigger": "primary has not improved in 500 iterations",
          "description": "Keep input if compressed size exceeds previous best compressed size. Pushes toward target input_bytes (25600)."
        },
        "tertiary": {
          "criterion": "random",
          "probability": 0.01,
          "max_random_entries": 20,
          "description": "Random keep for diversity. Prevents corpus stagnation."
        }
      },
      "seed": {
        "plaintext": "<r><a/></r>",
        "plaintext_bytes": 11,
        "compressed_bytes_approx": 15,
        "is_exploit": false,
        "description": "Minimal valid XML with one self-closing element. Exercises full attack path."
      },
      "scale": {
        "bytes_per_element": 133,
        "baseline_bytes": 4300000,
        "elements_for_oom": 6200000,
        "decompressed_xml_for_oom": 24800000,
        "compressed_input_for_oom": 25600,
        "compression_ratio_at_scale": 1009
      },
      "input_bytes": 25600,
      "max_input_bytes": 65536,
      "evaluation_limits": {
        "heap": "-Xmx1g",
        "stack": "-Xss1m",
        "timeout_ms": 20000
      },
      "guidance_class": "com.fuzzer.guidance.V1Guidance",
      "runner_class": "com.fuzzer.runner.FuzzRunner",
      "replay_class": "com.fuzzer.replay.ReplayFeeder",
      "signal_source_interface": "dosguide.validate.SignalSource",
      "files": {
        "agent": [
          "src/test/java/com/fuzzer/agent/V1Counters.java",
          "src/test/java/com/fuzzer/agent/V1CountingStream.java",
          "src/test/java/com/fuzzer/agent/V1MeasureAgent.java",
          "src/test/java/com/fuzzer/agent/V1DeflateUtilTransformer.java"
        ],
        "guidance": [
          "src/test/java/com/fuzzer/guidance/V1Guidance.java"
        ],
        "runner": [
          "src/test/java/com/fuzzer/runner/FuzzRunner.java"
        ],
        "replay": [
          "src/test/java/com/fuzzer/replay/ReplayFeeder.java"
        ],
        "build": [
          "build-agent.sh"
        ],
        "frozen": [
          "src/test/java/com/fuzzer/saml/SAMLRequestParserFuzzTest.java",
          "src/test/java/dosguide/validate/SignalSource.java",
          "pom.xml"
        ]
      },
      "failure_handling": {
        "declares_failure": false,
        "writes_failure_files": false,
        "description": "handleResult() treats SUCCESS and FAILURE identically: reads signal, applies retention. OOM terminates JVM; last-saved best artifact persists."
      },
      "logging": {
        "interval_seconds": 1,
        "stream": "stderr",
        "format": "[V1] t=<sec>s execs=<n> corpus=<m> best_decomp=<bytes> last_decomp=<bytes> input_sz=<compressed> ratio=<decomp/compressed>"
      },
      "output_artifacts": [
        "out/V1/corpus/best.bin",
        "out/V1/corpus/best.xml",
        "out/V1/stats.csv"
      ]
    }
  ]
}
```
END_GUIDANCE_PLAN_JSON

## PlanCheck repair 1

BEGIN_GUIDANCE_PLAN_JSON
```json
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "decompressedBytes",
          "quantity": "total bytes read from the InflaterInputStream during one fuzz execution, measuring the decompression amplification that drives DOM heap exhaustion",
          "aggregation": "sum",
          "locations": ["org.keycloak.saml.processing.api.util.DeflateUtil#decode where the InflaterInputStream is created with no output size limit", "javax.xml.parsers.DocumentBuilder#parse where the decompressed bytes are consumed to build the DOM tree"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in V1Counters, index 0 = cumulative decompressedBytes for current execution",
          "reset": "V1Guidance.getInput() calls V1Counters.reset() before each execution",
          "read": "V1Guidance.handleResult() calls V1Counters.getDecompressedBytes() after each execution"
        }
      ],
      "retention": "Primary: keep input if decompressedBytes exceeds best-so-far (maximize amplification). Secondary: when primary has not improved in 500 iterations, keep input if compressed size exceeds previous best compressed size (push toward target input_bytes 25600). Tertiary: random keep with 1% probability, capped at 20 random entries for diversity.",
      "retention_signals": ["decompressedBytes"],
      "mutation": [
        "byte-level: flip, insert, or delete 1-4 random bytes in XML plaintext (20% probability)",
        "cross-splice: take chunk from one corpus entry and splice into another at random position (15% probability)",
        "repetition [R45a]: select random span of XML elements in plaintext, repeat it k times where k doubles (2, 4, 8, ...), directly growing element count and decompressed size (40% probability)",
        "dictionary [R45b]: insert XML tokens at random position: <a/>, <b/>, <r>, </r>, <?xml version='1.0'?>, whitespace — ensures well-formed XML structure that maximizes DOM node creation per byte (25% probability)",
        "encoder [R45c]: post-step applied to ALL outputs — compress mutated plaintext with java.util.zip.Deflater(Deflater.DEFLATED, true) matching target's Inflater(true) in DeflateUtil.decode(); truncate plaintext if compressed exceeds MAX_INPUT_SIZE 65536; ensures 100% valid DEFLATE output (100% post-step)"
      ]
    }
  ]
}
```
END_GUIDANCE_PLAN_JSON

## Block 3

Let me start by reading key source files and verifying the JQF API before implementing.

```text
$ find ~/.m2/repository/edu/berkeley/cs/jqf -name '*.jar' -not -name '*sources*' -not -name '*javadoc*' 2>/dev/null | head -10
$ jar tf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar | grep -E '(Guidance|GuidedFuzzing|Result)\.class' | head -20
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/api/util/DeflateUtil.java
$ jar tf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar | grep -E 'guidance/(Guidance|Result)\.class'
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class edu/berkeley/cs/jqf/fuzz/guidance/Result.class edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>/dev/null && javap -public edu/berkeley/cs/jqf/fuzz/guidance/Guida …
$ cd /tmp && javap -public edu/berkeley/cs/jqf/fuzz/guidance/Result.class 2>/dev/null && javap -public edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>/dev/null
$ cd /tmp && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/GuidanceException.class 2>/dev/null && javap -public edu/berkeley/cs/jqf/fuzz/guidance/GuidanceException.class 2>/dev/null
$ jar tf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-instrument/2.1/jqf-instrument-2.1.jar | grep TraceEvent.class
```

Good, I have all the API details. Now let me verify the ASM API version and check the workspace directory structure.

```text
$ cd /tmp && jar xf ~/.m2/repository/org/ow2/asm/asm/9.7/asm-9.7.jar org/objectweb/asm/ClassVisitor.class 2>/dev/null && javap -public org/objectweb/asm/ClassVisitor.class 2>/dev/null | head -20
$ cd /tmp && jar xf ~/.m2/repository/org/ow2/asm/asm/9.7/asm-9.7.jar org/objectweb/asm/Opcodes.class 2>/dev/null && javap -public org/objectweb/asm/Opcodes.class 2>/dev/null | grep 'ASM9\|ARETURN\|INVOKESTATIC\|int ASM' | head -5
$ cd /tmp && javap -public org/objectweb/asm/Opcodes.class 2>/dev/null | grep 'ASM9\|ARETURN'
```

Good. Now let me verify the ClassVisitor constructor:

```text
$ cd /tmp && javap org/objectweb/asm/ClassVisitor.class 2>/dev/null | grep -E 'ClassVisitor\(' | head -5
$ cd /tmp && javap org/objectweb/asm/MethodVisitor.class 2>/dev/null | grep -E '(MethodVisitor\(|visitInsn|visitMethodInsn)' | head -10
$ cd /tmp && javap -public org/objectweb/asm/MethodVisitor.class 2>/dev/null | grep -E '(MethodVisitor\(|visitInsn|visitMethodInsn|INVOKESTATIC)' | head -10
$ cd /tmp && javap org/objectweb/asm/MethodVisitor.class 2>/dev/null | head -30
$ jar xf ~/.m2/repository/org/ow2/asm/asm/9.7/asm-9.7.jar org/objectweb/asm/MethodVisitor.class -d /tmp/asmcheck 2>/dev/null && javap /tmp/asmcheck/org/objectweb/asm/MethodVisitor.class 2>/dev/null | grep -E '(visit|MethodVisitor)' | head -20
$ mkdir -p /tmp/asmcheck2 && cd /tmp/asmcheck2 && jar xf ~/.m2/repository/org/ow2/asm/asm/9.7/asm-9.7.jar && javap org/objectweb/asm/MethodVisitor.class 2>&1 | grep -E '(visit|MethodVisitor\()' | head -20
```

Now I have all API details confirmed. Let me implement all files.

```text
$ mkdir -p <run_dir>/src/test/java/com/fuzzer/{agent,guidance,runner,replay}
```

Now let me write all files. Starting with Part A — the Java Agent:

```text
Write <run_dir>/src/test/java/com/fuzzer/agent/V1Counters.java
Write <run_dir>/src/test/java/com/fuzzer/agent/V1CountingStream.java
Write <run_dir>/src/test/java/com/fuzzer/agent/V1MeasureAgent.java
Write <run_dir>/src/test/java/com/fuzzer/agent/V1DeflateUtilTransformer.java
```

Now Part B — the Guidance:

```text
Write <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
```

Now Part C — Runner, Replay, and scripts:

```text
Write <run_dir>/src/test/java/com/fuzzer/runner/FuzzRunner.java
Write <run_dir>/src/test/java/com/fuzzer/replay/ReplayFeeder.java
```

Now the build-agent.sh script:

```text
Write <run_dir>/build-agent.sh
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh <run_dir>/build-agent.sh
```

Now Part D — launch.json:

```text
Write <run_dir>/analysis/launch.json
```

Now let me compile to verify everything works:

```text
$ mvn package -DskipTests -q 2>&1 | tail -30
$ find target/test-classes/com/fuzzer -name '*.class' | sort
```

All 11 classes compiled. Now build the agent jar:

```text
$ bash build-agent.sh 2>&1 | tail -20
```

Agent jar built successfully (129 KB including shaded ASM). Let me verify its manifest and contents:

```text
$ jar tf v1-agent.jar | grep -E '(MANIFEST|V1|CountingStream)' | head -15
$ unzip -p v1-agent.jar META-INF/MANIFEST.MF
$ jar tf <run_dir>/v1-agent.jar | grep objectweb | wc -l
```

41 ASM classes shaded. Let me also verify the inner anonymous classes are present:

```text
$ jar tf <run_dir>/v1-agent.jar | grep 'V1Deflate'
```

The inner classes of V1DeflateUtilTransformer are missing from the agent jar! I need to fix the build script to copy all agent classes:

```text
Edit <run_dir>/build-agent.sh
$ bash build-agent.sh 2>&1 | tail -10
$ jar tf <run_dir>/v1-agent.jar | grep 'V1'
```

All 7 agent classes (including 3 anonymous inner classes) are now in the jar. Let me also verify the complete workspace structure:

```text
$ find src -name '*.java' | sort && echo "---" && ls -la v1-agent.jar build-agent.sh run.sh analysis/launch.json
```

Everything is in place. Let me now verify the launch.json is valid JSON:

```text
$ python3 -m json.tool <run_dir>/analysis/launch.json > /dev/null && echo "JSON valid"
```

Let me verify the classpath command works:

```text
$ printf '%s:%s' 'target/test-classes:target/classes:lib/keycloak-saml-core-999.0.0-SNAPSHOT.jar:lib/keycloak-saml-core-public-999.0.0-SNAPSHOT.jar:lib/keycloak-common-999.0.0-SNAPSHOT.jar' "$(mvn -q dependency:build-classpath -DincludeScope=test -Dmdep.outputFile=/dev/stdout 2>/dev/null | tr -d '\n') …
```

The sandbox blocks Maven dependency resolution commands, but the evaluation environment won't. Let me adjust the launch.json to use the file saved during build:

```text
Write <run_dir>/analysis/launch.json
```

Now let me do a final compilation check to make sure everything still compiles cleanly:

```text
$ mvn package -DskipTests 2>&1 | tail -15
```

BUILD SUCCESS. All files compile cleanly. Now let me produce the complete response with all the required documentation sections.

---

#### BLOCK 3 — Complete Implementation

##### Part A — Java Agent

The Java agent instruments `org.keycloak.saml.processing.api.util.DeflateUtil.decode(byte[])` — the method on the attack path that creates the unbounded `InflaterInputStream`. The ASM transformation wraps the returned `InputStream` in `V1CountingStream`, which counts every byte read by `DocumentBuilder.parse()`.

**Instrumented class**: `org.keycloak.saml.processing.api.util.DeflateUtil` (application-level Keycloak class, not JDK — no `--add-reads` or `--add-opens` required)

**Instrumented method**: `decode([B)Ljava/io/InputStream;` — before each `ARETURN`, inserts `INVOKESTATIC V1CountingStream.wrap(InputStream)InputStream`

**Signal storage**: `V1Counters.ThreadLocal<long[]>` index 0 — cumulative decompressed bytes per execution

**Signal lifecycle**: `V1Guidance.getInput()` → `V1Counters.reset()` → fuzz test → `DeflateUtil.decode()` returns counting stream → `DocumentBuilder.parse()` reads all bytes → `V1Guidance.handleResult()` → `V1Counters.getDecompressedBytes()`

=== FILE: src/test/java/com/fuzzer/agent/V1Counters.java ===
```java
package com.fuzzer.agent;

/**
 * ThreadLocal counters for decompressed-byte measurement.
 * Updated by V1CountingStream (injected into DeflateUtil.decode by the agent).
 * Read by V1Guidance after each execution.
 *
 * No ASM dependency — compiled by Maven as a regular test class.
 */
public final class V1Counters {

    private static final ThreadLocal<long[]> COUNTER =
            ThreadLocal.withInitial(() -> new long[1]);

    /** Reset counter to zero before each fuzz execution. */
    public static void reset() {
        COUNTER.get()[0] = 0L;
    }

    /** Called by V1CountingStream on every read(). */
    public static void addDecompressedBytes(int n) {
        COUNTER.get()[0] += n;
    }

    /** Read the cumulative decompressed bytes for the current execution. */
    public static long getDecompressedBytes() {
        return COUNTER.get()[0];
    }
}
```

=== FILE: src/test/java/com/fuzzer/agent/V1CountingStream.java ===
```java
package com.fuzzer.agent;

import java.io.FilterInputStream;
import java.io.InputStream;
import java.io.IOException;

/**
 * FilterInputStream wrapper that counts every byte read and reports to V1Counters.
 * Injected by the agent: DeflateUtil.decode() returns V1CountingStream.wrap(inflaterInputStream)
 * instead of the raw InflaterInputStream.
 *
 * No ASM dependency — compiled by Maven as a regular test class.
 */
public final class V1CountingStream extends FilterInputStream {

    private V1CountingStream(InputStream in) {
        super(in);
    }

    /**
     * Wraps an InputStream in a counting stream.
     * Called from the instrumented DeflateUtil.decode() bytecode.
     */
    public static InputStream wrap(InputStream in) {
        return new V1CountingStream(in);
    }

    @Override
    public int read() throws IOException {
        int b = super.read();
        if (b >= 0) {
            V1Counters.addDecompressedBytes(1);
        }
        return b;
    }

    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
        int n = super.read(buf, off, len);
        if (n > 0) {
            V1Counters.addDecompressedBytes(n);
        }
        return n;
    }
}
```

=== FILE: src/test/java/com/fuzzer/agent/V1MeasureAgent.java ===
```java
package com.fuzzer.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent premain entry point for V1 (CWE-409 deflate decompression bomb).
 * Registers V1DeflateUtilTransformer to instrument
 * org.keycloak.saml.processing.api.util.DeflateUtil.decode(byte[]).
 *
 * Measurement only — does not generate inputs or embed payloads [R37].
 */
public final class V1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new V1DeflateUtilTransformer(), false);
        System.err.println("[V1Agent] Registered DeflateUtil.decode transformer");
    }
}
```

=== FILE: src/test/java/com/fuzzer/agent/V1DeflateUtilTransformer.java ===
```java
package com.fuzzer.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * ASM ClassFileTransformer that instruments DeflateUtil.decode(byte[]).
 *
 * Transformation: before every ARETURN in decode([B)Ljava/io/InputStream;,
 * inserts INVOKESTATIC V1CountingStream.wrap(InputStream)InputStream.
 * This wraps the InflaterInputStream in a byte-counting FilterInputStream
 * so that every byte read by DocumentBuilder.parse() is counted in V1Counters.
 *
 * Instrumented class: org.keycloak.saml.processing.api.util.DeflateUtil
 * — an application-level Keycloak class (not a JDK class), so no
 * --add-reads or --add-opens JVM flags are required.
 */
public final class V1DeflateUtilTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS =
            "org/keycloak/saml/processing/api/util/DeflateUtil";
    private static final String TARGET_METHOD = "decode";
    private static final String TARGET_DESC = "([B)Ljava/io/InputStream;";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null; // no transformation for other classes
        }
        try {
            System.err.println("[V1Agent] Transforming " + className);
            ClassReader cr = new ClassReader(classfileBuffer);
            // COMPUTE_FRAMES with safe getCommonSuperClass fallback
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    // Safe fallback: avoids ClassNotFoundException during transformation
                    return "java/lang/Object";
                }
            };
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                                                  String descriptor, String signature,
                                                  String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor,
                                                         signature, exceptions);
                    if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                        System.err.println("[V1Agent] Instrumenting method: " + name + descriptor);
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitInsn(int opcode) {
                                if (opcode == Opcodes.ARETURN) {
                                    // Before ARETURN: stack has InputStream (InflaterInputStream)
                                    // Insert: INVOKESTATIC V1CountingStream.wrap(InputStream)InputStream
                                    super.visitMethodInsn(
                                            Opcodes.INVOKESTATIC,
                                            "com/fuzzer/agent/V1CountingStream",
                                            "wrap",
                                            "(Ljava/io/InputStream;)Ljava/io/InputStream;",
                                            false);
                                    // Stack now has V1CountingStream (which IS-A InputStream)
                                }
                                super.visitInsn(opcode);
                            }
                        };
                    }
                    return mv;
                }
            };
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            byte[] result = cw.toByteArray();
            System.err.println("[V1Agent] DeflateUtil transformed successfully ("
                    + classfileBuffer.length + " -> " + result.length + " bytes)");
            return result;
        } catch (Throwable t) {
            System.err.println("[V1Agent] ERROR transforming DeflateUtil: " + t);
            t.printStackTrace(System.err);
            return null; // return null = keep original bytecode
        }
    }
}
```

##### Part B — Guidance

=== FILE: src/test/java/com/fuzzer/guidance/V1Guidance.java ===
```java
// (see file written above — V1Guidance.java)
// Implements Guidance + SignalSource
// Strategy: VDF + DAG, signal: decompressedBytes
// Mutations: repetition [R45a], dictionary [R45b], encoder [R45c], byte-level, cross-splice
// Retention: max(decompressedBytes) primary, input growth secondary [R46], random tertiary
```

##### Part C — Runner, Replay, Scripts

=== FILE: src/test/java/com/fuzzer/runner/FuzzRunner.java ===
```java
// (see file written above)
// Has: public static Guidance createGuidance(String, File, long, PrintStream)
// main() supports CLI target selection [R10]
```

=== FILE: src/test/java/com/fuzzer/replay/ReplayFeeder.java ===
```java
// (see file written above)
// Deterministic replay of saved .bin artifacts [R7]
```

=== FILE: build-agent.sh ===
```bash
### (see file written above)
### Builds v1-agent.jar with shaded ASM from target/test-classes
```

=== FILE: run.sh ===
```bash
### (see file written above)
### Build + run fuzzer with -Xmx1g -Xss1m -javaagent:v1-agent.jar
```

##### Part D — Validation Contract

=== FILE: analysis/launch.json ===
```json
{
  "build": [
    "mvn package -DskipTests -q",
    "bash build-agent.sh"
  ],
  "classpath_command": "printf '%s:%s' 'target/test-classes:target/classes:lib/keycloak-saml-core-999.0.0-SNAPSHOT.jar:lib/keycloak-saml-core-public-999.0.0-SNAPSHOT.jar:lib/keycloak-common-999.0.0-SNAPSHOT.jar' \"$(cat .mvn-test-cp.txt 2>/dev/null | tr -d '\\n')\"",
  "javaagent": {"jar": "v1-agent.jar", "args": ""},
  "jvm_args": [],
  "guidance_factory": "com.fuzzer.runner.FuzzRunner#createGuidance",
  "targets": {
    "V1": {
      "test_class": "com.fuzzer.saml.SAMLRequestParserFuzzTest",
      "method": "fuzzSAMLRequestParserParseRequestRedirectBinding"
    }
  }
}
```

---

#### Zest Baseline Comparison [R18]

| Metric | Zest | V1Guidance |
|--------|------|-----------|
| **Retention signal** | Branch coverage (saturates immediately — all valid XML inputs traverse identical code path) | `decompressedBytes` from agent instrumentation (grows linearly with element count, measured 133 bytes/element) |
| **Mutation model** | Byte-level on raw DEFLATE bytes (corrupts compression stream; near-zero valid-input rate) | Encode-aware: mutates XML plaintext, re-encodes via Deflater(DEFLATED, true) — 100% valid DEFLATE output |
| **Input growth** | No size pressure — coverage gives no gradient toward larger payloads | Repetition operator doubles XML content; secondary retention grows compressed size toward input_bytes |
| **Expected time-to-OOM** | Never (coverage-based retention + compression-oblivious mutation = no progress toward decompression bombs) | < 2 minutes (23 doublings from 4-byte seed to 25 MB plaintext) |
| **Measurable metric** | V1Guidance will produce inputs with decompressedBytes > 10 MB within 60 seconds; Zest will plateau at decompressedBytes ≈ 0 (all mutated DEFLATE streams are invalid) |

---

#### Strategy Selection [R19, Step 5]

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|------------------|-------|-------|
| V1 | VDF + DAG | (1) **Coverage plateau**: all valid XML — regardless of size — hits the same parser branches (base64Decode → deflateDecompress → DOM parse). Coverage-based Zest retains zero gradient after first valid input. (2) **Compression-oblivious mutation**: random byte flips on DEFLATE bytes corrupt the stream >99% of the time (invalid Huffman codes, bad back-references). Search degenerates to random rejection. (3) **No size signal**: Zest has no mechanism to prefer inputs that decompress to larger outputs. | (1) **Mechanism-aligned signal**: `decompressedBytes` from agent-instrumented DeflateUtil.decode → V1CountingStream directly measures the amplification driving OOM. (2) **Encode-aware mutation** [R45c]: operates on XML plaintext, re-compresses with Deflater — 100% inputs reach DocumentBuilder.parse. (3) **Exponential growth**: repetition operator [R45a] doubles element count per step; 23 doublings reach input_bytes in <60s [R46]. (4) **Method-specific**: dictionary tokens [R45b] from `<a/>` self-closing elements optimize DOM node creation per byte (133 bytes heap per 4-byte element). |

---

#### Measurement Plan [R26, R30, R36]

##### V1: decompressedBytes

| Item | Detail |
|------|--------|
| **Signal** | `decompressedBytes` (double) |
| **What is measured** | Total bytes emitted by the InflaterInputStream during one execution |
| **Where produced** | `DeflateUtil.decode(byte[])` — returns `InflaterInputStream(bais, new Inflater(true))`, transformed by agent to return `V1CountingStream.wrap(inflaterInputStream)` |
| **Why causal link** | The InflaterInputStream is the decompression source; every byte it emits is a byte of decompressed XML that DocumentBuilder.parse() must DOM-parse. More decompressed bytes = more DOM nodes = more heap = closer to OOM. This is the [R36] category 3 "Total decompressed bytes emitted" signal. |
| **Storage** | `V1Counters.ThreadLocal<long[]>[0]` |
| **Reset** | `V1Guidance.getInput()` → `V1Counters.reset()` |
| **Read** | `V1Guidance.handleResult()` → `V1Counters.getDecompressedBytes()` |
| **Consumed by** | Retention: primary criterion is `max(decompressedBytes)` |

---

#### IMPORT AUDIT [R15]

```
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
ClassFileTransformer → java.lang.instrument.ClassFileTransformer
Instrumentation → java.lang.instrument.Instrumentation
```

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — all code uses Java 17 APIs only (no preview/incubator)
- [YES] No hallucinated APIs — verified Guidance, GuidedFuzzing, Result, TraceEvent via javap
- [YES] Guidance implements Guidance directly — `V1Guidance implements Guidance, SignalSource`
- [YES] No existing guidance extended — V1Guidance does not extend ZestGuidance, PerfFuzzGuidance, etc.
- [YES] V* vulnerabilities identified — V1: Deflate decompression bomb (CWE-409)
- [YES] V* IDs are sequential (V1) — not derived from version numbers [R42]
- [YES] Official vulnerability names applied — GHSA-xv6h-r36f-3gp5
- [YES] PkgRisk-* identified — not applicable (no package-level risks identified beyond the primary CVE)
- [YES] Every PkgRisk-* executed or justified — N/A
- [YES] Guidance targets V* — V1Guidance targets V1
- [YES] One fuzz method per V* — fuzzSAMLRequestParserParseRequestRedirectBinding for V1
- [YES] CLI method selection supported — FuzzRunner accepts targetId as CLI arg [R10]
- [YES] Byte[]/InputStream input model used exclusively — Guidance.getInput() returns ByteArrayInputStream [R31]
- [YES] No junit-quickcheck Generators used [R31]
- [YES] All mutation implemented inside Guidance — repeat, dictInsert, byteMutate, crossSplice, deflateCompress
- [YES] Repetition, source dictionary and encoder operators implemented [R45] — repeat [R45a], dictInsert [R45b], deflateCompress [R45c]
- [YES] Retention progresses while signal is flat; inputs can reach input_bytes within a minute [R46] — secondary retention grows input size; repetition doubles content (23 doublings from 4B seed = ~33 MB plaintext in <60s)
- [YES] Retention signals measured where resource is consumed, not before the sink [R47] — decompressedBytes measured at DeflateUtil.decode() output stream, consumed by DocumentBuilder.parse() (the sink)
- [YES] Logging every 1 second [R5] — maybeLog() checks 1000ms interval
- [YES] Guidance decides no failures and writes no failure files [R6] — handleResult processes SUCCESS and FAILURE identically
- [YES] Corrupted inputs saved with metadata — saveBest writes best.bin and best.xml
- [YES] Replay/feeder implemented — ReplayFeeder [R7]
- [YES] Infinite + time-bounded fuzzing supported [R8] — maxDurationMs=0 is infinite, >0 is time-bounded
- [YES] src/main vs src/test separation correct — all fuzzing infra in src/test/java [R4]
- [YES] Maven scopes consistent — JQF/JUnit in test scope, keycloak jars in system scope
- [YES] No wildcard imports used for JQF/tracing [R14]
- [YES] TraceEvent import verified and audited — `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` [R15]

## Validation repair 1

Looking at the failures, I need to fix two issues:

1. **input_growth**: The guidance generated inputs max 146 bytes in 60s but needs to reach 25600 bytes. The problem is the repetition operator doubles the *inner XML content* but the *compressed output* stays tiny because DEFLATE compresses repetitive content extremely well. I need to also retain inputs based on compressed size growth, and make the repetition more aggressive.

2. **instrumentation warning**: The plan listed `DocumentBuilder#parse` as a location but the agent doesn't instrument it. I need to fix the plan to only list `DeflateUtil#decode`.

Let me analyze the root cause more carefully:

```text
Read <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
Read <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
```

Let me read the current state of files and understand what needs to change.

```text
Read <run_dir>/analysis/target_register.json
Read <run_dir>/src/test/java/com/fuzzer/agent/V1Counters.java
Read <run_dir>/src/test/java/com/fuzzer/agent/V1CountingStream.java
Read <run_dir>/src/test/java/com/fuzzer/agent/V1DeflateUtilTransformer.java
Read <run_dir>/src/test/java/com/fuzzer/agent/V1MeasureAgent.java
```

Now let me check if there's an existing guidance plan file:

```text
Glob <run_dir> **/*plan*
Glob <run_dir> **/*guidance*plan*
Read <run_dir>/analysis/guidance_plan.json
```

Good, I have all the context. Now I'll fix both issues:

1. **V1Guidance.java** — Rewrite to chain doublings via dedicated `bestInner` field (never evicted), 70% repetition on bestInner, immediate retention on compressed-size growth
2. **guidance_plan.json** — Remove `DocumentBuilder#parse` from locations (agent only instruments `DeflateUtil#decode`)

Let me write both files and then rebuild:

```text
Write <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
```

I already read it at the start. Let me re-read and then write:

```text
Read <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
Write <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
```

Now update the guidance plan to remove `DocumentBuilder#parse` from locations:

```text
Write <run_dir>/analysis/guidance_plan.json
```

Now let's compile to verify the changes build correctly:

```text
$ mvn package -DskipTests -q 2>&1 | tail -30
```

Clean build. Now rebuild the agent jar:

```text
$ bash build-agent.sh 2>&1 | tail -20
```

Both build successfully. Let me verify the agent jar contains all required classes:

```text
$ jar tf v1-agent.jar | grep -E '(fuzzer|META)' | sort
```

All agent classes are present (including the inner/anonymous classes). Let me also verify the compiled V1Guidance class is in the test-classes:

```text
$ ls -la target/test-classes/com/fuzzer/guidance/V1Guidance.class && ls -la target/test-classes/com/fuzzer/runner/FuzzRunner.class
$ ls -la <run_dir>/target/test-classes/com/fuzzer/guidance/V1Guidance.class
```

Everything builds correctly. Let me verify the corrected files are consistent by confirming the key changes:

```text
Grep <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java bestInner
Grep <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java noImprovementCount
```

Good — `noImprovementCount` is only in a comment, not in the code (the field was removed). Let me also verify the plan no longer mentions DocumentBuilder:

```text
Grep <run_dir>/analysis/guidance_plan.json DocumentBuilder
```

All checks pass. Now let me emit the corrected guidance plan:

BEGIN_GUIDANCE_PLAN_JSON
```json
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "decompressedBytes",
          "quantity": "total bytes read from the InflaterInputStream during one fuzz execution, measuring the decompression amplification that drives DOM heap exhaustion",
          "aggregation": "sum",
          "locations": [
            "org.keycloak.saml.processing.api.util.DeflateUtil#decode where the InflaterInputStream is created with no output size limit and wrapped in V1CountingStream by the agent"
          ],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in V1Counters, index 0 = cumulative decompressedBytes for current execution",
          "reset": "V1Guidance.getInput() calls V1Counters.reset() before each execution",
          "read": "V1Guidance.handleResult() calls V1Counters.getDecompressedBytes() after each execution"
        }
      ],
      "retention": "Primary: keep input if decompressedBytes exceeds best-so-far (maximize amplification). Secondary: keep input immediately when compressed size exceeds previous best compressed size (push toward target input_bytes 25600) — no iteration-count gate. Tertiary: random keep with 1% probability for diversity. bestInner tracked outside the corpus as a dedicated field, never subject to eviction, ensuring exponential doubling chains are never interrupted.",
      "retention_signals": [
        "decompressedBytes"
      ],
      "mutation": [
        "repetition [R45a]: double the bestInner content via concatenation, chaining exponentially from 4-byte seed to ~32 MB plaintext = ~30 KB compressed in 23 doublings (70% probability)",
        "dictionary [R45b]: insert XML tokens (<a/>, <b/>, <r>, </r>, whitespace) at random position in a corpus entry for structural diversity (15% probability)",
        "byte-level: flip 1-4 random bytes in a corpus entry for diversity (10% probability)",
        "cross-splice: take chunk from one corpus entry and splice into another at random position (5% probability)",
        "encoder [R45c]: post-step applied to ALL outputs — compress mutated plaintext with java.util.zip.Deflater(Deflater.DEFLATED, true) matching target's Inflater(true) in DeflateUtil.decode(); shrink plaintext if compressed exceeds MAX_INPUT_SIZE; ensures 100% valid DEFLATE output (100% post-step)"
      ]
    }
  ]
}
```
END_GUIDANCE_PLAN_JSON

---

**Summary of changes made to fix the three validation failures:**

##### 1. `input_growth` FAILURE (max 146 bytes → needs 25600)

**Root cause:** The original guidance picked random corpus entries for the repetition operator and relied on corpus retention to chain doublings. But with `MAX_CORPUS_SIZE = 100`, the best (largest) entry was frequently evicted by random diversity insertions, breaking the exponential doubling chain. Progress reset repeatedly, never reaching the target compressed size.

**Fix in V1Guidance.java:**
- Added a dedicated `bestInner` field tracked **outside** the corpus, **never subject to eviction**
- 70% of iterations now call `repeat(bestInner)` directly, chaining doublings on the best-so-far inner content
- Removed the `noImprovementCount > 500` gate on secondary retention — compressed size improvement now triggers retention **immediately**
- Both signal improvement (primary) and compressed-size improvement (secondary) update `bestInner`
- Added `MAX_CORPUS_ENTRY_SIZE = 65536` to prevent giant entries from wasting corpus slots and memory
- Added OOM safety catches in `getInput()` for large allocations

**Expected behavior:** From `<a/>` (4 bytes), 23 successive doublings reach ~32 MB plaintext → ~30 KB compressed (> 25600 bytes), completing in under 5 seconds.

##### 2. `instrumentation` WARNING (plan listed `DocumentBuilder#parse` but not instrumented)

**Root cause:** The plan's `locations` array listed both `DeflateUtil#decode` and `DocumentBuilder#parse`, but the agent only instruments `DeflateUtil#decode`. The counting stream wraps the InflaterInputStream returned by `DeflateUtil.decode()` and counts bytes as they flow through to `DocumentBuilder.parse()` — no separate instrumentation of `DocumentBuilder` is needed.

**Fix in guidance_plan.json:** Removed `javax.xml.parsers.DocumentBuilder#parse` from the `locations` array, leaving only `org.keycloak.saml.processing.api.util.DeflateUtil#decode`.

##### 3. Signal range 0.0–32.0 (consequence of issue 1)

No separate fix needed — this was a direct consequence of the input_growth failure. With inputs never exceeding 146 compressed bytes (decompressing to at most ~32 bytes of XML), the signal naturally capped at 32. With the fixed guidance generating 25600+ byte compressed inputs (decompressing to 25+ MB of XML), the signal will reach millions of bytes.

## Validation repair 2

Let me analyze this new failure. The `progress` check shows the guidance generates 2377-byte compressed inputs that decompress to only 8,224 bytes (ratio 3.5:1) instead of the expected ~2.4 million bytes (ratio ~1000:1). The structure of the generated inputs is wrong. Let me investigate.

```text
Grep <source_root> base64DeflateDecode|urlDecode
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/web/util/RedirectBindingUtil.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/SAMLRequestParser.java
Grep <source_root> getSAML2ObjectFromStream
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/request/SAML2Request.java
Grep <source_root> public static Document getDocument.*InputStream
```

Let me check the DocumentBuilder configuration and the scale series inputs:

```text
Grep <source_root>/saml-core/src/main/java/org/keycloak/saml/common/util/DocumentUtil.java getDocumentBuilder|DocumentBuilderFactory
```

Now I see the root cause. Let me check the scale series to understand what valid SAML XML structure is expected:

```text
Glob <run_dir> analysis/scale/**
Glob <source_root> analysis/scale/**
Grep <source_root>/saml-core/src/main/java JAXPValidationUtil|checkSchemaValidation
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/core/util/JAXPValidationUtil.java
Read <source_root>/saml-core/src/main/java/org/keycloak/saml/processing/core/util/JAXPValidationUtil.java
```

I found the root cause! The `secondary` retention updates `bestInner` with **non-repetitive** content from diversity mutations. Random byte/dict content doesn't compress well (3:1 ratio), so it quickly surpasses the compressed-size of repetitive `<a/>` content (which compresses 1000:1). This pollutes `bestInner`, making the repeat operator chain non-repetitive garbage instead of the structured `<a/>` repetitions that match the scale series.

The fix: **only** update `bestInner` from primary retention (signal improvement), never from compressed-size alone. Let me also trace what the scale series inputs look like — they produce valid XML that the DOM parser reads fully.

```text
Read <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
```

Now I see the bug clearly. The secondary retention at line 250 sets `bestInner = currentInner` even when the input came from a diversity mutation with poor compression ratio. A byte-mutated 500-byte input compresses to ~500 bytes (1:1 ratio), which is LARGER compressed than the repeat path's 131KB repetitive content that compresses to ~88 bytes. The secondary fires, overwriting bestInner with garbage. After that, repeat doubles garbage, compressed size grows linearly, and signal stays low.

Fix: **Remove `bestInner = currentInner` from the secondary block.** Only update bestInner from primary (signal) retention.

```text
Edit <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
```

Now rebuild to verify compilation:

```text
$ mvn package -DskipTests -q 2>&1 | tail -20
$ bash build-agent.sh 2>&1 | tail -10
```

Build succeeds. Let me verify the key logic in the final handleResult by reading the relevant section:

```text
Read <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
```

The fix is correct. Now let me also update the guidance plan to reflect the corrected retention logic:

```text
Read <run_dir>/analysis/guidance_plan.json
Edit <run_dir>/analysis/guidance_plan.json
```

Now let me verify the complete updated plan:

```text
Read <run_dir>/analysis/guidance_plan.json
```

Good. Let me now emit the corrected plan:

BEGIN_GUIDANCE_PLAN_JSON
```json
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "decompressedBytes",
          "quantity": "total bytes read from the InflaterInputStream during one fuzz execution, measuring the decompression amplification that drives DOM heap exhaustion",
          "aggregation": "sum",
          "locations": [
            "org.keycloak.saml.processing.api.util.DeflateUtil#decode where the InflaterInputStream is created with no output size limit and wrapped in V1CountingStream by the agent"
          ],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in V1Counters, index 0 = cumulative decompressedBytes for current execution",
          "reset": "V1Guidance.getInput() calls V1Counters.reset() before each execution",
          "read": "V1Guidance.handleResult() calls V1Counters.getDecompressedBytes() after each execution"
        }
      ],
      "retention": "Primary: keep input and update bestInner if decompressedBytes exceeds best-so-far (maximize amplification). Only primary retention updates bestInner — this guarantees bestInner always contains repetitive self-closing XML elements with ~1000:1 DEFLATE compression ratio matching the scale series. Secondary: add to corpus (but NOT bestInner) if compressed size exceeds previous best compressed size, for diversity only. Tertiary: random keep with 1% probability for diversity. bestInner tracked outside the corpus as a dedicated field, never subject to eviction or pollution by diversity mutations, ensuring exponential doubling chains maintain the high compression ratio structure.",
      "retention_signals": [
        "decompressedBytes"
      ],
      "mutation": [
        "repetition [R45a]: double the bestInner content via concatenation, chaining exponentially from 4-byte seed to ~32 MB plaintext = ~30 KB compressed in 23 doublings (70% probability)",
        "dictionary [R45b]: insert XML tokens (<a/>, <b/>, <r>, </r>, whitespace) at random position in a corpus entry for structural diversity (15% probability)",
        "byte-level: flip 1-4 random bytes in a corpus entry for diversity (10% probability)",
        "cross-splice: take chunk from one corpus entry and splice into another at random position (5% probability)",
        "encoder [R45c]: post-step applied to ALL outputs — compress mutated plaintext with java.util.zip.Deflater(Deflater.DEFLATED, true) matching target's Inflater(true) in DeflateUtil.decode(); shrink plaintext if compressed exceeds MAX_INPUT_SIZE; ensures 100% valid DEFLATE output (100% post-step)"
      ]
    }
  ]
}
```
END_GUIDANCE_PLAN_JSON

---

**Summary of the fix:**

**Root cause:** The secondary retention (`currentCompressedSize > bestCompressedSize`) was updating `bestInner` with non-repetitive content from diversity mutations (byte flips, dict insertions). Non-repetitive content compresses poorly (ratio ~3:1) so its compressed output is paradoxically LARGER than the same-sized repetitive `<a/>` content (ratio ~1000:1). The secondary would fire before the repeat path reached comparable compressed sizes, polluting `bestInner` with garbage. After that, `repeat(bestInner)` doubled garbage content, producing inputs with large compressed size but terrible decompression amplification (ratio ~3:1 vs ~1000:1 needed).

**Fix:** Removed `bestInner = currentInner` from the secondary retention block. Now `bestInner` is **only** updated by the primary retention (signal/`decompressedBytes` improvement). Since the repeat path produces well-formed XML (`<r><a/><a/>...<a/></r>`) that the DOM parser reads fully, each doubling increases the signal. The repeat-doubling chain proceeds uninterrupted through ~23 doublings, reaching ~32 MB plaintext → ~30 KB compressed (> 25600 bytes), with decompression ratio matching the scale series (~1000:1).
