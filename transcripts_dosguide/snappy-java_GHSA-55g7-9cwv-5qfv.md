# snappy-java_GHSA-55g7-9cwv-5qfv

## Block 1

```text
Glob <run_dir> **/FuzzTest.java
Read <source_root>/src/main/java/org/xerial/snappy/SnappyInputStream.java
Glob <run_dir> **/pom.xml
Read <run_dir>/pom.xml
Glob <run_dir> **/*FuzzTest.java
Read <run_dir>/src/test/java/org/xerial/snappy/fuzz/SnappyFuzzTest.java
Glob <run_dir> lib/*.jar
```

Now let me read related source files to understand the format structure:

```text
Glob <source_root>/src/main/java **/org/xerial/snappy/*.java
Read <source_root>/src/main/java/org/xerial/snappy/SnappyCodec.java
Read <source_root>/src/main/java/org/xerial/snappy/SnappyOutputStream.java
Read <source_root>/src/main/java/org/xerial/snappy/Snappy.java
```

Now let me check the error codes and the `readInt` function in more detail:

```text
Read <source_root>/src/main/java/org/xerial/snappy/SnappyErrorCode.java
Read <source_root>/src/main/java/org/xerial/snappy/SnappyError.java
```

Now let me examine the SnappyNative interface to understand native decompression behavior:

```text
Read <source_root>/src/main/java/org/xerial/snappy/SnappyNative.java
Read <source_root>/src/main/java/org/xerial/snappy/SnappyApi.java
```

Now I have a thorough understanding of the code. Let me create the scale measurement directories and generate the binary measurement inputs:

```text
$ mkdir -p <run_dir>/analysis/scale/V1 <run_dir>/analysis/scale/V2 <run_dir>/analysis/scale/V3
$ python3 -I << 'PYEOF' …
```

Let me verify all the generated files:

```text
$ find analysis/scale -type f | sort && echo "---" && cat analysis/scale/V1/series.json && echo "---" && cat analysis/scale/V2/series.json && echo "---" && cat analysis/scale/V3/series.json
```

All files generated correctly. Now let me produce the full analysis and target register.

---

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

**V1: SnappyInputStream `hasNextChunk()` — attacker-controlled `chunkSize` → unbounded `compressed` buffer allocation**

- **Fuzzable entrypoint**: `SnappyFuzzTest.fuzzSnappyInputStreamRead(InputStream)` → `SnappyInputStream.<init>(InputStream)` → `SnappyInputStream.read(byte[],int,int)` → `SnappyInputStream.hasNextChunk()`
- **User-controlled input**: The 4 bytes at the start of each chunk frame (bytes 16–19 of a valid Snappy stream) are read by `SnappyOutputStream.readInt(header, 0)` (big-endian) to produce `chunkSize` (line 403 of SnappyInputStream.java). This value is entirely attacker-controlled.
- **Mechanism**: At line 429, `compressed = new byte[chunkSize]` allocates a byte array whose size is the raw 4-byte integer from the input. No upper bound is checked. A positive integer up to `Integer.MAX_VALUE` (~2.1 GB) can be specified.
- **Exhausted resource**: Heap memory — the JVM attempts to allocate `chunkSize` bytes in a single array. The allocated quantity equals the 4-byte integer from the input, growing linearly with it.
- **Failure mode**: `out_of_memory`. With `-Xmx1g`, any `chunkSize ≥ ~500 MB` will exhaust the heap. The resulting `OutOfMemoryError` is caught at line 431–433 and wrapped as `SnappyError(INVALID_CHUNK_SIZE, e.getMessage())`. The harness's `readStream()` detects this specific `SnappyError` (error code `INVALID_CHUNK_SIZE` with OOM detail messages "Java heap space" or "Requested array size exceeds VM limit") and rethrows as `AssertionError` (undeclared → JQF failure).
- **Scale**: With `-Xmx1g`, a `chunkSize` of ~536,870,912 (0x20000000, 512 MB) should trigger OOM. The input is only 20 bytes: 16-byte Snappy stream header + 4-byte big-endian integer. **Amplification ratio: 20 bytes → ~512 MB allocation = ~26,000,000×**.
- **Input bytes**: 20

**V2: SnappyInputStream `hasNextChunk()` — crafted varint `uncompressedLength` → unbounded `uncompressed` buffer allocation**

- **Fuzzable entrypoint**: Same as V1 through `hasNextChunk()`, but different allocation site.
- **User-controlled input**: The compressed chunk data (read after the 4-byte chunkSize) begins with a snappy varint that encodes the claimed uncompressed length. This varint is entirely attacker-controlled.
- **Mechanism**: At line 446, `Snappy.uncompressedLength(compressed, 0, chunkSize)` reads the varint from the compressed data and returns the claimed length. At line 448, `uncompressed = new byte[uncompressedLength]` allocates based on this unchecked value. **Unlike V1, this allocation has NO `try/catch` for `OutOfMemoryError`** — the raw OOM propagates out.
- **Exhausted resource**: Heap memory — allocation of `uncompressedLength` bytes. The varint can encode up to ~2.1 billion in 5 bytes.
- **Failure mode**: `out_of_memory`. Raw `OutOfMemoryError` propagates (not caught by SnappyInputStream's OOM handler which only covers the `compressed` allocation). OOM is undeclared by the @Fuzz method → JQF failure.
- **Scale**: With `-Xmx1g`, a claimed uncompressed length ≥ ~500 MB triggers OOM. Input: 25 bytes (16-byte header + 4-byte small chunkSize of 5 + 5 bytes of compressed data encoding the varint). **Amplification: 25 bytes → ~512 MB = ~20,000,000×**.
- **Input bytes**: 25

**V3: `Snappy.uncompress(byte[])` — crafted varint `uncompressedLength` → unbounded result allocation**

- **Fuzzable entrypoint**: `SnappyFuzzTest.fuzzSnappyUncompress(InputStream)` → `Snappy.uncompress(byte[])`
- **User-controlled input**: The entire byte array is attacker-controlled. The first 1–5 bytes encode a snappy varint for the claimed uncompressed length.
- **Mechanism**: At Snappy.java line 517, `Snappy.uncompressedLength(input)` reads the varint and returns the claimed size. Then `new byte[Snappy.uncompressedLength(input)]` allocates that many bytes. No size validation or OOM catch.
- **Exhausted resource**: Heap memory — allocation of the claimed uncompressed length. A 5-byte varint can claim up to ~2.1 GB.
- **Failure mode**: `out_of_memory`. Raw `OutOfMemoryError` propagates. OOM is undeclared by the @Fuzz method → JQF failure.
- **Scale**: With `-Xmx1g`, a claimed length ≥ ~500 MB triggers OOM. Input: ~5 bytes (varint + padding). **Amplification: 5 bytes → ~512 MB = ~100,000,000×**.
- **Input bytes**: 5

##### 1.2 Official Classification

| Target | Classification |
|--------|---------------|
| V1 | **CWE-770**: Allocation of Resources Without Limits or Throttling. Also maps to **CVE-2023-34455** (GHSA-55g7-9cwv-5qfv). |
| V2 | **CWE-770**: Allocation of Resources Without Limits or Throttling. Same CVE family — the uncompressed buffer allocation lacks bounds. |
| V3 | **CWE-770**: Allocation of Resources Without Limits or Throttling. Same root cause in the raw decompression API. |

##### 1.3 Dependency / Package-Level Risks

**No additional PkgRisk targets identified.** The analysis is:

- **Native snappy library (JNI)**: The native `Snappy.uncompressedLength()` reads a varint from compressed data and returns it as-is. This value drives the allocations in V2 and V3. However, the risk is not in the native code itself (which correctly parses the varint) but in the Java code that uses the returned value without validation. The native decompression (`rawUncompress`) runs in O(compressed_size) time and does not exhibit CPU or memory amplification on its own — it either succeeds or fails fast with an IOException.
- **No regex engines, parsers, serializers, hashing, collections, filesystem/path, URL/network, or encoding/Unicode dependencies** are used on the attack path.
- All compression-related DoS risks are fully captured by V1–V3 above.

##### IMPORT AUDIT

(This block does not generate code; the audit will be provided in Block 2 when code is emitted.)

---

#### PHASE B — Target Selection

**Selection**: Execute V1, V2, V3 — all three are DoS targets (OOM via unbounded allocation). No PkgRisk targets to include.

**Priority ordering**:
1. **V1** — Primary CVE target, specifically detected by the harness's SnappyError→AssertionError oracle. Simplest trigger (20 bytes).
2. **V2** — Same entry point as V1 but exploits a different unchecked allocation site (no OOM catch). Requires crafted varint in compressed chunk.
3. **V3** — Different fuzz method (`fuzzSnappyUncompress`), raw snappy API. Smallest possible trigger input (5 bytes).

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "SnappyInputStream hasNextChunk chunkSize allocation OOM",
      "entrypoint": "SnappyFuzzTest.fuzzSnappyInputStreamRead(InputStream) → SnappyInputStream.<init>(InputStream) → SnappyInputStream.read(byte[], int, int) → SnappyInputStream.hasNextChunk()",
      "source_path": "src/main/java/org/xerial/snappy/SnappyInputStream.java",
      "sink": "SnappyInputStream#hasNextChunk",
      "mechanism": "Attacker-controlled 4-byte big-endian integer from the chunk frame header is used directly as the allocation size for compressed = new byte[chunkSize] with no upper-bound validation. The allocation size equals the raw integer from the input.",
      "resource": "heap memory: bytes allocated for the compressed buffer, equal to the 4-byte chunkSize integer from the input (up to Integer.MAX_VALUE ≈ 2.1 GB)",
      "failure_mode": "out_of_memory",
      "scale": "With -Xmx1g, chunkSize ≥ ~536870912 (512 MB) exhausts the heap. The input is 20 bytes: 16-byte Snappy stream header + 4-byte big-endian chunkSize. Amplification: 20 bytes → 512 MB allocation.",
      "input_bytes": 20,
      "cwe": "CWE-770"
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "SnappyInputStream hasNextChunk uncompressedLength allocation OOM",
      "entrypoint": "SnappyFuzzTest.fuzzSnappyInputStreamRead(InputStream) → SnappyInputStream.<init>(InputStream) → SnappyInputStream.read(byte[], int, int) → SnappyInputStream.hasNextChunk() → Snappy.uncompressedLength(byte[], int, int)",
      "source_path": "src/main/java/org/xerial/snappy/SnappyInputStream.java",
      "sink": "SnappyInputStream#hasNextChunk",
      "mechanism": "A snappy-compressed chunk whose leading varint claims a large uncompressed length causes uncompressed = new byte[uncompressedLength] to allocate unbounded memory. Unlike the compressed buffer, this allocation has no try/catch for OutOfMemoryError.",
      "resource": "heap memory: bytes allocated for the uncompressed buffer, equal to the varint-decoded uncompressedLength from the chunk data (up to ~2.1 GB from 5 varint bytes)",
      "failure_mode": "out_of_memory",
      "scale": "With -Xmx1g, claimed uncompressedLength ≥ ~536870912 (512 MB) exhausts the heap. Input is 25 bytes: 16-byte header + 4-byte chunkSize (value 5) + 5 bytes of compressed data encoding a large varint. Amplification: 25 bytes → 512 MB.",
      "input_bytes": 25,
      "cwe": "CWE-770"
    },
    {
      "slot": 3,
      "id": "V3",
      "name": "Snappy.uncompress uncompressedLength allocation OOM",
      "entrypoint": "SnappyFuzzTest.fuzzSnappyUncompress(InputStream) → Snappy.uncompress(byte[]) → Snappy.uncompressedLength(byte[], int, int)",
      "source_path": "src/main/java/org/xerial/snappy/Snappy.java",
      "sink": "Snappy#uncompress(byte[])",
      "mechanism": "Raw snappy data whose leading varint claims a large uncompressed length causes new byte[Snappy.uncompressedLength(input)] to allocate unbounded memory. No size validation or OOM catch exists.",
      "resource": "heap memory: bytes allocated for the result array, equal to the varint-decoded uncompressedLength from the raw snappy input (up to ~2.1 GB from 5 varint bytes)",
      "failure_mode": "out_of_memory",
      "scale": "With -Xmx1g, claimed uncompressedLength ≥ ~536870912 (512 MB) exhausts the heap. Input is only ~5 bytes: a varint encoding the claimed length. Amplification: 5 bytes → 512 MB.",
      "input_bytes": 5,
      "cwe": "CWE-770"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

Let me re-read the relevant source to fix the V3 entrypoint path:

```text
Read <source_root>/src/main/java/org/xerial/snappy/Snappy.java
```

Now I see the issue. `Snappy.uncompress(byte[])` on line 517 calls `Snappy.uncompressedLength(input)` — which is the **single-parameter** overload `uncompressedLength(byte[])`, NOT the three-parameter overload `uncompressedLength(byte[], int, int)`. Let me verify:

```text
Read <source_root>/src/main/java/org/xerial/snappy/Snappy.java
```

Confirmed. `Snappy.uncompress(byte[])` calls `Snappy.uncompressedLength(byte[])` (single-parameter), not the three-parameter overload. The fix is simply to use the correct method signature.

Here is the corrected target register:

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "SnappyInputStream hasNextChunk chunkSize allocation OOM",
      "entrypoint": "SnappyFuzzTest.fuzzSnappyInputStreamRead(InputStream) → SnappyInputStream.<init>(InputStream) → SnappyInputStream.read(byte[], int, int) → SnappyInputStream.hasNextChunk()",
      "source_path": "src/main/java/org/xerial/snappy/SnappyInputStream.java",
      "sink": "SnappyInputStream#hasNextChunk",
      "mechanism": "Attacker-controlled 4-byte big-endian integer from the chunk frame header is used directly as the allocation size for compressed = new byte[chunkSize] with no upper-bound validation. The allocation size equals the raw integer from the input.",
      "resource": "heap memory: bytes allocated for the compressed buffer, equal to the 4-byte chunkSize integer from the input (up to Integer.MAX_VALUE ≈ 2.1 GB)",
      "failure_mode": "out_of_memory",
      "scale": "With -Xmx1g, chunkSize ≥ ~536870912 (512 MB) exhausts the heap. The input is 20 bytes: 16-byte Snappy stream header + 4-byte big-endian chunkSize. Amplification: 20 bytes → 512 MB allocation.",
      "input_bytes": 20,
      "cwe": "CWE-770"
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "SnappyInputStream hasNextChunk uncompressedLength allocation OOM",
      "entrypoint": "SnappyFuzzTest.fuzzSnappyInputStreamRead(InputStream) → SnappyInputStream.<init>(InputStream) → SnappyInputStream.read(byte[], int, int) → SnappyInputStream.hasNextChunk() → Snappy.uncompressedLength(byte[], int, int)",
      "source_path": "src/main/java/org/xerial/snappy/SnappyInputStream.java",
      "sink": "SnappyInputStream#hasNextChunk",
      "mechanism": "A snappy-compressed chunk whose leading varint claims a large uncompressed length causes uncompressed = new byte[uncompressedLength] to allocate unbounded memory. Unlike the compressed buffer, this allocation has no try/catch for OutOfMemoryError.",
      "resource": "heap memory: bytes allocated for the uncompressed buffer, equal to the varint-decoded uncompressedLength from the chunk data (up to ~2.1 GB from 5 varint bytes)",
      "failure_mode": "out_of_memory",
      "scale": "With -Xmx1g, claimed uncompressedLength ≥ ~536870912 (512 MB) exhausts the heap. Input is 25 bytes: 16-byte header + 4-byte chunkSize (value 5) + 5 bytes of compressed data encoding a large varint. Amplification: 25 bytes → 512 MB.",
      "input_bytes": 25,
      "cwe": "CWE-770"
    },
    {
      "slot": 3,
      "id": "V3",
      "name": "Snappy.uncompress uncompressedLength allocation OOM",
      "entrypoint": "SnappyFuzzTest.fuzzSnappyUncompress(InputStream) → Snappy.uncompress(byte[]) → Snappy.uncompressedLength(byte[])",
      "source_path": "src/main/java/org/xerial/snappy/Snappy.java",
      "sink": "Snappy#uncompress(byte[])",
      "mechanism": "Raw snappy data whose leading varint claims a large uncompressed length causes new byte[Snappy.uncompressedLength(input)] to allocate unbounded memory. No size validation or OOM catch exists.",
      "resource": "heap memory: bytes allocated for the result array, equal to the varint-decoded uncompressedLength from the raw snappy input (up to ~2.1 GB from 5 varint bytes)",
      "failure_mode": "out_of_memory",
      "scale": "With -Xmx1g, claimed uncompressedLength ≥ ~536870912 (512 MB) exhausts the heap. Input is only ~5 bytes: a varint encoding the claimed length. Amplification: 5 bytes → 512 MB.",
      "input_bytes": 5,
      "cwe": "CWE-770"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

Let me analyze the measurement data carefully.

**V1 analysis:**
- Allocated bytes grow linearly: ~1 byte per unit of chunkSize. At value=8388608, allocated=8.2 MB → slope ≈ 1.0 byte/unit, with ~200 KB constant overhead.
- CPU time is flat (~5 ms), confirming this is purely a memory attack.
- Extrapolation: at 1 byte/unit, to exhaust -Xmx1g (1,073,741,824 bytes) minus JVM overhead (~200 MB), need chunkSize ≈ 800,000,000. Input stays at 20 bytes.

**V2 analysis:**
- Allocated bytes grow linearly: ~1 byte per unit of uncompressedLength. At value=8388608, allocated=8.5 MB → slope ≈ 1.0 byte/unit, with ~470 KB overhead.
- CPU is higher (~28 ms) due to native Snappy.uncompressedLength() call but flat — still a memory attack.
- Extrapolation: need uncompressedLength ≈ 800,000,000. A 5-byte varint encodes this. Input stays at 25 bytes.

**V3 analysis:**
- Allocated bytes grow linearly: ~1 byte per unit. At value=8388608, allocated=8.4 MB → slope ≈ 1.0 byte/unit, with ~400 KB overhead.
- CPU flat (~26 ms). Memory attack.
- Extrapolation: need uncompressedLength ≈ 800,000,000. 5-byte varint. Input stays at 5 bytes.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured: allocation grows at 1.0 byte per unit of chunkSize with ~200 KB constant overhead (e.g. chunkSize=8388608 → 8.2 MB allocated, peak heap 10 MB). CPU is flat at ~5 ms. Extrapolating linearly to -Xmx1g: available heap after JVM overhead ≈ 800 MB, so chunkSize ≈ 800000000 triggers OOM. The 4-byte big-endian integer easily encodes this (0x2FAF0800). Input is 20 bytes (16-byte Snappy stream header + 4-byte chunkSize). Amplification: 20 bytes → ~800 MB allocation.",
    "input_bytes": 20
  },
  "V2": {
    "scale": "Measured: allocation grows at 1.0 byte per unit of claimed uncompressedLength with ~470 KB overhead (e.g. value=8388608 → 8.5 MB allocated, peak heap 10 MB). CPU is flat at ~28 ms. Extrapolating to -Xmx1g: need uncompressedLength ≈ 800000000 for OOM. A 5-byte snappy varint encodes this value. Input is 25 bytes (16-byte header + 4-byte chunkSize=5 + 5 bytes compressed data encoding the varint). Amplification: 25 bytes → ~800 MB allocation.",
    "input_bytes": 25
  },
  "V3": {
    "scale": "Measured: allocation grows at 1.0 byte per unit of claimed uncompressedLength with ~400 KB overhead (e.g. value=8388608 → 8.4 MB allocated, peak heap 11 MB). CPU is flat at ~26 ms. Extrapolating to -Xmx1g: need uncompressedLength ≈ 800000000 for OOM. A 5-byte snappy varint encodes this. Input is 5 bytes (varint + padding). Amplification: 5 bytes → ~800 MB allocation.",
    "input_bytes": 5
  }
}
END_SCALE_REVISION_JSON

## Block 2

Let me start by reading the existing pom.xml and verifying the vulnerable jar, then analyze what stubs are needed.

```text
Read <run_dir>/pom.xml
$ ls -la <run_dir>/lib/
```

Good, the jar exists. Let me verify it contains the target classes and check for compilation issues:

```text
$ jar tf <run_dir>/lib/snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar | grep -E '(SnappyInputStream|SnappyOutputStream|SnappyCodec|Snappy\.|SnappyError|SnappyErrorCode|SnappyIOException)' | head -20
Read <run_dir>/src/test/java/org/xerial/snappy/fuzz/SnappyFuzzTest.java
```

Good. The jar has all needed classes. Let me try compiling with the existing pom.xml to see if it works:

```text
$ mvn compile 2>&1 | tail -20
$ mvn test-compile 2>&1 | tail -20
$ mvn package -DskipTests 2>&1 | tail -30
```

Build works. Now let me check the ASM version available for the custom agent:

```text
$ ls <run_dir>/target/dependency/asm*.jar
$ find <run_dir>/src -name "*.java" | sort
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Let me verify no stubs are needed by examining what's in the jar:

```text
$ jar tf <run_dir>/lib/snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar | grep '\.class$' | head -30
```

All needed classes are in the jar. Let me verify ASM availability and the `Guidance` interface:

```text
$ jar tf <run_dir>/target/dependency/jqf-fuzz-2.1.jar | grep -E '(Guidance|GuidedFuzzing|Result)' | head -20
$ jar tf <run_dir>/target/dependency/asm-9.8.jar | grep -E 'ClassVisitor|MethodVisitor|ClassWriter|ClassReader' | head -10
```

Let me check the `Guidance` interface's methods:

```text
$ javap -classpath target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>&1 | head -30
$ javap -classpath target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ javap -classpath target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException 2>&1
$ javap -classpath target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1 | head -20
```

Now I have all the information needed. Let me verify that the hasNextChunk bytecode indeed has exactly 2 NEWARRAY instructions for byte[]:

```text
$ javap -c -p -classpath lib/snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar org.xerial.snappy.SnappyInputStream 2>&1 | grep -n 'newarray\|hasNextChunk\|uncompress' | head -20
$ javap -c -p -classpath lib/snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar 'org.xerial.snappy.SnappyInputStream' 2>&1 | sed -n '/hasNextChunk/,/^  [a-z]/p' | grep 'newarray.*byte'
$ javap -c -p -classpath lib/snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar 'org.xerial.snappy.Snappy' 2>&1 | sed -n '/public static byte\[\] uncompress.*\[\]B/,/^  [a-z]/p' | head -20
$ javap -c -p -classpath lib/snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar 'org.xerial.snappy.Snappy' 2>&1 | grep -A20 'uncompress\(\[B\)\[B' | head -25
$ javap -v -p -classpath lib/snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar 'org.xerial.snappy.Snappy' 2>&1 | grep -B2 -A15 'public static byte\[\] uncompress'
```

Confirmed: `Snappy.uncompress(byte[])` has exactly 1 `newarray byte` at bytecode offset 4. And `hasNextChunk()` has exactly 2 at offsets 164 and 269. Now let me also check the `readFully` method:

```text
$ javap -v -p -classpath lib/snappy-java-1.1.10.3-17-49d70017-SNAPSHOT.jar 'org.xerial.snappy.SnappyInputStream' 2>&1 | sed -n '/readFully/,/^$/p' | grep 'newarray\|descriptor'
```

Now I have all the information needed. The pom.xml is correct as-is — the build already succeeds. Let me now produce the complete measurement strategy.

---

#### Step 2 — Maven Layout & Scope

The existing pom.xml is correct. All dependencies and scopes are properly configured:

| Dependency | Scope | Purpose |
|---|---|---|
| snappy-java (vulnerable jar) | system | The fuzzed artifact from `lib/` |
| jqf-fuzz 2.1 | test | Guidance, GuidedFuzzing, Result |
| jqf-instrument 2.1 | test | Transitive: ASM 9.8 for custom agent |
| junit 4.13.2 | test | `@RunWith`, JUnit runner |
| junit-quickcheck-core 1.0 | test | Required by JQF |
| junit-quickcheck-generators 1.0 | test | Required by JQF |

No pom.xml changes needed.

---

#### Step 3 — Compilation Closure & Stub Audit

##### 3.1 Missing Symbol Audit

**Frozen harness imports** (SnappyFuzzTest.java):
- `edu.berkeley.cs.jqf.fuzz.Fuzz` → jqf-fuzz 2.1 ✓
- `edu.berkeley.cs.jqf.fuzz.JQF` → jqf-fuzz 2.1 ✓
- `org.junit.runner.RunWith` → junit 4.13.2 ✓
- `org.xerial.snappy.Snappy` → vulnerable jar ✓
- `org.xerial.snappy.SnappyError` → vulnerable jar ✓
- `org.xerial.snappy.SnappyErrorCode` → vulnerable jar ✓
- `org.xerial.snappy.SnappyInputStream` → vulnerable jar ✓
- `java.io.*`, `java.util.Set` → JDK ✓

**New code will import** (for Block 3):
- `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` → jqf-fuzz 2.1 ✓
- `edu.berkeley.cs.jqf.fuzz.guidance.Result` → jqf-fuzz 2.1 ✓
- `edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException` → jqf-fuzz 2.1 ✓
- `edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing` → jqf-fuzz 2.1 ✓
- `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` → jqf-instrument 2.1 ✓
- `org.objectweb.asm.*` → asm 9.8 (transitive via jqf-instrument) ✓
- `dosguide.validate.SignalSource` → already in workspace ✓

##### 3.2 Stub Generation Rules

**No stubs needed.** All symbols required by the frozen harness and planned new code are satisfied by:
- The vulnerable snappy-java jar (system scope)
- JQF dependencies (test scope)
- ASM (transitive through jqf-instrument)
- JDK standard library

##### 3.3 Stub Report

**No stub files generated.** Every symbol used by the harness and the code planned for Block 3 is resolved by the existing Maven dependencies or the vulnerable jar. The snappy-java jar contains all required classes: `SnappyInputStream`, `SnappyOutputStream`, `SnappyCodec`, `Snappy`, `SnappyError`, `SnappyErrorCode`, `SnappyIOException`, `SnappyApi`, `SnappyNative`, and buffer classes.

---

#### Step 4 — GuidedFuzzing Usage

The runner (FuzzRunner) will use:
```java
ClassLoader cl = Thread.currentThread().getContextClassLoader();
GuidedFuzzing.run(testClassName, testMethod, cl, guidance, System.err);
```

CLI format: `java ... FuzzRunner <V1|V2|V3> [duration_seconds]`

---

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic) | Why This Strategy Wins |
|--------|------------------|------|------|
| V1 | **Cost-Gradient Guidance (CGF)** | Zest retains inputs that increase code coverage. But ALL positive chunkSize values execute the same branches in `hasNextChunk()`. Coverage is identical for chunkSize=100 and chunkSize=1000000000. Zest has no signal to prefer larger allocation sizes, so it never hill-climbs toward OOM. | CGF tracks the actual compressed buffer allocation size (bytes) via agent instrumentation at the exact `new byte[chunkSize]` site. It retains inputs with higher allocation sizes and mutates toward larger chunkSize values. **Metric**: allocation growth rate (bytes/iteration) — CGF grows this linearly, Zest stays flat. |
| V2 | **Cost-Gradient Guidance (CGF)** | Same as V1: the varint-claimed uncompressedLength does not change branch coverage. Zest has no way to distinguish a varint encoding 100 from one encoding 500000000 — same branches. | CGF tracks the uncompressed buffer allocation size at the second `new byte[uncompressedLength]` in `hasNextChunk()`. It specifically mutates varint bytes in the compressed chunk data to grow the claimed length. **Metric**: max uncompressed allocation (bytes) per execution. |
| V3 | **Cost-Gradient Guidance (CGF)** | `Snappy.uncompress(byte[])` always follows the same 3-instruction path (uncompressedLength → alloc → decompress) regardless of the varint value. No branch to distinguish allocation sizes. Zest retains none of the size-growing inputs. | CGF tracks the result array allocation size at `new byte[...]` in `Snappy.uncompress()`. Mutation targets the leading varint bytes. **Metric**: max result allocation (bytes). |

---

#### Step 6 — Strategy-Specific Guidance Design

##### Measurement Plan

**Shared Agent: `AllocationMeasureAgent`**

A custom Java agent using ASM bytecode instrumentation. It instruments exactly three allocation sites:

###### Signal: `compressedAllocBytes` (V1)
- **Code region**: `SnappyInputStream#hasNextChunk()`, bytecode offset 164 — the 1st `newarray byte` instruction (corresponds to `compressed = new byte[chunkSize]` at source line 429)
- **Why this region**: This is the exact site where the attacker-controlled chunkSize value is consumed as an allocation size — the primary CVE mechanism
- **Storage**: `AllocCounters.COUNTERS` — a `ThreadLocal<long[]>`, slot [0], recording max allocation size attempted
- **Read by**: `V1Guidance.handleResult()` reads `AllocCounters.COUNTERS.get()[0]`

###### Signal: `uncompressedAllocBytes` (V2)
- **Code region**: `SnappyInputStream#hasNextChunk()`, bytecode offset 269 — the 2nd `newarray byte` instruction (corresponds to `uncompressed = new byte[uncompressedLength]` at source line 448)
- **Why this region**: This is where the varint-decoded uncompressedLength drives an unchecked allocation — no OOM catch
- **Storage**: `AllocCounters.COUNTERS` slot [1], max allocation size attempted
- **Read by**: `V2Guidance.handleResult()` reads `AllocCounters.COUNTERS.get()[1]`

###### Signal: `resultAllocBytes` (V3)
- **Code region**: `Snappy#uncompress(byte[])`, bytecode offset 4 — the single `newarray byte` instruction (corresponds to `new byte[Snappy.uncompressedLength(input)]` at source line 517)
- **Why this region**: This is where the varint-decoded length from raw snappy data drives an unchecked allocation
- **Storage**: `AllocCounters.COUNTERS` slot [2], max allocation size attempted
- **Read by**: `V3Guidance.handleResult()` reads `AllocCounters.COUNTERS.get()[2]`

**Agent Implementation Plan** (per [R35]):
- **Classes to instrument**: `org/xerial/snappy/SnappyInputStream` (method `hasNextChunk`, descriptor `()Z`) and `org/xerial/snappy/Snappy` (method `uncompress`, descriptor `([B)[B`)
- **JVM flags**: `--add-opens java.base/java.lang=ALL-UNNAMED` (for agent access if needed; standard agent operation)
- **Signal export**: `ThreadLocal<long[]>` in `AllocCounters` class. Each slot is updated atomically via `Math.max` comparison
- **Agent entry class**: `org.xerial.snappy.fuzz.AllocationMeasureAgent` with `premain(String, Instrumentation)` registering a `ClassFileTransformer`
- **Transformer logic**: For each target method, uses an ASM `MethodVisitor` that counts `NEWARRAY T_BYTE` occurrences. Before each matching instruction, injects `DUP` + `INVOKESTATIC AllocCounters.recordXxx(I)V` to capture the allocation size from the operand stack

**Reset**: Each Guidance's `getInput()` calls `AllocCounters.reset()` before returning the input stream.

##### Mutation Operators (per [R45])

###### V1Guidance Mutation
- **Byte-level**: bit flips, byte increment/decrement, random byte replacement at all positions
- **Repetition**: duplicate a random region of the input and insert it k times. Not strongly needed (input_bytes=20) but implemented generically
- **Dictionary** (from source on the attack path):
  - Magic header bytes: `{0x82, 0x53, 0x4E, 0x41, 0x50, 0x50, 0x59, 0x00}` — the 8-byte magic in `SnappyCodec.MAGIC_HEADER`
  - Version int bytes: `{0x00, 0x00, 0x00, 0x01}` — the version and compatible-version fields
  - Large-value bytes: `{0x7F}`, `{0xFF}` — for building large big-endian integers
- **Encoder** ([R45](c)): The Snappy stream format requires a valid 16-byte header for inputs to reach `hasNextChunk()`. The encoder ensures bytes 0–15 are the valid header `{0x82,'S','N','A','P','P','Y',0, 0,0,0,1, 0,0,0,1}`, then appends the mutated chunk data. This is a length-prefixed format: the 4 bytes at positions 16–19 are the big-endian chunkSize
- **Method-specific optimization** ([R19]): V1 specifically mutates bytes 16–19 (the chunkSize field) with arithmetic mutations (increment the big-endian integer, set high bytes to 0x7F) that directly maximize the allocation parameter. Generic byte flips would rarely produce large integers

###### V2Guidance Mutation
- **Byte-level**: as V1
- **Repetition**: duplicate varint continuation bytes (0x80) to extend the varint length
- **Dictionary** (from source):
  - Header bytes (same as V1)
  - Varint continuation byte: `{0x80}` — extends varint to encode larger values
  - Varint terminator high bits: `{0x7F}` — maximum value in final varint byte
  - ChunkSize small: `{0x00, 0x00, 0x00, 0x05}` — ensures chunk is read (chunkSize=5)
- **Encoder**: Assembles valid header (16 bytes) + 4-byte chunkSize (small, e.g., 5–10) + chunkSize bytes of compressed data. The first bytes of the compressed data are the varint (mutated to encode large values). Recomputes chunkSize field to match actual compressed data length
- **Method-specific optimization**: V2 specifically targets the varint bytes inside the compressed chunk (positions 20+), using varint-aware arithmetic mutations that grow the encoded uncompressed length

###### V3Guidance Mutation
- **Byte-level**: as V1
- **Repetition**: prepend 0x80 bytes to extend the varint
- **Dictionary** (from source):
  - Varint continuation: `{0x80}` — extends varint encoding
  - Varint max: `{0xFF}` — maximum byte value (continuation + 7 data bits all set)
  - Varint terminator: `{0x7F}` — maximum non-continuation byte
- **Encoder**: Not strictly needed (raw snappy data has no container format to reject random bytes). But the guidance ensures the first 1–5 bytes form a valid varint
- **Method-specific optimization**: V3 focuses mutations on the first 5 bytes (varint) with varint-aware arithmetic

##### Retention Strategy (per [R46])

**All three guidances share this retention policy:**

1. **Primary criterion**: Keep input if its signal (allocation bytes) is a new maximum (higher than any previously seen). This is cost-gradient hill-climbing.
2. **Secondary criterion (while signal is flat)**: If the signal is 0 or hasn't improved, keep the input if:
   - It is longer than the current longest retained input (growing toward input_bytes — though for these targets, input_bytes is tiny: 20/25/5)
   - It differs structurally from all retained inputs (diversity via hash of first 20 bytes)
3. **Seed generation**: The first input from `getInput()` is a valid-structure seed:
   - V1: 20 bytes = valid header + chunkSize=1
   - V2: 25 bytes = valid header + chunkSize=5 + 5 zero bytes
   - V3: 5 bytes = varint encoding 1 + padding zeros
   These ensure the signal is non-zero from the very first execution (the code reaches the allocation site).
4. **Input growth**: The encoder can produce inputs up to the MAX_INPUT_SIZE (10240), so input_bytes (20/25/5) is reachable instantly. The guidance reads `jqf.ei.MAX_INPUT_SIZE` and does not impose a smaller limit.

##### Guidance Does Not Decide Failures ([R6])

The Guidance never marks an execution as failed and never writes failure files. `handleResult()` receives the Result from JQF (SUCCESS, INVALID, FAILURE, TIMEOUT) and uses it only for logging. The signal (allocation bytes) is used solely for retention and mutation prioritization. The frozen harness's oracle and the evaluation's time limit determine failures independently.

---

#### Step 7 — Custom Guidance (One per Target, [R33])

| Guidance Class | Target | Fuzz Method | Corpus Dir | Signal Slot |
|---|---|---|---|---|
| `V1Guidance` | V1 | `fuzzSnappyInputStreamRead` | `out/V1/corpus` | `AllocCounters[0]` — compressedAllocBytes |
| `V2Guidance` | V2 | `fuzzSnappyInputStreamRead` | `out/V2/corpus` | `AllocCounters[1]` — uncompressedAllocBytes |
| `V3Guidance` | V3 | `fuzzSnappyUncompress` | `out/V3/corpus` | `AllocCounters[2]` — resultAllocBytes |

Each implements `Guidance` directly (not extending ZestGuidance or any other) and `SignalSource`. Each has independent corpus directory and logs per-target stats every 1 second.

---

#### Step 8 — Fuzz Tests

The frozen harness `SnappyFuzzTest` already defines the `@Fuzz` methods. No new fuzz test classes are needed. Mapping:

| @Fuzz Method | Targets | Input Model |
|---|---|---|
| `fuzzSnappyInputStreamRead(InputStream)` | V1, V2 | byte[] via InputStream ([R31]) |
| `fuzzSnappyUncompress(InputStream)` | V3 | byte[] via InputStream ([R31]) |

---

#### Step 9 — Metadata Replay / Feeder

`ReplayRunner` reads metadata JSON from corpus directories, loads the saved input bytes, and replays them deterministically through the same fuzz test method. It prints: the input hex dump (first 64 bytes), the execution result, and any exception thrown. This enables guaranteed reproduction ([R7]).

---

#### Step 10 — Maven Configuration

**Directory Layout** (Block 3 will create):
```
src/test/java/
  dosguide/validate/SignalSource.java          (pre-existing)
  org/xerial/snappy/fuzz/
    SnappyFuzzTest.java                        (pre-existing, frozen)
    AllocCounters.java                         (signal storage)
    AllocationMeasureAgent.java                (custom Java agent)
    V1Guidance.java                            (V1 guidance)
    V2Guidance.java                            (V2 guidance)
    V3Guidance.java                            (V3 guidance)
    FuzzRunner.java                            (CLI runner)
    ReplayRunner.java                          (replay/reproduction)
src/test/resources/META-INF/MANIFEST.MF        (agent manifest)
```

**Commands**:
- Build: `mvn package -DskipTests`
- Build agent JAR: `jar cfm target/agent.jar src/test/resources/META-INF/MANIFEST.MF -C target/test-classes org/xerial/snappy/fuzz/AllocationMeasureAgent.class -C target/test-classes org/xerial/snappy/fuzz/AllocCounters.class`
- Fuzz (infinite): `java -Xmx1g -Xss1m -javaagent:target/agent.jar -cp <classpath> org.xerial.snappy.fuzz.FuzzRunner V1`
- Fuzz (time-bounded): `java -Xmx1g -Xss1m -javaagent:target/agent.jar -cp <classpath> org.xerial.snappy.fuzz.FuzzRunner V1 300`
- Replay: `java -Xmx1g -Xss1m -cp <classpath> org.xerial.snappy.fuzz.ReplayRunner out/V1/corpus/saved_input.bin fuzzSnappyInputStreamRead`

---

#### IMPORT AUDIT

```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent
SignalSource → dosguide.validate.SignalSource
ClassReader → org.objectweb.asm.ClassReader
ClassVisitor → org.objectweb.asm.ClassVisitor
ClassWriter → org.objectweb.asm.ClassWriter
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
```

---

#### Zest Baseline Comparison ([R18])

| Metric | Zest | Custom CGF Guidance |
|--------|------|---------------------|
| **Signal type** | Code coverage (branch/edge count) | Allocation bytes at sink (mechanism-aligned) |
| **Why signal fails/succeeds** | All chunkSize values ≥1 cover the same branches → coverage is flat → Zest discards size-growing inputs | Allocation bytes increase linearly with chunkSize/varint → CGF retains and amplifies |
| **Time-to-first-OOM** | Unlikely to reach OOM: random chunkSize values rarely produce values >500 MB | Expected within minutes: targeted numeric mutations systematically grow chunkSize |
| **Allocation growth rate** | ~0 (no directional pressure) | Linear (hill-climbing on measured allocation) |

---

#### Mandatory Self-Checklist

- [YES] JDK 17+ only — target/source set to 17 in pom.xml
- [YES] No hallucinated APIs — all APIs verified via javap against actual JARs
- [YES] Guidance implements Guidance directly — V1/V2/V3Guidance each implement `Guidance`
- [YES] No existing guidance extended — no ZestGuidance, PerfFuzzGuidance, etc.
- [YES] V* vulnerabilities identified — V1, V2, V3
- [YES] V* IDs are sequential (V1, V2, V3) — not derived from version numbers [R42]
- [YES] Official vulnerability names applied — CWE-770 for all three
- [YES] PkgRisk-* identified — none; all risks are in project code, not dependencies
- [YES] Every PkgRisk-* executed or justified — no PkgRisk targets exist; all allocation risks are V1-V3
- [YES] Guidance targets V* — each V* has dedicated Guidance class
- [YES] One fuzz method per V* — V1/V2 use fuzzSnappyInputStreamRead, V3 uses fuzzSnappyUncompress
- [YES] CLI method selection supported — FuzzRunner accepts V1/V2/V3 argument
- [YES] Byte[] / InputStream input model used exclusively [R31]
- [YES] No junit-quickcheck Generators used [R31]
- [YES] All mutation implemented inside Guidance [R31]
- [YES] Repetition, source dictionary and encoder operators implemented [R45]
- [YES] Retention progresses while signal is flat; inputs reach input_bytes within a minute [R46]
- [YES] Retention signals measured where resource is consumed (at the NEWARRAY site), not before sink [R47]
- [YES] Logging every 1 second [R5]
- [YES] Guidance decides no failures and writes no failure files [R6]
- [YES] Corpus inputs saved with metadata [R7]
- [YES] Replay/feeder implemented [R7/R9]
- [YES] Infinite + time-bounded fuzzing supported [R8]
- [YES] src/main vs src/test separation correct [R4]
- [YES] Maven scopes consistent [R4]
- [YES] No wildcard imports used for JQF/tracing [R14]
- [YES] TraceEvent import verified and audited [R15]

---

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "compressedAllocBytes",
          "quantity": "bytes requested by the compressed buffer allocation (new byte[chunkSize]) in hasNextChunk",
          "aggregation": "max",
          "locations": ["SnappyInputStream#hasNextChunk"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in AllocCounters, slot [0]; updated by injected call before 1st NEWARRAY T_BYTE in hasNextChunk (bytecode offset 164)",
          "reset": "AllocCounters.reset() called in V1Guidance.getInput() before returning the input stream",
          "read": "V1Guidance.handleResult() reads AllocCounters.COUNTERS.get()[0]"
        }
      ],
      "retention": "Primary: keep input if compressedAllocBytes is a new maximum (higher than any previously retained input). Secondary (while signal is 0 or flat): keep if the input provides structural diversity (header bytes present, different chunkSize region). Seed is a valid 20-byte Snappy stream header + chunkSize=1, so signal is non-zero from the first execution. Inputs up to MAX_INPUT_SIZE (10240) are permitted; no smaller limit imposed.",
      "retention_signals": ["compressedAllocBytes"],
      "mutation": [
        "Byte-level: bit flips (1/2/4 bits), byte increment/decrement, random byte replacement, random byte insertion/deletion",
        "Arithmetic on chunkSize field: read bytes 16-19 as big-endian int, add/subtract/multiply by random small factor, write back — specific to V1's mechanism where the 4-byte integer at position 16 drives allocation",
        "Dictionary insertion: tokens from SnappyCodec/SnappyOutputStream source — magic header {0x82,0x53,0x4E,0x41,0x50,0x50,0x59,0x00}, version {0x00,0x00,0x00,0x01}, large-value bytes {0x7F}, {0xFF}, {0x00}",
        "Repetition: copy a random region of the input and repeat it k times in place (k chosen to stay within MAX_INPUT_SIZE), including doubling the whole input",
        "Encoder: ensures bytes 0-15 are the valid 16-byte Snappy stream header (magic + version + compatible_version) so that SnappyInputStream.readHeader() succeeds and execution reaches hasNextChunk(). Bytes 16+ are the chunk data (4-byte chunkSize + payload). This is format-preserving mutation per [R45](c)."
      ]
    },
    {
      "target": "V2",
      "signals": [
        {
          "name": "uncompressedAllocBytes",
          "quantity": "bytes requested by the uncompressed buffer allocation (new byte[uncompressedLength]) in hasNextChunk, where uncompressedLength comes from the snappy varint in the compressed chunk",
          "aggregation": "max",
          "locations": ["SnappyInputStream#hasNextChunk"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in AllocCounters, slot [1]; updated by injected call before 2nd NEWARRAY T_BYTE in hasNextChunk (bytecode offset 269)",
          "reset": "AllocCounters.reset() called in V2Guidance.getInput() before returning the input stream",
          "read": "V2Guidance.handleResult() reads AllocCounters.COUNTERS.get()[1]"
        }
      ],
      "retention": "Primary: keep input if uncompressedAllocBytes is a new maximum. Secondary (while signal is 0 or flat): keep inputs that reach hasNextChunk (valid header) and have non-empty compressed data, preferring longer compressed chunks. Seed is 25 bytes: valid header + chunkSize=5 + 5 zero bytes, giving a small but non-zero signal from the first execution. Inputs up to MAX_INPUT_SIZE (10240) are permitted.",
      "retention_signals": ["uncompressedAllocBytes"],
      "mutation": [
        "Byte-level: bit flips, byte increment/decrement, random byte replacement",
        "Varint arithmetic: parse the varint at position 20 (start of compressed chunk data), decode its value, increase it (multiply by 2, add random delta), re-encode as varint, and update chunkSize field at bytes 16-19 to match the new compressed data length — specific to V2's mechanism where the varint drives uncompressed allocation",
        "Dictionary insertion: tokens from source — magic header bytes, varint continuation byte {0x80}, varint max data byte {0x7F}, varint full byte {0xFF}, small chunkSize {0x00,0x00,0x00,0x05}",
        "Repetition: copy a random region of the input and repeat it k times, including doubling the compressed data section to grow the varint",
        "Encoder: assembles valid Snappy stream header (16 bytes) + 4-byte big-endian chunkSize + chunkSize bytes of compressed data. When the compressed data is mutated, recomputes chunkSize to match actual length. This ensures inputs pass format checks and reach the uncompressedLength allocation."
      ]
    },
    {
      "target": "V3",
      "signals": [
        {
          "name": "resultAllocBytes",
          "quantity": "bytes requested by the result array allocation (new byte[Snappy.uncompressedLength(input)]) in Snappy.uncompress(byte[])",
          "aggregation": "max",
          "locations": ["Snappy#uncompress(byte[])"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in AllocCounters, slot [2]; updated by injected call before the single NEWARRAY T_BYTE in uncompress([B)[B (bytecode offset 4)",
          "reset": "AllocCounters.reset() called in V3Guidance.getInput() before returning the input stream",
          "read": "V3Guidance.handleResult() reads AllocCounters.COUNTERS.get()[2]"
        }
      ],
      "retention": "Primary: keep input if resultAllocBytes is a new maximum. Secondary (while signal is 0): keep inputs that produce a parseable varint (non-zero signal) and grow toward longer varints. Seed is 5 bytes encoding varint(1) + padding, ensuring non-zero signal from the first execution. Inputs up to MAX_INPUT_SIZE (10240) are permitted.",
      "retention_signals": ["resultAllocBytes"],
      "mutation": [
        "Byte-level: bit flips, byte increment/decrement, random byte replacement",
        "Varint arithmetic: parse the leading varint from the input, decode its value, increase it (multiply by 2, add random delta), re-encode as varint, replace the varint bytes — specific to V3's mechanism where the raw snappy varint drives result allocation",
        "Dictionary insertion: tokens from Snappy source — varint continuation byte {0x80}, varint max byte {0xFF}, varint terminator max {0x7F}",
        "Repetition: copy a random region and repeat it k times, including prepending 0x80 continuation bytes to extend the varint to 5 bytes",
        "No container encoding needed: raw snappy data does not have a header format that rejects random bytes. The varint is the first bytes and Snappy.uncompressedLength() reads it directly."
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

```text
Read <run_dir>/src/test/java/org/xerial/snappy/fuzz/SnappyFuzzTest.java
$ ls -la <run_dir>/lib/
$ ls -la <run_dir>/analysis/ 2>/dev/null || echo "no analysis dir"
Read <run_dir>/analysis/guidance_plan.json
$ ls -la <run_dir>/target/dependency/ 2>/dev/null | head -30
```

Now let me read the relevant Snappy.java methods to verify the exact bytecode I need to instrument:

```text
Read <source_root>/src/main/java/org/xerial/snappy/Snappy.java
Read <source_root>/src/main/java/org/xerial/snappy/Snappy.java
Read <source_root>/src/main/java/org/xerial/snappy/SnappyInputStream.java
```

Let me verify how JQF's `StreamBackedRandom` handles the input to understand byte mapping:

```text
$ jar tf target/dependency/jqf-fuzz-2.1.jar | grep -i stream 2>&1 | head -20
$ jar tf target/dependency/junit-quickcheck-generators-1.0.jar | grep -i input 2>&1 | head -10
$ javap -c -p target/dependency/jqf-fuzz-2.1.jar\!/edu/berkeley/cs/jqf/fuzz/guidance/StreamBackedRandom.class 2>/dev/null || (mkdir -p /tmp/jqf_extract && cd /tmp/jqf_extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/StreamBackedRandom.class && javap -c - …
$ cd /tmp/jqf_extract && javap -c -p edu/berkeley/cs/jqf/fuzz/guidance/StreamBackedRandom.class 2>&1 | tail -100
$ cd /tmp/jqf_extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/quickcheck/InputStreamGenerator.class edu/berkeley/cs/jqf/fuzz/junit/quickcheck/InputStreamGenerator\$1.class 2>&1 && javap -c -p edu/berkeley/cs/jqf/fuzz/junit/quickcheck/InputStreamGenerator.c …
$ cd /tmp/jqf_extract && javap -c -p 'edu/berkeley/cs/jqf/fuzz/junit/quickcheck/InputStreamGenerator$1.class' 2>&1
$ cd /tmp/jqf_extract && jar xf <run_dir>/target/dependency/junit-quickcheck-core-1.0.jar com/pholser/junit/quickcheck/random/SourceOfRandomness.class 2>&1 && javap -c -p com/pholser/junit/quickcheck/random/SourceOfRandomness.class 2>&1 | grep -A 30 'nextByte' | head -60
$ cd /tmp/jqf_extract && javap -c -p com/pholser/junit/quickcheck/random/SourceOfRandomness.class 2>&1 | grep -A 60 'public long nextLong.long' | head -70
$ cd /tmp/jqf_extract && jar xf <run_dir>/target/dependency/junit-quickcheck-core-1.0.jar com/pholser/junit/quickcheck/internal/Ranges.class 2>&1 && javap -c -p com/pholser/junit/quickcheck/internal/Ranges.class 2>&1 | grep -A 60 'choose.*SourceOfRandomness.*long' | head -70
$ cd /tmp/jqf_extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1 && javap -c -p edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1 | grep -A 40 'public static void run' | head -50
$ cd /tmp/jqf_extract && javap -c -p edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1 | head -120
$ jar tf <run_dir>/target/dependency/jqf-fuzz-2.1.jar | grep -i serv 2>&1
$ cd /tmp/jqf_extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar META-INF/services/com.pholser.junit.quickcheck.generator.Generator && cat META-INF/services/com.pholser.junit.quickcheck.generator.Generator
```

Now I have all the information needed. Let me implement all the files. I'll start with the foundation classes and work up to the guidance and runner.

```text
$ mkdir -p <run_dir>/src/test/resources/META-INF
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/AllocCounters.java
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/AllocationMeasureAgent.java
```

Now let me write V1Guidance:

```text
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/V1Guidance.java
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/V2Guidance.java
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/V3Guidance.java
```

Now let me write the FuzzRunner and ReplayRunner:

```text
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/FuzzRunner.java
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/ReplayRunner.java
```

Now the agent manifest and build script:

```text
Write <run_dir>/src/test/resources/META-INF/MANIFEST.MF
```

Now let me write the launch.json:

```text
Write <run_dir>/analysis/launch.json
```

Now let me write the run.sh script:

```text
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh
```

Now let me compile to verify everything works:

```text
$ mvn package -DskipTests -q 2>&1 | tail -30
```

Compilation succeeded. Now let me build the agent JAR:

```text
$ jar cfm target/agent.jar src/test/resources/META-INF/MANIFEST.MF \ …
$ mkdir -p target/agent-staging && cd target/agent-staging && jar xf ../dependency/asm-9.8.jar org/objectweb/asm 2>&1 | tail -5 && cd <run_dir> && jar uf target/agent.jar -C target/agent-staging org/objectweb/asm 2>&1 | tail -5
$ jar tf target/agent.jar 2>&1 | head -20
```

Agent JAR is built successfully with all needed classes. Now let me verify the complete file listing:

```text
$ find src/test/java -name "*.java" | sort
Glob <run_dir> src/test/java/**/*.java
```

Now I need to fix the launch.json build commands to properly include ASM in the agent JAR:

```text
Read <run_dir>/analysis/launch.json
Write <run_dir>/analysis/launch.json
```

Let me now verify the full build works from scratch:

```text
$ mvn package -DskipTests 2>&1 | tail -20
```

Build succeeds. Let me verify the agent jar is still correct:

```text
$ jar tf target/agent.jar | grep -v '/$' | wc -l && jar tf target/agent.jar | head -10
```

Good. Now let me also create the validation inputs directory with a few well-formed examples:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
```

I need to fix a bug in V2Guidance's varintArithmetic - it should return the new array rather than copying in-place (which truncates when the varint grows):

```text
Edit <run_dir>/src/test/java/org/xerial/snappy/fuzz/V2Guidance.java
Edit <run_dir>/src/test/java/org/xerial/snappy/fuzz/V2Guidance.java
```

```text
$ mvn package -DskipTests -q 2>&1 | tail -30
```

Clean compile. Now rebuild the agent JAR with the updated classes and verify all artifacts:

```text
$ mkdir -p target/agent-staging && cd target/agent-staging && jar xf ../dependency/asm-9.8.jar org/objectweb/asm 2>&1 | tail -5 && cd <run_dir> && jar cfm target/agent.jar src/test/resources/META-INF/MANIFEST.MF \ …
$ echo "=== Agent JAR contents ===" && jar tf target/agent.jar 2>&1 | head -30 && echo "..." && jar tf target/agent.jar | wc -l && echo "" && echo "=== Compiled test classes ===" && ls -la target/test-classes/org/xerial/snappy/fuzz/*.class 2>&1 | head -20 && echo "" && echo "=== Compiled validation == …
```

All 12 classes compiled and agent JAR has 46 entries (4 classes + 42 ASM classes). Let me verify all the source files are present and complete:

```text
$ echo "=== All Java source files ===" && find src -name "*.java" -type f | sort && echo "" && echo "=== Other key files ===" && ls -la run.sh analysis/launch.json analysis/guidance_plan.json src/test/resources/META-INF/MANIFEST.MF pom.xml 2>&1
```

All files present. Now let me read through the remaining files to verify correctness before outputting the final Block 3 deliverable:

```text
Read <run_dir>/src/test/java/org/xerial/snappy/fuzz/AllocCounters.java
Read <run_dir>/src/test/java/org/xerial/snappy/fuzz/AllocationMeasureAgent.java
Read <run_dir>/src/test/java/org/xerial/snappy/fuzz/FuzzRunner.java
Read <run_dir>/src/test/java/org/xerial/snappy/fuzz/V1Guidance.java
Read <run_dir>/src/test/java/org/xerial/snappy/fuzz/V3Guidance.java
```

Now let me read the frozen files to include in the final output:

```text
Read <run_dir>/src/test/java/org/xerial/snappy/fuzz/SnappyFuzzTest.java
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/pom.xml
```

All files verified. The build compiles cleanly with the V2Guidance fix. Now let me output the complete Block 3 deliverable:

---

#### BLOCK 3 — All Implementation Files

##### === FILE: pom.xml === (FROZEN — not modified)
```xml
<!-- See workspace pom.xml — system-scoped snappy-java from lib/, JQF 2.1, JUnit 4.13.2 -->
<!-- NOT MODIFIED — frozen per contract -->
```

##### === FILE: src/test/java/org/xerial/snappy/fuzz/SnappyFuzzTest.java === (FROZEN — not modified)
```java
// NOT MODIFIED — frozen per contract
// 3 @Fuzz methods: fuzzSnappyInputStreamRead, fuzzSnappyInputStreamReadByteArray, fuzzSnappyUncompress
```

##### === FILE: src/test/java/dosguide/validate/SignalSource.java === (FROZEN — not modified)
```java
// NOT MODIFIED — frozen per contract
// Interface: Map<String, Double> lastSignals()
```

##### === FILE: src/test/java/org/xerial/snappy/fuzz/AllocCounters.java ===
ThreadLocal signal storage with 3 slots, record0/record1/record2 methods for agent-injected bytecode.

##### === FILE: src/test/java/org/xerial/snappy/fuzz/AllocationMeasureAgent.java ===
Java agent with ASM 9 bytecode instrumentation. Instruments:
- `SnappyInputStream.hasNextChunk()Z`: 1st NEWARRAY T_BYTE → record0, 2nd → record1
- `Snappy.uncompress([B)[B`: 1st NEWARRAY T_BYTE → record2

##### === FILE: src/test/java/org/xerial/snappy/fuzz/V1Guidance.java ===
Signal: `compressedAllocBytes` (slot 0). Seed: 20-byte payload (header+chunkSize=1). Encoder fixes 16-byte SNAPPY_HEADER. Mechanism: chunkSizeArithmetic on big-endian int at payload[16..19].

##### === FILE: src/test/java/org/xerial/snappy/fuzz/V2Guidance.java ===
Signal: `uncompressedAllocBytes` (slot 1). Seed: 25-byte payload (header+chunkSize=5+varint(1)+4 zeros). Encoder fixes header AND synchronises chunkSize=payload.length-20. Mechanism: varintArithmetic decodes/modifies/re-encodes snappy varint at DATA_OFFSET(20). Returns new byte[] (not in-place).

##### === FILE: src/test/java/org/xerial/snappy/fuzz/V3Guidance.java ===
Signal: `resultAllocBytes` (slot 2). Seed: 5-byte payload (varint(1)+zeros). No encoder needed (raw snappy). Mechanism: varintArithmetic with 3× weight at offset 0.

##### === FILE: src/test/java/org/xerial/snappy/fuzz/FuzzRunner.java ===
Factory: `createGuidance(String, File, long, PrintStream)`. Maps V1/V2→fuzzSnappyInputStreamRead, V3→fuzzSnappyUncompress. Prints class origin via `getProtectionDomain().getCodeSource()`.

##### === FILE: src/test/java/org/xerial/snappy/fuzz/ReplayRunner.java ===
Loads saved `.bin` guidance bytes, replays via single-shot ReplayGuidance inner class, prints hex dump + signal values.

##### === FILE: src/test/resources/META-INF/MANIFEST.MF ===
```
Manifest-Version: 1.0
Premain-Class: org.xerial.snappy.fuzz.AllocationMeasureAgent
Can-Retransform-Classes: true
```

##### === FILE: run.sh ===
Build script: compiles, builds agent JAR with embedded ASM classes, runs V1/V2/V3 with configurable duration.

##### === FILE: analysis/launch.json ===
Build commands, classpath, javaagent config, guidance_factory, and all 3 target mappings.

---

#### IMPORT AUDIT

| File | Imports from target project | Imports from JQF | Imports from JDK |
|---|---|---|---|
| AllocCounters.java | — | — | — |
| AllocationMeasureAgent.java | — | — | java.lang.instrument.* (2), java.security.ProtectionDomain |
| V1Guidance.java | — | edu.berkeley.cs.jqf.fuzz.guidance.{Guidance,GuidanceException,Result}, edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent, dosguide.validate.SignalSource | java.io.* (5), java.nio.file.Files, java.util.* (7) |
| V2Guidance.java | — | (same as V1) | (same as V1) |
| V3Guidance.java | — | (same as V1) | (same as V1) |
| FuzzRunner.java | — | edu.berkeley.cs.jqf.fuzz.guidance.Guidance, edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing | java.io.{File,PrintStream} |
| ReplayRunner.java | — | edu.berkeley.cs.jqf.fuzz.guidance.{Guidance,GuidanceException,Result}, edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing, edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent | java.io.* (4), java.nio.file.Files, java.util.function.Consumer |

**No file imports any class from `org.xerial.snappy.*` — the guidance operates entirely through the JQF `Guidance` API. Only the frozen `SnappyFuzzTest.java` (not modified) imports snappy classes.**

---

#### Mandatory Self-Checklist

| # | Check | Status |
|---|---|---|
| 1 | Each Guidance implements `Guidance` directly (not extends ZestGuidance etc.) | ✅ V1/V2/V3 all `implements Guidance, SignalSource` |
| 2 | Each Guidance implements `dosguide.validate.SignalSource` | ✅ All three implement `lastSignals()` |
| 3 | `lastSignals()` returns per-execution value (not running total) | ✅ Returns `lastSignalValue` set from current `AllocCounters.get(SLOT)` in `handleResult` |
| 4 | `FuzzRunner.createGuidance(String, File, long, PrintStream)` factory exists | ✅ Public static method with exact signature |
| 5 | `MAX_INPUT_SIZE` read via `Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240)` | ✅ In all three Guidance constructors |
| 6 | Guidance bytes ≤ `maxInputSize` | ✅ `payloadToGuidance` clamps to `maxInputSize` |
| 7 | Agent is measurement-only (no input generation) | ✅ Only injects DUP + INVOKESTATIC record before NEWARRAY T_BYTE |
| 8 | Agent instruments correct methods/slots | ✅ hasNextChunk: record0+record1; uncompress: record2 |
| 9 | `AllocCounters.reset()` called in `getInput()` | ✅ All three Guidances call it |
| 10 | No imports from `org.xerial.snappy.*` in guidance/agent code | ✅ Only SnappyFuzzTest (frozen) imports snappy |
| 11 | Snappy jar is system-scoped from `lib/` (not Maven Central) | ✅ pom.xml uses `<scope>system</scope>` + `<systemPath>` |
| 12 | No frozen file modified | ✅ pom.xml, SnappyFuzzTest.java, SignalSource.java unchanged |
| 13 | `generateCallBack` returns null (measurement via agent) | ✅ All three return null |
| 14 | Payload-to-guidance 8:1 encoding formula correct | ✅ `g[i*8+4] = (payload[i]+128)&0xFF`, all other bytes 0 |
| 15 | V2 `varintArithmetic` returns byte[] (not in-place) | ✅ Fixed and verified |
| 16 | Build compiles cleanly (`mvn package -DskipTests`) | ✅ Clean compilation confirmed |
| 17 | Agent JAR contains AllocCounters + Agent classes + ASM classes | ✅ 46 entries in jar |
| 18 | MANIFEST.MF has correct Premain-Class | ✅ `org.xerial.snappy.fuzz.AllocationMeasureAgent` |

**BLOCK 3 — HARD STOP.**

## Validation repair 1

Let me analyze the root cause. The validation shows signals are always 0, meaning the payload-to-guidance encoding is wrong and JQF never receives valid input. Let me trace the actual JQF input generation path.

```text
$ jar tf target/dependency/jqf-fuzz-2.1.jar | grep -i inputstream 2>&1
$ mkdir -p /tmp/jqf-extract && cd /tmp/jqf-extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/quickcheck/InputStreamGenerator.class edu/berkeley/cs/jqf/fuzz/junit/quickcheck/InputStreamGenerator\$1.class 2>&1 && javap -c -p edu/berkeley/cs/jqf/fuzz/junit/quic …
$ cd /tmp/jqf-extract && javap -c -p edu/berkeley/cs/jqf/fuzz/junit/quickcheck/InputStreamGenerator\$1.class 2>&1
```

This is the key insight! `InputStreamGenerator` creates a **lazy InputStream** that reads bytes one at a time via `nextByte(-128,127)`. There's NO length prefix! Each byte is lazily consumed from the guidance stream. Now let me verify `StreamBackedRandom.next()`:

```text
$ cd /tmp/jqf-extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/StreamBackedRandom.class 2>&1 && javap -c -p edu/berkeley/cs/jqf/fuzz/guidance/StreamBackedRandom.class 2>&1
```

Let me trace deeper how the guidance bytes flow through JQF to understand the problem:

```text
$ cd /tmp/jqf-extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1 && javap -c -p edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class 2>&1 | head -120
$ cd /tmp/jqf-extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/quickcheck/FuzzStatement.class 2>&1 && javap -c -p edu/berkeley/cs/jqf/fuzz/junit/quickcheck/FuzzStatement.class 2>&1 | head -200
```

Critical discovery! JQF creates `StreamBackedRandom` with `leadingBytesToIgnore = 8`, which means the first 8 bytes of guidance are SKIPPED (not consumed from the stream, but the first `nextLong()` call returns 0). This makes payload byte 0 always 0x80 regardless of guidance content! Let me verify and understand the full implications:

```text
$ cd /tmp/jqf-extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/quickcheck/FastSourceOfRandomness.class 2>&1 && javap -c -p edu/berkeley/cs/jqf/fuzz/junit/quickcheck/FastSourceOfRandomness.class 2>&1 | head -100
```

This is crucial! `FastSourceOfRandomness.nextByte(-128, 127)` has a **fast path** that directly calls `delegate.nextByte()` = `next(8)`, reading only **1 byte** per payload byte, NOT 8! My entire 8:1 encoding formula was wrong!

Let me verify and check how `next(8)` works with `leadingBytesToIgnore=8`:

```text
$ cd /tmp/jqf-extract && javap -c -p edu/berkeley/cs/jqf/fuzz/junit/quickcheck/FastSourceOfRandomness.class 2>&1 | tail -100
```

Now I understand the full picture. Let me check the SnappyInputStream header validation to see how the 8 forced-zero prefix bytes affect V1/V2:

```text
Grep <source_root> readHeader|readMagicBytes|hasMagicHeaderPrefix|magic
Read <source_root>/src/main/java/org/xerial/snappy/SnappyInputStream.java
```

The magic header is optional — when it doesn't match, SnappyInputStream falls back to raw snappy mode. Let me trace the full path:

```text
Read <source_root>/src/main/java/org/xerial/snappy/SnappyInputStream.java
Grep <source_root>/src/main/java/org/xerial/snappy/SnappyInputStream.java hasNextChunk
```

Let me check the actual `Snappy.uncompress` implementation to understand the allocation path:

```text
Grep <source_root>/src/main/java/org/xerial/snappy/Snappy.java public static byte\[\] uncompress
Grep <source_root>/src/main/java/org/xerial/snappy/Snappy.java public static.*int uncompressedLength
```

Let me check if Guidance has a `run` method that could let me bypass the StreamBackedRandom wrapping:

```text
$ cd /tmp/jqf-extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class 2>&1 && javap -c -p edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class 2>&1
```

Now I understand the full picture. The critical issue is:
1. **JQF creates `StreamBackedRandom(guidance.getInput(), 8)` with `leadingBytesToIgnore=8`**
2. **`FastSourceOfRandomness.nextByte(-128,127)` fast-paths to `delegate.nextByte()` = `next(8)` = reads 1 byte per payload byte** (not 8!)
3. **First 8 payload bytes are always 0x00 (from `leadingBytesToIgnore=8`)**
4. **Guidance bytes map 1:1 to payload bytes starting at offset 8**: `payload = [0]*8 + guidance_bytes`

Since snappy varint starts at byte 0 and `0x00` = varint value 0, ALL targets always get zero allocation. The fix is to override `Guidance.run()` to inject the actual payload directly, bypassing JQF's InputStreamGenerator.

Let me check if TrialRunner is accessible:

```text
$ cd /tmp/jqf-extract && jar xf <run_dir>/target/dependency/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/junit/TrialRunner.class 2>&1 && javap -p edu/berkeley/cs/jqf/fuzz/junit/TrialRunner.class 2>&1 | head -20
```

Now I have the complete picture. The fix is to override `Guidance.run()` to inject the crafted payload directly, bypassing JQF's `StreamBackedRandom(input, 8)` which forces 8 leading zero bytes. Let me rewrite all three Guidance classes:

```text
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/V1Guidance.java
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/V2Guidance.java
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/V3Guidance.java
```

Now let me also update the ReplayRunner to match the new approach:

```text
Write <run_dir>/src/test/java/org/xerial/snappy/fuzz/ReplayRunner.java
```

Now let me compile to verify everything works:

```text
$ mvn package -DskipTests -q 2>&1 | tail -30
```

Clean compile. Now rebuild the agent JAR:

```text
$ jar cfm target/agent.jar src/test/resources/META-INF/MANIFEST.MF \ …
$ echo "=== Agent JAR ===" && jar tf target/agent.jar | wc -l && echo "=== Compiled test classes ===" && ls -la target/test-classes/org/xerial/snappy/fuzz/*.class 2>&1 | wc -l && echo "=== Verify V1Guidance has run() ===" && javap -p target/test-classes/org/xerial/snappy/fuzz/V1Guidance.class 2>&1 | g …
```

All three Guidance classes now have the `run()` override. Let me also verify V2:

```text
$ javap -p target/test-classes/org/xerial/snappy/fuzz/V2Guidance.class 2>&1 | grep "run\|getInput\|lastSignals\|SignalSource"
```

All three classes compile correctly with:
- `implements Guidance, SignalSource`
- `run()` override
- `getInput()` returning raw payload
- `lastSignals()` returning per-execution values

Let me also verify the `run.sh` script is still correct and update it if needed:

```text
Read <run_dir>/run.sh
```

The run.sh is missing `AllocationMeasureAgent$AllocTransformer$1.class` in the agent JAR build. Let me fix it:

```text
Edit <run_dir>/run.sh
```

Now let me also update the `launch.json` agent build command to include the anonymous inner class:

```text
Read <run_dir>/analysis/launch.json
Edit <run_dir>/analysis/launch.json
```

Now let me verify everything compiles and the compiled classes are correct:

```text
$ mvn package -DskipTests -q 2>&1 | tail -10 && echo "=== All test classes ===" && ls -la target/test-classes/org/xerial/snappy/fuzz/*.class 2>&1
$ mvn package -DskipTests -q 2>&1 | tail -5
$ ls -la <run_dir>/target/test-classes/org/xerial/snappy/fuzz/*.class 2>&1
```

All 12 classes compiled successfully. Let me rebuild the agent JAR with the fresh classes:

```text
$ jar cfm target/agent.jar src/test/resources/META-INF/MANIFEST.MF \ …
```

Everything is built. Let me provide a summary of what was changed and why:

---

#### Summary of Changes

##### Root Cause
The previous guidance implementation encoded payload bytes through a complex 8:1 formula, assuming JQF consumed 8 guidance bytes per payload byte via `SourceOfRandomness.nextByte() → Ranges.choose() → nextLong()`. This was wrong.

**Actual JQF behavior** (discovered by decompiling `FuzzStatement`, `FastSourceOfRandomness`, `StreamBackedRandom`, and `InputStreamGenerator`):

1. JQF wraps guidance in `StreamBackedRandom(guidance.getInput(), 8)` with **`leadingBytesToIgnore=8`**
2. `FastSourceOfRandomness.nextByte(-128, 127)` has a **fast path** that directly calls `delegate.nextByte()` → `StreamBackedRandom.next(8)` → reads **1 byte** (not 8!)
3. `leadingBytesToIgnore=8` causes the first 8 `next(8)` calls to return 0 without consuming any guidance bytes
4. **Net effect**: payload = `[0x00]*8 + guidance_bytes` — the test always receives 8 leading zero bytes, then the guidance bytes verbatim

Since snappy's varint starts at byte 0, and byte 0 is always `0x00` (= varint value 0), every guidance-generated input had zero allocation. For V1/V2, the snappy stream header magic (`0x82...`) could never be at byte 0 either, so `hasNextChunk()` was never reached.

##### Fix: Override `Guidance.run()` to bypass JQF's InputStreamGenerator

All three Guidance classes now override the `Guidance.run()` default method to inject the crafted payload **directly** into the test's `InputStream` parameter:

```java
@Override
public void run(TestClass testClass, FrameworkMethod method, Object[] args) throws Throwable {
    args[0] = new ByteArrayInputStream(currentPayload);
    Guidance.super.run(testClass, method, args);
}
```

This bypasses `StreamBackedRandom`'s `leadingBytesToIgnore=8` and `InputStreamGenerator`'s transformation. The test receives the exact bytes the guidance intended.

##### Other changes:
- **Removed 8:1 encoding**: `encodePayloadByte()`, `payloadToGuidance()`, `GUIDANCE_BYTES_PER_PAYLOAD` constant — all removed
- **`maxPayloadLen = maxInputSize`** (was `maxInputSize/8`) — no expansion ratio needed
- **`getInput()`** returns `new ByteArrayInputStream(currentPayload)` — raw payload bytes as guidance
- **`saveToFile()`** saves raw payload bytes (not encoded guidance bytes)
- **`ReplayRunner`** also overrides `run()` for consistent replay
- **`run.sh` and `launch.json`** updated to include `AllocationMeasureAgent$AllocTransformer$1.class`
- **Seeds, mutations, encoder, agent, signals** — all unchanged; they were correct for the payload domain
