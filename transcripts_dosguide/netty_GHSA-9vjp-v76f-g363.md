# netty_GHSA-9vjp-v76f-g363

## Block 1

I'll start by reading the main source file, the fuzz test, and understanding the project structure.

```text
Read <source_root>/codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java
Glob <run_dir> *FuzzTest.java
Glob <run_dir> pom.xml
Read <run_dir>/src/test/java/com/fuzzer/harness/SnappyFuzzTest.java
Read <run_dir>/pom.xml
```

Now let me read the Snappy class to understand the decode mechanism:

```text
Read <source_root>/codec/src/main/java/io/netty/handler/codec/compression/Snappy.java
```

Now let me examine the Snappy class more closely, specifically the decompression logic, and check for the lib directory:

```text
Glob <run_dir> lib/*.jar
Read <source_root>/codec/src/main/java/io/netty/handler/codec/compression/Snappy.java
```

Good. I have the vulnerable jars in `lib/` and I understand the code. Let me now trace the full vulnerability path and generate the scale measurement files.

Let me first create the directory structure and generate the scale measurement data:

```text
$ mkdir -p <run_dir>/analysis/scale/V1
$ python3 -c " …
```

Now let me verify the generated files are correct by hex-dumping one:

```text
$ xxd <run_dir>/analysis/scale/V1/n65536.bin
$ xxd <run_dir>/analysis/scale/V1/n2097152.bin
Read <run_dir>/analysis/scale/V1/series.json
```

The binary files are correctly formatted. Let me now verify the file structure end-to-end by tracing through the decoder logic:

- `n65536.bin`: Stream ID (10 bytes) + COMPRESSED_DATA (type=0x00, length=7, checksum=0, varint=[0x80,0x80,0x04] = 65536)
- `n2097152.bin`: Stream ID (10 bytes) + COMPRESSED_DATA (type=0x00, length=8, checksum=0, varint=[0x80,0x80,0x80,0x01] = 2097152)

---

#### PHASE A — Vulnerability & Dependency Analysis

##### 1.1 Code-Level Vulnerabilities

###### V1: Snappy COMPRESSED_DATA preamble-driven heap exhaustion (no upper bound on claimed uncompressed size)

**Fuzzable entrypoint & user-controlled inputs:**
- `fuzzSnappyFrameDecoderDecode(InputStream)` — the input bytes form a Snappy frame containing one or more `COMPRESSED_DATA` chunks. Each chunk's compressed payload begins with a varint preamble that the attacker fully controls.

**Mechanism — how input makes resource consumption grow:**

1. The `SnappyFrameDecoder.decode()` (line 98) parses chunk headers. For `COMPRESSED_DATA` (type byte `0x00`), it calls `snappy.decode(in.readSlice(chunkLength - 4), uncompressed)` at line 183.
2. Inside `Snappy.decode()` (line 270), the first thing is `readPreamble(in)` (line 277), which reads a varint from the compressed data declaring the claimed uncompressed size.
3. `readPreamble()` (lines 363–379) decodes a 1–4 byte varint. The **maximum** value with 4 bytes (28 bits) is `0x0FFFFFFF = 268,435,455` (~256 MB). There is **no upper bound check** on this value.
4. At line 287: `out.ensureWritable(uncompressedLength)` — this pre-allocates a heap byte array of size ≈ `uncompressedLength`. For 268,435,455, Netty's `calculateNewCapacity` rounds up to **268,435,456 bytes (256 MB)**.
5. The `SnappyFrameDecoder` has an explicit size check for `UNCOMPRESSED_DATA` chunks (`chunkLength > MAX_UNCOMPRESSED_DATA_SIZE` at line 143, limit 65540), but **no such limit exists for COMPRESSED_DATA** chunks.
6. Multiple `COMPRESSED_DATA` chunks can be packed into a single input frame. The `ByteToMessageDecoder.callDecode()` loop processes them sequentially; each decoded buffer is fired via `ctx.fireChannelRead()` and stored in the EmbeddedChannel's inbound queue. The fuzz test releases them only **after** `writeInbound()` returns, so all buffers are live simultaneously.
7. With 4 chunks × ~256 MB = ~1024 MB of live buffers, plus JVM overhead (~100–200 MB), the heap exceeds the 1 GB limit.

**Input construction for the attack (minimum):**
- Stream identifier: 10 bytes (`0xFF 0x06 0x00 0x00 'sNaPpY'`)
- Each COMPRESSED_DATA chunk: 12 bytes (1 type + 3 length + 4 checksum + 4 preamble varint)
- 4 chunks: 10 + 4×12 = **58 bytes** — far under the 10240-byte input limit

**Exhausted resource:** Heap memory — the number of live bytes allocated grows as `N × claimed_uncompressed_size` where N is the number of COMPRESSED_DATA chunks.

**Failure mode:** `out_of_memory` — `OutOfMemoryError` when `ByteBuf.ensureWritable()` tries to allocate the next ~256 MB array and the heap is already full from previously accumulated buffers.

**Scale:** 4 chunks each claiming 268,435,455 bytes ≈ 1024 MB total live allocation. Combined with JVM/framework overhead (~100–200 MB), this exceeds the 1 GB heap. Input: 58 bytes.

**Key vulnerable code locations:**
- `Snappy.java:287` — `out.ensureWritable(uncompressedLength)` with no upper bound on `uncompressedLength`
- `Snappy.java:363–379` — `readPreamble()` returns up to 268,435,455 from a 4-byte varint
- `SnappyFrameDecoder.java:160–193` — COMPRESSED_DATA case has no size check (unlike UNCOMPRESSED_DATA case at line 143)

##### 1.2 Official Classification

**V1:** CWE-770 — Allocation of Resources Without Limits or Throttling. Also classifiable as CWE-409 — Improper Handling of Highly Compressed Data (Decompression Bomb). The primary CWE is **CWE-770** because the root cause is the absence of an upper bound on the allocation requested by the varint preamble.

##### 1.3 Dependency / Package-Level Risks

Analysis of the dependency chain:

| Package / Class | Risk Assessment |
|---|---|
| `io.netty.buffer.ByteBuf` (`ensureWritable`) | The allocator works as designed — it allocates what the caller requests. The vulnerability is in the caller (`Snappy.decode`), not in ByteBuf. **Not a PkgRisk.** |
| `io.netty.handler.codec.compression.Crc32c` | Only used when `validateChecksums=true` (not the default, not used in fuzz test). **Not exercised.** |
| `io.netty.handler.codec.ByteToMessageDecoder` | Framework callback loop. Works as designed. **Not a PkgRisk.** |
| Java standard library | No regex, XML/JSON parsing, or external decompression libraries in the decode path. **No PkgRisk.** |

**Conclusion:** No dependency-level risks (PkgRisk) are identified. The vulnerability is entirely in the Netty Snappy codec's own code — the missing upper bound check in `Snappy.decode()` and the missing size validation in `SnappyFrameDecoder` for COMPRESSED_DATA chunks.

---

#### PHASE B — Target Selection & Register

**Selection rationale:** V1 is the only viable DoS target. The direct `Snappy.decode()` path via `fuzzSnappyDecode` produces at most one ~256 MB allocation per call, which doesn't exceed the 1 GB heap. The frame decoder path (`fuzzSnappyFrameDecoderDecode`) accumulates multiple ~256 MB allocations from successive COMPRESSED_DATA chunks, reliably causing `OutOfMemoryError`.

No PkgRisks were identified, so no PkgRisk targets are included.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Snappy COMPRESSED_DATA preamble-driven heap exhaustion via unchecked ensureWritable",
      "entrypoint": "SnappyFuzzTest.fuzzSnappyFrameDecoderDecode(InputStream) → SnappyFrameDecoder.decode(ChannelHandlerContext, ByteBuf, List) → Snappy.decode(ByteBuf, ByteBuf) → ByteBuf.ensureWritable(int)",
      "source_path": "codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java",
      "sink": "ByteBuf#ensureWritable",
      "mechanism": "Snappy.decode() reads a varint preamble from compressed data declaring the claimed uncompressed size (up to 268,435,455 bytes from 4 varint bytes) and calls out.ensureWritable(uncompressedLength) with no upper bound check. SnappyFrameDecoder processes multiple COMPRESSED_DATA chunks from a single input; each allocates a buffer proportional to the preamble claim. All buffers accumulate in the EmbeddedChannel inbound queue before release, so N chunks × ~256 MB live simultaneously.",
      "resource": "heap memory: total live bytes = number_of_chunks × claimed_uncompressed_size, each up to 268,435,455 bytes (~256 MB) per chunk",
      "failure_mode": "out_of_memory",
      "scale": "4 chunks each claiming 268,435,455 bytes (~256 MB) produce ~1024 MB of live heap allocations, exceeding the 1 GB heap with JVM overhead. Input: 10 bytes (stream identifier) + 4 × 12 bytes (compressed chunks) = 58 bytes.",
      "input_bytes": 58,
      "cwe": "CWE-770"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

Let me read the relevant source files to trace the exact call chain:

```text
Grep <source_root> public.*writeInbound
Grep <source_root>/codec class SnappyFrameDecoder
Read <source_root>/transport/src/main/java/io/netty/channel/embedded/EmbeddedChannel.java
Grep <source_root>/transport/src/main/java/io/netty/channel void fireChannelRead\(Object
Grep <source_root>/transport/src/main/java/io/netty/channel fireChannelRead\(Object
Grep <source_root>/transport/src/main/java/io/netty/channel/DefaultChannelPipeline.java public final ChannelPipeline fireChannelRead
Grep <source_root>/transport/src/main/java/io/netty/channel/AbstractChannelHandlerContext.java static void invokeChannelRead\(
Read <source_root>/transport/src/main/java/io/netty/channel/AbstractChannelHandlerContext.java
```

Now let me trace the exact call chain from `ByteToMessageDecoder.channelRead` to `SnappyFrameDecoder.decode`:

```text
Grep <source_root>/codec/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java void channelRead\(ChannelHandlerContext"
Grep <source_root>/codec/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java channelRead\(ChannelHandlerContext"
Grep <source_root>/codec/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java channelRead"
Grep <source_root>/codec/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java channelRead
Read <source_root>/codec/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java
Grep <source_root>/codec/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java callDecode|decodeRemovalReentryProtection
Read <source_root>/codec/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java
Read <source_root>/codec/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java
```

Now I have the complete call chain. Let me verify the key intermediate hops:

1. `EmbeddedChannel.writeInbound` → calls `p.fireChannelRead(m)` at line 343 where `p = pipeline()` which is `DefaultChannelPipeline`
2. `DefaultChannelPipeline.fireChannelRead` → calls `AbstractChannelHandlerContext.invokeChannelRead(head, msg)` at line 919 → dispatches to `handler().channelRead()` through 2 intermediate calls
3. `ByteToMessageDecoder.channelRead` → calls `callDecode(ctx, cumulation, out)` at line 276
4. `ByteToMessageDecoder.callDecode` → calls `decodeRemovalReentryProtection(ctx, in, out)` at line 446 → which calls `decode(ctx, in, out)` at line 507
5. `SnappyFrameDecoder.decode` → calls `snappy.decode(in.readSlice(chunkLength - 4), uncompressed)` at line 183
6. `Snappy.decode` → calls `readPreamble(in)` → `out.ensureWritable(uncompressedLength)` at line 287

The sink is in `Snappy.java`, not `SnappyFrameDecoder.java`. I need to update `source_path` to `Snappy.java` so the sink is in the declared source file.

Here is the corrected target register:

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Snappy COMPRESSED_DATA preamble-driven heap exhaustion via unchecked ensureWritable",
      "entrypoint": "SnappyFuzzTest.fuzzSnappyFrameDecoderDecode(InputStream) → EmbeddedChannel.writeInbound(Object...) → DefaultChannelPipeline.fireChannelRead(Object) → ByteToMessageDecoder.channelRead(ChannelHandlerContext, Object) → ByteToMessageDecoder.callDecode(ChannelHandlerContext, ByteBuf, List) → SnappyFrameDecoder.decode(ChannelHandlerContext, ByteBuf, List) → Snappy.decode(ByteBuf, ByteBuf)",
      "source_path": "codec/src/main/java/io/netty/handler/codec/compression/Snappy.java",
      "sink": "Snappy#decode",
      "mechanism": "Snappy.decode() reads a varint preamble from compressed data declaring the claimed uncompressed size (up to 268,435,455 bytes from 4 varint bytes) and calls out.ensureWritable(uncompressedLength) with no upper bound check. SnappyFrameDecoder processes multiple COMPRESSED_DATA chunks from a single input; each allocates a buffer proportional to the preamble claim. All buffers accumulate in the EmbeddedChannel inbound queue before release, so N chunks × ~256 MB live simultaneously.",
      "resource": "heap memory: total live bytes = number_of_chunks × claimed_uncompressed_size, each up to 268,435,455 bytes (~256 MB) per chunk",
      "failure_mode": "out_of_memory",
      "scale": "4 chunks each claiming 268,435,455 bytes (~256 MB) produce ~1024 MB of live heap allocations, exceeding the 1 GB heap with JVM overhead. Input: 10 bytes (stream identifier) + 4 × 12 bytes (compressed chunks) = 58 bytes.",
      "input_bytes": 58,
      "cwe": "CWE-770"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

The measurements show constant heap allocation (~7.3 MB) and peak heap (~5–9 MB) regardless of the claimed uncompressed size. This requires investigation into why the allocation doesn't appear on-heap.

Let me check what allocator the SnappyFrameDecoder uses:

```text
Grep <source_root>/codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java ctx\.alloc\(\)\.buffer
Grep <source_root>/buffer/src/main/java/io/netty/buffer DEFAULT_ALLOCATOR|DEFAULT =
Read <source_root>/buffer/src/main/java/io/netty/buffer/ByteBufUtil.java
Read <source_root>/buffer/src/main/java/io/netty/buffer/PooledByteBufAllocator.java
Grep <source_root>/common/src/main/java/io/netty/util/internal/PlatformDependent.java directBufferPreferred
Grep <source_root>/common/src/main/java/io/netty/util/internal/PlatformDependent.java DIRECT_BUFFER_PREFERRED\s*=
```

Now let me verify the pool's huge allocation threshold:

```text
Grep <source_root>/buffer/src/main/java/io/netty/buffer/PooledByteBufAllocator.java chunkSize|DEFAULT_PAGE_SIZE|DEFAULT_MAX_ORDER
Read <source_root>/buffer/src/main/java/io/netty/buffer/PooledByteBufAllocator.java
```

This confirms:
- Default allocator = `PooledByteBufAllocator` with `directBufferPreferred() = true`
- `ctx.alloc().buffer()` creates **direct (off-heap)** ByteBufs
- Default chunk size = 8192 << 11 = **16 MB**
- Allocations ≤ 16 MB are served from pre-allocated pool arena chunks → no new system allocation → invisible to heap probe
- Allocations > 16 MB are "huge" allocations that allocate dedicated direct memory

This explains the flat measurements: my series (64 KB – 2 MB) is entirely within the pool's chunk size (16 MB), so `ensureWritable` carves from existing arena chunks and requires no new heap allocation. The constant ~7.3 MB is baseline JVM/framework overhead.

**Extrapolation to attack size:**
- At `claimed_size = 268,435,455` (~256 MB) >> 16 MB chunk size: each chunk triggers a "huge" direct allocation of ~256 MB
- Direct memory budget: MaxDirectMemorySize defaults to ~`-Xmx` = ~1,073 MB
- Pool arena overhead: ~16 MB (1 used arena, 1 chunk)
- After 3 chunks: 16 + 3×268 = ~820 MB
- 4th chunk attempts +268 MB → total ~1088 MB > 1073 MB → **OutOfMemoryError: Direct buffer memory**

The mechanism is confirmed correct; the resource is direct (off-heap) memory, not Java heap, which is why the heap-only probe showed no growth.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Heap measurements show constant ~7.3 MB because ctx.alloc().buffer() in SnappyFrameDecoder uses the channel's default PooledByteBufAllocator, which creates direct (off-heap) ByteBufs. ensureWritable(claimed_size) allocates direct memory invisible to the heap probe. For claimed sizes up to 16 MB (the pool's chunk size, 8192 << 11), allocations come from pre-allocated arena chunks, explaining the flat measurements across the 64 KB–2 MB series. For the attack (claimed_size = 268,435,455, ~256 MB), each chunk's ensureWritable triggers a 'huge' direct allocation of ~256 MB outside the pool. Cost per chunk: ~268 MB of direct memory. The callDecode loop fires each buffer to the inbound queue before processing the next, so all are live simultaneously. Direct memory budget: MaxDirectMemorySize defaults to -Xmx (~1073 MB). After 3 chunks: ~16 MB (arena) + 3 × 268 MB = ~820 MB. The 4th chunk's ~268 MB allocation pushes total to ~1088 MB, exceeding the limit → OutOfMemoryError. Input: 10 bytes (stream identifier) + 4 × 12 bytes (compressed chunks) = 58 bytes. No denser encoding exists: 12 bytes per chunk is the minimum (1 type + 3 length + 4 checksum + 4 preamble varint).",
    "input_bytes": 58
  }
}
END_SCALE_REVISION_JSON

## Block 2

I'll start by reading the existing workspace files and understanding the build setup, then develop the measurement strategy.

```text
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/com/fuzzer/harness/SnappyFuzzTest.java
```

Good. Let me verify the lib jars exist and the build works:

```text
$ ls -la <run_dir>/lib/
```

Good, jars exist. Let me compile to verify the current build:

```text
$ mvn compile 2>&1 | tail -20
$ mvn test-compile 2>&1 | tail -20
$ mvn package -DskipTests 2>&1 | tail -30
```

Build succeeds. Now let me examine the key source files for instrumentation points:

```text
Read <source_root>/codec/src/main/java/io/netty/handler/codec/compression/Snappy.java
Read <source_root>/codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java
```

Now let me examine the `AbstractByteBuf.ensureWritable` to find the exact instrumentation point:

```text
Read <source_root>/buffer/src/main/java/io/netty/buffer/AbstractByteBuf.java
```

Good, the build works perfectly. Let me now read the exact `capacity()` method signature to plan instrumentation:

```text
Grep <source_root>/buffer/src/main/java/io/netty/buffer/ByteBuf.java public.*int capacity\(\)
$ ls -R <run_dir>/src/
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
```

Important — the evaluation provides a `SignalSource` interface that the Guidance must implement. Now let me verify what ASM version is available and create the directory structure:

```text
$ ls <run_dir>/target/deps/asm*.jar 2>/dev/null
```

Good — ASM 9.8 (core) is available. Now let me create the directory tree for all the code that Block 3 will produce:

```text
$ \ …
```

Now let me verify the pom.xml build still works and that the Netty jar contains the target Snappy class:

```text
$ jar tf <run_dir>/lib/netty-codec-4.1.68.Final-SNAPSHOT.jar | grep -E 'Snappy|compression' | head -20
$ jar tf <run_dir>/lib/netty-codec-4.1.68.Final-SNAPSHOT.jar | grep Snappy
```

`Snappy.class` and `SnappyFrameDecoder.class` confirmed in the vulnerable jar. Now let me verify the exact method descriptor of `Snappy.decode` using javap:

```text
$ javap -p -s <run_dir>/lib/netty-codec-4.1.68.Final-SNAPSHOT.jar\!/io/netty/handler/codec/compression/Snappy.class 2>/dev/null || \ …
$ cd /tmp && javap -p -s io/netty/handler/codec/compression/Snappy.class 2>&1 | grep -A2 'decode'
```

Confirmed: `Snappy.decode` descriptor is `(Lio/netty/buffer/ByteBuf;Lio/netty/buffer/ByteBuf;)V`. It's a non-static method, so `this` is slot 0, `in` is slot 1, `out` is slot 2.

Now let me verify the full directory tree:

```text
$ find <run_dir>/src -type d | sort
```

Let me re-read the current state of key files to ensure accuracy before producing the Block 2 output.

```text
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/com/fuzzer/harness/SnappyFuzzTest.java
```

Now let me check the existing analysis artifacts and target register:

```text
Glob <run_dir>/analysis **/*.json
$ find <run_dir> -maxdepth 1 -name '*.json' -o -name '*.md' | sort
Read <run_dir>/analysis/target_register.json
Read <run_dir>/analysis/scale.json
Read <run_dir>/analysis/run_config.json
```

Let me read the prompt to get the exact Block 2 output format requirements:

```text
Read <dosguide>/prompt/prompt.txt
Read <dosguide>/prompt/prompt.txt
Read <dosguide>/prompt/prompt.txt
Read <dosguide>/prompt/prompt.txt
```

Now let me find the Block 2 specific instructions from the prompt (the block-specific section):

```text
Grep <dosguide>/prompt/prompt.txt Block 2|BLOCK 2|block.2|HARD STOP|guidance.plan|GUIDANCE_PLAN
Grep <dosguide>/prompt HARD.STOP|BEGIN_GUIDANCE|END_GUIDANCE|guidance_plan|block_2|Block_2
Glob <dosguide>/prompt **/*.txt
Read <dosguide>/prompt/guidance_prompt.txt
```

Let me check the transcript for the Block 2 instructions to ensure I output the exact format required:

```text
$ cat <session_dir>/<session>.jsonl | python3 -c " …
$ cat <session_dir>/<session>.jsonl | python3 -c " …
$ cat <session_dir>/<session>.jsonl | python3 -c " …
$ python3 -c " …
$ wc -l <session_dir>/<session>.jsonl 2>&1
$ python3 << 'PYEOF' …
$ python3 -c " …
$ python3 -c " …
$ python3 -c " …
$ python3 -c " …
```

Line 274 (47572 chars) and line 419 (14436 chars) are the Block 2 prompts. Let me read them:

```text
$ python3 -c " …
$ python3 << 'PYEOF' …
$ python3 << 'PYEOF' …
$ python3 << 'PYEOF' …
```

Now I have the full Block 2 requirements. Let me also read the continuation message (line 419):

```text
$ python3 << 'PYEOF' …
$ python3 << 'PYEOF' …
```

Let me verify the current build compiles:

```text
$ mvn compile 2>&1 | tail -20
```

Good, the build compiles. Let me also verify the lib jars are intact:

```text
$ ls -la <run_dir>/lib/*.jar 2>&1
```

Now let me verify the existing directories are all created:

```text
$ find <run_dir>/src -type f | sort
```

Good. All directories are created (empty directories for agent, guidance, runner, replay). Now let me produce the complete Block 2 output.

---

#### Step 2 — Maven Layout & Scope

**Layout verification:**

| Directory | Purpose | Status |
|---|---|---|
| `src/main/java/` | Production stubs only (`dummy/Placeholder.java`) | ✅ Correct — no JQF/JUnit here |
| `src/test/java/com/fuzzer/harness/` | Frozen fuzz test (`SnappyFuzzTest.java`) | ✅ Correct — test scope |
| `src/test/java/com/fuzzer/guidance/` | V1Guidance, V1Signal (to be implemented Block 3) | ✅ Created |
| `src/test/java/com/fuzzer/agent/` | V1MeasureAgent, V1Transformer (to be implemented Block 3) | ✅ Created |
| `src/test/java/com/fuzzer/runner/` | FuzzRunner (to be implemented Block 3) | ✅ Created |
| `src/test/java/com/fuzzer/replay/` | ReplayRunner (to be implemented Block 3) | ✅ Created |
| `src/test/resources/META-INF/` | Agent MANIFEST.MF (to be implemented Block 3) | ✅ Created |
| `src/test/java/dosguide/validate/` | SignalSource.java (evaluation framework, read-only) | ✅ Present |
| `lib/` | Vulnerable Netty 4.1.68.Final-SNAPSHOT jars (system scope) | ✅ Present |

**Scope check:**

| Dependency | Scope | Valid |
|---|---|---|
| io.netty:netty-codec (lib/) | system | ✅ Local vulnerable jar |
| io.netty:netty-buffer (lib/) | system | ✅ Local vulnerable jar |
| io.netty:netty-common (lib/) | system | ✅ Local vulnerable jar |
| io.netty:netty-transport (lib/) | system | ✅ Local vulnerable jar |
| io.netty:netty-resolver (lib/) | system | ✅ Local vulnerable jar |
| edu.berkeley.cs.jqf:jqf-fuzz | test | ✅ |
| edu.berkeley.cs.jqf:jqf-instrument | test | ✅ (provides ASM 9.x transitively) |
| junit:junit | test | ✅ |
| com.pholser:junit-quickcheck-core | test | ✅ |
| com.pholser:junit-quickcheck-generators | test | ✅ |

No forbidden Maven coordinates are declared as normal dependencies. All Netty jars use `<scope>system</scope>` with `<systemPath>` pointing to `${project.basedir}/lib/`. No pom.xml changes needed.

#### Step 3 — Compilation Closure via Minimal Stubs

##### 3.1 Missing Symbol Audit

All classes needed to compile the harness and the upcoming fuzzing infrastructure:

| Symbol | Package | Classification | Resolution |
|---|---|---|---|
| `SnappyFrameDecoder` | `io.netty.handler.codec.compression` | In `lib/netty-codec-*.jar` | ✅ Already on classpath |
| `Snappy` | `io.netty.handler.codec.compression` | In `lib/netty-codec-*.jar` | ✅ Already on classpath |
| `DecompressionException` | `io.netty.handler.codec.compression` | In `lib/netty-codec-*.jar` | ✅ Already on classpath |
| `ByteBuf` | `io.netty.buffer` | In `lib/netty-buffer-*.jar` | ✅ Already on classpath |
| `Unpooled` | `io.netty.buffer` | In `lib/netty-buffer-*.jar` | ✅ Already on classpath |
| `EmbeddedChannel` | `io.netty.channel.embedded` | In `lib/netty-transport-*.jar` | ✅ Already on classpath |
| `ReferenceCountUtil` | `io.netty.util` | In `lib/netty-common-*.jar` | ✅ Already on classpath |
| `Guidance` | `edu.berkeley.cs.jqf.fuzz.guidance` | jqf-fuzz test dep | ✅ Already on classpath |
| `GuidedFuzzing` | `edu.berkeley.cs.jqf.fuzz.junit` | jqf-fuzz test dep | ✅ Already on classpath |
| `@Fuzz` | `edu.berkeley.cs.jqf.fuzz` | jqf-fuzz test dep | ✅ Already on classpath |
| `JQF` | `edu.berkeley.cs.jqf.fuzz` | jqf-fuzz test dep | ✅ Already on classpath |
| `SignalSource` | `dosguide.validate` | In workspace `src/test/java` | ✅ Already present |
| ASM (`ClassVisitor`, `MethodVisitor`, etc.) | `org.objectweb.asm` | Transitive dep of jqf-instrument | ✅ Available |

**Result: No unresolved symbols. No stubs required.**

##### 3.2 Stub Generation Rules

N/A — all required classes are resolved via the local vulnerable jars in `lib/` and declared Maven test dependencies.

##### 3.3 Stub Report

| Stub File | Required By | Reachable During Fuzzing |
|---|---|---|
| `src/main/java/dummy/Placeholder.java` | Maven requires at least one source file | No — inert placeholder |

No additional stubs needed. The vulnerable Netty classes come from the pre-built `lib/` jars. The JQF/JUnit/ASM classes come from Maven test-scope dependencies.

#### Step 4 — GuidedFuzzing Usage

The runner (`FuzzRunner`) will invoke:
```java
ClassLoader cl = Thread.currentThread().getContextClassLoader();
GuidedFuzzing.run("com.fuzzer.harness.SnappyFuzzTest", testMethod, cl, guidance, System.out);
```

CLI method selection via `args[0]` = target ID ("V1"), `args[1]` = duration in seconds (0 = infinite). The target ID maps to:
- `V1` → method `fuzzSnappyFrameDecoderDecode`, guidance `V1Guidance`

The runner will:
1. Parse CLI args for target selection and duration
2. Instantiate the appropriate Guidance
3. Call `GuidedFuzzing.run(...)` with the matching `@Fuzz` method name
4. Handle SIGINT for clean shutdown

#### Step 5 — Guidance Strategy Selection

| Target | Selected Strategy | Why Zest Fails (Mechanistic Explanation) | Why This Strategy Wins |
|---|---|---|---|
| V1 | **CGF + VDF** (Hybrid: Cost-Gradient + Vulnerability-Directed) | Zest uses coverage as its retention signal. The Snappy decode path has very few branches: `readPreamble()` decodes a varint (a tight loop over 1-4 bytes), then `ensureWritable(uncompressedLength)` executes one allocation call. Coverage is saturated within the first few inputs — a valid Snappy frame with any preamble value covers all reachable branches. Once coverage plateaus, Zest degenerates to random mutation with no directional signal, so it cannot distinguish a preamble claiming 64KB from one claiming 256MB — both cover identical branches. Zest's retained corpus becomes dominated by random inputs, not memory-maximizing ones, and the probability of stumbling onto multiple chunks with maximal preambles by pure chance within the timeout is negligible. | CGF hill-climbs the measured capacity growth of the `out` ByteBuf inside `Snappy.decode()` — a signal that correlates directly with the claimed uncompressed size in the preamble varint. VDF adds structure: the Guidance's Snappy frame encoder and chunk repetition operators ensure inputs are well-formed frames with multiple COMPRESSED_DATA chunks, steering mutation toward the attack structure (multiple chunks × maximal preamble). The combined signal-plus-structure approach ensures that every retained input either increases the per-chunk capacity claim or increases the number of chunks, directly climbing toward the ~1GB direct memory exhaustion threshold. |

**Zest baseline comparison (R18):**
- **Closest Zest config**: Default Zest with `fuzzSnappyFrameDecoderDecode(InputStream)`, byte-level mutations, coverage-guided retention.
- **Why Zest underperforms**: Zest's proxy signal is edge coverage. The vulnerability's amplification (preamble value → allocation size) is invisible to coverage because `readPreamble()` has the same branches for all varint values, and `ensureWritable()` has the same branches whether allocating 64KB or 256MB. Coverage cannot distinguish benign from pathological inputs.
- **Measurable metric where custom Guidance outperforms**: **Capacity growth per execution** — the custom Guidance is expected to maximize `out.capacity()` growth inside `Snappy.decode()` within orders of magnitude fewer iterations than Zest, because every retention decision directly rewards larger allocation claims, whereas Zest has no signal to prefer them.

#### Step 6 — Strategy-Specific Guidance Design

##### Measurement Plan

###### Signal: `capacityGrowth`

| Attribute | Value |
|---|---|
| **What is measured** | Total capacity growth of the `out` ByteBuf parameter across all invocations of `Snappy.decode(ByteBuf in, ByteBuf out)` during a single fuzz execution. For each decode call: `capacityAfter - capacityBefore` of the `out` buffer. Summed across all calls in one execution (one writeInbound may trigger multiple chunk decodes). |
| **Why this is the DoS mechanism** | `Snappy.decode()` calls `out.ensureWritable(uncompressedLength)` at line 287, where `uncompressedLength` is the attacker-controlled varint preamble (up to 268,435,455). This forces the `out` buffer to grow its capacity to hold the claimed uncompressed data. The capacity growth directly measures how much memory the decode forces the allocator to reserve. Multiple COMPRESSED_DATA chunks each allocate a fresh `out` buffer (allocated at SnappyFrameDecoder line 171), so the total capacity growth across all decode calls in one execution equals the total memory pressure. |
| **Code region** | `io.netty.handler.codec.compression.Snappy#decode(ByteBuf, ByteBuf)` — non-static, descriptor `(Lio/netty/buffer/ByteBuf;Lio/netty/buffer/ByteBuf;)V` |
| **Technique** | **Tier 1 — bytecode instrumentation** via custom Java agent (V1MeasureAgent + V1Transformer). ASM ClassVisitor instruments `Snappy.decode()` entry and exit: <br> **Entry**: read `out.capacity()` (slot 2, invoke `ByteBuf.capacity()`) and store baseline in a `ThreadLocal<long[]>` accumulator in `V1Signal`. <br> **Exit**: read `out.capacity()` again, compute `after - before`, add to the accumulator. |
| **Storage** | `ThreadLocal<long[]>` in `com.fuzzer.guidance.V1Signal`. Index 0 = accumulated capacity growth for current execution. |
| **Reset** | `V1Signal.reset()` called by `V1Guidance.getInput()` at the start of each execution — sets accumulator to 0. |
| **Read** | `V1Signal.getCapacityGrowth()` called by `V1Guidance.handleResult()` after each execution. The value is used for retention decisions and is returned by `V1Guidance.lastSignals()` as `{"capacityGrowth": <value>}`. |

###### Instrumentation Feasibility Check (R35)

| Item | Details |
|---|---|
| **Exact classes/methods** | `io.netty.handler.codec.compression.Snappy`, method `decode`, descriptor `(Lio/netty/buffer/ByteBuf;Lio/netty/buffer/ByteBuf;)V` |
| **Required JVM flags** | `-javaagent:target/v1-agent.jar` — No `--add-opens` needed because the agent instruments application code (Netty), not JDK internals |
| **Signal export** | `V1Signal` class on the application classpath (in `src/test/java`). Agent injects calls to `V1Signal.onDecodeEntry(ByteBuf out)` and `V1Signal.onDecodeExit(ByteBuf out)` at method entry/exit. `V1Signal` uses `ThreadLocal<long[]>` for thread-safe accumulation. |
| **Agent implementation plan** | **V1MeasureAgent** (Premain-Class): registers `V1Transformer` with `Instrumentation.addTransformer()`. **V1Transformer**: checks for class `io/netty/handler/codec/compression/Snappy`, instruments `decode` method by visiting method entry/exit with ASM. At entry: `ALOAD 2` (out param) → `INVOKESTATIC V1Signal.onDecodeEntry(Lio/netty/buffer/ByteBuf;)V`. Before each RETURN: `ALOAD 2` → `INVOKESTATIC V1Signal.onDecodeExit(Lio/netty/buffer/ByteBuf;)V`. Agent jar built post-`mvn package` via `build-agent.sh` script. |

##### Mutation Operators

The Guidance implements the following mutation operators inside `V1Guidance`:

1. **Byte-level mutations** (standard):
   - Single-byte random flip at random position
   - Single-byte random overwrite at random position
   - Insert a random byte at a random position
   - Delete a byte at a random position

2. **Repetition operator (R45a)**:
   - Identify 12-byte chunk boundaries within the input (after the 10-byte stream identifier, every 12 bytes is a COMPRESSED_DATA chunk: 1 type + 3 length + 4 checksum + 4 preamble varint).
   - Duplicate a randomly selected chunk region and repeat it k times (k chosen uniformly from 1 to `(maxInputSize - currentLength) / 12`).
   - Also: whole-input doubling — copy the entire input and append it.
   - This grows a single-chunk input (22 bytes) toward the target 58 bytes (4 chunks) within a few mutations.

3. **Dictionary of tokens from source (R45b)**:
   Extracted from the Snappy frame format code on the attack path:
   - `0xFF` — stream identifier chunk type (SnappyFrameDecoder line 219)
   - `0x00` — compressed data chunk type (SnappyFrameDecoder line 215)
   - `{0x06, 0x00, 0x00}` — stream identifier chunk length (3 bytes LE, value 6)
   - `{0x73, 0x4E, 0x61, 0x50, 0x70, 0x59}` — magic `sNaPpY` (SnappyFrameDecoder lines 112-117)
   - `{0x00, 0x00, 0x00, 0x00}` — zero checksum (4 bytes, SnappyFrameDecoder line 170)
   - `{0x08, 0x00, 0x00}` — chunk length 8 in LE (for minimal compressed chunk = 4 checksum + 4 preamble)
   - `{0x80}` — reserved skippable type (SnappyFrameDecoder line 221)
   - Varint preamble bytes: `{0x80}`, `{0xFF}`, `{0xFE, 0xFF, 0xFF, 0x7F}` — partial varint fragments that the `readPreamble()` loop processes (Snappy.java lines 363-379)
   
   Each token is inserted or overwritten at a random position during mutation. Tokens are single syntactic units from the source, not assembled payloads.

4. **Well-formed Snappy frame encoder (R45c)**:
   The Snappy framing format requires correct chunk type + 3-byte LE length + magic/data for the decoder to reach `Snappy.decode()`. Random bytes fail at the `mapChunkType` or length checks.
   
   The encoder mutates a **decoded representation** and re-encodes:
   - Representation: a list of chunks, each with `{type, payload_bytes}`.
   - Mutations on the decoded form: change a preamble varint value, add/remove a chunk, swap chunk order.
   - Encoding: for each chunk, emit `type_byte + 3-byte LE length + payload`. Always prefix with the stream identifier frame.
   - The checksum field is set to 0 (validateChecksums=false by default in SnappyFrameDecoder constructor).
   - The encoder ensures inputs pass format validation and reach `snappy.decode(in, uncompressed)` at line 183.

##### Retention Policy

**Primary signal**: `capacityGrowth` — retain inputs that maximize total capacity growth across all decode calls.

**Flat-signal handling (R46)**: When capacityGrowth is 0 (no Snappy.decode call reached), the secondary retention criterion is **input length growth**. Inputs are retained if they are longer than the current best zero-signal input. This encourages the search to build longer inputs that may eventually form a valid Snappy frame and reach the decode path. Combined with the dictionary tokens and encoder, this allows the Guidance to cross the "valid frame" threshold quickly.

**Retention rules**:
- Corpus is a set of saved inputs, each annotated with its `capacityGrowth` signal.
- A new input is retained if:
  1. Its `capacityGrowth` > the best `capacityGrowth` seen so far (strict improvement), OR
  2. Its `capacityGrowth` == best AND its length is different (diversity), OR
  3. `capacityGrowth` == 0 for all inputs so far AND this input is longer than the longest retained zero-signal input (growing toward `input_bytes = 58`)
- Parent selection for mutation: weighted by `capacityGrowth` (or length if all signals are 0).

**Input growth**: The repetition operator can double a 22-byte single-chunk input to 34 bytes (stream identifier + 2 chunks) in one step, and to 58 bytes (4 chunks) in 2-3 steps. The encoder can directly emit multi-chunk frames. Combined with the dictionary tokens (which include the stream identifier and chunk headers), the Guidance can generate inputs reaching 58 bytes well within the first minute.

**Stop/continue conditions**: Fuzzing runs indefinitely by default. Time-bounded via CLI arg (seconds). No signal threshold stops the search — the evaluation framework handles failure detection.

##### Prioritization Logic

Inputs in the corpus are prioritized by:
1. `capacityGrowth` (descending) — inputs causing larger allocations are mutated more often
2. Recency — recently saved inputs get a small bonus to explore new regions
3. Length diversity — maintain at least one short and one long input to enable both specialization and growth

#### Step 7-10 — Design Notes (Implementation Deferred to Block 3)

**Step 7**: V1Guidance implements `Guidance` and `SignalSource` directly. No delegation to existing guidances. Corpus stored in `out/V1/corpus/`. Logs stats every 1 second (total execs, best capacityGrowth, corpus size, execs/sec).

**Step 8**: Uses frozen `SnappyFuzzTest.fuzzSnappyFrameDecoderDecode(InputStream)` — no new fuzz tests needed.

**Step 9**: ReplayRunner reads saved corpus files and replays them through the same harness, printing metadata (input hex, size, signal values).

**Step 10**: Maven config is the existing pom.xml. Agent jar built via `build-agent.sh` post-package. Commands documented in Block 3.

---

#### Mandatory Self-Checklist

| Item | Status | Justification |
|---|---|---|
| JDK 17+ only | YES | pom.xml targets Java 17; no preview/incubator APIs |
| No hallucinated APIs | YES | All JQF, Netty, ASM APIs verified against source/javadoc |
| Guidance implements Guidance directly | YES | V1Guidance will implement `edu.berkeley.cs.jqf.fuzz.guidance.Guidance` + `dosguide.validate.SignalSource` |
| No existing guidance extended | YES | No Zest/PerfFuzz/other guidance extended or delegated |
| V* vulnerabilities identified | YES | V1 = Snappy preamble-driven allocation exhaustion |
| V* IDs are sequential (V1, V2, ...) | YES | Single target V1, sequential |
| Official vulnerability names applied | YES | CWE-770 (Allocation of Resources Without Limits or Throttling) |
| PkgRisk-* identified | YES | No additional package risks beyond V1 — Snappy is the only decompression/parsing code in scope |
| Every PkgRisk-* executed or justified | YES | No PkgRisks identified; the Snappy vulnerability is already V1 |
| Guidance targets V* and PkgRisk-* | YES | V1Guidance targets V1 exclusively |
| One fuzz method per V* or PkgRisk | YES | V1 → `fuzzSnappyFrameDecoderDecode` |
| CLI method selection supported | YES | FuzzRunner accepts target ID as CLI arg |
| Byte[] / InputStream input model used exclusively | YES | Harness uses InputStream; Guidance provides raw bytes |
| No junit-quickcheck Generators used | YES | No generators; raw bytes only |
| All mutation implemented inside Guidance | YES | Byte flips, repetition, dictionary, encoder — all in V1Guidance |
| Repetition, source dictionary, encoder operators implemented [R45] | YES | All three specified in measurement plan above |
| Retention progresses while signal is flat [R46] | YES | Secondary criterion: input length growth toward 58 bytes |
| Retention signals measured where resource is consumed [R47] | YES | Signal measured at Snappy#decode (the sink), not before it |
| Logging every 1 second | YES | V1Guidance will log stats every 1s |
| Guidance decides no failures and writes no failure files [R6] | YES | handleResult only updates retention; no failure decisions |
| Corrupted inputs saved with metadata | YES | Corpus entries saved with signal values and timestamps |
| Replay/feeder implemented | YES | ReplayRunner loads corpus files and replays |
| Infinite + time-bounded fuzzing supported | YES | Duration=0 → infinite; Duration>0 → time-bounded |
| src/main vs src/test separation correct | YES | All fuzzing infra in src/test/java; only dummy placeholder in src/main/java |
| Maven scopes consistent | YES | Netty=system, JQF/JUnit=test |
| No wildcard imports used for JQF / tracing | YES | All imports will be explicit |
| TraceEvent import verified if tracing used | YES | TraceEvent not used — custom agent uses ASM directly |

---

#### IMPORT AUDIT

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
SignalSource → dosguide.validate.SignalSource
Consumer<TraceEvent> → java.util.function.Consumer (generic; TraceEvent not directly imported by Guidance)
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
ClassVisitor → org.objectweb.asm.ClassVisitor
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
AdviceAdapter → org.objectweb.asm.commons.AdviceAdapter
Instrumentation → java.lang.instrument.Instrumentation
ClassFileTransformer → java.lang.instrument.ClassFileTransformer
```

All symbols verified as existing in their respective artifacts (JQF 2.1, ASM 9.x via jqf-instrument, JDK 17 java.lang.instrument).

---

BEGIN_GUIDANCE_PLAN_JSON
```json
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "capacityGrowth",
          "quantity": "total capacity growth of the out ByteBuf parameter across all Snappy.decode() invocations during one fuzz execution: sum of (out.capacity() after decode - out.capacity() before decode) for each call",
          "aggregation": "sum",
          "locations": ["Snappy#decode"],
          "technique": "bytecode",
          "storage": "ThreadLocal<long[]> in V1Signal (index 0 = accumulated capacity growth for current execution)",
          "reset": "V1Guidance.getInput() calls V1Signal.reset() which zeroes the accumulator before each execution",
          "read": "V1Guidance.handleResult() calls V1Signal.getCapacityGrowth() to retrieve the accumulated value; returned by V1Guidance.lastSignals() as {\"capacityGrowth\": <double>}"
        }
      ],
      "retention": "Retain inputs that maximize capacityGrowth (primary). When capacityGrowth is 0 for all inputs (signal is flat because no valid Snappy frame reached decode), retain inputs by length growth toward input_bytes=58 as secondary criterion, enabling the search to cross the valid-frame threshold. Parent selection weighted by capacityGrowth (or length if all signals are 0).",
      "retention_signals": ["capacityGrowth"],
      "mutation": [
        "Byte-level: single-byte random flip, single-byte overwrite, single-byte insert, single-byte delete at random positions",
        "Repetition: identify 12-byte chunk boundaries after the 10-byte stream identifier; duplicate a randomly selected chunk region k times (k from 1 to (maxInputSize - currentLength) / 12); also whole-input doubling. Grows single-chunk (22 bytes) to multi-chunk (58 bytes = 4 chunks) in 2-3 mutation steps.",
        "Dictionary tokens from source: 0xFF (stream identifier type, SnappyFrameDecoder:219), 0x00 (compressed data type, SnappyFrameDecoder:215), {0x06,0x00,0x00} (stream id length LE), {0x73,0x4E,0x61,0x50,0x70,0x59} (magic 'sNaPpY', SnappyFrameDecoder:112-117), {0x00,0x00,0x00,0x00} (zero checksum), {0x08,0x00,0x00} (chunk length 8 LE), 0x80 (reserved skippable type), varint fragments {0x80}, {0xFF}, {0xFE,0xFF,0xFF,0x7F} (Snappy.readPreamble lines 363-379). Each inserted/overwritten at random positions.",
        "Snappy frame encoder: mutate a decoded representation (list of chunks with type and payload bytes), then re-encode with correct chunk-type byte + 3-byte LE length + payload. Always prefix with stream identifier frame. Checksum set to 0 (validateChecksums=false default). Mutations on decoded form: change preamble varint value, add/remove a chunk, swap chunk order. Ensures inputs pass format checks and reach Snappy.decode() at SnappyFrameDecoder:183."
      ]
    }
  ]
}
```
END_GUIDANCE_PLAN_JSON

## Block 3

Let me verify the JQF Guidance interface before implementing:

```text
$ mvn dependency:resolve -DincludeScope=test 2>&1 | tail -5
$ find /root/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1 -name "*.jar" 2>/dev/null | head -5
$ find ~/.m2/repository/edu/berkeley/cs/jqf 2>/dev/null -name "*.jar" | head -10
$ jar tf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar | grep -E "Guidance|GuidedFuzzing|Result" | head -20
$ javap -p -c ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar 2>/dev/null || unzip -p ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class | javap -p -cp /dev/stdin edu.berkeley.cs.jqf.fuzz.guidance.Guidance 2>/dev/null  …
$ mkdir -p /tmp/jqf_inspect && cd /tmp/jqf_inspect && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-fuzz/2.1/jqf-fuzz-2.1.jar edu/berkeley/cs/jqf/fuzz/guidance/Guidance.class edu/berkeley/cs/jqf/fuzz/guidance/Result.class edu/berkeley/cs/jqf/fuzz/junit/GuidedFuzzing.class && javap -public edu.berkel …
$ cd /tmp/jqf_inspect && javap -public edu.berkeley.cs.jqf.fuzz.guidance.Result 2>&1
$ cd /tmp/jqf_inspect && javap -public edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1
```

Good. Now let me check TraceEvent and GuidanceException:

```text
$ cd /tmp/jqf_inspect && jar xf ~/.m2/repository/edu/berkeley/cs/jqf/jqf-instrument/2.1/jqf-instrument-2.1.jar edu/berkeley/cs/jqf/instrument/tracing/events/TraceEvent.class 2>&1 && javap -public edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent 2>&1
```

Good. Now let me also check if ASM AdviceAdapter exists in the jqf-instrument transitive deps:

```text
$ find ~/.m2/repository/org/ow2/asm -name "*.jar" | head -10
$ find ~/.m2/repository/org/ow2/asm/asm-commons -name "*.jar" | head -5
```

Let me re-read the Snappy.java source to verify the decode method structure for the agent:

```text
Read <source_root>/codec/src/main/java/io/netty/handler/codec/compression/Snappy.java
```

Now I have all the information I need. Let me implement all the Block 3 files. I'll start with the signal storage, then agent, guidance, runner, and scripts.

```text
Write <run_dir>/src/test/java/com/fuzzer/guidance/V1Signal.java
Write <run_dir>/src/test/java/com/fuzzer/agent/V1MeasureAgent.java
Write <run_dir>/src/test/java/com/fuzzer/agent/V1Transformer.java
Write <run_dir>/src/test/resources/META-INF/MANIFEST.MF
```

Now the main Guidance class:

```text
Write <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
```

Now the FuzzRunner:

```text
Write <run_dir>/src/test/java/com/fuzzer/runner/FuzzRunner.java
```

Now the ReplayRunner:

```text
Write <run_dir>/src/test/java/com/fuzzer/replay/ReplayRunner.java
```

Now let me write the build scripts:

```text
Write <run_dir>/build-agent.sh
Write <run_dir>/run.sh
$ chmod +x <run_dir>/run.sh <run_dir>/build-agent.sh
```

Now write the launch.json and guidance_plan.json:

```text
Write <run_dir>/analysis/launch.json
Write <run_dir>/analysis/guidance_plan.json
$ ls -la <run_dir>/analysis/guidance_plan.json 2>&1
Read <run_dir>/analysis/guidance_plan.json
```

Good, the guidance_plan.json already exists from Block 2. It's correct — no changes needed.

Now let me create validation inputs:

```text
$ mkdir -p <run_dir>/analysis/validation_inputs
$ cd <run_dir>/analysis/validation_inputs && python3 << 'PYEOF' …
```

Good. Now let me compile everything to verify correctness:

```text
$ cd <run_dir> && mvn package -DskipTests 2>&1 | tail -30
```

Build succeeds. Let me verify the compiled classes exist:

```text
$ find <run_dir>/target/test-classes -name "*.class" | sort
```

All classes compile. Now build the agent jar:

```text
$ bash build-agent.sh 2>&1
```

Let me verify the agent jar contents:

```text
$ jar tf <run_dir>/target/v1-agent.jar | grep -E "V1|MANIFEST" | head -10
$ unzip -p <run_dir>/target/v1-agent.jar META-INF/MANIFEST.MF
```

Agent jar is correctly built with the right Premain-Class. Let me also verify the ASM classes are bundled:

```text
$ jar tf <run_dir>/target/v1-agent.jar | grep "org/objectweb/asm" | wc -l
```

Good — 40 ASM classes bundled. Now let me verify the complete file tree:

```text
$ find <run_dir> -maxdepth 1 -type f | sort && echo "---" && find <run_dir>/src -type f | sort && echo "---" && find <run_dir>/analysis -type f | sort
```

Everything is in place. Now let me do a final verification — make sure the classpath_command in launch.json works:

```text
$ eval "$(cat analysis/launch.json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["classpath_command"])')" 2>&1 | head -5
```

Everything compiles and the agent builds correctly. Let me now verify one more aspect — that the Snappy class would indeed be loaded from our vulnerable lib jar (not some other source):

```text
$ jar tf <run_dir>/lib/netty-codec-4.1.68.Final-SNAPSHOT.jar | grep "Snappy.class" | head -5
```

Now let me do a final review of each file to make sure nothing was missed. Let me re-read the key files:

```text
Read <run_dir>/src/test/java/com/fuzzer/guidance/V1Guidance.java
```

Good. Let me verify one final thing — the launch.json is valid JSON:

```text
$ python3 -c "import json; json.load(open('<run_dir>/analysis/launch.json')); print('Valid JSON')"
```

Now let me provide the complete Block 3 output with all required sections:

---

#### Part A — Java Agent

##### Files emitted:

=== FILE: src/test/java/com/fuzzer/agent/V1MeasureAgent.java ===
```java
// Premain-Class that registers V1Transformer for Snappy.decode instrumentation.
// Measurement-only: observes execution, does not generate inputs.
```

=== FILE: src/test/java/com/fuzzer/agent/V1Transformer.java ===
```java
// ASM ClassFileTransformer targeting io.netty.handler.codec.compression.Snappy.
// Instruments decode(ByteBuf,ByteBuf):V with V1Signal.onDecodeEntry/onDecodeExit
// at method entry and before each RETURN instruction.
// Slot 2 = out parameter (ByteBuf) whose capacity() is measured.
```

=== FILE: src/test/java/com/fuzzer/guidance/V1Signal.java ===
```java
// ThreadLocal<long[]> signal storage.
// [0] = accumulated capacity growth, [1] = baseline capacity at decode entry.
// reset() zeroed by V1Guidance.getInput(), read by V1Guidance.handleResult().
```

=== FILE: src/test/resources/META-INF/MANIFEST.MF ===
```
Premain-Class: com.fuzzer.agent.V1MeasureAgent
```

=== FILE: build-agent.sh ===
```bash
### Builds target/v1-agent.jar from: V1MeasureAgent + V1Transformer + ASM core classes
```

##### Instrumentation details (R35, R36):
- **Class**: `io.netty.handler.codec.compression.Snappy`
- **Method**: `decode(ByteBuf, ByteBuf)V` — descriptor `(Lio/netty/buffer/ByteBuf;Lio/netty/buffer/ByteBuf;)V`
- **Mechanism category**: Allocation / Memory Blowup (R36 §6) + Integer / Arithmetic Blowups (R36 §7)
- **What is measured**: Capacity growth of the `out` ByteBuf = `out.capacity()` after − `out.capacity()` before, accumulated across all decode calls per execution
- **JVM flag**: `-javaagent:target/v1-agent.jar` — no `--add-opens` needed (instrumenting app code, not JDK)
- **Signal export**: ThreadLocal in `V1Signal` on the app classpath; agent injects INVOKESTATIC calls into transformed bytecode

#### Part B — Guidance

##### V1Guidance (CGF + VDF hybrid)

**Strategy justification table:**

| Target | Selected Strategy | Why Zest Fails | Why This Strategy Wins |
|---|---|---|---|
| V1 | CGF + VDF | Coverage saturates instantly: `readPreamble()` and `ensureWritable()` cover identical branches regardless of varint value (64KB vs 256MB). Once all code paths are seen, Zest retains inputs randomly with no directional signal toward larger allocations. | Directly hill-climbs `capacityGrowth` measured at `Snappy.decode()` by the custom agent. Every retained input has higher measured allocation, and the Snappy frame encoder + chunk repetition operators build valid multi-chunk frames. The signal is mechanism-aligned (measures the exact allocation at the vulnerability sink), not a proxy. |

**Zest baseline comparison (R18):**
- **Closest Zest config**: Default Zest with `fuzzSnappyFrameDecoderDecode(InputStream)`, coverage-guided retention
- **Why Zest underperforms**: Zest's signal is edge coverage. The amplification (varint value → allocation size) is invisible to coverage because readPreamble and ensureWritable have identical control flow for all values.
- **Measurable metric**: **Time to reach capacityGrowth > 1MB** — custom guidance expected to reach this within seconds (via varint hill-climbing), while Zest would need random luck to stumble on large varint values.

**Method-specific optimization (R19):** The Snappy frame encoder mutation is specific to `fuzzSnappyFrameDecoderDecode` — it knows the Snappy framing format (stream identifier, COMPRESSED_DATA chunks, 3-byte LE lengths, zero checksum). This is not generic to all memory blowup targets.

**Input model (R25, R31):** Raw bytes via InputStream. `getInput()` provides mutated byte arrays. The fuzz test receives InputStream and wraps bytes with `Unpooled.wrappedBuffer(data)`.

**Signal legality (R30):**
- (A) Derived from actual execution of Snappy.decode() via bytecode instrumentation ✓
- (B) Measured at the sink (Snappy#decode is the target register's sink) ✓
- (C) Consumed by handleResult() to affect retention decisions ✓

#### Part C — Runner + Replay

##### FuzzRunner
- `createGuidance(targetId, outputDir, maxDurationMs, log)` factory method (DoSGuide contract)
- CLI: `FuzzRunner V1 60` runs V1 target for 60 seconds
- Calls `GuidedFuzzing.run(testClass, testMethod, cl, guidance, System.out)`
- MAX_INPUT_SIZE read from `jqf.ei.MAX_INPUT_SIZE` system property (default 10240)

##### ReplayRunner
- Reads saved corpus files and replays through fresh `SnappyFrameDecoder` pipeline
- Prints hex dump, size, outcome (SUCCESS / DecompressionException / OOM)

##### run.sh
1. `mvn package -DskipTests -q` (compile)
2. `bash build-agent.sh` (build agent jar)
3. `java -Xmx1g -Xss1m -javaagent:target/v1-agent.jar -cp <classpath> com.fuzzer.runner.FuzzRunner V1 60`

##### Commands:
- **Fuzzing (60s)**: `./run.sh V1 60`
- **Infinite fuzzing**: `./run.sh V1 0`
- **Time-bounded**: `./run.sh V1 300`
- **Replay**: `java -cp <classpath> com.fuzzer.replay.ReplayRunner out/V1/corpus`

#### Part D — Validation contract

- `analysis/launch.json` — build commands, classpath, javaagent, guidance_factory, targets
- `analysis/guidance_plan.json` — signal "capacityGrowth" at Snappy#decode via bytecode
- `analysis/validation_inputs/` — 5 well-formed example inputs (stream-id only, small chunk, 256-byte chunk, two chunks, random bytes)

##### Class Origin Check (to be verified):
The Snappy class is loaded from `lib/netty-codec-4.1.68.Final-SNAPSHOT.jar` (system-scope dependency in pom.xml, NOT from Maven Central). This can be verified with:
```java
System.out.println(io.netty.handler.codec.compression.Snappy.class.getProtectionDomain().getCodeSource().getLocation());
```
Expected output: `.../lib/netty-codec-4.1.68.Final-SNAPSHOT.jar` or `.../target/deps/netty-codec-4.1.68.Final-SNAPSHOT.jar` (same file, copied by maven-dependency-plugin).

---

#### Mandatory Self-Checklist

| Item | Status | Justification |
|---|---|---|
| JDK 17+ only | YES | pom.xml targets Java 17; HexFormat (Java 17); no preview/incubator APIs |
| No hallucinated APIs | YES | All JQF (Guidance, GuidedFuzzing, Result, TraceEvent), ASM (ClassReader, ClassWriter, ClassVisitor, MethodVisitor, Opcodes), Netty APIs verified via javap/source |
| Guidance implements Guidance directly | YES | `V1Guidance implements Guidance, SignalSource` — no extends, no delegation |
| No existing guidance extended | YES | V1Guidance does not extend ZestGuidance, PerfFuzzGuidance, or any other |
| V* vulnerabilities identified | YES | V1 = Snappy preamble-driven allocation exhaustion (CWE-770) |
| V* IDs are sequential | YES | Single target V1, sequential from 1 |
| Official vulnerability names applied | YES | CWE-770 (Allocation Without Limits) |
| PkgRisk-* identified | YES | None beyond V1; Snappy is the sole decompression/parsing code in scope |
| Every PkgRisk-* executed or justified | YES | No PkgRisks identified |
| Guidance targets V* and PkgRisk-* | YES | V1Guidance targets V1 exclusively |
| One fuzz method per V* or PkgRisk | YES | V1 → fuzzSnappyFrameDecoderDecode (frozen harness) |
| CLI method selection supported | YES | FuzzRunner accepts targetId ("V1") as CLI arg |
| Byte[] / InputStream input model used exclusively | YES | getInput() returns ByteArrayInputStream of mutated bytes |
| No junit-quickcheck Generators used | YES | No generators; raw bytes only |
| All mutation implemented inside Guidance | YES | byteFlip, byteOverwrite, byteInsert, byteDelete, dictionaryInsert, chunkRepeat, snappyFrameEncode — all in V1Guidance |
| Repetition, source dictionary, encoder operators implemented [R45] | YES | chunkRepeat duplicates Snappy frame chunks; DICTIONARY has 9 tokens from source; snappyFrameEncode builds valid frames |
| Retention progresses while signal is flat [R46] | YES | When capacityGrowth==0 for all inputs, retains longer inputs (growing toward input_bytes=58) |
| Retention signals measured at the sink [R47] | YES | capacityGrowth measured inside Snappy#decode (the registered sink), not before it |
| Logging every 1 second | YES | handleResult() prints structured log line every 1000ms |
| Guidance decides no failures and writes no failure files [R6] | YES | handleResult() only updates corpus; no failure decisions or failure files |
| Corrupted inputs saved with metadata | YES | saveToCorpus() writes files with exec count, capacityGrowth, and length in filename |
| Replay/feeder implemented | YES | ReplayRunner reads files and replays through SnappyFrameDecoder |
| Infinite + time-bounded fuzzing supported | YES | Duration=0 → infinite; Duration>0 → time-bounded |
| src/main vs src/test separation correct | YES | Only dummy/Placeholder.java in src/main; all fuzzing code in src/test |
| Maven scopes consistent | YES | Netty=system (lib/), JQF/JUnit=test, ASM=transitive |
| No wildcard imports used for JQF / tracing | YES | All imports are explicit |
| TraceEvent import verified and audited if tracing is used | YES | TraceEvent imported in V1Guidance for generateCallBack() return type; verified via javap as `edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent` in jqf-instrument-2.1.jar |

---

#### IMPORT AUDIT

```
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz (in SnappyFuzzTest, frozen)
@RunWith → org.junit.runner.RunWith (in SnappyFuzzTest, frozen)
JQF → edu.berkeley.cs.jqf.fuzz.JQF (in SnappyFuzzTest, frozen)
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance (in V1Guidance)
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException (in V1Guidance)
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result (in V1Guidance)
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing (in FuzzRunner)
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent (in V1Guidance, for generateCallBack return type)
SignalSource → dosguide.validate.SignalSource (in V1Guidance)
Consumer → java.util.function.Consumer (in V1Guidance, for generateCallBack)
ClassReader → org.objectweb.asm.ClassReader (in V1Transformer)
ClassWriter → org.objectweb.asm.ClassWriter (in V1Transformer)
ClassVisitor → org.objectweb.asm.ClassVisitor (in V1Transformer)
MethodVisitor → org.objectweb.asm.MethodVisitor (in V1Transformer)
Opcodes → org.objectweb.asm.Opcodes (in V1Transformer)
Instrumentation → java.lang.instrument.Instrumentation (in V1MeasureAgent)
ClassFileTransformer → java.lang.instrument.ClassFileTransformer (in V1Transformer)
```
