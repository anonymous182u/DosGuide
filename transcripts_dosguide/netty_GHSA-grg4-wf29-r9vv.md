# netty_GHSA-grg4-wf29-r9vv

## Block 1

```text
$ cd <run_dir>; find . -type f | head -50; find . -name "*FuzzTest.java" -exec cat {} \;
Read <source_root>/codec/src/main/java/io/netty/handler/codec/compression/Bzip2Decoder.java
$ cd <run_dir>; cat analysis/run_config.json; grep -n systemPath pom.xml
$ cd <source_root>/codec/src/main/java/io/netty/handler/codec/compression; ls Bzip2*; cat Bzip2Constants.java | grep -v '^ \*\|^/\*\|^$'; grep -n "blockLength\|blockSize\|throw\|public int read\|private int decodeNextBWTByte\|repeat\|rle" Bzip2Blo …
Read <source_root>/codec/src/main/java/io/netty/handler/codec/compression/Bzip2BlockDecompressor.java
Grep <source_root>/codec/src/main/java/io/netty/handler/codec/compression/Bzip2Constants.java static final int
$ cd /tmp && python3 -I -c " …
$ mkdir -p analysis/scale/V1 && python3 -I -c " …
```

#### Bzip2Decoder DoS analysis (Block 1)

I found one DoS target, V1: a decompression bomb in `Bzip2Decoder` that leads to running out of memory. I worked out its scale from the source. I wrote the measurement series for DoSGuide but did not run anything; running Java is blocked in this block. The block-size estimate below is checked against Python's bzip2 compressor (libbzip2, the same format), but the memory growth inside Netty has not been measured yet.

##### Entry point and input model
The frozen `Bzip2DecoderFuzzTest` has two `@Fuzz` methods, `fuzzBzip2DecoderDecode(InputStream)` and `fuzzBzip2DecoderDecode2(InputStream)`. Both call `decodeAll(byte[])`, which builds an `EmbeddedChannel` containing a default `Bzip2Decoder` followed by a handler that releases each message. It then writes the whole input as a single ByteBuf, so one `decode()` call handles every block in it.

The input model is raw bytes (`InputStream` → `byte[]`). Only `DecompressionException` is declared, so any `OutOfMemoryError` or `StackOverflowError` counts as a failure.

##### 1.1 Code-level vulnerabilities

**V1: unbounded decompression with every block kept in memory**
- **How the input gets in:** a bzip2 stream, starting from `BZh` + a digit 1–9 for the block size.
- **How the growth happens:**
  - In `Bzip2Decoder.decode`, the `DECODE_HUFFMAN_DATA` case allocates `ctx.alloc().buffer(blockLength)` and calls `blockDecompressor.read()` until it returns −1, writing each byte with `writeByte`. It then calls `out.add(uncompressed)`, sets the state back to `INIT_BLOCK` and uses `break`, not `return`.
  - The `for(;;)` loop therefore decodes the next block in the same call. All blocks pile up in `out`, and `ByteToMessageDecoder` only passes them to the next handler after `decode()` returns.
  - There is no limit on the decompressed size, either per block or in total.
- **Where the amplification comes from:**
  - A block's run-length stage (`RUNA`/`RUNB`, which encode run lengths in binary) can fill all 900,000 BWT bytes of a block from a few bits.
  - The last decoding stage, run-length decoding in `read()`, then turns each 5 BWT bytes (4 identical bytes plus a count) into up to 259 output bytes.
  - So one block can produce about 900,000 / 5 × 259 ≈ 46.6 MB of output.
- **CRC behaviour:** the block CRC is checked only after the whole block has been decompressed. Blocks with a valid CRC are kept; the stream CRC is never reached before memory runs out.
- **Exhausted resource:** memory (heap and Netty's direct buffers, both capped at about 1 GB by `-Xmx1g`). What grows is the decompressed bytes held in `out`: about 46.6 MB per valid maximum-size block, plus a temporary second copy when a buffer grows.
- **Failure mode:** `out_of_memory`. This is either a heap `OutOfMemoryError` or Netty's `OutOfDirectMemoryError`, which is a subclass of it.
- **Scale:**
  - About 1 GB divided by 46.6 MB per block means roughly 21–22 retained blocks.
  - Compressing with Python's `bz2` gives about 32 bytes per maximum-size block, plus about 50 bytes of overhead (16 blocks fit in 561 bytes).
  - That puts the failing input at about 750 bytes, well under the 10,240-byte limit.
- **Classification:** CWE-409 (Improper Handling of Highly Compressed Data, "decompression bomb"), together with CWE-400 and CWE-770.

I rejected other candidates as non-DoS or bounded:
- The `bwtBlock` (≤ 900 KB) and `bwtMergedPointers` (≤ 3.6 MB) arrays are allocated per block and freed when the next block starts.
- The selectors array is capped at 18,002 entries.
- The Huffman table loops are capped at 6 tables of 258 symbols each.

##### 1.2 Official classification
- **V1:** CWE-409, plus CWE-400 / CWE-770 (GHSA-grg4-wf29-r9vv).

##### 1.3 Package-level risks
There are no DoS-relevant third-party dependencies on this path. The decoder uses only Netty's own ByteBuf allocator, channel pipeline and `Crc32`; there is no regex, JDK inflater or external parser. The memory sink is inside Netty itself (V1), so no PkgRisk targets are registered. Under R12 none are left to run, and the empty set is justified above.

##### Scale measurement
I wrote five inputs and `series.json` to `analysis/scale/V1/`. Each input is one bzip2 stream with k maximum-size blocks:

| File | Blocks (k) | Size |
|---|---|---|
| `blocks1.bin` | 1 | 80 B |
| `blocks2.bin` | 2 | 112 B |
| `blocks4.bin` | 4 | 176 B |
| `blocks8.bin` | 8 | 305 B |
| `blocks16.bin` | 16 | 561 B |

Because block boundaries don't fall exactly at a multiple of k, each file may hold one extra partial block. These files are only for measuring growth and must not be used as seeds.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Bzip2Decoder unbounded multi-block decompression bomb (all decoded blocks retained in out list within one decode call)",
      "entrypoint": "Bzip2DecoderFuzzTest.fuzzBzip2DecoderDecode(InputStream) → Bzip2DecoderFuzzTest.decodeAll(byte[]) → EmbeddedChannel.writeInbound(Object[]) → ByteToMessageDecoder.channelRead(ChannelHandlerContext, Object) → ByteToMessageDecoder.callDecode(ChannelHandlerContext, ByteBuf, List) → ByteToMessageDecoder.decodeRemovalReentryProtection(ChannelHandlerContext, ByteBuf, List) → Bzip2Decoder.decode(ChannelHandlerContext, ByteBuf, List) → Bzip2BlockDecompressor.read()",
      "source_path": "codec/src/main/java/io/netty/handler/codec/compression/Bzip2Decoder.java",
      "sink": "io.netty.handler.codec.compression.Bzip2Decoder#decode",
      "mechanism": "Each bzip2 block's RUNA/RUNB run-length stage fills up to 900k BWT bytes from a few bits; the final run-length stage in Bzip2BlockDecompressor.read() expands every 4-byte+count group to up to 259 bytes, written by writeByte into a per-block ByteBuf with no output size cap; after out.add() the decode loop breaks back to INIT_BLOCK and decodes the next block in the same call, so every CRC-valid block's output is held in the out list until decode() returns",
      "resource": "heap/direct memory: retained decompressed bytes in the out list, about 46.6 MB per valid maximum-size block (plus a temporary copy when the buffer grows)",
      "failure_mode": "out_of_memory",
      "scale": "about 21-22 retained maximum-size blocks (about 46.6 MB each) exhaust the 1 GB heap/direct-memory limit; about 32 compressed bytes per block plus about 50 bytes of stream overhead, so about 750 bytes",
      "input_bytes": 750,
      "cwe": "CWE-409"
    }
  ]
}
END_TARGET_REGISTER_JSON

## CheckPath repair 1

```text
Grep <source_root>/transport/src/main/java/io/netty/channel public final ChannelPipeline fireChannelRead|static void invokeChannelRead|private void invokeChannelRead|channelRead\(ChannelHandlerContext ctx, Object msg\)
Read <source_root>/transport/src/main/java/io/netty/channel/AbstractChannelHandlerContext.java
Read <source_root>/transport/src/main/java/io/netty/channel/DefaultChannelPipeline.java
```

I fixed hop 3 → hop 4 by spelling out how `EmbeddedChannel.writeInbound` reaches the decoder. It goes into `DefaultChannelPipeline.fireChannelRead` (line 918). That calls the static `AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext, Object)` on the head context, then the instance `invokeChannelRead(Object)` (line 379), which calls the handler's `channelRead`. For the head context that is `HeadContext.channelRead`, which forwards with `ctx.fireChannelRead(msg)` (via `findContextInbound`). The same two `invokeChannelRead` steps then reach `ByteToMessageDecoder.channelRead`.

The other hops are unchanged. The mechanism, resource, failure mode and scale are also unchanged, since nothing on this path changes them.

BEGIN_TARGET_REGISTER_JSON
{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "Bzip2Decoder unbounded multi-block decompression bomb (all decoded blocks retained in out list within one decode call)",
      "entrypoint": "Bzip2DecoderFuzzTest.fuzzBzip2DecoderDecode(InputStream) → Bzip2DecoderFuzzTest.decodeAll(byte[]) → EmbeddedChannel.writeInbound(Object[]) → DefaultChannelPipeline.fireChannelRead(Object) → AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext, Object) → AbstractChannelHandlerContext.invokeChannelRead(Object) → HeadContext.channelRead(ChannelHandlerContext, Object) → AbstractChannelHandlerContext.fireChannelRead(Object) → AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext, Object) → AbstractChannelHandlerContext.invokeChannelRead(Object) → ByteToMessageDecoder.channelRead(ChannelHandlerContext, Object) → ByteToMessageDecoder.callDecode(ChannelHandlerContext, ByteBuf, List) → ByteToMessageDecoder.decodeRemovalReentryProtection(ChannelHandlerContext, ByteBuf, List) → Bzip2Decoder.decode(ChannelHandlerContext, ByteBuf, List) → Bzip2BlockDecompressor.read()",
      "source_path": "codec/src/main/java/io/netty/handler/codec/compression/Bzip2Decoder.java",
      "sink": "io.netty.handler.codec.compression.Bzip2Decoder#decode",
      "mechanism": "Each bzip2 block's RUNA/RUNB run-length stage fills up to 900k BWT bytes from a few bits; the final run-length stage in Bzip2BlockDecompressor.read() expands every 4-byte+count group to up to 259 bytes, written by writeByte into a per-block ByteBuf with no output size cap; after out.add() the decode loop breaks back to INIT_BLOCK and decodes the next block in the same call, so every CRC-valid block's output is held in the out list until decode() returns",
      "resource": "heap/direct memory: retained decompressed bytes in the out list, about 46.6 MB per valid maximum-size block (plus a temporary copy when the buffer grows)",
      "failure_mode": "out_of_memory",
      "scale": "about 21-22 retained maximum-size blocks (about 46.6 MB each) exhaust the 1 GB heap/direct-memory limit; about 32 compressed bytes per block plus about 50 bytes of stream overhead, so about 750 bytes",
      "input_bytes": 750,
      "cwe": "CWE-409"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

The measurement didn't give a cost per block. All five inputs hit the 2,000 ms time cap, including the 80-byte one, which holds only one or two full blocks. So I can only bound the CPU cost: at least about 1 s per maximum-size block (about 46.6 MB of output), and possibly around 2 s per block if the smallest input is taken as a single block. Allocation and peak heap were not reported for any input.

What this changes:
- **CPU grows faster than expected.** Decoding is per byte: a `writeByte` call and a CRC update for every output byte. At 1–2 s per block, the 20,000 ms per-execution limit is reached after about 10–20 retained blocks. That is roughly 370–690 bytes of input, possibly before memory runs out.
- **The memory estimate is unchanged.** It still comes from the source: about 21–22 blocks fill 1 GB, which takes about 750 bytes in the measured encoding (about 32 bytes per block plus about 50 bytes of stream overhead).
- **Which failure comes first is unknown.** At 1 s per block, memory runs out at about 22 s, just past the time limit. At 2 s per block, the time limit is hit first.

I kept `input_bytes` at 750, because by then the input passes both the memory threshold and the upper end of the timeout estimate. Both are within the 10,240-byte limit. The measured encoding is already about as dense as bzip2 allows. A hand-built stream with minimal Huffman tables might save a few bytes per block, but would not change the scale much.

BEGIN_SCALE_REVISION_JSON
{"V1": {"scale": "Measured: all five inputs (1 to 16 maximum-size blocks, 80 to 561 bytes) hit the 2000 ms probe time cap. Even the smallest input, with one or two full blocks (about 46.6 MB of decoded output each), runs longer than 2 s, so the CPU cost is at least about 1 s per block (writeByte plus a CRC update per output byte); allocation and peak heap were not reported. Extrapolation: retained output grows about 46.6 MB per CRC-valid block, so about 21-22 blocks exhaust the 1 GB heap/direct-memory limit (out_of_memory). At 1-2 s per block, 10-20 blocks already pass the 20000 ms limit, so a timeout may come before the out-of-memory error; which comes first was not determined. In the measured libbzip2 encoding (about 32 compressed bytes per block plus about 50 bytes of overhead), 22 blocks take about 750 bytes; the timeout range is about 370-690 bytes. This is already close to the densest encoding; a hand-built stream with minimal Huffman tables could save only a few bytes per block.", "input_bytes": 750}}
END_SCALE_REVISION_JSON

## Block 2

```text
$ cd <run_dir>; cat pom.xml; cat src/test/java/dosguide/validate/SignalSource.java
Read <run_dir>/pom.xml
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
$ cd <run_dir>; mvn -q -DskipTests package 2>&1 | tail -20; ls target/dependency | head -40; unzip -l lib/netty-codec-4.1.68.Final-SNAPSHOT.jar | grep -i bzip2 | head -20
Grep <source_root>/codec/src/main/java/io/netty/handler/codec/compression ^\s*(public |protected |private |static |final )*[\w<>\[\]]+ \w+\(.*\)\s*\{|^\s*(public )?(final )?class|Bzip2\w+\(.*\) \{
Grep <source_root>/buffer/src/main/java/io/netty/buffer/AbstractByteBuf.java writeByte|ensureWritable|calculateNewCapacity|class .*ByteBuf
$ cd <run_dir>; mkdir -p src/test/java/fuzzing/agent src/test/java/fuzzing/v1 out/V1/corpus; ls -R src out | head; grep -c "" lib/*.jar >/dev/null; unzip -l lib/netty-codec-4.1.68.Final-SNAPSHOT.jar | grep -c class
```

### Block 2: Netty `Bzip2Decoder` fuzzing setup (target V1): build, strategy and measurement plan

The workspace builds with the provided `pom.xml` unchanged: `mvn -q -DskipTests package` succeeded and reported no errors. All Netty classes come from the five local jars in `lib/`, built from SOURCE_ROOT and attached as system dependencies; no Netty coordinates are pulled from Maven Central. JQF 2.1 and junit-quickcheck 1.0 are on the test scope. ASM 9.8 is already on the test classpath through `jqf-instrument`, so the custom agent needs no new dependency. Nothing has been run yet: running Java is blocked here, so the class-origin check comes in Block 3.

The plan below is designed, not tested. The main open risk is how long Netty's `Bzip2Encoder` takes on very long runs. I estimate about 0.5 s per full block (about 46.6 MB of plaintext), so roughly 10 s to encode a 22-block input. That makes the search near the failure slow, but it should still find it.

#### Step 2: Maven layout and scope
- **`src/main/java`:** empty. No production code or stubs are needed.
- **`src/test/java`:** all fuzzing code. The frozen harness `fuzzing/Bzip2DecoderFuzzTest.java` and `dosguide/validate/SignalSource.java` are already there. Block 3 will add:
  - `fuzzing/agent/V1MeasureAgent.java` and `fuzzing/agent/V1Transformer.java` (the measurement agent)
  - `fuzzing/v1/V1Counters.java`, `fuzzing/v1/V1Guidance.java`, `fuzzing/v1/V1Bzip2Codec.java` (counters, guidance, encoder helper)
  - `fuzzing/FuzzRunner.java`, `fuzzing/ReproV1.java`, `fuzzing/ReplayV1.java`
- **Output:** each target gets its own corpus directory, `out/V1/corpus/` (created).
- **Scopes:** the Netty jars are `system` scope with a `systemPath` under `lib/`. Everything for fuzzing is `test` scope.
- **Agent jar:** built in Block 3 with the `jar` tool from `target/test-classes`. Its manifest sets `Premain-Class: fuzzing.agent.V1MeasureAgent` and adds `target/dependency/asm-9.8.jar` to `Class-Path`.

#### Step 3: Compilation closure
**3.1 Missing-symbol audit**

| Symbol | Kind | Resolution |
|---|---|---|
| `io.netty.handler.codec.compression.*` (`Bzip2Decoder`, `Bzip2Encoder`, `DecompressionException`) | internal | `lib/netty-codec` jar (212 classes, all `Bzip2*` present) |
| `io.netty.buffer.*` | internal | `lib/netty-buffer` jar |
| `io.netty.channel.*`, `io.netty.channel.embedded.EmbeddedChannel` | internal | `lib/netty-transport` jar |
| `io.netty.util.*` | internal | `lib/netty-common` jar |
| `io.netty.resolver.*` | internal | `lib/netty-resolver` jar |
| `org.objectweb.asm.*` | external (A) | transitive through `jqf-instrument` 2.1 (`asm-9.8`) |
| JQF / JUnit | external (A) | declared in `pom.xml` |

There are no unresolved internal types.

**3.2 / 3.3 Stub report:** no stub files. None are needed, so none are reachable during fuzzing.

#### Step 4: GuidedFuzzing usage
`FuzzRunner <method> [--duration=SECONDS]` (default: runs forever) will build `new V1Guidance(...)` and call:
`GuidedFuzzing.run("fuzzing.Bzip2DecoderFuzzTest", method, Thread.currentThread().getContextClassLoader(), guidance, System.out)`

Methods are selected on the command line. V1 is driven through `fuzzBzip2DecoderDecode`, the register's entry point. `fuzzBzip2DecoderDecode2` makes the same calls and gets its own `out/V1-decode2/corpus` if it is selected.

**Input model:** the harness takes an `InputStream`, so `V1Guidance.getInput()` hands over the raw bytes of the bzip2 stream. There are no generators.

#### Step 5: Strategy selection

| Target | Selected strategy | Why Zest fails (mechanism) | Why this strategy wins |
|---|---|---|---|
| V1 | Hybrid: vulnerability-directed + cost-gradient + shape-aware encoding | A block's output is only kept if its 32-bit CRC matches. Random byte mutations break the CRC and the Huffman and selector bit fields, so mutated inputs stop at the first bad block. One small valid block already covers every branch of `decode()` and `read()`, so coverage stops growing while the amount of kept output (the actual cause of OOM) is never measured. PerfFuzz climbs per-edge hit counts, which is generic cost; it stays stuck inside one block because a mutation that adds a block invalidates the CRC. Both fail because they follow stand-in signals rather than the mechanism. | The agent measures, inside the decoder, the bytes produced by `Bzip2BlockDecompressor#read()` and the bytes of blocks that passed `checkCRC()` (the ones `decode()` keeps in `out`). Mutation works on the decoded content and re-encodes it with Netty's own `Bzip2Encoder`, so every candidate has valid CRCs and adds kept blocks. |

**Closest Zest configuration:** `mvn jqf:fuzz -Dclass=fuzzing.Bzip2DecoderFuzzTest -Dmethod=fuzzBzip2DecoderDecode` (ZestGuidance, same JVM limits).

**Metrics where V1Guidance should beat Zest:**
- time to the first `OutOfMemoryError` or timeout;
- the largest `retainedBytes` reached within 10 minutes;
- the best amplification ratio (output bytes per input byte, both measured).

#### Step 6: Measurement plan (Tier 1, custom ASM agent `V1MeasureAgent`)
The agent's `premain` registers `V1Transformer`. It transforms only the internal class names `io/netty/handler/codec/compression/Bzip2BlockDecompressor` and `io/netty/handler/codec/compression/Bzip2Decoder`. It uses `ClassWriter.COMPUTE_MAXS`: the inserted code is just `DUP` + `INVOKESTATIC` with no branches, so no stack frames need recomputing. No `--add-opens` is needed because these are application classes. Launch with `-Xmx1g -Xss1m -javaagent:target/v1-agent.jar`.

The counters are static `long` fields in `fuzzing.v1.V1Counters`, loaded once by the app class loader. `EmbeddedChannel` runs on the fuzzing thread, so the agent and the guidance use the same thread. `V1Guidance.getInput()` resets the counters before each run, and `V1Guidance.handleResult()` reads them; `lastSignals()` returns that run's values.

| Signal | Code that produces it | Why it is causal | Storage → read |
|---|---|---|---|
| `decodedBytes` | each `IRETURN` in `Bzip2BlockDecompressor#read()`: `DUP; INVOKESTATIC V1Counters.onRead(I)V` counts returned values ≥ 0, also into the current block's byte count | each such byte is one `uncompressed.writeByte` in `Bzip2Decoder#decode`; this is the output-size amplification itself | `V1Counters.decodedBytes` → `handleResult` |
| `retainedBytes` (primary) | normal return of `Bzip2BlockDecompressor#checkCRC()` → `V1Counters.onBlockAccepted()`, which adds the current block's bytes and resets the per-block count | `decode()` calls `out.add(uncompressed)` right after `checkCRC()` succeeds and keeps looping; the sum is the memory held in `out`, which is what runs out | `V1Counters.retainedBytes`, `V1Counters.validBlocks` → `handleResult` |
| `bwtBytes` (secondary, for flat-signal progress) | return of `Bzip2BlockDecompressor#blockLength()`, called once per block in `decode()` before the output buffer is allocated | shows a block reached the `DECODE_HUFFMAN_DATA` state of the sink even if its CRC later fails | `V1Counters.bwtBytes`, `V1Counters.blocksReached` → `handleResult` |

All three signals are measured inside `Bzip2Decoder#decode` or the decompressor code it runs, as required by R47. None is computed from the input.

**Mutation operators (inside V1Guidance):**
- **Decoded content and encoder (R45c):** each corpus entry stores a genome next to its bytes. The genome is a block-size digit (1–9) plus a list of (byte value, run length) records describing the plaintext. Operators on the genome:
  - change a record's byte or length (±1, ×2, ÷2, random value);
  - insert, delete or swap records;
  - repeat a slice of records k times, or double the whole list (R45a);
  - multiply all run lengths;
  - splice with another corpus entry.

  The plaintext is streamed in 1 MB chunks through `EmbeddedChannel(new Bzip2Encoder(digit))`, and the output is read back, so block and stream CRCs are always valid. Encoded results are cached by genome hash, and each encode has a time budget.
- **Byte level on the encoded input:** bit and byte flips, random insertions and deletions.
- **Byte-level repetition:** a random chunk repeated k times, up to `jqf.ei.MAX_INPUT_SIZE`, including doubling the whole input. This lets inputs reach 750 bytes or more within seconds.
- **Dictionary of source literals (R45b):** inserted or overwritten at random positions:
  - `"BZh"` (`MAGIC_NUMBER`) and the block-size digits `'1'`–`'9'`;
  - the 48-bit block magic `0x314159`/`0x265359`;
  - the end-of-stream magic `0x177245`/`0x385090`.
- **Operator mix:** about 70% genome + encoder, about 30% byte level.
- **Seeds:** short genomes of random records (plaintext under 100 bytes, random digit). They contain no concrete triggering values (R23).

**Retention:**
1. Keep the input if it sets a new maximum `retainedBytes`, or a new maximum of `retainedBytes` per input byte.
2. Otherwise keep it if it reaches a new `(blocksReached, validBlocks)` pair, or a new maximum of `decodedBytes` or `bwtBytes`.
3. Flat-signal fallback (R46): when every signal is 0, keep inputs that set a new maximum length (growing toward `input_bytes`, 750) or that reach `blocksReached > 0` for the first time.

**Prioritization:**
- Parents are chosen in proportion to the rank of their `retainedBytes`.
- Entries are boosted when they have high `validBlocks` (more kept blocks is the method-specific mechanism) or a high output-per-input-byte ratio.
- Entries with `blocksReached = 0` are rarely picked once any valid block exists.

**R19, method-specific rule:** reward kept blocks per `decode()` call (`validBlocks`), a quantity that only exists because `Bzip2Decoder#decode` re-enters `INIT_BLOCK` within one call. The genome also carries the block-size digit, which sets `blockSize * 100000`.

**Run control and logging:**
- Runs forever by default; `--duration` or `-Dv1.duration` bounds the run.
- One JSON line per second: execs, corpus size, best `retainedBytes`, `validBlocks`, `decodedBytes`, maximum input length, encoder time.
- The guidance never declares a failure and writes only `out/V1/corpus/*.bin` plus `*.json` metadata files (R6). Failures are recorded by the evaluation.
- Block 3 adds `ReproV1` (one input file through the harness) and `ReplayV1` (reads a metadata JSON, loads its input, replays it and prints the metadata and the exception).

#### IMPORT AUDIT
```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz            (harness, frozen)
@RunWith → org.junit.runner.RunWith              (harness, frozen)
JQF → edu.berkeley.cs.jqf.fuzz.JQF               (harness, frozen)
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent  (required by Guidance.generateCallBack signature; no JQF tracing used for measurement)
ClassReader/ClassWriter/ClassVisitor/MethodVisitor/Opcodes → org.objectweb.asm.* (explicit imports, asm-9.8)
Instrumentation/ClassFileTransformer → java.lang.instrument.*
SignalSource → dosguide.validate.SignalSource
```

#### Self-checklist
- [x] **JDK 17+ only:** YES, the compiler targets 17.
- [x] **No hallucinated APIs:** YES, the Netty and ASM APIs were checked in the source and jars.
- [x] **Guidance implements `Guidance` directly:** YES, `V1Guidance implements Guidance, SignalSource`.
- [x] **No existing guidance extended:** YES.
- [x] **V* vulnerabilities identified:** YES, V1.
- [x] **V* IDs sequential (R42):** YES.
- [x] **Official names applied:** YES, CWE-409.
- [x] **PkgRisk-* identified:** YES, none exist; justified in Block 1.
- [x] **Every PkgRisk executed or justified:** YES, the empty set was justified.
- [x] **Guidance targets the register:** YES, V1 only.
- [x] **One fuzz method per target:** YES, `fuzzBzip2DecoderDecode` for V1.
- [x] **CLI method selection:** YES, `FuzzRunner <method>`.
- [x] **Byte[]/InputStream input model only:** YES.
- [x] **No junit-quickcheck Generators:** YES.
- [x] **All mutation inside the Guidance:** YES.
- [x] **Repetition, source dictionary and encoder (R45):** YES, using Netty's `Bzip2Encoder`.
- [x] **Flat-signal progress; `input_bytes` reachable within a minute (R46):** YES, through byte-level repetition and length-growth retention.
- [x] **Signals measured at the sink (R47):** YES, in `read()`/`checkCRC()`/`blockLength()` inside `decode()`.
- [x] **Logging every second:** YES.
- [x] **Guidance decides no failures and writes no failure files (R6):** YES.
- [x] **Inputs saved with metadata:** YES, corpus entries plus JSON metadata.
- [x] **Replay/feeder:** YES, `ReplayV1` (Block 3).
- [x] **Infinite and time-bounded runs:** YES.
- [x] **`src/main` vs `src/test` separation:** YES.
- [x] **Maven scopes consistent:** YES.
- [x] **No wildcard JQF imports:** YES.
- [x] **TraceEvent import verified:** YES.

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "retainedBytes",
          "quantity": "decompressed bytes of blocks whose CRC check passed; Bzip2Decoder#decode keeps these in the out list within one decode() call",
          "aggregation": "sum",
          "locations": ["io.netty.handler.codec.compression.Bzip2BlockDecompressor#checkCRC", "io.netty.handler.codec.compression.Bzip2BlockDecompressor#read"],
          "technique": "bytecode",
          "storage": "static long fields retainedBytes/validBlocks/currentBlockBytes in fuzzing.v1.V1Counters, updated by V1Transformer-inserted calls",
          "reset": "V1Guidance.getInput() calls V1Counters.reset() before each execution",
          "read": "V1Guidance.handleResult()"
        },
        {
          "name": "decodedBytes",
          "quantity": "number of decoded bytes (return value >= 0) produced by Bzip2BlockDecompressor#read(), i.e. writeByte calls on the output buffer",
          "aggregation": "count",
          "locations": ["io.netty.handler.codec.compression.Bzip2BlockDecompressor#read"],
          "technique": "bytecode",
          "storage": "static long decodedBytes in fuzzing.v1.V1Counters",
          "reset": "V1Guidance.getInput() calls V1Counters.reset()",
          "read": "V1Guidance.handleResult()"
        },
        {
          "name": "bwtBytes",
          "quantity": "sum of BWT block lengths returned by Bzip2BlockDecompressor#blockLength() (blocks that reached DECODE_HUFFMAN_DATA), plus the blocksReached count",
          "aggregation": "sum",
          "locations": ["io.netty.handler.codec.compression.Bzip2BlockDecompressor#blockLength"],
          "technique": "bytecode",
          "storage": "static long bwtBytes/blocksReached in fuzzing.v1.V1Counters",
          "reset": "V1Guidance.getInput() calls V1Counters.reset()",
          "read": "V1Guidance.handleResult()"
        }
      ],
      "retention": "Keep the input if it sets a new maximum retainedBytes or retainedBytes per input byte. Otherwise keep it if it reaches a new (blocksReached, validBlocks) pair or a new maximum decodedBytes/bwtBytes. While all signals are 0, keep inputs that set a new maximum length (growing toward input_bytes = 750) or that first reach blocksReached > 0. Parents are chosen in proportion to retainedBytes rank, with boosts for high validBlocks (kept blocks per decode() call, specific to the Bzip2Decoder INIT_BLOCK re-entry loop) and high measured output/input ratio.",
      "retention_signals": ["retainedBytes", "decodedBytes", "bwtBytes"],
      "mutation": [
        "genome (block-size digit + list of (byte, runLength) plaintext records) re-encoded with Netty's own io.netty.handler.codec.compression.Bzip2Encoder through an EmbeddedChannel, so block and stream CRCs are always valid",
        "genome record mutations: change byte or run length (+-1, x2, /2, random), insert, delete, swap records, change the block-size digit",
        "decoded-level repetition: repeat a slice of records k times, double the whole record list, multiply all run lengths",
        "splice genomes of two corpus entries",
        "byte-level on encoded bytes: bit and byte flips, random insertions and deletions",
        "byte-level repetition: repeat a random chunk k times up to jqf.ei.MAX_INPUT_SIZE, including doubling the whole input",
        "dictionary tokens from Bzip2Decoder/Bzip2Constants inserted or overwritten: 'BZh' (MAGIC_NUMBER), block-size digits '1'-'9', block magic 0x314159 0x265359, end-of-stream magic 0x177245 0x385090"
      ]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

```text
$ cd <run_dir>; javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance edu.berkeley.cs.jqf.fuzz.guidance.Result; javap -cp target/dependency/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing …
Read <source_root>/codec/src/main/java/io/netty/handler/codec/compression/Bzip2Encoder.java
```

I'll now write the agent, counters, guidance, runner, replay and build files.

```text
Write <run_dir>/src/test/java/fuzzing/v1/V1Counters.java
Write <run_dir>/src/test/java/fuzzing/agent/V1MeasureAgent.java
Write <run_dir>/src/test/java/fuzzing/agent/V1Transformer.java
Write <run_dir>/agent/MANIFEST.MF
```

Next, the guidance class.

```text
Write <run_dir>/src/test/java/fuzzing/v1/V1Guidance.java
Write <run_dir>/src/test/java/fuzzing/FuzzRunner.java
Write <run_dir>/src/test/java/fuzzing/ReproV1.java
Write <run_dir>/src/test/java/fuzzing/ReplayV1.java
Write <run_dir>/src/test/java/fuzzing/ClassOriginCheck.java
Edit <run_dir>/src/test/java/fuzzing/v1/V1Guidance.java
Write <run_dir>/run.sh
Write <run_dir>/analysis/launch.json
$ cd <run_dir>; chmod +x run.sh; mvn -q -DskipTests package 2>&1 | tail -30; jar cfm target/v1-agent.jar agent/MANIFEST.MF -C target/test-classes fuzzing/agent -C target/test-classes fuzzing/v1/V1Counters.class && unzip -l target/v1-ag …
$ cd <run_dir>; chmod +x run.sh; mvn -q -DskipTests package 2>&1 | tail -30
$ cd <run_dir>/target; jar cfm v1-agent.jar ../agent/MANIFEST.MF -C test-classes fuzzing/agent -C test-classes fuzzing/v1/V1Counters.class; unzip -l v1-agent.jar | tail -8; ls classes 2>&1 | head -3
$ cd <run_dir> && mkdir -p analysis/validation_inputs && python3 -I -c " …
```

### Block 3: V1 agent, guidance and runner written; compiled but not run

Everything for target V1 is written and compiles with `mvn -q -DskipTests package` (no errors). The agent jar `target/v1-agent.jar` builds with the planned manifest. Nothing was run: Java execution is blocked here. That means the agent rewriting the class, the signal values and the 60 s input-growth check are all untested until DoSGuide runs them. The 1 s log lines and the `[V1Agent] instrumented 3 methods` message will confirm the first two.

#### Files written
| File | Purpose |
|---|---|
| `src/test/java/fuzzing/agent/V1MeasureAgent.java` | The agent's `premain`; registers the transformer |
| `src/test/java/fuzzing/agent/V1Transformer.java` | ASM transformer for `Bzip2BlockDecompressor` |
| `agent/MANIFEST.MF` | `Premain-Class: fuzzing.agent.V1MeasureAgent`, `Class-Path: dependency/asm-9.8.jar` |
| `src/test/java/fuzzing/v1/V1Counters.java` | Static counters written by the instrumented code |
| `src/test/java/fuzzing/v1/V1Guidance.java` | `implements Guidance, SignalSource` |
| `src/test/java/fuzzing/FuzzRunner.java` | CLI runner; `createGuidance(String, File, long, PrintStream)` |
| `src/test/java/fuzzing/ReproV1.java` | Runs one input through the harness |
| `src/test/java/fuzzing/ReplayV1.java` | Replays inputs from corpus metadata |
| `src/test/java/fuzzing/ClassOriginCheck.java` | Prints where the Netty classes load from |
| `run.sh` | Build, agent jar, origin check, fuzz run (executable) |
| `analysis/launch.json` | Build and run description for DoSGuide |
| `analysis/validation_inputs/ex0..2.bz2` | Three small ordinary bzip2 streams (59–425 bytes), not failure inputs |

The frozen `Bzip2DecoderFuzzTest.java` and `pom.xml` are untouched. There are no stubs and no copied Netty source.

#### Part A: agent
The agent rewrites only `io/netty/handler/codec/compression/Bzip2BlockDecompressor`, adding a counter call before every `IRETURN`:

| Method | Inserted code | Counter effect |
|---|---|---|
| `read()I` | `DUP; INVOKESTATIC V1Counters.onRead(I)V` | counts each returned value ≥ 0 into `decodedBytes` and the current block's byte count |
| `blockLength()I` | `DUP; INVOKESTATIC V1Counters.onBlockLength(I)V` | adds to `bwtBytes` and `blocksReached`, starts a new block |
| `checkCRC()I` | `INVOKESTATIC V1Counters.onBlockAccepted()V` | adds the block's bytes to `retainedBytes` and increments `validBlocks` |

- **Why these points:** `checkCRC()` returning normally is exactly when `Bzip2Decoder#decode` calls `out.add(uncompressed)`. So `retainedBytes` is the memory held in the `out` list.
- **Frames:** the inserted code has no branches, so `COMPUTE_MAXS` is enough.
- **JVM flags:** only `-javaagent:target/v1-agent.jar`; no `--add-opens` needed.
- **Signal path:**
  - Counters are static fields in `fuzzing.v1.V1Counters`, which the agent jar and the test classes share on the app class loader.
  - `getInput()` resets them after encoding and right before the execution.
  - `handleResult()` reads them.
  - `lastSignals()` returns `retainedBytes`, `decodedBytes` and `bwtBytes` for the last execution only.

#### Part B: `V1Guidance`
**Input model:** raw `InputStream` bytes, because the harness reads `data.readAllBytes()`. The maximum input length comes from `jqf.ei.MAX_INPUT_SIZE` when the guidance is created, and every generated input is cut to it, including the encoder's output.

**Encoder:** each entry can carry a genome: a block-size digit plus a list of (byte, run length) plaintext records. The plaintext is streamed in 1 MB chunks through `EmbeddedChannel(new Bzip2Encoder(level))`, so block and stream CRCs are always valid. Encoding stops when the output reaches the input limit or after `-Dv1.encodeBudgetMs` (default 15000).

**Genome mutations:**
- change a record's byte or length (±, ×2, ÷2, random);
- insert, delete, swap or merge records;
- repeat a record slice k times;
- double the whole list;
- multiply every run length by 2–16;
- change the block-size digit;
- splice two genomes.

**Byte-level mutations:**
- bit flip, set byte, arithmetic change, insert, delete;
- repeat a chunk k times (up to the input limit);
- double the whole input;
- splice two inputs;
- insert or overwrite dictionary tokens: `BZh`, digits `1`–`9`, block magic `31 41 59 26 53 59`, end-of-stream magic `17 72 45 38 50 90`.

**Seeds:** random small genomes only (plaintext under about 400 bytes). No triggering values are built in.

**Retention:** an input is kept if it sets a new best `retainedBytes`, `validBlocks`, retained-per-input-byte, `decodedBytes` or `bwtBytes`. Otherwise it is kept if it reaches a new (`blocksReached`, `validBlocks`) pair, or a new maximum input length (the fallback while the signal is flat). Inputs whose result is FAILURE or TIMEOUT are not kept as parents.

**Method-specific prioritization:** parents are picked by a score dominated by `validBlocks`. That rewards the decoder keeping several CRC-valid blocks within one `decode()` call (the `INIT_BLOCK` re-entry in `Bzip2Decoder`). Parent choice is a tournament on that score, a pick from the newest entries, or a uniform pick.

**Reaching 750 bytes:** while the longest input is under 1 KB, byte-level operators are used 45% of the time and favour repetition and doubling. That should reach 750 bytes in a handful of executions.

**Corpus and logging:**
- The corpus goes to `out/V1/corpus/id_NNNNNN.bin` with a `.json` metadata file next to each (signals, parent, operators, genome summary, result). The guidance writes no failure files.
- A daemon thread prints a JSON stats line every second.
- Runs are infinite by default, or bounded by a duration.

#### Part C: runner, repro, replay
- **Fuzz:** `FuzzRunner V1 [seconds]` uses `fuzzBzip2DecoderDecode` and `out/V1/corpus`. `FuzzRunner fuzzBzip2DecoderDecode2` uses `out/V1-decode2`. `V1:<method>` is also accepted. `-Dfuzz.duration` and `-Dfuzz.out` work as properties. The runner calls `GuidedFuzzing.run(TEST_CLASS, method, Thread.currentThread().getContextClassLoader(), guidance, System.out)`.
- **Reproduce:** `ReproV1 <bin> [method]` calls the harness method by reflection and reports whether the throwable is declared.
- **Replay:** `ReplayV1 <meta.json|corpus-dir>` prints the metadata, loads the input it names and replays it.
- **Class origin:**
  - `target/classes` does not exist (there is no `src/main`). The Netty classes are only present in `lib/*.jar` and their copies in `target/dependency/`.
  - `ClassOriginCheck`, run by `run.sh`, prints each class's code source at runtime. It has not been run yet.

**Commands:**
- Fuzz 60 s: `./run.sh 60 V1`
- Run forever: `./run.sh 0 V1`
- Select the other method: `./run.sh 60 fuzzBzip2DecoderDecode2`
- Reproduce: `java -Xmx1g -Xss1m -cp "$CP" fuzzing.ReproV1 out/V1/corpus/id_000000.bin`
- Replay: `java -Xmx1g -Xss1m -cp "$CP" fuzzing.ReplayV1 out/V1/corpus/id_000000.json`

#### Strategy table
| Target | Strategy | Why Zest fails | Why this wins |
|---|---|---|---|
| V1 | Hybrid: vulnerability-directed + cost-gradient + encoder-based shape-aware mutation | Byte mutations break the 32-bit block CRC and the Huffman bit fields, so later blocks are never kept. Coverage stops growing after one small valid block. PerfFuzz's per-edge hit counts are a stand-in signal and cannot grow the number of kept blocks. | Mutations happen on the plaintext and are re-encoded by Netty's own encoder, so CRCs stay valid. Retention follows the measured `retainedBytes` and `validBlocks` from inside the decompressor. |

The closest Zest setup is `mvn jqf:fuzz -Dclass=fuzzing.Bzip2DecoderFuzzTest -Dmethod=fuzzBzip2DecoderDecode`. Metrics for the comparison: time to the first `OutOfMemoryError` or timeout, best `retainedBytes` after 10 minutes, and best measured output per input byte.

#### IMPORT AUDIT
```IMPORT AUDIT
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent   (used only in the generateCallBack signature; no JQF tracing for measurement)
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz            (frozen harness)
JQF → edu.berkeley.cs.jqf.fuzz.JQF               (frozen harness)
@RunWith → org.junit.runner.RunWith              (frozen harness)
SignalSource → dosguide.validate.SignalSource
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
ClassVisitor → org.objectweb.asm.ClassVisitor
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
ClassFileTransformer → java.lang.instrument.ClassFileTransformer
Instrumentation → java.lang.instrument.Instrumentation
```
The `Guidance`, `Result` and `GuidedFuzzing` signatures were checked with `javap` against `jqf-fuzz-2.1.jar`.

#### Self-checklist
- [x] JDK 17+ only: YES, compiles with source/target 17.
- [x] No hallucinated APIs: YES, JQF signatures checked with `javap`; Netty APIs read in the source.
- [x] Guidance implements `Guidance` directly: YES.
- [x] No existing guidance extended: YES.
- [x] V* vulnerabilities identified: YES, V1.
- [x] V* IDs sequential (R42): YES.
- [x] Official names applied: YES, CWE-409.
- [x] PkgRisk-* identified: YES, none; justified in Block 1.
- [x] Every PkgRisk executed or justified: YES, the empty set was justified.
- [x] Guidance targets the register: YES, V1 only.
- [x] One fuzz method per target: YES, `fuzzBzip2DecoderDecode` (frozen harness).
- [x] CLI method selection: YES.
- [x] Byte[]/InputStream input model only: YES.
- [x] No junit-quickcheck Generators: YES.
- [x] All mutation inside the Guidance: YES.
- [x] Repetition, source dictionary and encoder (R45): YES, with Netty's `Bzip2Encoder`.
- [x] Flat-signal progress; `input_bytes` reachable within a minute (R46): YES by design (length-growth retention plus extra repetition early); not yet measured.
- [x] Signals measured at the sink (R47): YES, inside `Bzip2BlockDecompressor`, which `decode()` drives.
- [x] Logging every second: YES, scheduled daemon thread.
- [x] Guidance decides no failures and writes no failure files (R6): YES.
- [x] Inputs saved with metadata: YES, corpus `.bin` plus `.json`; failures themselves are recorded by the evaluation.
- [x] Replay/feeder: YES, `ReplayV1`.
- [x] Infinite and time-bounded runs: YES.
- [x] `src/main` vs `src/test` separation: YES, everything is under `src/test`.
- [x] Maven scopes consistent: YES, `pom.xml` unchanged.
- [x] No wildcard JQF/tracing imports: YES.
- [x] TraceEvent import verified and audited: YES.
