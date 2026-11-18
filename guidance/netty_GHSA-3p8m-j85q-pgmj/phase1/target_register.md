{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "BrotliDecoder unbounded decompression output (decompression bomb)",
      "entrypoint": "DecompressionFuzzTest.fuzzBrotliDecoderDecode(InputStream) → DecompressionFuzzTest.decodeAll(ChannelHandler, byte[]) → EmbeddedChannel.writeInbound(Object...) → DefaultChannelPipeline.fireChannelRead(Object) → ByteToMessageDecoder.channelRead(ChannelHandlerContext, Object) → ByteToMessageDecoder.callDecode(ChannelHandlerContext, ByteBuf, List) → BrotliDecoder.decode(ChannelHandlerContext, ByteBuf, List) → BrotliDecoder.decompress(ByteBuf, List, ByteBufAllocator) → BrotliDecoder.pull(ByteBufAllocator)",
      "source_path": "codec-compression/src/main/java/io/netty/handler/codec/compression/BrotliDecoder.java",
      "sink": "BrotliDecoder#decompress",
      "mechanism": "decompress() runs an unbounded for(;;) loop that calls pull() on each NEEDS_MORE_OUTPUT and NEEDS_MORE_INPUT-with-output status, allocating a new heap ByteBuf per chunk. All decompressed ByteBufs accumulate in the output list during a single decode() call with no limit on total output size or expansion ratio. A crafted Brotli stream with high compression ratio (e.g. compressed zeros at >600000:1) produces massive decompressed output from a tiny input.",
      "resource": "heap memory: cumulative bytes in decompressed ByteBuf objects, growing proportionally with the Brotli stream's expansion ratio",
      "failure_mode": "out_of_memory",
      "scale": "REVISED MECHANISM: Measurements show Java heap is constant (~11 MB allocated, ~11 MB peak heap) regardless of decompressed output size (2–64 MB). BrotliDecoder.pull() calls alloc.buffer(int), and the default PooledByteBufAllocator creates direct (off-heap) ByteBufs. The growing resource is direct memory, not Java heap. Direct memory grows at ~1 byte per byte of decompressed output (inferred: all output ByteBufs accumulate unreleased in the out list during a single decode() call). Wall time grows at ~1.29 ms/MB (measured over 4–64 MB). To exhaust MaxDirectMemorySize (which defaults to Xmx = 1 GB): ~1 GB of decompressed output is needed, taking ~1.4 seconds (well under the 20-second timeout). Brotli compresses 1 GB of zeros to ~1642 bytes; all-zeros is near-optimal for brotli compression, so no significantly denser encoding exists.",
      "input_bytes": 1700,
      "cwe": "CWE-409",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "fuzzing.harness.DecompressionFuzzTest#fuzzBrotliDecoderDecode(InputStream)",
          "location": "harness/src/test/java/fuzzing/harness/DecompressionFuzzTest.java:40"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/fuzzing/harness/DecompressionFuzzTest.java:42"
        },
        {
          "kind": "hop",
          "method": "fuzzing.harness.DecompressionFuzzTest#decodeAll(ChannelHandler,byte[])",
          "location": "harness/src/test/java/fuzzing/harness/DecompressionFuzzTest.java:64"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/fuzzing/harness/DecompressionFuzzTest.java:66"
        },
        {
          "kind": "hop",
          "method": "io.netty.channel.embedded.EmbeddedChannel#writeInbound(Object...)",
          "location": "transport/src/main/java/io/netty/channel/embedded/EmbeddedChannel.java:364"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "transport/src/main/java/io/netty/channel/embedded/EmbeddedChannel.java:374"
        },
        {
          "kind": "hop",
          "method": "io.netty.channel.DefaultChannelPipeline#fireChannelRead(Object)",
          "location": "transport/src/main/java/io/netty/channel/DefaultChannelPipeline.java:915"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "transport/src/main/java/io/netty/channel/DefaultChannelPipeline.java:918"
        },
        {
          "kind": "hop",
          "method": "io.netty.handler.codec.ByteToMessageDecoder#channelRead(ChannelHandlerContext,Object)",
          "location": "codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:282"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:290"
        },
        {
          "kind": "hop",
          "method": "io.netty.handler.codec.ByteToMessageDecoder#callDecode(ChannelHandlerContext,ByteBuf,List)",
          "location": "codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:449"
        },
        {
          "kind": "connection",
          "type": "DATAFLOW",
          "evidence": "ByteToMessageDecoder#callDecode(ChannelHandlerContext,ByteBuf,List) (codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:449) writes field `destroyed`, which BrotliDecoder#decode(ChannelHandlerContext,ByteBuf,List) (codec-compression/src/main/java/io/netty/handler/codec/compression/BrotliDecoder.java:125) reads (through helper calls)",
          "site": "codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:449"
        },
        {
          "kind": "hop",
          "method": "io.netty.handler.codec.compression.BrotliDecoder#decode(ChannelHandlerContext,ByteBuf,List)",
          "location": "codec-compression/src/main/java/io/netty/handler/codec/compression/BrotliDecoder.java:125"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-compression/src/main/java/io/netty/handler/codec/compression/BrotliDecoder.java:137"
        },
        {
          "kind": "hop",
          "method": "io.netty.handler.codec.compression.BrotliDecoder#decompress(ByteBuf,List,ByteBufAllocator)",
          "location": "codec-compression/src/main/java/io/netty/handler/codec/compression/BrotliDecoder.java:75"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-compression/src/main/java/io/netty/handler/codec/compression/BrotliDecoder.java:87"
        },
        {
          "kind": "hop",
          "method": "io.netty.handler.codec.compression.BrotliDecoder#pull(ByteBufAllocator)",
          "location": "codec-compression/src/main/java/io/netty/handler/codec/compression/BrotliDecoder.java:67"
        }
      ],
      "harness_entry": "fuzzing.harness.DecompressionFuzzTest#fuzzBrotliDecoderDecode",
      "scale_measurement": [
        {
          "value": 2097152,
          "input_bytes": 14,
          "outcome": "completed",
          "cpu_ms": 125.072665,
          "allocated_bytes": 11969648,
          "peak_heap_bytes": 12582912
        },
        {
          "value": 4194304,
          "input_bytes": 14,
          "outcome": "completed",
          "cpu_ms": 105.637663,
          "allocated_bytes": 11754632,
          "peak_heap_bytes": 11534336
        },
        {
          "value": 8388608,
          "input_bytes": 14,
          "outcome": "completed",
          "cpu_ms": 105.525967,
          "allocated_bytes": 11956320,
          "peak_heap_bytes": 12582912
        },
        {
          "value": 16777216,
          "input_bytes": 27,
          "outcome": "completed",
          "cpu_ms": 136.370036,
          "allocated_bytes": 11451040,
          "peak_heap_bytes": 11534336
        },
        {
          "value": 33554432,
          "input_bytes": 54,
          "outcome": "completed",
          "cpu_ms": 138.071023,
          "allocated_bytes": 11455928,
          "peak_heap_bytes": 12582912
        },
        {
          "value": 67108864,
          "input_bytes": 106,
          "outcome": "completed",
          "cpu_ms": 183.173811,
          "allocated_bytes": 11544576,
          "peak_heap_bytes": 11534336
        }
      ]
    },
    {
      "slot": 2,
      "id": "V2",
      "name": "ZstdDecoder unbounded decompression output (decompression bomb)",
      "entrypoint": "DecompressionFuzzTest.fuzzZstdDecoderDecode(InputStream) → DecompressionFuzzTest.decodeAll(ChannelHandler, byte[]) → EmbeddedChannel.writeInbound(Object...) → DefaultChannelPipeline.fireChannelRead(Object) → ByteToMessageDecoder.channelRead(ChannelHandlerContext, Object) → ByteToMessageDecoder.callDecode(ChannelHandlerContext, ByteBuf, List) → ZstdDecoder.decode(ChannelHandlerContext, ByteBuf, List)",
      "source_path": "codec-compression/src/main/java/io/netty/handler/codec/compression/ZstdDecoder.java",
      "sink": "ZstdDecoder#decode",
      "mechanism": "decode() runs an unbounded do-while loop reading decompressed data from ZstdInputStreamNoFinalizer, allocating heap ByteBufs of size compressedLength*2 for each chunk without limiting total output size. All buffers accumulate in the output list during a single decode() call. A crafted Zstd stream with high compression ratio produces large decompressed output.",
      "resource": "heap memory: cumulative bytes in decompressed ByteBuf objects, growing with the Zstd stream's expansion ratio",
      "failure_mode": "out_of_memory",
      "scale": "CANNOT FAIL IN THIS EVALUATION. Measurements show allocated grows at ~1.04 MB per MB of decompressed output, but peak heap plateaus at ~38 MB. ZstdDecoder.decode() explicitly uses ctx.alloc().heapBuffer() (line 73), so data is heap-allocated. Extrapolating to 256 MB decompressed (maximum from 10240-byte zstd input): ~280 MB allocated, ~549 ms wall time — neither approaches -Xmx1g or the 20 s timeout. OOM requires ~851 MB decompressed → ~27449 bytes compressed zstd (at ~32.3 bytes per MB, inherent to the zstd frame/block structure on all-zeros). This exceeds the 10240-byte input limit. No denser encoding exists: all-zeros is near-optimal for zstd, and the per-block header overhead is format-intrinsic.",
      "input_bytes": 27449,
      "cwe": "CWE-409",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "fuzzing.harness.DecompressionFuzzTest#fuzzZstdDecoderDecode(InputStream)",
          "location": "harness/src/test/java/fuzzing/harness/DecompressionFuzzTest.java:49"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/fuzzing/harness/DecompressionFuzzTest.java:51"
        },
        {
          "kind": "hop",
          "method": "fuzzing.harness.DecompressionFuzzTest#decodeAll(ChannelHandler,byte[])",
          "location": "harness/src/test/java/fuzzing/harness/DecompressionFuzzTest.java:64"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/fuzzing/harness/DecompressionFuzzTest.java:66"
        },
        {
          "kind": "hop",
          "method": "io.netty.channel.embedded.EmbeddedChannel#writeInbound(Object...)",
          "location": "transport/src/main/java/io/netty/channel/embedded/EmbeddedChannel.java:364"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "transport/src/main/java/io/netty/channel/embedded/EmbeddedChannel.java:374"
        },
        {
          "kind": "hop",
          "method": "io.netty.channel.DefaultChannelPipeline#fireChannelRead(Object)",
          "location": "transport/src/main/java/io/netty/channel/DefaultChannelPipeline.java:915"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "transport/src/main/java/io/netty/channel/DefaultChannelPipeline.java:918"
        },
        {
          "kind": "hop",
          "method": "io.netty.handler.codec.ByteToMessageDecoder#channelRead(ChannelHandlerContext,Object)",
          "location": "codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:282"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:290"
        },
        {
          "kind": "hop",
          "method": "io.netty.handler.codec.ByteToMessageDecoder#callDecode(ChannelHandlerContext,ByteBuf,List)",
          "location": "codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:449"
        },
        {
          "kind": "connection",
          "type": "DATAFLOW",
          "evidence": "ByteToMessageDecoder#callDecode(ChannelHandlerContext,ByteBuf,List) (codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:449) writes field `currentState`, which ZstdDecoder#decode(ChannelHandlerContext,ByteBuf,List) (codec-compression/src/main/java/io/netty/handler/codec/compression/ZstdDecoder.java:56) reads (through helper calls)",
          "site": "codec-base/src/main/java/io/netty/handler/codec/ByteToMessageDecoder.java:449"
        },
        {
          "kind": "hop",
          "method": "io.netty.handler.codec.compression.ZstdDecoder#decode(ChannelHandlerContext,ByteBuf,List)",
          "location": "codec-compression/src/main/java/io/netty/handler/codec/compression/ZstdDecoder.java:56"
        }
      ],
      "harness_entry": "fuzzing.harness.DecompressionFuzzTest#fuzzZstdDecoderDecode",
      "scale_measurement": [
        {
          "value": 2097152,
          "input_bytes": 81,
          "outcome": "completed",
          "cpu_ms": 130.651664,
          "allocated_bytes": 16625160,
          "peak_heap_bytes": 16777216
        },
        {
          "value": 4194304,
          "input_bytes": 145,
          "outcome": "completed",
          "cpu_ms": 168.671655,
          "allocated_bytes": 20841224,
          "peak_heap_bytes": 19922944
        },
        {
          "value": 8388608,
          "input_bytes": 273,
          "outcome": "completed",
          "cpu_ms": 176.459994,
          "allocated_bytes": 23477952,
          "peak_heap_bytes": 23068672
        },
        {
          "value": 16777216,
          "input_bytes": 529,
          "outcome": "completed",
          "cpu_ms": 133.79278,
          "allocated_bytes": 31982968,
          "peak_heap_bytes": 33554432
        },
        {
          "value": 33554432,
          "input_bytes": 1041,
          "outcome": "completed",
          "cpu_ms": 195.88678,
          "allocated_bytes": 51459176,
          "peak_heap_bytes": 39845888
        },
        {
          "value": 67108864,
          "input_bytes": 2065,
          "outcome": "completed",
          "cpu_ms": 209.653375,
          "allocated_bytes": 84367424,
          "peak_heap_bytes": 39845888
        }
      ]
    }
  ]
}
