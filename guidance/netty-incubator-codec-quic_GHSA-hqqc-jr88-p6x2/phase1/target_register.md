{
  "ordered_targets": [
    {
      "slot": 1,
      "id": "V1",
      "name": "HashDoS on QuicheQuicCodec.connectionIdToChannel via attacker-chosen client DCIDs (unseeded ByteBuffer.hashCode keys)",
      "entrypoint": "QuicCodecFuzzTest.fuzzQuicServerCodecChannelRead(InputStream) → QuicCodecFuzzTest.serveInitialPackets(byte[]) → EmbeddedChannel.writeInbound(Object...) → QuicheQuicCodec.channelRead(ChannelHandlerContext, Object) → QuicheQuicCodec.handleQuicPacket(InetSocketAddress, InetSocketAddress, ByteBuf) → QuicHeaderParser.parse(InetSocketAddress, InetSocketAddress, ByteBuf, QuicHeaderParser.QuicHeaderProcessor) → QuicheQuicCodec$QuicCodecHeaderProcessor.process(InetSocketAddress, InetSocketAddress, ByteBuf, QuicPacketType, long, ByteBuf, ByteBuf, ByteBuf) → QuicheQuicServerCodec.quicPacketRead(ChannelHandlerContext, InetSocketAddress, InetSocketAddress, QuicPacketType, long, ByteBuf, ByteBuf, ByteBuf, ByteBuf, ByteBuf, Consumer, int, QuicheConfig) → QuicheQuicCodec.getChannel(ByteBuffer) → HashMap.get(Object)",
      "source_path": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java",
      "sink": "io.netty.incubator.codec.quic.QuicheQuicCodec#getChannel",
      "mechanism": "Each client Initial's raw DCID is stored as a key (ByteBuffer.wrap(originalId)) in connectionIdToChannel and looked up for every datagram; ByteBuffer.hashCode is an unseeded base-31 polynomial, so distinct DCIDs with equal hash land in one treeified bin whose keys are not self-Comparable, forcing TreeNode.find to scan both subtrees: O(n) per lookup/insert/remove, O(n^2) over n packets; channels never close (no ClientHello) so entries accumulate",
      "resource": "CPU time: HashMap tree-bin nodes visited / ByteBuffer.equals calls per getChannel lookup, growing linearly with the number of colliding DCIDs already mapped (quadratic in total)",
      "failure_mode": "timeout",
      "scale": "Measured (fixed startup cost of ~530 ms subtracted): about 92 ms at 1024, 315 ms at 2048 and 1040 ms at 4096 colliding 20-byte DCIDs; doubling 2048→4096 costs ×3.3, close to quadratic. Fit cost ≈ 49 ns·n² + 54 µs·n (the linear part is the per-packet harness crypto and native connection setup); this predicts ~4.2 s at 8192, matching the probe's time cap there. Solving 4.9e-5·n² + 0.054·n = 20,000 ms gives n ≈ 19,600 colliding packets; at 21 bytes per record (length byte + 20-byte DCID), about 413 KB. Shorter DCIDs give a denser encoding (11 bytes per record with 10-byte IDs; see PkgRisk1).",
      "input_bytes": 413000,
      "cwe": "CWE-407",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.fuzz.QuicCodecFuzzTest#fuzzQuicServerCodecChannelRead(InputStream)",
          "location": "harness/src/test/java/io/netty/incubator/codec/quic/fuzz/QuicCodecFuzzTest.java:62"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/io/netty/incubator/codec/quic/fuzz/QuicCodecFuzzTest.java:63"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.fuzz.QuicCodecFuzzTest#serveInitialPackets(byte[])",
          "location": "harness/src/test/java/io/netty/incubator/codec/quic/fuzz/QuicCodecFuzzTest.java:97"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/io/netty/incubator/codec/quic/fuzz/QuicCodecFuzzTest.java:109"
        },
        {
          "kind": "hop",
          "method": "EmbeddedChannel.writeInbound(Object...)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 3 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicCodec#channelRead(ChannelHandlerContext,Object)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:178"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:188"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicCodec#handleQuicPacket(InetSocketAddress,InetSocketAddress,ByteBuf)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:200"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:202"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicHeaderParser#parse(InetSocketAddress,InetSocketAddress,ByteBuf,QuicHeaderProcessor)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicHeaderParser.java:68"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicHeaderParser.java:142"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicCodec.QuicCodecHeaderProcessor#process(InetSocketAddress,InetSocketAddress,ByteBuf,QuicPacketType,long,ByteBuf,ByteBuf,ByteBuf)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:362"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:364"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicServerCodec#quicPacketRead(ChannelHandlerContext,InetSocketAddress,InetSocketAddress,QuicPacketType,long,ByteBuf,ByteBuf,ByteBuf,ByteBuf,ByteBuf,Consumer,int,QuicheConfig)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicServerCodec.java:107"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicServerCodec.java:115"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicCodec#getChannel(ByteBuffer)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:80"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:81"
        },
        {
          "kind": "hop",
          "method": "HashMap.get(Object)",
          "location": "outside the source tree"
        }
      ],
      "harness_entry": "io.netty.incubator.codec.quic.fuzz.QuicCodecFuzzTest#fuzzQuicServerCodecChannelRead",
      "scale_measurement": [
        {
          "value": 512,
          "input_bytes": 10752,
          "outcome": "completed",
          "cpu_ms": 576.757929,
          "allocated_bytes": 38733176,
          "peak_heap_bytes": 27262976
        },
        {
          "value": 1024,
          "input_bytes": 21504,
          "outcome": "completed",
          "cpu_ms": 622.572188,
          "allocated_bytes": 61781024,
          "peak_heap_bytes": 20971520
        },
        {
          "value": 2048,
          "input_bytes": 43008,
          "outcome": "completed",
          "cpu_ms": 844.350149,
          "allocated_bytes": 123414864,
          "peak_heap_bytes": 46137344
        },
        {
          "value": 4096,
          "input_bytes": 86016,
          "outcome": "completed",
          "cpu_ms": 1567.259113,
          "allocated_bytes": 311831320,
          "peak_heap_bytes": 20661200
        },
        {
          "value": 8192,
          "input_bytes": 172032,
          "outcome": "time_cap"
        }
      ]
    },
    {
      "slot": 2,
      "id": "PkgRisk1",
      "name": "java.util.HashMap tree-bin degeneration on non-Comparable java.nio.ByteBuffer keys with colliding polynomial hashes (insertion path)",
      "entrypoint": "QuicCodecFuzzTest.fuzzQuicServerCodecChannelRead2(InputStream) → QuicCodecFuzzTest.serveInitialPackets(byte[]) → EmbeddedChannel.writeInbound(Object...) → QuicheQuicCodec.channelRead(ChannelHandlerContext, Object) → QuicheQuicCodec.handleQuicPacket(InetSocketAddress, InetSocketAddress, ByteBuf) → QuicHeaderParser.parse(InetSocketAddress, InetSocketAddress, ByteBuf, QuicHeaderParser.QuicHeaderProcessor) → QuicheQuicCodec$QuicCodecHeaderProcessor.process(InetSocketAddress, InetSocketAddress, ByteBuf, QuicPacketType, long, ByteBuf, ByteBuf, ByteBuf) → QuicheQuicServerCodec.quicPacketRead(ChannelHandlerContext, InetSocketAddress, InetSocketAddress, QuicPacketType, long, ByteBuf, ByteBuf, ByteBuf, ByteBuf, ByteBuf, Consumer, int, QuicheConfig) → QuicheQuicServerCodec.handleServer(ChannelHandlerContext, InetSocketAddress, InetSocketAddress, QuicPacketType, long, ByteBuf, ByteBuf, ByteBuf, ByteBuf, ByteBuf, Consumer, int, QuicheConfig) → QuicheQuicCodec.addChannel(QuicheQuicChannel) → HashMap.put(Object, Object) → HashMap.putVal(int, Object, Object, boolean, boolean) → HashMap$TreeNode.putTreeVal(HashMap, Node[], int, Object, Object) → HashMap$TreeNode.find(int, Object, Class)",
      "source_path": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java",
      "sink": "java.util.HashMap$TreeNode#find",
      "mechanism": "JDK ByteBuffer.hashCode is deterministic and unkeyed; HashMap treeifies a crowded bin but comparableClassFor returns null for HeapByteBuffer/DirectByteBuffer, so putTreeVal performs a full two-subtree find on every insert of a new colliding key; each new connection inserts its client DCID into the same bin",
      "resource": "CPU time: tree-bin nodes visited inside HashMap$TreeNode.find/putTreeVal per insertion, linear in bin size, quadratic in the number of colliding inserts",
      "failure_mode": "timeout",
      "scale": "Measured (fixed startup cost of ~530 ms subtracted): about 66 ms at 1024, 598 ms at 2048 and over 1470 ms at 4096 colliding 10-byte DCIDs (4096 hit the 2 s probe cap); the growth is superlinear and consistent with quadratic bin traversal, with a coefficient of about 74–140 ns per n², above V1's 49 ns. Solving a·n² + 0.054·n = 20,000 ms gives n ≈ 14,000–16,000 colliding inserts; taking about 16,000 at 11 bytes per record (length byte + 10-byte DCID) gives about 176 KB. A denser encoding exists: 8-byte DCIDs at 9 bytes per record (16,000 packets ≈ 144 KB), but reaching 16,000 colliding 8-byte IDs needs a more general collision construction than the two-byte-block substitution used here, which yields only 6,561.",
      "input_bytes": 176000,
      "cwe": "CWE-407",
      "checkpath_status": "PASS",
      "normalized_path": [
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.fuzz.QuicCodecFuzzTest#fuzzQuicServerCodecChannelRead2(InputStream)",
          "location": "harness/src/test/java/io/netty/incubator/codec/quic/fuzz/QuicCodecFuzzTest.java:91"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/io/netty/incubator/codec/quic/fuzz/QuicCodecFuzzTest.java:92"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.fuzz.QuicCodecFuzzTest#serveInitialPackets(byte[])",
          "location": "harness/src/test/java/io/netty/incubator/codec/quic/fuzz/QuicCodecFuzzTest.java:97"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "harness/src/test/java/io/netty/incubator/codec/quic/fuzz/QuicCodecFuzzTest.java:109"
        },
        {
          "kind": "hop",
          "method": "EmbeddedChannel.writeInbound(Object...)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 3 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicCodec#channelRead(ChannelHandlerContext,Object)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:178"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:188"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicCodec#handleQuicPacket(InetSocketAddress,InetSocketAddress,ByteBuf)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:200"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:202"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicHeaderParser#parse(InetSocketAddress,InetSocketAddress,ByteBuf,QuicHeaderProcessor)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicHeaderParser.java:68"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicHeaderParser.java:142"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicCodec.QuicCodecHeaderProcessor#process(InetSocketAddress,InetSocketAddress,ByteBuf,QuicPacketType,long,ByteBuf,ByteBuf,ByteBuf)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:362"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:364"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicServerCodec#quicPacketRead(ChannelHandlerContext,InetSocketAddress,InetSocketAddress,QuicPacketType,long,ByteBuf,ByteBuf,ByteBuf,ByteBuf,ByteBuf,Consumer,int,QuicheConfig)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicServerCodec.java:107"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicServerCodec.java:119"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicServerCodec#handleServer(ChannelHandlerContext,InetSocketAddress,InetSocketAddress,QuicPacketType,long,ByteBuf,ByteBuf,ByteBuf,ByteBuf,ByteBuf,Consumer,int,QuicheConfig)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicServerCodec.java:138"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicServerCodec.java:275"
        },
        {
          "kind": "hop",
          "method": "io.netty.incubator.codec.quic.QuicheQuicCodec#addChannel(QuicheQuicChannel)",
          "location": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:120"
        },
        {
          "kind": "connection",
          "type": "CALL",
          "site": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java:124"
        },
        {
          "kind": "hop",
          "method": "HashMap.put(Object, Object)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 11 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "HashMap.putVal(int, Object, Object, boolean, boolean)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 12 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "HashMap$TreeNode.putTreeVal(HashMap, Node[], int, Object, Object)",
          "location": "outside the source tree"
        },
        {
          "kind": "connection",
          "type": "UNCHECKED",
          "evidence": "hop 13 is outside the source tree, so calls made inside it cannot be inspected"
        },
        {
          "kind": "hop",
          "method": "HashMap$TreeNode.find(int, Object, Class)",
          "location": "outside the source tree"
        }
      ],
      "harness_entry": "io.netty.incubator.codec.quic.fuzz.QuicCodecFuzzTest#fuzzQuicServerCodecChannelRead2",
      "scale_measurement": [
        {
          "value": 1024,
          "input_bytes": 11264,
          "outcome": "completed",
          "cpu_ms": 596.152563,
          "allocated_bytes": 61822000,
          "peak_heap_bytes": 42991616
        },
        {
          "value": 2048,
          "input_bytes": 22528,
          "outcome": "completed",
          "cpu_ms": 1128.099531,
          "allocated_bytes": 123720688,
          "peak_heap_bytes": 14327992
        },
        {
          "value": 4096,
          "input_bytes": 45056,
          "outcome": "time_cap"
        },
        {
          "value": 8192,
          "input_bytes": 90112,
          "outcome": "time_cap"
        },
        {
          "value": 16384,
          "input_bytes": 180224,
          "outcome": "time_cap"
        }
      ]
    }
  ]
}
