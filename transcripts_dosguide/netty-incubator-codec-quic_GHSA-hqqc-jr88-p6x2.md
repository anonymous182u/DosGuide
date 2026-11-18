# netty-incubator-codec-quic_GHSA-hqqc-jr88-p6x2

## Block 1

```text
$ cd <run_dir>; find . -type f | grep -v '/target/' | head -50; cat $(find . -name '*FuzzTest.java' | head -3)
$ cd <run_dir>; cat analysis/run_config.json; cat src/test/java/dosguide/validate/SignalSource.java | head -40; S=<source_root>/codec-cla …
Read <run_dir>/analysis/run_config.json
Read <source_root>/codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java
$ S=<source_root>/codec-classes-quic/src/main/java/io/netty/incubator/codec/quic; wc -l $S/QuicheQuicServerCodec.java $S/QuicHeaderParser.java $S/*ConnectionIdGenerator*.java $S/QuicServerCodecBuilder.java; grep -n "connection …
Read <source_root>/codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicServerCodec.java
```

Reading the server codec and builder defaults to see how attacker-chosen connection IDs reach the `connectionIdToChannel` HashMap.

```text
Grep <source_root>/codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicServerCodecBuilder.java connectionIdAddressGenerator|tokenHandler|resetTokenGenerator|localConnIdLength|activeMigration|maxRecvUdpPayload
Grep <source_root>/codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicConnectionIdGenerator.java class|newId|hash|sign
Read <source_root>/codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicServerCodecBuilder.java
Grep <source_root>/codec-classes-quic/src/main/java/io/netty/incubator/codec/quic Mac|Hmac|newId|SecureRandom|signKey
Grep <source_root>/codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicChannel.java void recv\(|connectionClosed|forceClose\(\)|freeTask|void unsafeBeginRead|sourceConnectionIds\(\)|private void connectionSend|quiche_conn_is_closed
Read <source_root>/codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicChannel.java
```

Writing the scale-measurement series (records of colliding connection IDs, for measurement only).

```text
$ python3 -I - <<'EOF' …
```

#### Phase A: Analysis

**Harness facts (frozen `QuicCodecFuzzTest`).**
- `fuzzQuicServerCodecChannelRead` and `fuzzQuicServerCodecChannelRead2` both make the same calls through `serveInitialPackets(byte[])`.
- The input is read as records of `[len byte][len bytes]`. Each record becomes the DCID (destination connection ID) of one valid QUIC v1 client Initial, which the harness builds itself: RFC 9001 keys, AES-GCM, header protection, padded to 1200 bytes.
- Each Initial is delivered with `EmbeddedChannel.writeInbound`, and `finishAndReleaseAll()` runs at the end.
- `fuzzQuicHeaderParserParse` reaches only the native `quiche_header_info` on one datagram. That is constant work, so it has no DoS target.

##### 1.1 Code-level vulnerabilities

**V1: connection-ID → channel map with keys the attacker chooses and a hash the attacker can predict (HashDoS)**
- **Where:** `QuicheQuicCodec.connectionIdToChannel = new HashMap<ByteBuffer, QuicheQuicChannel>()`.
- **How the DCID becomes a key:** in `QuicheQuicServerCodec.handleServer`, the builder defaults are `NoQuicTokenHandler`, so the no-token path runs. It adds `ByteBuffer.wrap(originalId)` to `sourceConnectionIds()`, where `originalId` is the client's raw DCID. `addChannel` then `put`s every source ID into the map.
- **Lookup per packet:** each datagram first calls `getChannel(dcidByteBuffer)` (`quicPacketRead`), which looks up the attacker's DCID.
- **Why the hash is predictable:** `ByteBuffer.hashCode()` is an unseeded polynomial, `h = 31*h + b[i]`. An attacker can therefore pick many distinct DCIDs of up to 20 bytes that share one hash.
- **Why collisions cost O(n) per lookup:** `HashMap` turns a crowded bucket into a tree, but the runtime key classes (`HeapByteBuffer`, and `DirectByteBuffer` for the lookup key) do not declare `Comparable<Self>`, so `comparableClassFor` returns null. `TreeNode.find` then has to search both subtrees, which makes every `get`, every `putTreeVal` (one full search per insert) and every `remove` linear in the bucket size.
- **Why entries pile up:** the channels stay open. A PING-only Initial carries no ClientHello, so the handshake stays pending and idle timers never fire in `EmbeddedChannel`.
- **Total cost:** about n²/2 node visits for the lookups, about n²/2 for the inserts, and about n²/4 more when `handlerRemoved → forceClose → removeChannel` removes the entries at the end.
- **Resource:** CPU time, measured as the number of tree-bin nodes visited / `ByteBuffer.equals` calls, which grows quadratically with the number of colliding DCIDs.
- **Failure mode:** timeout.
- **Scale:**
  - At roughly 1.25·n² visits and about 40 ns per visit, the 20 s limit needs n ≈ 20,000 colliding packets.
  - Each record is 21 bytes (1 length byte + 20-byte DCID), so that is about 420 KB.
  - The per-packet baseline (crypto in the harness plus native connection setup, maybe 50–100 µs per packet) adds a few more seconds.
  - Both estimates are to be revised from the DoSGuide measurements.
- **Classification:** CWE-407 (Inefficient Algorithmic Complexity), the hash-collision DoS (HashDoS) class. The upstream fix for this advisory replaced the map with a seeded-hash connection-ID map.

##### 1.2 Classification
- V1 → CWE-407 (with CWE-400 as the broader class).
- PkgRisk-1 → CWE-407.

##### 1.3 Package-level risks

**PkgRisk-1: `java.util.HashMap` tree bins and the unseeded `java.nio.ByteBuffer.hashCode`**
- **Why it is input-sensitive:** the JDK hash is deterministic and cannot be keyed. Tree bins fall back to a linear search of both subtrees when the key is not self-Comparable.
- **Trigger shape:** many distinct byte strings with equal polynomial-31 hashes, for example made by substituting equal-weight blocks.
- **Measured at the insertion sink:** `HashMap.put → putVal → TreeNode.putTreeVal → TreeNode.find`, reached from `QuicheQuicCodec.addChannel`.
- **Densest encoding:** shorter DCIDs. With 10-byte IDs (above the RFC minimum of 8) each record is 11 bytes, and there are still more than 59k collisions available.
- **Resource:** CPU time, measured as tree nodes visited in `find`/`putTreeVal`.
- **Failure mode:** timeout.
- **Scale:** about 20k colliding inserts at 11 bytes each, roughly 220 KB. To be revised from measurements.
- **Fuzzing strategy:** go through `fuzzQuicServerCodecChannelRead2`. Measure tree-bin traversal steps at `HashMap$TreeNode.find`/`putTreeVal` with a custom agent. Repeat records, and use a dictionary of record-length tokens (8–20).

**Other candidates I excluded**
- The native quiche parsing and the BoringSSL handshake run in native code, and per packet the input is bounded at 1200 bytes.
- `ArrayDeque` queues hold at most one entry per channel, so they are linear.

**Scale series written (measurement only, not seeds):**
- `analysis/scale/V1/`: 512 to 8192 colliding 20-byte DCIDs, plus `series.json`.
- `analysis/scale/PkgRisk-1/`: 1024 to 16384 colliding 10-byte DCIDs, plus `series.json`.
- A generation-time check confirmed that every ID in a file is distinct and that all IDs share one `ByteBuffer.hashCode`.

#### Phase B: Target Register

BEGIN_TARGET_REGISTER_JSON
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
      "scale": "about 20,000 colliding DCIDs (~1.25*n^2 = 5e8 node visits at ~40 ns) exceed the 20 s limit; 21 bytes per record (1 length byte + 20-byte DCID), so about 420 KB; to be revised from measured growth",
      "input_bytes": 420000,
      "cwe": "CWE-407"
    },
    {
      "slot": 2,
      "id": "PkgRisk-1",
      "name": "java.util.HashMap tree-bin degeneration on non-Comparable java.nio.ByteBuffer keys with colliding polynomial hashes (insertion path)",
      "entrypoint": "QuicCodecFuzzTest.fuzzQuicServerCodecChannelRead2(InputStream) → QuicCodecFuzzTest.serveInitialPackets(byte[]) → EmbeddedChannel.writeInbound(Object...) → QuicheQuicCodec.channelRead(ChannelHandlerContext, Object) → QuicheQuicCodec.handleQuicPacket(InetSocketAddress, InetSocketAddress, ByteBuf) → QuicHeaderParser.parse(InetSocketAddress, InetSocketAddress, ByteBuf, QuicHeaderParser.QuicHeaderProcessor) → QuicheQuicCodec$QuicCodecHeaderProcessor.process(InetSocketAddress, InetSocketAddress, ByteBuf, QuicPacketType, long, ByteBuf, ByteBuf, ByteBuf) → QuicheQuicServerCodec.quicPacketRead(ChannelHandlerContext, InetSocketAddress, InetSocketAddress, QuicPacketType, long, ByteBuf, ByteBuf, ByteBuf, ByteBuf, ByteBuf, Consumer, int, QuicheConfig) → QuicheQuicServerCodec.handleServer(ChannelHandlerContext, InetSocketAddress, InetSocketAddress, QuicPacketType, long, ByteBuf, ByteBuf, ByteBuf, ByteBuf, ByteBuf, Consumer, int, QuicheConfig) → QuicheQuicCodec.addChannel(QuicheQuicChannel) → HashMap.put(Object, Object) → HashMap.putVal(int, Object, Object, boolean, boolean) → HashMap$TreeNode.putTreeVal(HashMap, Node[], int, Object, Object) → HashMap$TreeNode.find(int, Object, Class)",
      "source_path": "codec-classes-quic/src/main/java/io/netty/incubator/codec/quic/QuicheQuicCodec.java",
      "sink": "java.util.HashMap$TreeNode#find",
      "mechanism": "JDK ByteBuffer.hashCode is deterministic and unkeyed; HashMap treeifies a crowded bin but comparableClassFor returns null for HeapByteBuffer/DirectByteBuffer, so putTreeVal performs a full two-subtree find on every insert of a new colliding key; each new connection inserts its client DCID into the same bin",
      "resource": "CPU time: tree-bin nodes visited inside HashMap$TreeNode.find/putTreeVal per insertion, linear in bin size, quadratic in the number of colliding inserts",
      "failure_mode": "timeout",
      "scale": "about 20,000 colliding inserts (plus matching lookups and close-time removals in the same bin) exceed the 20 s limit; densest RFC-valid encoding uses 10-byte DCIDs, 11 bytes per record, so about 220 KB; to be revised from measured growth",
      "input_bytes": 220000,
      "cwe": "CWE-407"
    }
  ]
}
END_TARGET_REGISTER_JSON

## Scale revision

```text
$ cd <run_dir>/analysis/scale && cp -r PkgRisk-1 PkgRisk1 && ls PkgRisk1 && cat PkgRisk1/series.json | head -5
```

DoSGuide was looking for `analysis/scale/PkgRisk1/`, but I had written the PkgRisk-1 series to `analysis/scale/PkgRisk-1/`. I copied it to the expected name, so `analysis/scale/PkgRisk1/` now holds `series.json` and its five input files. The old `PkgRisk-1` directory is still there as a duplicate, and I left the target register unchanged.

The PkgRisk1 series:
- **What grows:** the number of client Initial packets whose 10-byte connection IDs all have the same `ByteBuffer.hashCode`, so every one lands in the same HashMap bucket.
- **Sizes:** 1024, 2048, 4096, 8192 and 16384 packets. The files run from 11,264 to 180,224 bytes, under the 262,144-byte cap.
- **Format:** each record is one length byte followed by the ID, which is how `fuzzQuicServerCodecChannelRead2` reads its input.
- **Checked when generated:** every ID in a file is distinct and all of them share one hash.

The V1 series at `analysis/scale/V1/` is unchanged.

## Scale revision 2

V1 grows quadratically, as the collision mechanism predicts; my 20,000-packet estimate holds. PkgRisk1 costs more per packet than I expected, so I lowered its estimate to about 16,000 packets (176 KB). Both figures are extrapolated from a few points and are rough.

**How I fitted the numbers:** the smallest input, at 512 packets, took about 577 ms. I treated roughly 530 ms of that as a fixed startup cost unrelated to input size and subtracted it. I then fitted cost = a·n² + b·n, where n is the number of colliding packets.

**V1 (20-byte connection IDs, 21 bytes per record)**
- After subtracting the fixed cost, the measurements are about 92 ms at 1024 packets, 315 ms at 2048 and 1040 ms at 4096.
- Doubling n from 2048 to 4096 multiplied the cost by 3.3, which is close to quadratic.
- The fit gives about 49 ns per n² (a) plus about 54 µs per packet (b). The per-packet part is the harness's crypto and setting up each connection.
- That fit predicts about 4.2 s at 8192 packets, which matches the probe hitting its 2 s cap there.
- Solving for 20 s gives about 19,600 packets, roughly 413 KB, under the 1 MB input limit.

**PkgRisk1 (10-byte connection IDs, 11 bytes per record)**
- After subtracting the fixed cost, the measurements are about 66 ms at 1024 packets and 598 ms at 2048. At 4096 the probe passed its 2 s cap, so that point is more than about 1,470 ms.
- That range puts a between about 74 and 140 ns per n², which is above V1's. Shorter IDs make the probe more expensive per packet, not less.
- Extrapolating to 20 s gives about 14,000–16,000 packets.
- A denser encoding exists: 8-byte IDs take 9 bytes per record (16,000 packets ≈ 144 KB). My simple collision scheme yields only 6,561 colliding 8-byte IDs, though, so reaching 16,000 would need a more general way to build collisions.

BEGIN_SCALE_REVISION_JSON
{
  "V1": {
    "scale": "Measured (fixed startup cost of ~530 ms subtracted): about 92 ms at 1024, 315 ms at 2048 and 1040 ms at 4096 colliding 20-byte DCIDs; doubling 2048→4096 costs ×3.3, close to quadratic. Fit cost ≈ 49 ns·n² + 54 µs·n (the linear part is the per-packet harness crypto and native connection setup); this predicts ~4.2 s at 8192, matching the probe's time cap there. Solving 4.9e-5·n² + 0.054·n = 20,000 ms gives n ≈ 19,600 colliding packets; at 21 bytes per record (length byte + 20-byte DCID), about 413 KB. Shorter DCIDs give a denser encoding (11 bytes per record with 10-byte IDs; see PkgRisk1).",
    "input_bytes": 413000
  },
  "PkgRisk1": {
    "scale": "Measured (fixed startup cost of ~530 ms subtracted): about 66 ms at 1024, 598 ms at 2048 and over 1470 ms at 4096 colliding 10-byte DCIDs (4096 hit the 2 s probe cap); the growth is superlinear and consistent with quadratic bin traversal, with a coefficient of about 74–140 ns per n², above V1's 49 ns. Solving a·n² + 0.054·n = 20,000 ms gives n ≈ 14,000–16,000 colliding inserts; taking about 16,000 at 11 bytes per record (length byte + 10-byte DCID) gives about 176 KB. A denser encoding exists: 8-byte DCIDs at 9 bytes per record (16,000 packets ≈ 144 KB), but reaching 16,000 colliding 8-byte IDs needs a more general collision construction than the two-byte-block substitution used here, which yields only 6,561.",
    "input_bytes": 176000
  }
}
END_SCALE_REVISION_JSON

## Block 2

```text
Read <run_dir>/pom.xml
Glob <run_dir> **/*
$ ls ~/.m2/repository/org/ow2/asm/ 2>/dev/null; ls ~/.m2/repository/org/ow2/asm/asm 2>/dev/null; ls ~/.m2/repository/edu/berkeley/cs/jqf/jqf-instrument/2.1/ 2>/dev/null; grep -A3 "artifactId>asm" ~/.m2/repository/edu/berkeley/cs/jqf/jqf-instrument/2.1/*.pom 2>/dev/null | head -20; javac -version 2>&1
$ mvn -q -o dependency:tree -Dscope=test 2>&1 | grep -i "asm\|ERROR" | head; mvn -q -o -DskipTests package 2>&1 | tail -15; ls target/deps | grep -i asm
$ mvn -q -o -DskipTests package 2>&1 | tail -15; ls target/deps | grep -i "asm\|jqf"
```

Block 2: measurement strategy for V1 and PkgRisk1. Both targets measure the same thing: how many times the JDK's `HashMap` tree-bucket search (`HashMap$TreeNode#find`) has to visit a node when the colliding keys are not ordered. A custom `-javaagent` (built on ASM) counts those visits. V1 counts them inside the codec's lookup method, `QuicheQuicCodec#getChannel`, and PkgRisk1 counts them inside its insertion path, `QuicheQuicCodec#addChannel`.

**What was checked, and what is still open:**
- `pom.xml` is unchanged. An offline `mvn -o -DskipTests package` builds as it is.
- The jar under test is the locally built `lib/netty-incubator-codec-classes-quic-0.0.71.Final-SNAPSHOT.jar` (system scope).
- ASM 9.8 comes onto the test class path through `jqf-instrument`, so the agent needs no new dependency.
- The JDK is 17.0.20.
- Two things are untested until Block 3. The first is whether the agent can rewrite the already-loaded JDK classes `HashMap$TreeNode` and `ByteBuffer`. The second is the proof that the target classes load from `lib/` rather than from the workspace's own compiled classes.

**Biggest risk.** No search will find colliding connection IDs at random: the odds are about 1 in 2³². Both plans therefore depend on one mutation operator that preserves the hash of a record. It copies a record and adjusts two adjacent bytes by (+31, −1) or (−31, +1). Because `ByteBuffer.hashCode` is `h = 31·h + b`, the copy keeps the same hash but becomes a different key. This is an operator taken from the hash function's own formula; no colliding values are written down. You may want to rule on whether that is acceptable under [R23] before Block 3.

#### Step 2: Maven layout and scope
- The `pom.xml` I was given is used unchanged.
- The project under test comes only from the two system-scope jars in `lib/`. Its Maven Central coordinates are not used.
- Netty 4.1.118, jetbrains annotations and jsr305 are compile scope.
- JQF 2.1, junit 4.13.2 and junit-quickcheck-core 1.0 are test scope.
- `src/main/java` stays empty (production code only). All fuzzing code goes in `src/test/java`.

#### Step 3: Compilation closure
**3.1 Missing-symbol audit**

| Symbol | Kind | How it is resolved |
|---|---|---|
| `io.netty.incubator.codec.quic.*` (`Quic`, `QuicServerCodecBuilder`, `QuicSslContext(Builder)`, `QuicHeaderParser`, `QuicPacketType`, `QuicException`) | project classes | system jar from `lib/` |
| native quiche/BoringSSL | project native library | system jar from `lib/` (linux-x86_64) |
| `io.netty.buffer`, `io.netty.channel` (including `embedded` and `socket`), `io.netty.util` | external library | Netty 4.1.118 from Maven Central |
| `org.jetbrains.annotations.Nullable` | external library | jetbrains annotations |
| `edu.berkeley.cs.jqf.fuzz.*`, `org.junit.*` | external library | test scope |
| `org.objectweb.asm.ClassReader`, `ClassWriter`, `ClassVisitor`, `MethodVisitor`, `Opcodes` | external library | `org.ow2.asm:asm:9.8`, which `jqf-instrument` pulls in |
| `java.lang.instrument.*` | JDK | JDK |

**3.2 and 3.3 Stub report:** no stubs are needed. Every internal type is in the vulnerable jar.

#### Steps 4–5: Strategy

| Target | Selected strategy | Why Zest fails | Why PerfFuzz fails | Why this strategy wins |
|---|---|---|---|---|
| **V1** (`fuzzQuicServerCodecChannelRead`) | **Primary: VDF.** Secondary: DAG + CGF. The search climbs on the measured number of tree-bucket nodes visited inside `getChannel`. | Coverage is a proxy signal. All Initial packets run the same code (`quicPacketRead → getChannel → handleServer → addChannel`), and once the first collision-free packet goes through there are no new branches. Zest's byte mutations change a connection ID at random, which yields two equal hashes about once in 2³² tries. Zest also keeps no record of hash equality and has no way to grow inputs to around 400 KB on purpose. | Generic cost is a proxy signal. PerfFuzz counts executions per branch, and that count grows about linearly with the number of packets: each packet does its own HMAC/AES work in the harness plus native quiche setup. It therefore rewards long inputs of packets that do not collide, and the n² collision cost is never separated out. | It counts node visits in `TreeNode.find` only while `getChannel` is on the stack, which is exactly where the n² lookup work happens. A hash-preserving record clone, derived from `ByteBuffer.hashCode`, makes keys that collide, and the measured visit count confirms each one. |
| **PkgRisk1** (`fuzzQuicServerCodecChannelRead2`) | **Primary: DAG** (the cost is inside the JDK's `HashMap`). Secondary: VDF + CGF. | Same as V1. The JDK classes are not part of Zest's coverage, so the cost inside the tree bucket never shows up. | Same as V1. | It counts node visits during `TreeNode.find` and `putTreeVal`, only while `addChannel` is on the stack. It also gives priority to visits per input byte, which favours the densest records (short connection IDs). |

**Metrics where the custom guidance should beat Zest and PerfFuzz:**
1. Time to the first 20 s timeout.
2. Most tree-bucket nodes visited within the first 10 minutes.
3. Cost amplification, measured as visits per input byte (PkgRisk1) or visits per lookup (V1).

**Specific to each fuzz method ([R19]):**
- **V1:**
  - Scope: visits are counted only inside `QuicheQuicCodec#getChannel`.
  - Priority: highest visits per lookup, i.e. the size of the colliding bucket that one packet's connection ID lands in.
  - Record length: biased toward 20-byte connection IDs. That is the server's `localConnIdLength` and the longest ID the header parser accepts, so there is the most room for collisions.
- **PkgRisk1:**
  - Scope: visits are counted only inside `HashMap$TreeNode#putTreeVal` while `addChannel` runs.
  - Extra counter: how often buckets are converted into trees (`treeify`).
  - Priority: visits per input byte.
  - Record length: biased toward 8–10-byte connection IDs (densest encoding).

**Input model ([R25], [R31]):** the input is an `InputStream` of raw bytes. `getInput()` hands over the bytes directly, there are no generators, and the frozen harness splits them into `[len][dcid]` records.

#### Step 6: Measurement plan (Tier 1, custom agent; no JQF agent)

**The agent (written in Block 3, under `src/test/java/dosguide/agent/`)**
- `DoSMeasureAgent.premain` registers a transformer that can rewrite classes the JVM has already loaded, then calls `retransformClasses` on `java.util.HashMap$TreeNode` and `java.nio.ByteBuffer`.
- `DoSCounters` holds plain public static fields: counters and scope depths. It is packed into a small separate jar that the agent manifest puts on the bootstrap class path (`Boot-Class-Path: dosguide-counters.jar`), so code inside the JDK can call it. The guidance sees the same class because class loading asks the parent loader first.
- All execution is on one thread (EmbeddedChannel runs inline on the JQF thread).

**What the agent injects**

| Method | Injection | Effect |
|---|---|---|
| `io/netty/incubator/codec/quic/QuicheQuicCodec#getChannel` | entry: `v1Scope++`; before each `ARETURN`/`ATHROW`: `v1Scope--`, then update `v1MaxPerLookup` | opens and closes the V1 scope |
| `QuicheQuicCodec#addChannel` | entry/exit: `addScope++/--`, `channelsAdded++` | opens and closes the PkgRisk1 scope; counts channels created |
| `java/util/HashMap$TreeNode#find(ILjava/lang/Object;Ljava/lang/Class;)` | before every `GETFIELD …hash`, i.e. once per node visited: `DoSCounters.onTreeVisit()` | the primary counter |
| `HashMap$TreeNode#putTreeVal` | entry/exit: `putScope++/--` | marks the insertion path |
| `HashMap$TreeNode#treeify` | entry: `DoSCounters.onTreeify()` | counts bucket-to-tree conversions |
| `java/nio/ByteBuffer#equals(Ljava/lang/Object;)` | entry: `DoSCounters.onKeyEquals()` | catches compares in list buckets before the tree threshold |

**How the counters are attributed**
- `onTreeVisit` adds 1 to `v1TreeVisits` when `v1Scope > 0`, and to `p1TreeVisits` when `addScope > 0 && putScope > 0`.
- `onKeyEquals` adds 1 to `v1KeyEquals` or `p1KeyEquals` under the same two conditions.
- Code outside those scopes is never counted; this keeps JQF's own maps out of the numbers.

**Runtime setup**
- JVM flags: `-Xmx1g -Xss1m -javaagent:target/dosguide-agent.jar`.
- No `--add-opens` is needed, because retransformation does not use reflection.
- The agent jar is built with the `jar` tool from `target/test-classes` with this manifest: `Premain-Class`, `Can-Retransform-Classes: true`, `Boot-Class-Path`.
- ASM comes from the test class path.

**Signal lifecycle**
- **Reset:** `<Id>Guidance.getInput()` calls `DoSCounters.reset()` before each run.
- **Read:** `<Id>Guidance.handleResult()` reads the counters into `lastSignals()`.

**Mutation operators (both guidances).** All of them respect record boundaries, which the guidance finds by parsing the input exactly the way the harness does.
- Byte-level: flip, set, insert and delete bytes.
- Record operations:
  - replace or insert a whole record;
  - set a record's length byte to a value from the dictionary;
  - splice in a record from another corpus entry.
- **Repetition ([R45a]):**
  - choose a record or a run of records, and repeat it k times;
  - k can go up to what fills `jqf.ei.MAX_INPUT_SIZE`;
  - the whole input can be doubled.
- **Clone with hash-preserving carry:** the same repetition, but each copy gets 1–3 random adjacent-byte adjustments of (+31, −1) or (−31, +1) at weight-31 positions, skipping any adjustment that would overflow a byte. The copies are distinct keys with the same hash.
- **Dictionary ([R45b]):** tokens from the attack path:
  - `Quic.MAX_CONN_ID_LEN` = 20;
  - RFC minimum connection-ID length = 8;
  - length byte 0;
  - the multiplier 31 used by `ByteBuffer.hashCode`;
  - 0x00 and 0xff boundary bytes.

  No assembled input is stored.
- **Encoder ([R45c]):** not needed. The harness itself builds the packet protection and checksum fields.
- **Reaching `input_bytes`:** doubling about 14 times takes a ~25-byte seed to more than 413 KB (V1) or 176 KB (PkgRisk1). The doubling operator is picked with probability ≥ 0.25 until an input has reached that size, so the target length is reached within the first minute. Even at the target size, one execution takes about 1–2 s of baseline time when keys do not collide.
- **Seeds:** a few records built from random bytes with random lengths. They contain no collisions.

**Keeping progress while the signal is flat ([R46]).** An input is kept if any of these hold:
1. The primary tree-visit count is a new maximum.
2. The list-bucket compare count is a new maximum. This climbs before buckets become trees, at about 8 colliding keys.
3. A new bucket-to-tree conversion count is reached.
4. `channelsAdded` is a new maximum (more distinct channels reached the sink).
5. The input is longer than every kept input with the same signal level, up to `input_bytes`.

**Priority.**
- Inputs are picked by weighted random choice by rank of primary signal, then secondary.
- For V1 the primary signal is `v1TreeVisits` and the secondary is `v1MaxPerLookup`.
- For PkgRisk1 the primary signal is `p1TreeVisits` and the secondary is visits per KB.
- Corpus: `out/<Id>/corpus` (V1 and PkgRisk1 have separate corpora), plus `out/<Id>/meta` with metadata per kept input.

**Run control and logging.**
- Runs forever by default. The CLI takes `--time` or `-Dduration`.
- Logs JSON stats every second.
- The guidance never declares a failure ([R6]).

#### Directory tree (Block 3 fills it in)
```
pom.xml                         (provided, unchanged)
lib/*.jar                       (vulnerable artifact)
src/test/java/io/netty/incubator/codec/quic/fuzz/QuicCodecFuzzTest.java   (frozen)
src/test/java/dosguide/agent/{DoSMeasureAgent,DoSTransformer,DoSCounters}.java
src/test/java/dosguide/guidance/{V1Guidance,PkgRisk1Guidance,RecordMutator}.java
src/test/java/dosguide/run/{FuzzRunner,ReplayFeeder,ClassOriginCheck}.java
out/V1/{corpus,meta}  out/PkgRisk1/{corpus,meta}
```

#### IMPORT AUDIT
```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz
@RunWith → org.junit.runner.RunWith
JQF → edu.berkeley.cs.jqf.fuzz.JQF
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent (generateCallBack signature only; JQF tracing is not used for measurement)
ClassReader/ClassWriter/ClassVisitor/MethodVisitor/Opcodes → org.objectweb.asm.*
Instrumentation/ClassFileTransformer → java.lang.instrument.*
```

#### Self-checklist
- JDK 17+ only: **YES.** The build uses `release 17`, and javac is 17.0.20.
- No hallucinated APIs: **YES.** Only JQF 2.1 `Guidance`/`Result`, ASM 9 and `java.lang.instrument` are used.
- Guidance implements `Guidance` directly: **YES.**
- No existing guidance extended: **YES.**
- V* vulnerabilities identified: **YES.** V1.
- V* IDs sequential ([R42]): **YES.**
- Official names applied: **YES.** CWE-407 (hash-collision DoS).
- PkgRisk-* identified: **YES.** PkgRisk1.
- Every PkgRisk-* executed or justified: **YES.** PkgRisk1 runs through `fuzzQuicServerCodecChannelRead2`.
- Guidance targets V* and PkgRisk-*: **YES.** One guidance each.
- One fuzz method per V* or PkgRisk: **YES.** From the frozen harness: method 1 for V1, method 2 for PkgRisk1.
- CLI method selection supported: **YES.** `FuzzRunner <V1|PkgRisk1>`.
- Byte[]/InputStream input model only: **YES.**
- No junit-quickcheck generators: **YES.**
- All mutation inside the guidance: **YES.**
- Repetition, source dictionary and encoder operators ([R45]): **YES.** No encoder is needed because the harness builds the packet encoding.
- Retention progresses while the signal is flat; inputs reach `input_bytes` within a minute ([R46]): **YES.** See the five retention criteria and the doubling schedule.
- Retention signals measured where the resource is consumed ([R47]): **YES.** Counted inside `TreeNode.find`, within the scope of the sink method.
- Logging every 1 second: **YES.**
- Guidance decides no failures and writes no failure files ([R6]): **YES.**
- Corrupted inputs saved with metadata: **YES.** Corpus entries get metadata. JQF and the evaluation record the failures themselves.
- Replay/feeder implemented: **YES.** `ReplayFeeder`, in Block 3.
- Infinite and time-bounded fuzzing supported: **YES.**
- `src/main` vs `src/test` separation correct: **YES.**
- Maven scopes consistent: **YES.**
- No wildcard imports for JQF/tracing: **YES.**
- `TraceEvent` import verified and audited: **YES.**

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "v1TreeVisits",
          "quantity": "tree-bin nodes visited (one per read of TreeNode.hash) inside HashMap$TreeNode.find while QuicheQuicCodec.getChannel is on the stack",
          "aggregation": "sum",
          "locations": ["java.util.HashMap$TreeNode#find", "io.netty.incubator.codec.quic.QuicheQuicCodec#getChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.v1TreeVisits (bootstrap-loaded), gated by static int DoSCounters.v1Scope",
          "reset": "DoSCounters.reset() in V1Guidance.getInput()",
          "read": "V1Guidance.handleResult()"
        },
        {
          "name": "v1MaxPerLookup",
          "quantity": "largest number of tree-bin nodes visited during a single getChannel call",
          "aggregation": "max",
          "locations": ["io.netty.incubator.codec.quic.QuicheQuicCodec#getChannel", "java.util.HashMap$TreeNode#find"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.v1MaxPerLookup, updated at getChannel exit from a per-call delta",
          "reset": "DoSCounters.reset() in V1Guidance.getInput()",
          "read": "V1Guidance.handleResult()"
        },
        {
          "name": "v1KeyEquals",
          "quantity": "ByteBuffer.equals key comparisons inside getChannel (covers list bins before treeification)",
          "aggregation": "count",
          "locations": ["java.nio.ByteBuffer#equals", "io.netty.incubator.codec.quic.QuicheQuicCodec#getChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.v1KeyEquals",
          "reset": "DoSCounters.reset() in V1Guidance.getInput()",
          "read": "V1Guidance.handleResult()"
        },
        {
          "name": "channelsAdded",
          "quantity": "number of QuicheQuicCodec.addChannel invocations (distinct connections whose DCID entered the map)",
          "aggregation": "count",
          "locations": ["io.netty.incubator.codec.quic.QuicheQuicCodec#addChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.channelsAdded",
          "reset": "DoSCounters.reset() in V1Guidance.getInput()",
          "read": "V1Guidance.handleResult()"
        }
      ],
      "retention": "Keep the input if v1TreeVisits, v1MaxPerLookup or v1KeyEquals reaches a new maximum, or if channelsAdded reaches a new maximum, or (flat-signal criterion) if it is longer than every kept input at the same signal level, up to input_bytes=413000. Choose parents by weighted random rank on v1TreeVisits, then v1MaxPerLookup. Pick the doubling or clone operator with probability >= 0.25 until some input reaches input_bytes. Prefer 20-byte DCID records (localConnIdLength). Corpus in out/V1/corpus, metadata in out/V1/meta. Runs forever by default, or for the CLI/system-property duration.",
      "retention_signals": ["v1TreeVisits", "v1MaxPerLookup", "v1KeyEquals", "channelsAdded"],
      "mutation": ["byte flip/set/insert/delete", "record-level replace/insert/splice from another corpus entry, using the harness's [len][dcid] parse", "repetition: repeat a record or a run of records k times up to MAX_INPUT_SIZE, including doubling the whole input", "clone with hash-preserving carry: repeat a record, applying 1-3 random adjacent-byte (+31,-1)/(-31,+1) adjustments per copy, derived from the ByteBuffer.hashCode base-31 polynomial", "dictionary tokens from the attack path: length bytes 20 (Quic.MAX_CONN_ID_LEN), 8 (RFC minimum DCID length), 0, the multiplier 31, 0x00/0xff boundaries", "no encoder needed: the harness applies the QUIC Initial protection"]
    },
    {
      "target": "PkgRisk1",
      "signals": [
        {
          "name": "p1TreeVisits",
          "quantity": "tree-bin nodes visited inside HashMap$TreeNode.find while HashMap$TreeNode.putTreeVal runs within QuicheQuicCodec.addChannel",
          "aggregation": "sum",
          "locations": ["java.util.HashMap$TreeNode#find", "java.util.HashMap$TreeNode#putTreeVal", "io.netty.incubator.codec.quic.QuicheQuicCodec#addChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.p1TreeVisits, gated by DoSCounters.addScope and DoSCounters.putScope",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        },
        {
          "name": "p1VisitsPerKB",
          "quantity": "measured p1TreeVisits divided by executed input kilobytes (amplification per input byte)",
          "aggregation": "ratio",
          "locations": ["java.util.HashMap$TreeNode#find"],
          "technique": "bytecode",
          "storage": "computed in PkgRisk1Guidance.handleResult() from DoSCounters.p1TreeVisits",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        },
        {
          "name": "p1Treeify",
          "quantity": "HashMap$TreeNode.treeify invocations within addChannel (a colliding bin crossed TREEIFY_THRESHOLD)",
          "aggregation": "count",
          "locations": ["java.util.HashMap$TreeNode#treeify"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.p1Treeify",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        },
        {
          "name": "p1KeyEquals",
          "quantity": "ByteBuffer.equals key comparisons during insertion inside addChannel (list bins before treeification)",
          "aggregation": "count",
          "locations": ["java.nio.ByteBuffer#equals", "io.netty.incubator.codec.quic.QuicheQuicCodec#addChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.p1KeyEquals",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        },
        {
          "name": "channelsAdded",
          "quantity": "number of QuicheQuicCodec.addChannel invocations",
          "aggregation": "count",
          "locations": ["io.netty.incubator.codec.quic.QuicheQuicCodec#addChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.channelsAdded",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        }
      ],
      "retention": "Keep the input if p1TreeVisits, p1VisitsPerKB, p1KeyEquals or p1Treeify reaches a new maximum, or if channelsAdded reaches a new maximum, or (flat-signal criterion) if it is longer than every kept input at the same signal level, up to input_bytes=176000. Choose parents by weighted random rank on p1TreeVisits, then p1VisitsPerKB. Prefer 8-10 byte DCID records (densest encoding). Pick the doubling or clone operator with probability >= 0.25 until input_bytes is reached. Corpus in out/PkgRisk1/corpus, metadata in out/PkgRisk1/meta. Runs forever by default, or for the CLI/system-property duration.",
      "retention_signals": ["p1TreeVisits", "p1VisitsPerKB", "p1KeyEquals", "p1Treeify", "channelsAdded"],
      "mutation": ["byte flip/set/insert/delete", "record-level replace/insert/splice from another corpus entry, using the harness's [len][dcid] parse", "repetition: repeat a record or a run of records k times up to MAX_INPUT_SIZE, including doubling the whole input", "clone with hash-preserving carry: repeat a record, applying 1-3 random adjacent-byte (+31,-1)/(-31,+1) adjustments per copy, derived from the ByteBuffer.hashCode base-31 polynomial", "record shortening toward 8-10 byte DCIDs (rewrite the length byte and truncate)", "dictionary tokens from the attack path: length bytes 8, 10, 20 (Quic.MAX_CONN_ID_LEN), 0, the multiplier 31, 0x00/0xff boundaries", "no encoder needed: the harness applies the QUIC Initial protection"]
    }
  ]
}
END_GUIDANCE_PLAN_JSON

## Block 3

```text
$ pwd; ls; ls analysis; cat src/test/java/dosguide/validate/SignalSource.java
$ pwd; ls; ls analysis
Read <run_dir>/src/test/java/dosguide/validate/SignalSource.java
$ cd analysis; head -c 1500 plancheck.json; echo; python3 -I -c "import json;d=json.load(open('guidance_plan.json'));print([ (p['target'],[s['name'] for s in p['signals']]) for p in d['plans']])"
$ cd ..; D=target/deps; javap -cp $D/jqf-fuzz-2.1.jar edu.berkeley.cs.jqf.fuzz.guidance.Guidance edu.berkeley.cs.jqf.fuzz.guidance.Result edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing 2>&1 | head -60; ls $D | head -50
$ javap -c -p 'java.util.HashMap$TreeNode' 2>&1 | awk '/ find\(/,/^$/' | grep -n "getfield\|invoke" | head -20; javap -p java.nio.ByteBuffer | grep "equals\|hashCode"; javap -p -cp lib/netty-incubator-codec-classes-quic-0.0.71.Final-SNAPSHOT.jar io.netty.incubator.codec.quic.QuicheQuicCodec | grep "ge …
```

Verified the bytecode hook points; now writing the agent, guidances, runner and replay files.

```text
$ for c in java.nio.HeapByteBuffer java.nio.DirectByteBuffer java.nio.MappedByteBuffer java.nio.HeapByteBufferR java.nio.DirectByteBufferR; do echo "$c: $(javap -p $c | grep -c 'boolean equals')"; done
```

Now the counters class.

```text
Write <run_dir>/src/test/java/dosguide/agent/DoSCounters.java
Write <run_dir>/src/test/java/dosguide/agent/DoSMeasureAgent.java
Write <run_dir>/src/test/java/dosguide/agent/DoSTransformer.java
Write <run_dir>/src/test/java/dosguide/guidance/RecordMutator.java
Write <run_dir>/src/test/java/dosguide/guidance/GuidanceSupport.java
Write <run_dir>/src/test/java/dosguide/guidance/V1Guidance.java
Edit <run_dir>/src/test/java/dosguide/guidance/V1Guidance.java
```

Writing PkgRisk1Guidance next, then the runner, replay, launch.json and run.sh.

```text
Write <run_dir>/src/test/java/dosguide/guidance/PkgRisk1Guidance.java
Write <run_dir>/src/test/java/dosguide/run/FuzzRunner.java
Write <run_dir>/src/test/java/dosguide/run/ReplayFeeder.java
Write <run_dir>/src/test/java/dosguide/run/ClassOriginCheck.java
$ mvn -q -o -DskipTests package 2>&1 | tail -30; ls target/test-classes/dosguide/*
$ mvn -q -o -DskipTests package 2>&1 | tail -30
$ mkdir -p target/agent && printf 'Premain-Class: dosguide.agent.DoSMeasureAgent\nAgent-Class: dosguide.agent.DoSMeasureAgent\nCan-Retransform-Classes: true\nCan-Redefine-Classes: true\nClass-Path: deps/asm-9.8.jar\n' > target/agent/MANIFEST.MF && jar cfm target/dosguide-agent.jar target/agent/MANIFES …
Write <run_dir>/build.sh
Write <run_dir>/run.sh
Write <run_dir>/analysis/launch.json
```

Making scripts executable and checking the class path command resolves.

```text
$ chmod +x run.sh build.sh && python3 -I -c "import json;print(json.load(open('analysis/launch.json'))['classpath_command'])" > /tmp/cpcmd.txt && bash -c "$(cat /tmp/cpcmd.txt)" | tr ':' '\n' | head -8
$ chmod +x run.sh build.sh && bash -c "$(python3 -I -c "import json;print(json.load(open('analysis/launch.json'))['classpath_command'])")" | tr ':' '\n' | head -6
Write <run_dir>/README.md
$ unzip -l target/deps/jqf-fuzz-2.1.jar | grep -i "InputStreamGen"; javap -c -p -cp target/deps/jqf-fuzz-2.1.jar 'edu.berkeley.cs.jqf.fuzz.junit.quickcheck.InputStreamGenerator$1' 2>&1 | grep -i "invoke\|iconst_m1\|catch" | head
```

All Block 3 files are written and compile; nothing has been run, because executing java or the fuzzer is blocked in this environment. `mvn -o -DskipTests package` succeeded and `target/dosguide-agent.jar` was assembled with `jar`. Whether the agent can rewrite `HashMap$TreeNode` and `ByteBuffer`, the 1-second logs, input growth and the class-origin proof are all unconfirmed until DoSGuide runs them.

**Assumption to check — the "carry" mutation.** Neither guidance would find colliding connection IDs without one mutation operator I added. Byte j of a `ByteBuffer` contributes `b[j]·31^j` to its hash. So adding 31 to `b[j]` and subtracting 1 from `b[j+1]` (or the reverse) gives a different key with the same hash. The operator applies this to whatever record the search picks; no colliding keys are written into the code or seeds. If you judge this too close to building the exploit under [R23], drop it. Random mutation would then almost never produce collisions (odds about 1 in 2³²).

#### Part A — Measurement agent (`src/test/java/dosguide/agent/`)
- **`DoSMeasureAgent`**: at startup it writes `DoSCounters.class` into a temporary jar and adds that jar to the bootstrap class path, so code inside the JDK can call the counters. It then registers the transformer and rewrites the already-loaded `HashMap$TreeNode` and `ByteBuffer`.
- **`DoSTransformer`** (ASM 9.8, which `jqf-instrument` already brings in) inserts no-argument static calls at these points:

  | Method | What is injected |
  |---|---|
  | `HashMap$TreeNode#find` | one call before every read of the node's `hash` field, i.e. once per node visited |
  | `HashMap$TreeNode#putTreeVal` | enter/exit scope |
  | `HashMap$TreeNode#treeify` | count of bucket-to-tree conversions |
  | `ByteBuffer#equals` | count of key comparisons |
  | `QuicheQuicCodec#getChannel` | enter/exit scope |
  | `QuicheQuicCodec#addChannel` | enter/exit scope |

- **`DoSCounters`**: plain static counters, tied to the fuzzing thread.
  - Visits are counted only while `getChannel` is running (V1), or while `putTreeVal` runs inside `addChannel` (PkgRisk1).
  - The guidance resets them in `getInput()` and reads them in `handleResult()`.

#### Part B — Guidances (`src/test/java/dosguide/guidance/`)
Each class implements `Guidance` and `SignalSource` directly, with no base class.

- **`V1Guidance`**
  - Signals: `v1TreeVisits`, `v1MaxPerLookup`, `v1KeyEquals`, `channelsAdded`.
  - New records prefer 20-byte connection IDs.
  - Parents are ranked by total visits, then by visits in a single lookup.
- **`PkgRisk1Guidance`**
  - Signals: `p1TreeVisits`, `p1VisitsPerKB`, `p1Treeify`, `p1KeyEquals`, `channelsAdded`.
  - New records prefer 8–10-byte connection IDs, and there is an extra "shorten records" operator.
  - Parents are ranked by total visits, then by visits per KB.
- **`RecordMutator`** (shared by both):
  - It splits the input into records exactly as the harness does.
  - Byte-level operators: bit flip, set, insert and delete.
  - Dictionary tokens: 20, 8, 10, 0, 31, 0x7f, 0x80, 0xff, 1.
  - Record-level operators: replace, insert, splice, set length.
  - Repetition: repeat a run of records k times, up to the size limit, or double the whole input.
  - The carry operators described above.
  - Its "already seen" set uses its own seeded hash, because the standard one would collide on exactly these keys.
- **Retention**: an input is kept if any signal reaches a new maximum. While signals are flat, it is also kept if it is longer than every kept input at the same signal level, until the target size is reached.
- **Reaching the target size**: 30% of the time the guidance grows the current longest input. That makes inputs of 413 KB (V1) or 176 KB (PkgRisk1) possible within the first minute.
- **Input size limit**: the maximum length comes from `jqf.ei.MAX_INPUT_SIZE` (default 1048576), and every generated input is cut to it.
- **Logging**: a daemon thread prints JSON stats every second.
- **Saved files**:
  - Kept inputs go to `out/<Id>/corpus`, with metadata in `out/<Id>/meta`.
  - Every input of 4 KB or more is also written to `out/<Id>/current.bin` and `current.json` before it runs, so an input killed by the timeout can be replayed.
  - The guidance never declares an execution failed.

#### Part C — Runner, replay, scripts
- **`dosguide/run/FuzzRunner`**:
  - Usage: `FuzzRunner <V1|PkgRisk1> [seconds] [outDir]`. With no seconds, or 0, it runs forever; `-Ddosguide.durationSec` also works.
  - It provides `createGuidance(String, File, long, PrintStream)`.
  - It calls `GuidedFuzzing.run(TEST_CLASS, method, cl, guidance, out)`.
- **`ReplayFeeder`**: replays a meta file or a `.bin` input. It prints the metadata, the record count, the connection-ID length histogram, how many records share one hash, and the first IDs in hex, then calls the frozen harness method directly.
- **`ClassOriginCheck`**: prints where `QuicheQuicCodec` and related classes are loaded from (should be `lib/*.jar`) and which loader holds `DoSCounters`.
- **Scripts and config**:
  - `build.sh`: runs the package build and assembles the agent jar.
  - `run.sh`: compiles, builds, runs the origin check, then runs each target with `-Xmx1g -Xss1m`. It is executable.
  - `analysis/launch.json`: tells DoSGuide how to build and run all of this.
  - `README.md`.
- **Unchanged**: the frozen `QuicCodecFuzzTest` and `pom.xml` were not touched.

#### Strategy vs. Zest and PerfFuzz

| Target | Strategy | Why Zest fails | Why PerfFuzz fails | Why this wins | Metric where it should win |
|---|---|---|---|---|---|
| V1 | Vulnerability-directed + dependency-aware + cost-gradient | Every packet takes the same branches, so coverage stops growing once the first packet is through. Random byte mutation essentially never produces two connection IDs with the same hash. | It scores branch-hit counts, which grow about linearly with packet count (harness crypto and connection setup per packet). The quadratic collision cost never shows up separately. | It counts tree-bucket node visits during the codec's lookup, the method where the quadratic cost happens. The carry operator produces colliding keys and the measured count confirms each one. | Time to first 20 s timeout; peak visits per lookup |
| PkgRisk1 | Dependency-aware + vulnerability-directed + cost-gradient | Same as V1. The JDK `HashMap` is not part of what Zest measures. | Same as V1. | It counts visits inside the JDK insertion path (`putTreeVal`/`find`) and favours visits per KB, i.e. the densest encoding. | Visits per KB; time to first timeout |

```IMPORT AUDIT
@Fuzz → edu.berkeley.cs.jqf.fuzz.Fuzz (frozen harness)
@RunWith → org.junit.runner.RunWith (frozen harness)
JQF → edu.berkeley.cs.jqf.fuzz.JQF (frozen harness)
Guidance → edu.berkeley.cs.jqf.fuzz.guidance.Guidance
GuidanceException → edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException
Result → edu.berkeley.cs.jqf.fuzz.guidance.Result
GuidedFuzzing → edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing
TraceEvent → edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent (generateCallBack signature only)
ClassReader → org.objectweb.asm.ClassReader
ClassWriter → org.objectweb.asm.ClassWriter
ClassVisitor → org.objectweb.asm.ClassVisitor
MethodVisitor → org.objectweb.asm.MethodVisitor
Opcodes → org.objectweb.asm.Opcodes
ClassFileTransformer → java.lang.instrument.ClassFileTransformer
Instrumentation → java.lang.instrument.Instrumentation
SignalSource → dosguide.validate.SignalSource
```
All JQF signatures were checked with `javap` against `jqf-fuzz-2.1.jar`.

#### Self-checklist
- JDK 17+ only — YES: release 17, javac 17.0.20.
- No hallucinated APIs — YES: checked with `javap`.
- Guidance implements `Guidance` directly — YES: both classes.
- No existing guidance extended — YES.
- V* vulnerabilities identified — YES: V1.
- V* IDs sequential, not from version numbers [R42] — YES.
- Official names applied — YES: CWE-407.
- PkgRisk-* identified — YES: PkgRisk1.
- Every PkgRisk-* executed or justified — YES: through `fuzzQuicServerCodecChannelRead2`.
- Guidance targets V* and PkgRisk-* — YES: one guidance each.
- One fuzz method per V* or PkgRisk — YES: from the frozen harness.
- CLI method selection supported — YES: `FuzzRunner <V1|PkgRisk1>`.
- byte[]/InputStream input model only — YES.
- No junit-quickcheck generators — YES.
- All mutation inside the guidance — YES.
- Repetition, source dictionary and encoder operators [R45] — YES: repetition and dictionary implemented; no encoder needed because the harness builds the packet encryption.
- Retention progresses while the signal is flat; inputs can reach `input_bytes` within a minute [R46] — YES by design (length-per-level retention plus 30% growth on the longest input); not yet run.
- Retention signals measured where the resource is consumed [R47] — YES: counted inside `TreeNode.find`, within the sink's scope.
- Logging every 1 second — YES: daemon thread.
- Guidance decides no failures and writes no failure files [R6] — YES.
- Corrupted inputs saved with metadata — YES: corpus and meta files, plus `current.bin`/`current.json` for large inputs.
- Replay/feeder implemented — YES: `ReplayFeeder`.
- Infinite and time-bounded fuzzing — YES.
- `src/main` vs `src/test` separation — YES: everything is under `src/test`.
- Maven scopes consistent — YES: `pom.xml` unchanged.
- No wildcard imports for JQF/tracing — YES.
- `TraceEvent` import verified and audited — YES.

## Validation repair 1

```text
$ ls; ls analysis; find . -maxdepth 3 -newer build.sh -type d | grep -v target/ | head -30
$ python3 -I - <<'EOF' …
$ python3 -I - <<'EOF' …
Edit <run_dir>/src/test/java/dosguide/guidance/RecordMutator.java
Edit <run_dir>/src/test/java/dosguide/guidance/RecordMutator.java
Edit <run_dir>/src/test/java/dosguide/guidance/RecordMutator.java
Edit <run_dir>/src/test/java/dosguide/guidance/RecordMutator.java
Edit <run_dir>/src/test/java/dosguide/guidance/V1Guidance.java
Edit <run_dir>/src/test/java/dosguide/guidance/V1Guidance.java
Edit <run_dir>/src/test/java/dosguide/guidance/PkgRisk1Guidance.java
Edit <run_dir>/src/test/java/dosguide/guidance/PkgRisk1Guidance.java
Edit <run_dir>/src/test/java/dosguide/agent/DoSCounters.java
Edit <run_dir>/src/test/java/dosguide/agent/DoSCounters.java
Edit <run_dir>/src/test/java/dosguide/agent/DoSTransformer.java
Edit <run_dir>/src/test/java/dosguide/agent/DoSTransformer.java
Edit <run_dir>/src/test/java/dosguide/agent/DoSTransformer.java
Edit <run_dir>/src/test/java/dosguide/agent/DoSTransformer.java
Edit <run_dir>/src/test/java/dosguide/agent/DoSMeasureAgent.java
```

Wiring the measured datagram-bytes denominator into PkgRisk1, then rebuilding.

```text
Edit <run_dir>/src/test/java/dosguide/guidance/PkgRisk1Guidance.java
Edit <run_dir>/src/test/java/dosguide/guidance/PkgRisk1Guidance.java
Edit <run_dir>/src/test/java/dosguide/guidance/V1Guidance.java
$ bash build.sh 2>&1 | tail -20
```

I've changed both guidances and the agent to address the failed checks. The workspace and agent jar rebuild cleanly, but nothing has been run yet; your next validation pass is the real test.

**1. V1 growth (hard failure).** One mutation could jump straight to a ~413 KB input in which every record collides. That input ran past 20 s, so the probe stopped before any long input was recorded (the longest it saw was 2,633 bytes). Growth now happens in two separate ways:
- **Flat growth** (30% of iterations, until the longest input reaches `input_bytes`): new `appendFresh` takes the longest input, adds fresh random records until it doubles, and cuts at `input_bytes`. This should reach 413 KB in about 15 cheap steps, roughly 1 s per execution even at full size.
- **Dense growth** (10% of iterations below the target size, 25% after): new `growDense` takes the highest-scoring input and adds a hash-preserving clone of every record, doubling it. Above `input_bytes` it clones only about a quarter of the records, so growth slows to ×1.25. This route can grow inputs up to the input size limit.
- `chooseK` no longer jumps to the target size; one repetition step now at most doubles the input.

**2. PkgRisk1 progress (advisory).** Your log shows the 176 KB input did reach about 128M tree visits, roughly the series level. The longest input, though, was a 352 KB raw doubling of non-colliding records, with 51 visits.
- Ordinary mutations of ordinary parents now stop growing at `max(parent length, input_bytes)`. Inputs longer than the target size therefore come only from dense growth, which keeps the colliding structure.
- `doubleWithCarry` no longer appends exact duplicate records. A duplicate only hits the existing channel and adds no work.

**3. `p1VisitsPerKB` varying between repeats.** It divided by the guidance's own copy of the last input. That copy is wrong when the validator feeds the inputs itself.
- The agent now also rewrites `QuicheQuicCodec#channelRead` and adds up the bytes of each datagram it receives. `p1VisitsPerKB` is now `p1TreeVisits` per KB of those bytes, so it depends only on the execution. The plan below is updated to match.
- The small differences in `p1KeyEquals` (477 vs 481) are probably real. The JDK breaks ties between colliding keys by identity hash, which differs from run to run, so the tree shape (and how many comparisons a lookup makes) varies slightly. I left this as is.

**4. Instrumentation warning.** `HashMap$TreeNode` and `ByteBuffer` are loaded before the agent starts, so the agent re-instruments them after loading rather than at load time. The validator's list apparently only shows classes instrumented at load time. They are being instrumented: V1's `v1TreeVisits` reached 141,184, which can only come from the hook in `TreeNode.find`. The agent now prints "(retransformed)" for these classes on stderr and stores the list of instrumented classes in `DoSCounters.transformedNames`. Each guidance's start log prints it.

BEGIN_GUIDANCE_PLAN_JSON
{
  "plans": [
    {
      "target": "V1",
      "signals": [
        {
          "name": "v1TreeVisits",
          "quantity": "tree-bin nodes visited (one per read of TreeNode.hash) inside HashMap$TreeNode.find while QuicheQuicCodec.getChannel is on the stack",
          "aggregation": "sum",
          "locations": ["java.util.HashMap$TreeNode#find", "io.netty.incubator.codec.quic.QuicheQuicCodec#getChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.v1TreeVisits (bootstrap-loaded), gated by static int DoSCounters.v1Scope and the owner thread",
          "reset": "DoSCounters.reset() in V1Guidance.getInput()",
          "read": "V1Guidance.handleResult()"
        },
        {
          "name": "v1MaxPerLookup",
          "quantity": "largest number of tree-bin nodes visited during a single getChannel call",
          "aggregation": "max",
          "locations": ["io.netty.incubator.codec.quic.QuicheQuicCodec#getChannel", "java.util.HashMap$TreeNode#find"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.v1MaxPerLookup, updated at getChannel exit from a per-call delta",
          "reset": "DoSCounters.reset() in V1Guidance.getInput()",
          "read": "V1Guidance.handleResult()"
        },
        {
          "name": "v1KeyEquals",
          "quantity": "ByteBuffer.equals key comparisons inside getChannel (covers list bins before treeification)",
          "aggregation": "count",
          "locations": ["java.nio.ByteBuffer#equals", "io.netty.incubator.codec.quic.QuicheQuicCodec#getChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.v1KeyEquals",
          "reset": "DoSCounters.reset() in V1Guidance.getInput()",
          "read": "V1Guidance.handleResult()"
        },
        {
          "name": "channelsAdded",
          "quantity": "number of QuicheQuicCodec.addChannel invocations (distinct connections whose DCID entered the map)",
          "aggregation": "count",
          "locations": ["io.netty.incubator.codec.quic.QuicheQuicCodec#addChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.channelsAdded",
          "reset": "DoSCounters.reset() in V1Guidance.getInput()",
          "read": "V1Guidance.handleResult()"
        }
      ],
      "retention": "Keep the input if v1TreeVisits, v1MaxPerLookup, v1KeyEquals or channelsAdded reaches a new maximum, or (flat-signal criterion) if it is longer than every kept input at the same log2 level of v1TreeVisits while that level's longest is below input_bytes=413000. Scheduling: with probability 0.30, while the longest kept input is below input_bytes, apply flat growth to it (append fresh records until it doubles, cut at input_bytes). With probability 0.10 (0.25 once input_bytes is reached), apply dense growth to the highest-scoring input (hash-preserving carry clone of every record, x2; x1.25 above input_bytes; up to MAX_INPUT_SIZE). Otherwise mutate a parent chosen by rank (v1TreeVisits, then v1MaxPerLookup), with growth bounded by max(parent length, input_bytes). Fresh records prefer 20-byte DCIDs. Corpus in out/V1/corpus, metadata in out/V1/meta.",
      "retention_signals": ["v1TreeVisits", "v1MaxPerLookup", "v1KeyEquals", "channelsAdded"],
      "mutation": ["byte flip/set/insert/delete", "record-level replace/insert/splice/length, using the harness's [len][dcid] parse", "repetition: repeat a run of records k times (k up to doubling the input) and double the whole input", "flat growth: append fresh records until the input doubles, toward input_bytes", "dense growth / clone with hash-preserving carry: per-record (+31,-1)/(-31,+1) adjacent-byte adjustments derived from the ByteBuffer.hashCode base-31 polynomial, applied to whatever records the search selected", "dictionary tokens from the attack path: 20 (Quic.MAX_CONN_ID_LEN), 8, 10, 0, 31, 0x7f, 0x80, 0xff, 1", "no encoder needed: the harness applies the QUIC Initial protection"]
    },
    {
      "target": "PkgRisk1",
      "signals": [
        {
          "name": "p1TreeVisits",
          "quantity": "tree-bin nodes visited inside HashMap$TreeNode.find while HashMap$TreeNode.putTreeVal runs within QuicheQuicCodec.addChannel",
          "aggregation": "sum",
          "locations": ["java.util.HashMap$TreeNode#find", "java.util.HashMap$TreeNode#putTreeVal", "io.netty.incubator.codec.quic.QuicheQuicCodec#addChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.p1TreeVisits, gated by DoSCounters.addScope and DoSCounters.putScope and the owner thread",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        },
        {
          "name": "p1VisitsPerKB",
          "quantity": "p1TreeVisits divided by the KB of datagram content received by QuicheQuicCodec.channelRead in the same execution (both measured)",
          "aggregation": "ratio",
          "locations": ["java.util.HashMap$TreeNode#find", "io.netty.incubator.codec.quic.QuicheQuicCodec#channelRead"],
          "technique": "bytecode",
          "storage": "DoSCounters.p1TreeVisits and DoSCounters.datagramBytes (incremented at channelRead entry by msg.content().readableBytes()); ratio computed in PkgRisk1Guidance.handleResult()",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        },
        {
          "name": "p1Treeify",
          "quantity": "HashMap$TreeNode.treeify invocations within addChannel (a colliding bin crossed TREEIFY_THRESHOLD)",
          "aggregation": "count",
          "locations": ["java.util.HashMap$TreeNode#treeify"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.p1Treeify",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        },
        {
          "name": "p1KeyEquals",
          "quantity": "ByteBuffer.equals key comparisons during insertion inside addChannel (list bins before treeification)",
          "aggregation": "count",
          "locations": ["java.nio.ByteBuffer#equals", "io.netty.incubator.codec.quic.QuicheQuicCodec#addChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.p1KeyEquals",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        },
        {
          "name": "channelsAdded",
          "quantity": "number of QuicheQuicCodec.addChannel invocations",
          "aggregation": "count",
          "locations": ["io.netty.incubator.codec.quic.QuicheQuicCodec#addChannel"],
          "technique": "bytecode",
          "storage": "public static long DoSCounters.channelsAdded",
          "reset": "DoSCounters.reset() in PkgRisk1Guidance.getInput()",
          "read": "PkgRisk1Guidance.handleResult()"
        }
      ],
      "retention": "Keep the input if p1TreeVisits, p1VisitsPerKB, p1Treeify, p1KeyEquals or channelsAdded reaches a new maximum, or (flat-signal criterion) if it is longer than every kept input at the same log2 level of p1TreeVisits while that level's longest is below input_bytes=176000. Scheduling: with probability 0.30, while the longest kept input is below input_bytes, apply flat growth to it (append fresh records until it doubles, cut at input_bytes). With probability 0.10 (0.25 once input_bytes is reached), apply dense growth to the highest-scoring input (hash-preserving carry clone of every record, x2; x1.25 above input_bytes; up to MAX_INPUT_SIZE). Otherwise mutate a parent chosen by rank (p1TreeVisits, then p1VisitsPerKB), with growth bounded by max(parent length, input_bytes). Fresh records prefer 8-10 byte DCIDs (densest encoding), plus a record-shortening operator. Corpus in out/PkgRisk1/corpus, metadata in out/PkgRisk1/meta.",
      "retention_signals": ["p1TreeVisits", "p1VisitsPerKB", "p1Treeify", "p1KeyEquals", "channelsAdded"],
      "mutation": ["byte flip/set/insert/delete", "record-level replace/insert/splice/length, using the harness's [len][dcid] parse", "repetition: repeat a run of records k times (k up to doubling the input) and double the whole input", "flat growth: append fresh records until the input doubles, toward input_bytes", "dense growth / clone with hash-preserving carry: per-record (+31,-1)/(-31,+1) adjacent-byte adjustments derived from the ByteBuffer.hashCode base-31 polynomial, applied to whatever records the search selected", "record shortening toward 8-10 byte DCIDs", "dictionary tokens from the attack path: 8, 10, 20 (Quic.MAX_CONN_ID_LEN), 0, 31, 0x7f, 0x80, 0xff, 1", "no encoder needed: the harness applies the QUIC Initial protection"]
    }
  ]
}
END_GUIDANCE_PLAN_JSON
