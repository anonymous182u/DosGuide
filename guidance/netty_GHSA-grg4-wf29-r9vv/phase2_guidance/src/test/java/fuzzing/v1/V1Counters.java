package fuzzing.v1;

/**
 * Measurement counters for target V1 (Bzip2Decoder multi-block decompression bomb).
 *
 * <p>Written ONLY by bytecode that {@code fuzzing.agent.V1Transformer} inserts into
 * {@code io.netty.handler.codec.compression.Bzip2BlockDecompressor}:</p>
 * <ul>
 *   <li>{@code read()}        IRETURN -> {@link #onRead(int)}       (each decoded output byte)</li>
 *   <li>{@code blockLength()} IRETURN -> {@link #onBlockLength(int)} (block reached DECODE_HUFFMAN_DATA output stage)</li>
 *   <li>{@code checkCRC()}    IRETURN -> {@link #onBlockAccepted()} (block passed CRC; Bzip2Decoder.decode then
 *       calls out.add(uncompressed) and keeps the block in the out list)</li>
 * </ul>
 * <p>Reset by {@code V1Guidance.getInput()} before each execution and read by
 * {@code V1Guidance.handleResult()}. The decoder runs on the fuzzing thread (EmbeddedChannel), so plain
 * static fields are sufficient; they are volatile only so the 1 s logger thread sees recent values.</p>
 */
public final class V1Counters {
    private V1Counters() { }

    /** Number of methods the agent instrumented (0 means the agent is not attached). */
    public static volatile int instrumentedMethods;

    public static volatile long decodedBytes;
    public static volatile long retainedBytes;
    public static volatile long validBlocks;
    public static volatile long bwtBytes;
    public static volatile long blocksReached;
    public static volatile long currentBlockBytes;

    public static void reset() {
        decodedBytes = 0;
        retainedBytes = 0;
        validBlocks = 0;
        bwtBytes = 0;
        blocksReached = 0;
        currentBlockBytes = 0;
    }

    /** Called with the return value of Bzip2BlockDecompressor#read(); -1 means end of block. */
    public static void onRead(int value) {
        if (value >= 0) {
            decodedBytes++;
            currentBlockBytes++;
        }
    }

    /** Called with the return value of Bzip2BlockDecompressor#blockLength() (once per block, before output). */
    public static void onBlockLength(int bwtLength) {
        blocksReached++;
        bwtBytes += bwtLength;
        currentBlockBytes = 0;
    }

    /** Called when Bzip2BlockDecompressor#checkCRC() returns normally (CRC matched). */
    public static void onBlockAccepted() {
        validBlocks++;
        retainedBytes += currentBlockBytes;
        currentBlockBytes = 0;
    }
}
