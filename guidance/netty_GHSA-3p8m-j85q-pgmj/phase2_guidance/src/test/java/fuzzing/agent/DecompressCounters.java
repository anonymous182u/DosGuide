package fuzzing.agent;

/**
 * ThreadLocal counters for measuring decompressed bytes emitted by
 * BrotliDecoder and ZstdDecoder.  Populated by the DecompressAgent's
 * bytecode instrumentation; read by the Guidance after each execution.
 *
 * Index 0 = brotli decompressed bytes, Index 1 = zstd decompressed bytes.
 */
public final class DecompressCounters {

    private static final ThreadLocal<long[]> COUNTERS =
            ThreadLocal.withInitial(() -> new long[2]);

    private DecompressCounters() { }

    /** Reset both counters to zero (called before each fuzz execution). */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
    }

    /** Called by the agent from BrotliDecoder#pull before ARETURN. */
    public static void addBrotliBytes(long bytes) {
        COUNTERS.get()[0] += bytes;
    }

    /** Called by the agent from ZstdDecoder#decode before List.add. */
    public static void addZstdBytes(long bytes) {
        COUNTERS.get()[1] += bytes;
    }

    public static long getBrotliBytes() {
        return COUNTERS.get()[0];
    }

    public static long getZstdBytes() {
        return COUNTERS.get()[1];
    }
}
