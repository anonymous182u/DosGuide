package org.jose4j.fuzz.agent;

/**
 * Shared counters for measuring DeflateRFC1951CompressionAlgorithm.decompress() output.
 * Lives on the app classloader alongside both the instrumented jose4j class and
 * the V1Guidance — no bootstrap classloader needed.
 *
 * Index 0: total decompressed bytes (sum of decompress() return array lengths)
 * Index 1: number of decompress() calls
 */
public final class InflateCounters {

    private static final ThreadLocal<long[]> COUNTERS =
            ThreadLocal.withInitial(() -> new long[2]);

    /** Called by instrumented decompress() — adds the returned array length. */
    public static void addBytes(int n) {
        if (n > 0) {
            long[] c = COUNTERS.get();
            c[0] += n;
            c[1]++;
        }
    }

    /** Returns [totalInflatedBytes, inflateCallCount] for the current thread. */
    public static long[] get() {
        return COUNTERS.get();
    }

    /** Resets counters to zero before each fuzz execution. */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
    }
}
