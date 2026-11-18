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
