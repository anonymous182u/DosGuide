package com.fasterxml.jackson.fuzz.agent;

/**
 * ThreadLocal counter for tracking the maximum allocation size parameter
 * passed to CBORParser._finishBytes(int len) during execution.
 *
 * The agent inserts a call to record(len) at the entry of _finishBytes.
 * The Guidance calls reset() before each execution and maxLen() after.
 */
public final class AllocationSizeCounters {

    private static final ThreadLocal<long[]> COUNTERS =
            ThreadLocal.withInitial(() -> new long[1]);

    /**
     * Called by the agent at the entry of _finishBytes(int len).
     * Records the maximum len seen during this execution.
     */
    public static void record(long len) {
        long[] c = COUNTERS.get();
        if (len > c[0]) {
            c[0] = len;
        }
    }

    /** Called by the Guidance before each execution. */
    public static void reset() {
        COUNTERS.get()[0] = 0;
    }

    /** Called by the Guidance after each execution. */
    public static long maxLen() {
        return COUNTERS.get()[0];
    }

    private AllocationSizeCounters() { }
}
