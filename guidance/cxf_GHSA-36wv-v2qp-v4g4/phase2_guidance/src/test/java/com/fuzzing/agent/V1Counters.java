package com.fuzzing.agent;

/**
 * ThreadLocal signal storage for V1: measures chars appended to StringBuilder
 * in CachedOutputStream.writeCacheTo(StringBuilder, String).
 *
 * The agent injects calls to onEntry/onExit at the boundary of that method.
 * The Guidance reads getCharsAppended() after each execution.
 */
public final class V1Counters {

    // index 0 = StringBuilder.length() at method entry
    // index 1 = total chars appended across all calls in this execution
    private static final ThreadLocal<long[]> COUNTERS = ThreadLocal.withInitial(() -> new long[2]);

    private V1Counters() {}

    /** Reset before each execution (called by Guidance.getInput()). */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
    }

    /**
     * Called by injected bytecode at entry of writeCacheTo(StringBuilder, String).
     * Records the current StringBuilder.length() so the exit hook can compute the delta.
     */
    public static void onEntry(StringBuilder sb) {
        if (sb != null) {
            COUNTERS.get()[0] = sb.length();
        }
    }

    /**
     * Called by injected bytecode at exit of writeCacheTo(StringBuilder, String).
     * Accumulates the delta (chars appended) into index 1.
     */
    public static void onExit(StringBuilder sb) {
        if (sb != null) {
            long[] c = COUNTERS.get();
            long delta = sb.length() - c[0];
            if (delta > 0) {
                c[1] += delta;
            }
        }
    }

    /** Read the total chars appended in the current execution. */
    public static long getCharsAppended() {
        return COUNTERS.get()[1];
    }
}
