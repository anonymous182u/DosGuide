package com.fuzzer;

/**
 * Shared iteration counter for V1 (Scalar25519.reduceBasisVar loop).
 * The agent instruments ScalarUtil.addShifted_NP and ScalarUtil.subShifted_NP
 * to call increment(). The Guidance reads the counter in handleResult().
 *
 * Placed on the bootstrap classpath by V1MeasureAgent so that both the
 * instrumented Bouncy Castle classes and the Guidance (on the app classpath)
 * see the same static field.
 */
public final class V1Counters {

    /**
     * Per-thread iteration counter. Index 0 holds the count of loop iterations
     * in reduceBasisVar for the current execution.
     */
    public static final ThreadLocal<long[]> ITERATIONS =
            ThreadLocal.withInitial(() -> new long[1]);

    /** Called by instrumented ScalarUtil.addShifted_NP / subShifted_NP. */
    public static void increment() {
        ITERATIONS.get()[0]++;
    }

    /** Reset before each fuzz execution. */
    public static void reset() {
        ITERATIONS.get()[0] = 0;
    }

    /** Read the current count. */
    public static long get() {
        return ITERATIONS.get()[0];
    }

    private V1Counters() {}
}
