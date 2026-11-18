package com.fuzzer.guidance;

import io.netty.buffer.ByteBuf;

/**
 * Thread-local signal storage for V1 target (Snappy capacity growth measurement).
 * Bytecode injected by V1MeasureAgent into Snappy.decode() calls the static
 * methods here to record the capacity of the {@code out} ByteBuf before and
 * after each decode invocation.
 *
 * <p>Index 0 of the long[] accumulator holds the running total of capacity growth
 * across all Snappy.decode() calls in the current fuzz execution.
 * Index 1 holds the baseline capacity recorded at method entry (temporary).</p>
 */
public final class V1Signal {

    // [0] = accumulated capacity growth for this execution
    // [1] = baseline capacity at most recent decode entry
    private static final ThreadLocal<long[]> COUNTERS =
            ThreadLocal.withInitial(() -> new long[2]);

    private V1Signal() { } // utility class

    /**
     * Reset the accumulator. Called by V1Guidance.getInput() before each execution.
     */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0L;
        c[1] = 0L;
    }

    /**
     * Injected at entry of {@code Snappy.decode(ByteBuf in, ByteBuf out)}.
     * Records {@code out.capacity()} as the baseline for this call.
     *
     * @param out the {@code out} parameter (slot 2), passed as Object to avoid
     *            requiring ByteBuf on the agent's classpath
     */
    public static void onDecodeEntry(Object out) {
        try {
            long cap = ((ByteBuf) out).capacity();
            COUNTERS.get()[1] = cap;
        } catch (Throwable ignored) {
            // Never let instrumentation break the target
        }
    }

    /**
     * Injected before each RETURN in {@code Snappy.decode(ByteBuf in, ByteBuf out)}.
     * Computes the capacity growth = current capacity - baseline, and adds it to
     * the running total.
     *
     * @param out the {@code out} parameter (slot 2)
     */
    public static void onDecodeExit(Object out) {
        try {
            long cap = ((ByteBuf) out).capacity();
            long[] c = COUNTERS.get();
            long growth = cap - c[1];
            if (growth > 0) {
                c[0] += growth;
            }
            c[1] = 0L; // clear baseline
        } catch (Throwable ignored) {
            // Never let instrumentation break the target
        }
    }

    /**
     * Read the accumulated capacity growth for the current execution.
     * Called by V1Guidance.handleResult() after the fuzz test completes.
     */
    public static long getCapacityGrowth() {
        return COUNTERS.get()[0];
    }
}
