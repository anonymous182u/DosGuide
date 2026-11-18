package com.fuzzer.agent;

/**
 * Thread-safe counter for sort comparisons inside QuotedQualityCSV.sort().
 * Instrumented by V1MeasureAgent via ASM bytecode transformation.
 * Measurement-only — does not generate inputs or embed payloads ([R37]).
 */
public final class V1Counters {

    /**
     * Per-thread counter: [0] = number of Double.compareTo() calls in sort().
     * ThreadLocal ensures correctness if JQF runs executions on different threads.
     */
    private static final ThreadLocal<long[]> SORT_COMPARISONS =
            ThreadLocal.withInitial(() -> new long[1]);

    /** Called by instrumented bytecode before each Double.compareTo in sort(). */
    public static void incrementComparisons() {
        SORT_COMPARISONS.get()[0]++;
    }

    /** Read the comparison count after an execution completes. */
    public static long getComparisons() {
        return SORT_COMPARISONS.get()[0];
    }

    /** Reset the counter before each new execution. */
    public static void resetComparisons() {
        SORT_COMPARISONS.get()[0] = 0L;
    }

    private V1Counters() { }
}
