package com.fuzzing.agent;

/**
 * ThreadLocal counters for V1 measurement signals.
 * Instrumented by V1MeasureAgent at readBoundary/readHeaders/readByte.
 * Read by V1Guidance after each execution.
 */
public final class V1Counters {

    // slot[0] = boundaryIterations (readBoundary call count)
    // slot[1] = headerBytes (readByte calls while in readHeaders)
    // slot[2] = inHeaders flag (1 = inside readHeaders, 0 = outside)
    private static final ThreadLocal<long[]> COUNTERS = ThreadLocal.withInitial(() -> new long[3]);

    private V1Counters() {}

    /** Reset all counters before each execution. */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
        c[2] = 0;
    }

    /** Called at entry of readBoundary(). */
    public static void incrementBoundary() {
        COUNTERS.get()[0]++;
    }

    /** Called at entry of readHeaders(). */
    public static void enterHeaders() {
        COUNTERS.get()[2] = 1;
    }

    /** Called at every exit of readHeaders() (normal + exceptional). */
    public static void exitHeaders() {
        COUNTERS.get()[2] = 0;
    }

    /** Called at entry of readByte() — only increments if in readHeaders. */
    public static void onReadByte() {
        long[] c = COUNTERS.get();
        if (c[2] == 1) {
            c[1]++;
        }
    }

    public static long getBoundaryIterations() {
        return COUNTERS.get()[0];
    }

    public static long getHeaderBytes() {
        return COUNTERS.get()[1];
    }

    public static boolean isInHeaders() {
        return COUNTERS.get()[2] == 1;
    }
}
