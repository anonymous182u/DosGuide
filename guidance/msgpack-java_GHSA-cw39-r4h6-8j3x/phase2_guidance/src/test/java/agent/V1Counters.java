package agent;

/**
 * ThreadLocal counters for tracking recursion depth of MessageUnpacker.unpackValue().
 * Index 0 = current depth, Index 1 = max depth observed during this execution.
 * Measurement-only ([R37]): does not generate inputs or embed payloads.
 */
public final class V1Counters {

    private static final ThreadLocal<long[]> COUNTERS = ThreadLocal.withInitial(() -> new long[2]);

    private V1Counters() {}

    /** Called at entry of unpackValue() by instrumented bytecode. */
    public static void enter() {
        long[] c = COUNTERS.get();
        c[0]++;
        if (c[0] > c[1]) {
            c[1] = c[0];
        }
    }

    /** Called at exit (normal or exceptional) of unpackValue() by instrumented bytecode. */
    public static void exit() {
        long[] c = COUNTERS.get();
        c[0]--;
    }

    /** Returns the maximum recursion depth observed since last reset. */
    public static long getMaxDepth() {
        return COUNTERS.get()[1];
    }

    /** Resets both current depth and max depth to 0 before each execution. */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
    }
}
