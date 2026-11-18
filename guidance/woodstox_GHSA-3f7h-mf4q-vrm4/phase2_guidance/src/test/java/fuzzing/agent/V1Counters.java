package fuzzing.agent;

/**
 * Thread-local counters for measuring recursion depth of
 * FullDTDReader#readContentSpec. Loaded on the bootstrap classloader
 * (via Instrumentation.appendToBootstrapClassLoaderSearch) so that both
 * the instrumented Woodstox code and the Guidance can access it.
 *
 * Index 0 = current recursion depth (incremented on entry, decremented on exit).
 * Index 1 = maximum recursion depth observed during this execution.
 */
public final class V1Counters {

    // long[2]: [0] = currentDepth, [1] = maxDepth
    private static final ThreadLocal<long[]> COUNTERS =
            ThreadLocal.withInitial(() -> new long[]{0L, 0L});

    private V1Counters() { }

    /** Called at the start of each fuzz execution to zero the counters. */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0L;
        c[1] = 0L;
    }

    /** Called by instrumented code on entry to readContentSpec. */
    public static void enter() {
        long[] c = COUNTERS.get();
        c[0]++;
        if (c[0] > c[1]) {
            c[1] = c[0];
        }
    }

    /** Called by instrumented code on exit from readContentSpec. */
    public static void exit() {
        long[] c = COUNTERS.get();
        if (c[0] > 0) {
            c[0]--;
        }
    }

    /** Returns the maximum recursion depth recorded since the last reset. */
    public static long getMaxDepth() {
        return COUNTERS.get()[1];
    }

    /** Returns the current recursion depth. */
    public static long getCurrentDepth() {
        return COUNTERS.get()[0];
    }

    /** Returns the raw counter array. For direct access in the Guidance. */
    public static long[] get() {
        return COUNTERS.get();
    }
}
