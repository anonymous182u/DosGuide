package v1;

/**
 * ThreadLocal counters for measuring recursion depth in Composer.composeNode().
 * Injected by V1DepthAgent bytecode instrumentation at method entry/exit.
 *
 * Indices in the long[]: [0] = current depth, [1] = max depth, [2] = node count.
 */
public final class DepthCounters {

    private static final ThreadLocal<long[]> COUNTERS = ThreadLocal.withInitial(() -> new long[3]);

    /** Called at entry of Composer.composeNode by injected bytecode. */
    public static void enter() {
        long[] c = COUNTERS.get();
        c[0]++;          // current depth
        if (c[0] > c[1]) {
            c[1] = c[0]; // max depth
        }
        c[2]++;           // node count
    }

    /** Called at exit of Composer.composeNode by injected bytecode. */
    public static void exit() {
        long[] c = COUNTERS.get();
        c[0]--;
    }

    /** Reset all counters — called before each fuzz execution. */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
        c[2] = 0;
    }

    /** Maximum recursion depth seen since last reset. */
    public static long getMaxDepth() {
        return COUNTERS.get()[1];
    }

    /** Total node count (calls to composeNode) since last reset. */
    public static long getNodeCount() {
        return COUNTERS.get()[2];
    }
}
