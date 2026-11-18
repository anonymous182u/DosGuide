package fuzzing.agent;

/**
 * ThreadLocal counters for tracking JSONML.parse() recursion depth.
 * Called by bytecode injected by V1DepthTransformer and read by V1Guidance.
 *
 * Layout: long[2] where [0] = current depth, [1] = max depth this execution.
 */
public final class V1DepthCounters {

    private static final ThreadLocal<long[]> COUNTERS =
            ThreadLocal.withInitial(() -> new long[2]);

    /** Reset both current and max depth to zero.  Called before each execution. */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
    }

    /** Called at the entry of every JSONML.parse() invocation. */
    public static void onEnter() {
        long[] c = COUNTERS.get();
        c[0]++;
        if (c[0] > c[1]) {
            c[1] = c[0];
        }
    }

    /** Called at every normal return of JSONML.parse(). */
    public static void onExit() {
        long[] c = COUNTERS.get();
        if (c[0] > 0) {
            c[0]--;
        }
    }

    /** Return the maximum recursion depth recorded since the last reset(). */
    public static long maxDepth() {
        return COUNTERS.get()[1];
    }
}
