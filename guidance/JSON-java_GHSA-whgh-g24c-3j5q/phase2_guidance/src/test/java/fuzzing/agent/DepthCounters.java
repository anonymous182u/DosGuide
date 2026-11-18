package fuzzing.agent;

/**
 * Volatile static counters for measuring JSONTokener.nextValue() recursion depth.
 * Uses volatile statics (not ThreadLocal) to avoid classloader mismatch issues
 * between the instrumented target code and the guidance.
 *
 * Fields:
 *   currentDepth — incremented on enter, decremented on exit
 *   maxDepth     — high-water mark for the execution
 *   nodeCount    — total enter() calls in the execution
 */
public final class DepthCounters {

    private static volatile long currentDepth = 0;
    private static volatile long maxDepth = 0;
    private static volatile long nodeCount = 0;

    /** Called at entry of JSONTokener.nextValue(). */
    public static void enter() {
        long d = currentDepth + 1;
        currentDepth = d;
        nodeCount = nodeCount + 1;
        if (d > maxDepth) {
            maxDepth = d;
        }
    }

    /** Called at exit (normal return) of JSONTokener.nextValue(). */
    public static void exit() {
        currentDepth = currentDepth - 1;
    }

    /** Reset all counters before the next execution. */
    public static void reset() {
        currentDepth = 0;
        maxDepth = 0;
        nodeCount = 0;
    }

    /** Return the max depth reached since the last reset. */
    public static long getMaxDepth() {
        return maxDepth;
    }

    /** Return the total invocation count since the last reset. */
    public static long getNodeCount() {
        return nodeCount;
    }

    private DepthCounters() { }
}
