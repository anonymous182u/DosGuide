package fuzzing.agent;

/**
 * ThreadLocal counters for measuring JSON parser recursion depth and node count.
 * Instrumented by DepthMeasureAgent into JSONParserBase methods.
 *
 * Index layout of the long[] array:
 *   [0] = currentDepth  (incremented on readArray/readObject entry, decremented on exit)
 *   [1] = maxDepth      (peak of currentDepth during the execution)
 *   [2] = nodeCount     (total entries into readArray + readObject + readMain)
 */
public final class DepthCounters {

    private static final ThreadLocal<long[]> COUNTERS = ThreadLocal.withInitial(() -> new long[3]);

    /** Called at the entry of readArray and readObject. */
    public static void enterDepth() {
        long[] c = COUNTERS.get();
        c[0]++;          // currentDepth
        if (c[0] > c[1]) {
            c[1] = c[0]; // maxDepth
        }
        c[2]++;          // nodeCount
    }

    /** Called at every exit (normal return or exception) of readArray and readObject. */
    public static void exitDepth() {
        long[] c = COUNTERS.get();
        c[0]--;          // currentDepth
    }

    /** Called at the entry of readMain (counts nodes but does not affect depth). */
    public static void enterNode() {
        COUNTERS.get()[2]++;
    }

    /** Reset all counters before a new execution. */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
        c[2] = 0;
    }

    /** Return the maximum recursion depth reached in the current/last execution. */
    public static long getMaxDepth() {
        return COUNTERS.get()[1];
    }

    /** Return the total number of parser node entries in the current/last execution. */
    public static long getNodeCount() {
        return COUNTERS.get()[2];
    }
}
