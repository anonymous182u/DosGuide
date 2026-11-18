package com.fasterxml.jackson.fuzz.agent;

/**
 * ThreadLocal counters for tracking nesting depth of BaseNodeDeserializer's
 * mutually recursive deserializeArray / deserializeObject methods.
 *
 * Layout: long[2] where [0] = current depth, [1] = max depth this execution.
 * The agent inserts calls to enter()/exit() around the instrumented methods.
 * The Guidance calls reset() before each execution and maxDepth() after.
 */
public final class NestingDepthCounters {

    private static final ThreadLocal<long[]> COUNTERS =
            ThreadLocal.withInitial(() -> new long[2]);

    /** Called by the agent at method entry. */
    public static void enter() {
        long[] c = COUNTERS.get();
        c[0]++;
        if (c[0] > c[1]) {
            c[1] = c[0];
        }
    }

    /** Called by the agent at method exit (in a finally block). */
    public static void exit() {
        long[] c = COUNTERS.get();
        c[0]--;
    }

    /** Called by the Guidance before each execution to zero both counters. */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
    }

    /** Called by the Guidance after each execution to read the peak depth. */
    public static long maxDepth() {
        return COUNTERS.get()[1];
    }

    private NestingDepthCounters() { }
}
