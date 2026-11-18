package org.xnio.fuzz.agent;

/**
 * Thread-local recursion depth counters, incremented/decremented by the
 * custom Java agent at instrumented method entry/exit.
 * <p>
 * For each target the array is:
 *   [0] = current recursion depth
 *   [1] = maximum depth seen during the current execution
 * <p>
 * Measurement-only: does not generate inputs or embed payloads.
 */
public final class RecursionCounters {

    private RecursionCounters() {}

    // V1: NotifierState.notifyDone recursion depth
    private static final ThreadLocal<long[]> NOTIFY_DEPTH =
            ThreadLocal.withInitial(() -> new long[2]);

    // V2: CancellableState.cancel recursion depth
    private static final ThreadLocal<long[]> CANCEL_DEPTH =
            ThreadLocal.withInitial(() -> new long[2]);

    // --- V1: called by instrumented NotifierState.notifyDone ---

    public static void enterNotify() {
        long[] d = NOTIFY_DEPTH.get();
        d[0]++;
        if (d[0] > d[1]) d[1] = d[0];
    }

    public static void exitNotify() {
        NOTIFY_DEPTH.get()[0]--;
    }

    public static long getNotifyMaxDepth() {
        return NOTIFY_DEPTH.get()[1];
    }

    public static void resetNotify() {
        long[] d = NOTIFY_DEPTH.get();
        d[0] = 0;
        d[1] = 0;
    }

    // --- V2: called by instrumented CancellableState.cancel ---

    public static void enterCancel() {
        long[] d = CANCEL_DEPTH.get();
        d[0]++;
        if (d[0] > d[1]) d[1] = d[0];
    }

    public static void exitCancel() {
        CANCEL_DEPTH.get()[0]--;
    }

    public static long getCancelMaxDepth() {
        return CANCEL_DEPTH.get()[1];
    }

    public static void resetCancel() {
        long[] d = CANCEL_DEPTH.get();
        d[0] = 0;
        d[1] = 0;
    }
}
