package fuzz.agent;

/**
 * Thread-local counters for measuring BigInteger operations inside DToA methods.
 * This class is placed in src/main/java so it is visible to both the agent-instrumented
 * DToA code (loaded from the Rhino jar) and the Guidance code (in test scope).
 *
 * NOT a copy of any Rhino class — this is new measurement infrastructure.
 */
public final class DToACounters {

    /*
     * Counter indices:
     *   [0] = BigInteger operation count (multiply, divideAndRemainder, pow) within DToA
     *   [1] = JS_dtoa entry time (nanoTime)
     *   [2] = JS_dtoa cumulative time (ns)
     *   [3] = JS_dtobasestr entry time (nanoTime)
     *   [4] = JS_dtobasestr cumulative time (ns)
     *   [5] = pow5mult call count
     *   [6] = JS_dtostr entry time (nanoTime)
     *   [7] = JS_dtostr cumulative time (ns)
     */
    private static final int NUM_COUNTERS = 8;

    private static final ThreadLocal<long[]> COUNTERS =
            ThreadLocal.withInitial(() -> new long[NUM_COUNTERS]);

    /** Reset all counters for a new execution. */
    public static void reset() {
        long[] c = COUNTERS.get();
        for (int i = 0; i < c.length; i++) {
            c[i] = 0L;
        }
    }

    /** Increment BigInteger operation counter. Called by instrumented DToA code. */
    public static void incrementBigIntOps() {
        COUNTERS.get()[0]++;
    }

    /** Record entry time for JS_dtoa. */
    public static void enterJsDtoa() {
        COUNTERS.get()[1] = System.nanoTime();
    }

    /** Record exit time for JS_dtoa, accumulate. */
    public static void exitJsDtoa() {
        long[] c = COUNTERS.get();
        if (c[1] != 0) {
            c[2] += System.nanoTime() - c[1];
            c[1] = 0;
        }
    }

    /** Record entry time for JS_dtobasestr. */
    public static void enterJsDtobasestr() {
        COUNTERS.get()[3] = System.nanoTime();
    }

    /** Record exit time for JS_dtobasestr, accumulate. */
    public static void exitJsDtobasestr() {
        long[] c = COUNTERS.get();
        if (c[3] != 0) {
            c[4] += System.nanoTime() - c[3];
            c[3] = 0;
        }
    }

    /** Increment pow5mult call count. */
    public static void incrementPow5mult() {
        COUNTERS.get()[5]++;
    }

    /** Record entry time for JS_dtostr. */
    public static void enterJsDtostr() {
        COUNTERS.get()[6] = System.nanoTime();
    }

    /** Record exit time for JS_dtostr, accumulate. */
    public static void exitJsDtostr() {
        long[] c = COUNTERS.get();
        if (c[6] != 0) {
            c[7] += System.nanoTime() - c[6];
            c[6] = 0;
        }
    }

    // --- Getters ---

    /** Total BigInteger operations (multiply/divideAndRemainder/pow) in DToA methods. */
    public static long getBigIntOps() {
        return COUNTERS.get()[0];
    }

    /** Cumulative wall-clock time inside JS_dtoa (nanoseconds). */
    public static long getJsDtoaTimeNs() {
        return COUNTERS.get()[2];
    }

    /** Cumulative wall-clock time inside JS_dtobasestr (nanoseconds). */
    public static long getJsDtobasestrTimeNs() {
        return COUNTERS.get()[4];
    }

    /** Number of pow5mult calls. */
    public static long getPow5multCalls() {
        return COUNTERS.get()[5];
    }

    /** Cumulative wall-clock time inside JS_dtostr (nanoseconds). */
    public static long getJsDtostrTimeNs() {
        return COUNTERS.get()[7];
    }
}
