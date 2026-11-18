package fuzzing.agent;

/**
 * ThreadLocal counters for V1 (readStored stale-buffer re-serving).
 * Written by V1MeasureAgent at the instrumented readStored return sites.
 * Read by V1Guidance in handleResult().
 */
public final class V1Counters {

    private static final ThreadLocal<long[]> STORED_BYTES = ThreadLocal.withInitial(() -> new long[1]);

    /** Add bytes returned by one readStored call (called from instrumented bytecode). */
    public static void addBytes(int n) {
        if (n > 0) {
            STORED_BYTES.get()[0] += n;
        }
    }

    /** Get total storedBytesRead for the current execution. */
    public static long get() {
        return STORED_BYTES.get()[0];
    }

    /** Reset before each execution. */
    public static void reset() {
        STORED_BYTES.get()[0] = 0;
    }

    private V1Counters() {}
}
