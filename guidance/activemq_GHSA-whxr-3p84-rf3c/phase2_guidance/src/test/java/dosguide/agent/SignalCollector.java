package dosguide.agent;

/**
 * Shared static signal storage for the DoS fuzz agent.
 * The custom Java agent injects bytecode that writes to these fields;
 * each Guidance reads from them after execution completes.
 *
 * All signals are per-thread to allow concurrent fuzz trials (though JQF
 * runs single-threaded). Reset before each execution by the Guidance.
 */
public final class SignalCollector {

    private SignalCollector() {}

    // ── V1: allocation size in looseUnmarshalByteArray ──
    // Stores the total bytes requested via new byte[size].
    // Written by injected bytecode before NEWARRAY in BaseDataStreamMarshaller.looseUnmarshalByteArray.
    private static final ThreadLocal<long[]> ALLOC_BYTES = ThreadLocal.withInitial(() -> new long[]{0L});

    // ── V2: throwable recursion depth in looseUnmarsalThrowable ──
    // [0] = current depth, [1] = max depth seen this execution.
    private static final ThreadLocal<int[]> THROWABLE_DEPTH = ThreadLocal.withInitial(() -> new int[]{0, 0});

    // ── V3: nesting depth in looseUnmarsalNestedObject ──
    // [0] = current depth, [1] = max depth seen this execution.
    private static final ThreadLocal<int[]> NESTING_DEPTH = ThreadLocal.withInitial(() -> new int[]{0, 0});

    /** Reset all signals before each fuzz execution. */
    public static void reset() {
        ALLOC_BYTES.get()[0] = 0L;
        int[] td = THROWABLE_DEPTH.get();
        td[0] = 0; td[1] = 0;
        int[] nd = NESTING_DEPTH.get();
        nd[0] = 0; nd[1] = 0;
    }

    // ── V1 accessors ──

    /** Called by injected bytecode: records the size of a new byte[] allocation. */
    public static void recordAlloc(int size) {
        if (size > 0) {
            ALLOC_BYTES.get()[0] += size;
        }
    }

    /** Read total allocation bytes for this execution. */
    public static long getAllocBytes() {
        return ALLOC_BYTES.get()[0];
    }

    // ── V2 accessors ──

    /** Called by injected bytecode on entry to looseUnmarsalThrowable. */
    public static void enterThrowable() {
        int[] td = THROWABLE_DEPTH.get();
        td[0]++;
        if (td[0] > td[1]) td[1] = td[0];
    }

    /** Called by injected bytecode on exit from looseUnmarsalThrowable. */
    public static void exitThrowable() {
        int[] td = THROWABLE_DEPTH.get();
        if (td[0] > 0) td[0]--;
    }

    /** Read max throwable recursion depth for this execution. */
    public static int getThrowableDepth() {
        return THROWABLE_DEPTH.get()[1];
    }

    // ── V3 accessors ──

    /** Called by injected bytecode on entry to looseUnmarsalNestedObject. */
    public static void enterNesting() {
        int[] nd = NESTING_DEPTH.get();
        nd[0]++;
        if (nd[0] > nd[1]) nd[1] = nd[0];
    }

    /** Called by injected bytecode on exit from looseUnmarsalNestedObject. */
    public static void exitNesting() {
        int[] nd = NESTING_DEPTH.get();
        if (nd[0] > 0) nd[0]--;
    }

    /** Read max nesting depth for this execution. */
    public static int getNestingDepth() {
        return NESTING_DEPTH.get()[1];
    }
}
