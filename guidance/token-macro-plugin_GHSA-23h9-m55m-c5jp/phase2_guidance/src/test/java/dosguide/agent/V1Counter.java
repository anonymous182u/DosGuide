package dosguide.agent;

/**
 * Thread-local counter incremented by the DoSMeasureAgent each time
 * {@code Parser#processToken()} is entered.  The Guidance resets before
 * each execution and reads after {@code handleResult}.
 */
public final class V1Counter {

    /** One-element array avoids boxing; index 0 = invocation count. */
    public static final ThreadLocal<long[]> count =
            ThreadLocal.withInitial(() -> new long[]{0});

    /** Called from instrumented bytecode. */
    public static void increment() {
        count.get()[0]++;
    }

    /** Called by the Guidance before each execution. */
    public static void reset() {
        count.get()[0] = 0;
    }

    private V1Counter() { }
}
