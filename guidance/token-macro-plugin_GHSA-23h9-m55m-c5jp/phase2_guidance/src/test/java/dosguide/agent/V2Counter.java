package dosguide.agent;

/**
 * Thread-local counter incremented by {@link CharSequenceProxy#charAt}
 * each time the regex engine reads a character.  The count approximates
 * the number of regex-VM steps / backtracking states (R36).
 *
 * The Guidance resets before each execution and reads after
 * {@code handleResult}.  The signal name in the plan is "findNanos"
 * (historical); the value is a step count, not nanoseconds.
 */
public final class V2Counter {

    /** One-element array avoids boxing; index 0 = charAt access count. */
    public static final ThreadLocal<long[]> findNanos =
            ThreadLocal.withInitial(() -> new long[]{0});

    /** Called from {@link CharSequenceProxy#charAt}. */
    public static void increment() {
        findNanos.get()[0]++;
    }

    /** Called by the Guidance before each execution. */
    public static void reset() {
        findNanos.get()[0] = 0;
    }

    private V2Counter() { }
}
