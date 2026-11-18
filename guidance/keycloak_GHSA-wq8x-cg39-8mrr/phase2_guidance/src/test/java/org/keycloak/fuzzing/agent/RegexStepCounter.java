package org.keycloak.fuzzing.agent;

/**
 * ThreadLocal counter for regex NFA backtracking steps.
 * <p>
 * Added to the bootstrap classpath by {@link V1MeasureAgent} so that
 * instrumented {@code java.util.regex.Pattern$Node} subclasses (which are
 * bootstrap classes) can call {@link #increment()}.
 * <p>
 * The Guidance resets the counter before each execution via
 * {@link #getAndReset()} and reads it after via {@link #get()}.
 */
public final class RegexStepCounter {

    private static final ThreadLocal<long[]> STEPS =
            ThreadLocal.withInitial(() -> new long[]{0L});

    /** Called by injected bytecode in Pattern$Node.match(). */
    public static void increment() {
        STEPS.get()[0]++;
    }

    /** Return the current step count for this thread. */
    public static long get() {
        return STEPS.get()[0];
    }

    /** Return the current count and reset to zero. */
    public static long getAndReset() {
        long[] arr = STEPS.get();
        long val = arr[0];
        arr[0] = 0L;
        return val;
    }

    private RegexStepCounter() { }
}
