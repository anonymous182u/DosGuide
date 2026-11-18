package tech.kwik.fuzz.agent;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Shared counter for {@code ConnectionSource.equals} invocations.
 * <p>
 * This class is added to the bootstrap class loader by {@link V1MeasureAgent}
 * so it is visible from every class loader in the JVM.
 */
public final class V1Counters {

    private static final AtomicLong EQUALS_COUNT = new AtomicLong(0);

    private V1Counters() { }

    /** Called from instrumented {@code ConnectionSource.equals}. */
    public static void incrementEquals() {
        EQUALS_COUNT.incrementAndGet();
    }

    /** Returns the current equals-call count. */
    public static long getEqualsCount() {
        return EQUALS_COUNT.get();
    }

    /** Resets the counter to zero (call before each fuzz execution). */
    public static void reset() {
        EQUALS_COUNT.set(0);
    }
}
