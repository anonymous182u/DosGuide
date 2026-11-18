package com.powsybl.fuzzing.counter;

/**
 * Thread-local counter for NFA backtracking steps.
 *
 * <p>This class is loaded on the bootstrap classpath via the agent jar's
 * {@code Boot-Class-Path} manifest entry. Because bootstrap classes are
 * visible to every classloader, both the instrumented {@code Pattern$Node}
 * subclasses (bootstrap) and the Guidance classes (app classloader) see
 * the same {@code RegexStepCounter} class — no reflection or shared-memory
 * hacks required.</p>
 *
 * <p>Each thread gets its own {@code long[1]} so there is no contention.</p>
 */
public final class RegexStepCounter {

    private static final ThreadLocal<long[]> COUNTER =
            ThreadLocal.withInitial(() -> new long[1]);

    private RegexStepCounter() { /* utility class */ }

    /** Called from instrumented {@code Pattern$Node.match()} entry points. */
    public static void increment() {
        COUNTER.get()[0]++;
    }

    /** Read the current step count (this execution, since last reset). */
    public static long get() {
        return COUNTER.get()[0];
    }

    /** Reset to zero — called by Guidance before each execution. */
    public static void reset() {
        COUNTER.get()[0] = 0;
    }
}
