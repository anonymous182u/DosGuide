package com.vaadin.fuzz;

/**
 * Thread-safe regex step counter for measuring Pattern$Node.match() invocations.
 *
 * This class is placed on the bootstrap classpath via the agent jar's
 * Boot-Class-Path manifest attribute, so it is visible to the instrumented
 * java.util.regex.Pattern$* classes loaded by the bootstrap classloader.
 *
 * MUST have zero external dependencies (no ASM, no JQF, no third-party).
 */
public final class RegexStepCounter {

    private static final ThreadLocal<long[]> counter =
            ThreadLocal.withInitial(() -> new long[1]);

    private RegexStepCounter() { }

    /** Called by injected bytecode at the start of every Pattern$Node.match(). */
    public static void increment() {
        counter.get()[0]++;
    }

    /** Returns the current step count for this thread. */
    public static long get() {
        return counter.get()[0];
    }

    /** Resets the step count for this thread to zero. Called before each execution. */
    public static void reset() {
        counter.get()[0] = 0;
    }
}
