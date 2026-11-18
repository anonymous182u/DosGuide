package com.fuzzing.agent;

/**
 * Thread-local counter for regex VM steps (Pattern$Node.match() invocations).
 * This class is added to the bootstrap classpath by V1MeasureAgent so that
 * instrumented code in java.util.regex.Pattern inner classes can call step().
 * The Guidance reads the counter via reflection on the bootstrap-loaded class.
 *
 * Measurement-only ([R37]): does not generate inputs or embed payloads.
 */
public final class V1Counters {

    private static final ThreadLocal<long[]> STEPS =
            ThreadLocal.withInitial(() -> new long[1]);

    /** Called from instrumented Pattern$Node.match() — one call per regex VM step. */
    public static void step() {
        STEPS.get()[0]++;
    }

    /** Return the step count for the current thread since the last reset. */
    public static long getStepCount() {
        return STEPS.get()[0];
    }

    /** Reset the step counter to zero (called before each fuzz execution). */
    public static void reset() {
        STEPS.get()[0] = 0;
    }

    private V1Counters() { }
}
