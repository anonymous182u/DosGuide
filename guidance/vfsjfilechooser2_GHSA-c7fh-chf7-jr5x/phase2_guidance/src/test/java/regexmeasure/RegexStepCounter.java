package regexmeasure;

/**
 * Thread-local counter for regex NFA node evaluations (Pattern$Node.match() calls).
 * This class is added to the bootstrap classpath by V1MeasureAgent so that
 * instrumented java.base classes can call it.
 *
 * <p>Uses {@code ThreadLocal.withInitial} (Java 8 lambda) to avoid generating an
 * anonymous inner class file that would also need to be on the bootstrap classpath.
 */
public class RegexStepCounter {

    private static final ThreadLocal<long[]> COUNTER =
            ThreadLocal.withInitial(() -> new long[1]);

    /** Called from instrumented Pattern$Node.match() — one call per NFA step. */
    public static void increment() {
        COUNTER.get()[0]++;
    }

    /** Returns the step count for the current thread since last reset. */
    public static long get() {
        return COUNTER.get()[0];
    }

    /** Resets the counter to zero. Called by V1Guidance.getInput() before each execution. */
    public static void reset() {
        COUNTER.get()[0] = 0;
    }
}
