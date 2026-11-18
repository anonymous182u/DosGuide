package org.elasticsearch.compute.data.fuzz.agent;

/**
 * Thread-local counter for measuring array allocation bytes at the NEWARRAY hotspot
 * in IntBlockBuilder and LongBlockBuilder constructors.
 *
 * The custom Java agent instruments those constructors to call {@link #recordAlloc}
 * just before the NEWARRAY bytecode instruction, passing the array size and element size.
 *
 * The Guidance resets the counter before each execution via {@link #reset} and reads
 * the accumulated allocation via {@link #getAlloc} after the execution completes.
 */
public final class AllocCounter {

    private static final ThreadLocal<long[]> ALLOC = ThreadLocal.withInitial(() -> new long[1]);

    private AllocCounter() {}

    /**
     * Called by agent-instrumented code just before NEWARRAY in the block builder constructor.
     *
     * @param arraySize the number of elements being allocated (initialSize)
     * @param elemSize  the size of each element in bytes (4 for int, 8 for long)
     */
    public static void recordAlloc(int arraySize, int elemSize) {
        // Use long arithmetic to compute the TRUE allocation size,
        // deliberately avoiding the integer overflow that is the vulnerability.
        ALLOC.get()[0] += (long) arraySize * elemSize;
    }

    /** Returns the accumulated allocation bytes for the current execution. */
    public static long getAlloc() {
        return ALLOC.get()[0];
    }

    /** Resets the counter to zero. Called by Guidance before each execution. */
    public static void reset() {
        ALLOC.get()[0] = 0L;
    }
}
