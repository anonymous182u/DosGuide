package org.xerial.snappy.fuzz;

/**
 * ThreadLocal counters for allocation measurement, written to by agent-injected bytecode.
 * <p>
 * Slot 0: V1 – compressed buffer in SnappyInputStream.hasNextChunk (1st NEWARRAY T_BYTE)
 * Slot 1: V2 – uncompressed buffer in SnappyInputStream.hasNextChunk (2nd NEWARRAY T_BYTE)
 * Slot 2: V3 – result buffer in Snappy.uncompress(byte[]) (1st NEWARRAY T_BYTE)
 */
public final class AllocCounters {

    public static final int NUM_SLOTS = 3;

    /** Per-thread counters: each slot tracks the max allocation size for the current execution. */
    public static final ThreadLocal<long[]> COUNTERS =
            ThreadLocal.withInitial(() -> new long[NUM_SLOTS]);

    private AllocCounters() {}

    /** Reset all slots to 0. Called by Guidance.getInput() before each execution. */
    public static void reset() {
        long[] c = COUNTERS.get();
        c[0] = 0;
        c[1] = 0;
        c[2] = 0;
    }

    /** Record allocation for slot 0 (V1: compressedAllocBytes). Injected before 1st NEWARRAY in hasNextChunk. */
    public static void record0(int size) {
        long[] c = COUNTERS.get();
        long s = Integer.toUnsignedLong(size);
        if (s > c[0]) c[0] = s;
    }

    /** Record allocation for slot 1 (V2: uncompressedAllocBytes). Injected before 2nd NEWARRAY in hasNextChunk. */
    public static void record1(int size) {
        long[] c = COUNTERS.get();
        long s = Integer.toUnsignedLong(size);
        if (s > c[1]) c[1] = s;
    }

    /** Record allocation for slot 2 (V3: resultAllocBytes). Injected before NEWARRAY in Snappy.uncompress. */
    public static void record2(int size) {
        long[] c = COUNTERS.get();
        long s = Integer.toUnsignedLong(size);
        if (s > c[2]) c[2] = s;
    }

    /** Read the signal value for a given slot. */
    public static long get(int slot) {
        return COUNTERS.get()[slot];
    }
}
