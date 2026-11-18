package fuzzing.agent;

/**
 * ThreadLocal counters for PkgRisk1 (bzip2 decompression bomb).
 * Written by PkgRisk1MeasureAgent at the instrumented BZip2CompressorInputStream.read return sites.
 * Read by PkgRisk1Guidance in handleResult().
 */
public final class PkgRisk1Counters {

    private static final ThreadLocal<long[]> DECOMPRESSED_BYTES = ThreadLocal.withInitial(() -> new long[1]);

    /** Add bytes returned by one BZip2CompressorInputStream.read(byte[],int,int) call. */
    public static void addBytes(int n) {
        if (n > 0) {
            DECOMPRESSED_BYTES.get()[0] += n;
        }
    }

    /** Get total decompressedBytes for the current execution. */
    public static long get() {
        return DECOMPRESSED_BYTES.get()[0];
    }

    /** Reset before each execution. */
    public static void reset() {
        DECOMPRESSED_BYTES.get()[0] = 0;
    }

    private PkgRisk1Counters() {}
}
