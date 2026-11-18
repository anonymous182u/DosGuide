package org.jose4j.fuzz.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent entry point for V1 (Decompression Bomb) measurement.
 *
 * Instruments org.jose4j.zip.DeflateRFC1951CompressionAlgorithm.decompress(byte[])
 * to track total decompressed output bytes and call count via InflateCounters.
 *
 * The target class (DeflateRFC1951CompressionAlgorithm) is loaded DURING the
 * test execution (not at JVM bootstrap), so registering the transformer in
 * premain is sufficient — no retransform needed. This also means:
 * - The validation framework sees the rewrite happen during the test
 * - Only jose4j decompression is captured (not JVM-internal inflate calls)
 * - Signals are deterministic across repeated runs of the same input
 *
 * Measurement-only — does NOT generate inputs or embed payloads ([R37]).
 */
public final class V1MeasureAgent {

    private V1MeasureAgent() {}

    public static void premain(String args, Instrumentation inst) {
        try {
            // Register our transformer. No need for retransform support since
            // the target class (DeflateRFC1951CompressionAlgorithm) hasn't been
            // loaded yet at premain time — it's loaded when the test runs.
            InflaterTransformer transformer = new InflaterTransformer();
            inst.addTransformer(transformer, false);

            System.err.println("[V1MeasureAgent] Registered transformer for "
                    + "DeflateRFC1951CompressionAlgorithm.decompress()");
        } catch (Exception e) {
            System.err.println("[V1MeasureAgent] Agent setup failed: " + e);
            e.printStackTrace(System.err);
        }
    }
}
