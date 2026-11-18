package org.xerial.snappy.fuzz;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the snappy-java DoS fuzz campaign.
 * <p>
 * Usage: java ... FuzzRunner &lt;V1|V2|V3&gt; [duration_seconds]
 * <p>
 * Creates the target-specific Guidance and runs it via GuidedFuzzing.run()
 * against the frozen SnappyFuzzTest harness.
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "org.xerial.snappy.fuzz.SnappyFuzzTest";

    /**
     * Factory method required by the validation contract (DoSGuide).
     *
     * @param targetId      "V1", "V2", or "V3"
     * @param outputDir     directory for corpus and logs
     * @param maxDurationMs maximum fuzzing duration in milliseconds (0 = infinite)
     * @param log           stream for periodic status logs
     * @return the target's Guidance instance
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                          long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            case "V2":
                return new V2Guidance(outputDir, maxDurationMs, log);
            case "V3":
                return new V3Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId
                        + ". Expected V1, V2, or V3.");
        }
    }

    /** Maps target ID to the @Fuzz method name in SnappyFuzzTest. */
    private static String methodForTarget(String targetId) {
        switch (targetId) {
            case "V1": return "fuzzSnappyInputStreamRead";
            case "V2": return "fuzzSnappyInputStreamRead";
            case "V3": return "fuzzSnappyUncompress";
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <V1|V2|V3> [duration_seconds]");
            System.exit(1);
        }

        String targetId = args[0];
        long durationMs = args.length >= 2 ? Long.parseLong(args[1]) * 1000 : 0;

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        PrintStream log = System.err;
        Guidance guidance = createGuidance(targetId, outputDir, durationMs, log);
        String method = methodForTarget(targetId);

        log.printf("Starting fuzzer for %s → %s.%s (duration=%s)%n",
                targetId, TEST_CLASS, method,
                durationMs > 0 ? durationMs + "ms" : "infinite");

        // Verify class origin (prints CodeSource)
        try {
            Class<?> snappyClass = Class.forName("org.xerial.snappy.SnappyInputStream");
            log.println("SnappyInputStream loaded from: "
                    + snappyClass.getProtectionDomain().getCodeSource().getLocation());
        } catch (Exception e) {
            log.println("Could not verify class origin: " + e);
        }

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, method, cl, guidance, log);

        log.printf("Fuzzing complete for %s.%n", targetId);
    }
}
