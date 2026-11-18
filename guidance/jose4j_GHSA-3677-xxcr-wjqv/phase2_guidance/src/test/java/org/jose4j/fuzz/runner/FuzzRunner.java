package org.jose4j.fuzz.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import org.jose4j.fuzz.guidance.V1Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for V1 decompression bomb fuzzing.
 *
 * Usage: FuzzRunner <targetId> [maxDurationSeconds]
 *   targetId: V1
 *   maxDurationSeconds: optional time bound (default: infinite)
 *
 * Uses GuidedFuzzing.run(testClassName, testMethod, cl, guidance, out) per [R10].
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "org.jose4j.fuzz.JsonWebEncryptionFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [maxDurationSeconds]");
            System.err.println("  targetId: V1");
            System.exit(1);
        }

        String targetId = args[0];
        long maxDurationMs = 0; // infinite by default ([R8])
        if (args.length >= 2) {
            maxDurationMs = Long.parseLong(args[1]) * 1000L;
        }

        // Also check system property
        String durationProp = System.getProperty("jqf.ei.MAX_DURATION");
        if (durationProp != null && maxDurationMs == 0) {
            maxDurationMs = Long.parseLong(durationProp) * 1000L;
        }

        String testMethod = resolveTestMethod(targetId);
        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        // Class origin check: verify we are loading from the vulnerable jar
        try {
            Class<?> cls = Class.forName("org.jose4j.zip.DeflateRFC1951CompressionAlgorithm");
            System.out.println("[FuzzRunner] CodeSource: "
                    + cls.getProtectionDomain().getCodeSource().getLocation());
        } catch (Exception e) {
            System.err.println("[FuzzRunner] Warning: could not verify CodeSource: " + e);
        }

        System.out.println("[FuzzRunner] Target: " + targetId);
        System.out.println("[FuzzRunner] Test: " + TEST_CLASS + "#" + testMethod);
        System.out.println("[FuzzRunner] Duration: " + (maxDurationMs > 0 ? maxDurationMs + "ms" : "infinite"));
        System.out.println("[FuzzRunner] MAX_INPUT_SIZE: " + Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240));

        Guidance guidance = createGuidance(targetId, outputDir, maxDurationMs, System.err);

        // Run the fuzz test via JQF ([R10])
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, guidance, System.out);

        System.out.println("[FuzzRunner] Done.");
    }

    /**
     * Factory method for creating the target's Guidance.
     * Called by DoSGuide validation and by main() above.
     *
     * @param targetId       target identifier (V1)
     * @param outputDir      directory for corpus output
     * @param maxDurationMs  maximum duration in milliseconds (0 = infinite)
     * @param log            log stream for structured logging
     * @return the Guidance instance
     */
    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException("Unknown target: " + targetId
                    + ". Supported: V1");
        };
    }

    /** Resolve the @Fuzz test method name for a given target. */
    private static String resolveTestMethod(String targetId) {
        return switch (targetId) {
            case "V1" -> "fuzzJsonWebEncryptionGetPlaintextBytes";
            default -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };
    }
}
