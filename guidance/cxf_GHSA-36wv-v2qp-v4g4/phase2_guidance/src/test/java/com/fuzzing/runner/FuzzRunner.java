package com.fuzzing.runner;

import com.fuzzing.guidance.V1Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the CXF CachedOutputStream fuzzer.
 *
 * Usage: java ... FuzzRunner <targetId> [durationSeconds]
 *
 * Targets:
 *   V1 — fuzzCachedOutputStreamCleanerForceClean (unbounded toString in cleaner logs)
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "org.apache.cxf.io.fuzz.CachedOutputStreamFuzzTest";

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [durationSeconds]");
            System.err.println("  Targets: V1");
            System.exit(1);
        }

        String targetId = args[0];
        long durationMs = 0;
        if (args.length >= 2) {
            durationMs = Long.parseLong(args[1]) * 1000L;
        }

        String method = resolveMethod(targetId);
        File outputDir = new File("out", targetId);
        outputDir.mkdirs();

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.out);

        // Verify class origin
        try {
            Class<?> cosClass = Class.forName("org.apache.cxf.io.CachedOutputStream");
            System.out.println("[FuzzRunner] CachedOutputStream loaded from: "
                + cosClass.getProtectionDomain().getCodeSource().getLocation());
        } catch (ClassNotFoundException e) {
            System.err.println("[FuzzRunner] CachedOutputStream not found on classpath!");
        }

        System.out.println("[FuzzRunner] Starting " + targetId + " -> " + TEST_CLASS + "#" + method);
        if (durationMs > 0) {
            System.out.println("[FuzzRunner] Duration: " + (durationMs / 1000) + " seconds");
        } else {
            System.out.println("[FuzzRunner] Duration: infinite (Ctrl-C to stop)");
        }

        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            GuidedFuzzing.run(TEST_CLASS, method, cl, guidance, System.out);
        } catch (Exception e) {
            System.err.println("[FuzzRunner] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Factory method required by DoSGuide validation contract.
     * Returns the Guidance instance for the given target.
     */
    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };
    }

    private static String resolveMethod(String targetId) {
        return switch (targetId) {
            case "V1" -> "fuzzCachedOutputStreamCleanerForceClean";
            default -> throw new IllegalArgumentException("Unknown target: " + targetId + ". Available: V1");
        };
    }
}
