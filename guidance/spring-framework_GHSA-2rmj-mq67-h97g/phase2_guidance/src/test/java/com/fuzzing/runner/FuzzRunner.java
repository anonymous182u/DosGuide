package com.fuzzing.runner;

import java.io.File;
import java.io.PrintStream;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import com.fuzzing.guidance.V1Guidance;

/**
 * CLI runner for the custom Guidance fuzzers.
 *
 * Usage: java ... FuzzRunner <targetId> [durationSeconds]
 *   targetId: V1
 *   durationSeconds: optional, 0 = infinite
 *
 * Supports CLI target selection ([R10]).
 */
public final class FuzzRunner {

    private static final String TEST_CLASS =
            "com.fuzzing.httpheaders.HttpHeadersFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [durationSeconds]");
            System.err.println("  targetId: V1");
            System.err.println("  durationSeconds: 0 = infinite (default)");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSeconds = args.length >= 2 ? Long.parseLong(args[1]) : 0;

        // Also check system property
        String maxDurProp = System.getProperty("jqf.ei.MAX_DURATION");
        if (maxDurProp != null && durationSeconds == 0) {
            durationSeconds = Long.parseLong(maxDurProp);
        }

        long durationMs = durationSeconds > 0 ? durationSeconds * 1000 : 0;
        File outputDir = new File("out", targetId);
        outputDir.mkdirs();

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.out);

        String testMethod = getTestMethod(targetId);
        System.out.printf("[FuzzRunner] Starting %s → %s.%s (duration=%s)%n",
                targetId, TEST_CLASS, testMethod,
                durationSeconds > 0 ? durationSeconds + "s" : "infinite");

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, guidance, System.out);

        System.out.println("[FuzzRunner] Finished " + targetId);
    }

    /**
     * Factory method required by DoSGuide validation contract.
     * Returns the target's Guidance instance.
     */
    public static Guidance createGuidance(String targetId,
                                          File outputDir,
                                          long maxDurationMs,
                                          PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException(
                    "Unknown target: " + targetId + ". Supported: V1");
        };
    }

    private static String getTestMethod(String targetId) {
        return switch (targetId) {
            case "V1" -> "fuzzHttpHeadersGetIfNoneMatch";
            default -> throw new IllegalArgumentException(
                    "Unknown target: " + targetId);
        };
    }

    private FuzzRunner() { }
}
