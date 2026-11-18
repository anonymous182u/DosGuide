package com.fuzzer.runner;

import com.fuzzer.guidance.V1Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for DoS fuzzing. Supports target selection ([R10]).
 *
 * Usage: java ... com.fuzzer.runner.FuzzRunner <targetId> [durationSeconds]
 *
 * Target IDs:
 *   V1 — QuotedQualityCSV.sort() cubic-time DoS
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "com.fuzzer.harness.JettyFuzzTest";

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [durationSeconds]");
            System.err.println("  targetId: V1");
            System.exit(1);
        }

        String targetId = args[0];
        long durationMs = 0; // infinite by default ([R8])
        if (args.length >= 2) {
            durationMs = Long.parseLong(args[1]) * 1000L;
        }

        File outputDir = new File("out");
        outputDir.mkdirs();

        // Class origin check — proves we load from the vulnerable jar, not target/classes
        System.out.println("QuotedQualityCSV loaded from: " +
                org.eclipse.jetty.http.QuotedQualityCSV.class
                        .getProtectionDomain().getCodeSource().getLocation());

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.out);

        String testMethod;
        switch (targetId) {
            case "V1":
                testMethod = "fuzzHttpFieldsGetQualityCSV";
                break;
            default:
                System.err.println("Unknown target: " + targetId);
                System.exit(1);
                return;
        }

        System.out.printf("Starting fuzzing: target=%s method=%s duration=%s%n",
                targetId, testMethod,
                durationMs > 0 ? (durationMs / 1000) + "s" : "infinite");

        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            GuidedFuzzing.run(TEST_CLASS, testMethod, cl, guidance, System.out);
        } catch (Exception e) {
            System.err.println("Fuzzing error: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("Fuzzing complete for target " + targetId);
    }

    /**
     * Factory method for DoSGuide validation (Part D).
     * Creates the appropriate Guidance for the given target ID.
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                           long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }
    }
}
