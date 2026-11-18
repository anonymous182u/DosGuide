package com.fuzzer;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the DoS fuzzer.
 *
 * Usage: java ... FuzzRunner <targetId> <durationSeconds>
 *
 * Factory method signature (required by DoSGuide validation):
 *   public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log)
 *
 * The runner invokes JQF's GuidedFuzzing.run() with the created Guidance
 * and the frozen Ed25519FuzzTest harness.
 */
public class FuzzRunner {

    /**
     * Factory method used by DoSGuide to instantiate the Guidance for a target.
     *
     * @param targetId      target identifier ("V1")
     * @param outputDir     output directory for corpus, logs, etc.
     * @param maxDurationMs maximum fuzzing duration in milliseconds
     * @param log           PrintStream for logging
     * @return a Guidance instance (also implements SignalSource)
     */
    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <targetId> <durationSeconds>");
            System.err.println("  targetId: V1");
            System.err.println("  durationSeconds: max fuzzing duration (0 = unlimited)");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = Long.parseLong(args[1]);
        long durationMs = durationSec * 1000L;

        // Output directory: out/<targetId>
        File outputDir = new File("out", targetId);
        outputDir.mkdirs();

        System.out.printf("[FuzzRunner] target=%s, duration=%ds, output=%s%n",
                targetId, durationSec, outputDir.getAbsolutePath());

        // Create guidance
        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.out);

        // Run the fuzzer using JQF
        try {
            org.junit.runner.Result result = GuidedFuzzing.run(
                    Ed25519FuzzTest.class,
                    "fuzzEd25519Verify",
                    guidance,
                    System.out
            );
            System.out.printf("[FuzzRunner] Fuzzing complete. Failures: %d%n",
                    result.getFailureCount());
        } catch (Exception e) {
            System.err.printf("[FuzzRunner] Fuzzing failed: %s%n", e.getMessage());
            e.printStackTrace();
            System.exit(2);
        }
    }
}
