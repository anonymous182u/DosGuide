package org.xnio.fuzz;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI entry point for the XNIO fuzz campaign.
 *
 * Usage:  java ... FuzzRunner <targetId> <durationSeconds>
 *
 * The {@link #createGuidance} factory method is also the programmatic entry
 * point used by the validation framework.
 */
public final class FuzzRunner {

    /** Target → test class mapping. */
    private static final String TEST_CLASS = "org.xnio.fuzz.XnioFuzzTest";

    private FuzzRunner() {}

    /**
     * Factory method for the validation framework and programmatic use.
     *
     * @param targetId      "V1" or "V2"
     * @param outputDir     directory for corpus/crash output
     * @param maxDurationMs maximum fuzzing duration in milliseconds
     * @param log           output stream for progress logging
     * @return a configured Guidance instance
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                           long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            case "V2":
                return new V2Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId
                        + " (expected V1 or V2)");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <targetId> <durationSeconds>");
            System.err.println("  targetId: V1 or V2");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = Long.parseLong(args[1]);
        long durationMs = durationSec * 1000;

        // Print class origin check — verify we are using the vulnerable artifact
        try {
            Class<?> aif = Class.forName("org.xnio.AbstractIoFuture");
            System.out.println("[FuzzRunner] AbstractIoFuture loaded from: "
                    + aif.getProtectionDomain().getCodeSource().getLocation());
        } catch (Exception e) {
            System.err.println("[FuzzRunner] WARNING: Could not determine AbstractIoFuture origin: " + e);
        }

        // Resolve test method for the target
        String testMethod;
        switch (targetId) {
            case "V1":
                testMethod = "fuzzIoFutureAddNotifier";
                break;
            case "V2":
                testMethod = "fuzzFutureResultAddCancelHandler";
                break;
            default:
                System.err.println("Unknown target: " + targetId);
                System.exit(1);
                return;
        }

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        System.out.printf("[FuzzRunner] Starting target=%s method=%s duration=%ds output=%s%n",
                targetId, testMethod, durationSec, outputDir.getAbsolutePath());

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.out);

        // Run the fuzzing campaign via JQF
        GuidedFuzzing.run(TEST_CLASS, testMethod, guidance, System.out);

        System.out.printf("[FuzzRunner] Campaign complete for %s%n", targetId);
    }
}
