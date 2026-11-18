package com.vaadin.fuzz;

import java.io.File;
import java.io.PrintStream;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

/**
 * CLI runner for the Vaadin EmailValidator fuzz targets.
 *
 * Usage:
 *   java ... com.vaadin.fuzz.FuzzRunner V1 [durationSeconds]
 *   java ... com.vaadin.fuzz.FuzzRunner V2 [durationSeconds]
 *
 * Omit durationSeconds for infinite fuzzing (until killed).
 */
public final class FuzzRunner {

    private static final String TEST_CLASS = "com.vaadin.fuzz.EmailValidatorFuzzTest";

    /**
     * Factory method required by the DoSGuide validation contract.
     *
     * @param targetId       "V1" or "V2"
     * @param outputDir      directory for corpus / output
     * @param maxDurationMs  maximum fuzzing duration in milliseconds
     * @param log            stream for structured logging
     * @return a fresh Guidance instance for the requested target
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
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <V1|V2> [durationSeconds]");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSeconds = (args.length >= 2) ? Long.parseLong(args[1]) : Long.MAX_VALUE / 1000;
        long maxDurationMs = durationSeconds * 1000;

        // Determine test method from target
        String testMethod;
        switch (targetId) {
            case "V1":
                testMethod = "fuzzEmailValidatorIsValid";
                break;
            case "V2":
                testMethod = "fuzzEmailValidatorApply";
                break;
            default:
                System.err.println("Unknown target: " + targetId);
                System.exit(1);
                return;
        }

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        System.out.printf("[FuzzRunner] target=%s method=%s duration=%ds%n",
                targetId, testMethod, durationSeconds);

        Guidance guidance = createGuidance(targetId, outputDir, maxDurationMs, System.out);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, guidance, System.out);

        System.out.printf("[FuzzRunner] %s finished.%n", targetId);
    }
}
