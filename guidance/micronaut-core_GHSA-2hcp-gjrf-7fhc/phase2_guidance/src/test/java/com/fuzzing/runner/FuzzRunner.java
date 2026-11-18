package com.fuzzing.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import com.fuzzing.guidance.V1Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI entry point for running JQF-based DoS fuzzing with custom guidance.
 *
 * Usage:  java ... FuzzRunner &lt;targetId&gt; &lt;maxDurationSec&gt; [outputDir]
 *
 * Factory method createGuidance() is the programmatic API used by DoSGuide validation.
 */
public class FuzzRunner {

    /**
     * Factory method: creates the appropriate Guidance (+ SignalSource) for the given target.
     *
     * @param targetId      target identifier (e.g. "V1")
     * @param outputDir     directory for saving best inputs and logs
     * @param maxDurationMs maximum fuzzing duration in milliseconds
     * @param log           stream for progress logging
     * @return a Guidance that also implements dosguide.validate.SignalSource
     */
    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <targetId> <maxDurationSec> [outputDir]");
            System.exit(1);
        }

        String targetId = args[0];
        long maxDurationMs = Long.parseLong(args[1]) * 1000;
        File outputDir = args.length > 2
                ? new File(args[2])
                : new File("fuzz-output/" + targetId);

        System.out.printf("[FuzzRunner] target=%s maxDuration=%ds output=%s%n",
                targetId, maxDurationMs / 1000, outputDir.getAbsolutePath());

        Guidance guidance = createGuidance(targetId, outputDir, maxDurationMs, System.out);

        String testClass = "com.fuzzing.harness.SanitizerFuzzTest";
        String testMethod;

        switch (targetId) {
            case "V1":
                testMethod = "fuzzHtmlErrorResponseBodyProviderBody";
                break;
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }

        GuidedFuzzing.run(testClass, testMethod,
                Thread.currentThread().getContextClassLoader(),
                guidance, System.out);

        System.out.println("[FuzzRunner] Fuzzing complete.");
    }
}
