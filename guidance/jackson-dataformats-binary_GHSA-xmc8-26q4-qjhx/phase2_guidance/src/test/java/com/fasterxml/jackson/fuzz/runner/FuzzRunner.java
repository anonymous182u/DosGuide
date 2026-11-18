package com.fasterxml.jackson.fuzz.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import com.fasterxml.jackson.fuzz.guidance.V1Guidance;
import com.fasterxml.jackson.fuzz.guidance.PkgRisk1Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the CBOR DoS fuzzing campaign.
 *
 * Usage: java ... FuzzRunner <targetId> [durationSeconds]
 *
 * Target IDs: V1, PkgRisk1
 * Duration: 0 = infinite (default), positive integer = seconds to fuzz.
 */
public final class FuzzRunner {

    private static final String TEST_CLASS_NAME =
            "com.fasterxml.jackson.fuzz.harness.CBORFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [durationSeconds]");
            System.err.println("  Targets: V1, PkgRisk1");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = args.length > 1 ? Long.parseLong(args[1]) : 0;
        long durationMs = durationSec > 0 ? durationSec * 1000 : 0;

        File outputDir = new File("out", targetId);
        outputDir.mkdirs();

        PrintStream log = System.err;
        log.printf("[FuzzRunner] Target: %s, Duration: %s, Output: %s%n",
                targetId, durationSec > 0 ? durationSec + "s" : "infinite",
                outputDir.getAbsolutePath());

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, log);
        String testMethod = getTestMethod(targetId);

        log.printf("[FuzzRunner] Test: %s#%s%n", TEST_CLASS_NAME, testMethod);
        log.printf("[FuzzRunner] MaxInputSize: %s%n",
                System.getProperty("jqf.ei.MAX_INPUT_SIZE", "10240"));

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS_NAME, testMethod, cl, guidance, System.out);

        log.println("[FuzzRunner] Done.");
    }

    /**
     * Factory method required by DoSGuide validation contract.
     * Creates and returns the Guidance for the given target.
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                           long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            case "PkgRisk1":
                return new PkgRisk1Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId
                        + ". Valid targets: V1, PkgRisk1");
        }
    }

    private static String getTestMethod(String targetId) {
        switch (targetId) {
            case "V1":
                return "fuzzCBORParserNextTokenScalarValues";
            case "PkgRisk1":
                return "fuzzObjectMapperReadTree";
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }
    }
}
