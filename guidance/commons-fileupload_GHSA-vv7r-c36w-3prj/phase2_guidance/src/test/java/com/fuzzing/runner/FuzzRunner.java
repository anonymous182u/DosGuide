package com.fuzzing.runner;

import com.fuzzing.guidance.V1Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI entry point for running guided fuzz targets.
 *
 * Usage:
 *   java -cp &lt;classpath&gt; -javaagent:&lt;agent.jar&gt; \
 *        com.fuzzing.runner.FuzzRunner &lt;targetId&gt; &lt;durationSeconds&gt; [outputDir]
 *
 * Factory method {@link #createGuidance} is also used by the DoSGuide
 * validation harness.
 */
public class FuzzRunner {

    /** Target-to-test-class mapping. */
    private static final String TEST_CLASS  = "com.fuzzing.harness.MultipartFuzzTest";

    /** Target-to-test-method mapping. */
    private static String testMethodFor(String targetId) {
        return switch (targetId) {
            case "V1" -> "fuzzMultipartStreamReadHeaders";
            default   -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };
    }

    /**
     * Factory method: create a Guidance instance for the given target.
     * Called by both this runner and the DoSGuide validation harness.
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                           long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            default   -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <targetId> <durationSeconds> [outputDir]");
            System.exit(1);
        }

        String targetId       = args[0];
        long   durationSec    = Long.parseLong(args[1]);
        long   maxDurationMs  = durationSec * 1000L;
        File   outputDir      = new File(args.length >= 3 ? args[2] : "fuzz-output/" + targetId);

        PrintStream log = System.out;
        log.printf("[FuzzRunner] target=%s duration=%ds output=%s%n",
                targetId, durationSec, outputDir.getAbsolutePath());

        Guidance guidance = createGuidance(targetId, outputDir, maxDurationMs, log);
        String testMethod = testMethodFor(targetId);

        log.printf("[FuzzRunner] class=%s method=%s%n", TEST_CLASS, testMethod);

        GuidedFuzzing.run(TEST_CLASS, testMethod, guidance, log);

        log.println("[FuzzRunner] done.");
    }
}
