package com.powsybl.fuzzing.runner;

import com.powsybl.fuzzing.guidance.V1Guidance;
import com.powsybl.fuzzing.guidance.PkgRisk1Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI entry point for fuzzing. Dispatches to the appropriate Guidance
 * based on the target ID, then runs {@link GuidedFuzzing}.
 *
 * <p>Usage: {@code java ... FuzzRunner <targetId> <durationSeconds>}</p>
 *
 * <p>Targets: V1, PkgRisk1</p>
 */
public class FuzzRunner {

    private static final String TEST_CLASS =
            "com.powsybl.fuzzing.tests.RegexCriterionFuzzTest";
    private static final String TEST_METHOD = "fuzzRegexCriterionFilter";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <targetId> <durationSeconds>");
            System.err.println("  targetId: V1 | PkgRisk1");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = Long.parseLong(args[1]);
        long durationMs = durationSec * 1000;

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        PrintStream log = System.out;
        log.printf("[FuzzRunner] Target=%s, Duration=%ds, OutputDir=%s%n",
                targetId, durationSec, outputDir.getAbsolutePath());

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, log);

        // Run the fuzzer via JQF's GuidedFuzzing
        GuidedFuzzing.run(TEST_CLASS, TEST_METHOD,
                Thread.currentThread().getContextClassLoader(),
                guidance, log);

        log.println("[FuzzRunner] Fuzzing complete for target " + targetId);
    }

    /**
     * Factory method that creates the Guidance instance for the given target.
     *
     * <p>This method is called by the DoSGuide validation framework to
     * instantiate the guidance with its own parameters.</p>
     *
     * @param targetId      one of "V1", "PkgRisk1"
     * @param outputDir     directory for corpus and artifacts
     * @param maxDurationMs maximum fuzzing duration in milliseconds
     * @param log           stream for structured logging
     * @return the Guidance (also implements {@link dosguide.validate.SignalSource})
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                          long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            case "PkgRisk1" -> new PkgRisk1Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException(
                    "Unknown target: " + targetId + ". Expected V1 or PkgRisk1");
        };
    }
}
