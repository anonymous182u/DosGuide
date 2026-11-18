package com.fuzzer.runner;

import com.fuzzer.guidance.V1Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the custom guidances.
 * Usage: java ... FuzzRunner &lt;targetId&gt; [durationSeconds]
 *
 * Supports CLI target selection [R10].
 */
public class FuzzRunner {

    /**
     * Factory method required by DoSGuide validation contract (Part D).
     *
     * @param targetId      target identifier (e.g. "V1")
     * @param outputDir     corpus/output directory
     * @param maxDurationMs maximum fuzzing duration in milliseconds (0 = infinite)
     * @param log           stream for structured logging
     * @return a Guidance (also implements SignalSource) for the given target
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

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [durationSeconds]");
            System.err.println("  targetId: V1");
            System.err.println("  durationSeconds: 0 = infinite (default), >0 = time-bounded");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSecs = args.length > 1 ? Long.parseLong(args[1]) : 0;
        long maxDurationMs = durationSecs > 0 ? durationSecs * 1000 : 0;

        File outputDir = new File("out", targetId);
        outputDir.mkdirs();

        PrintStream log = System.err;
        Guidance guidance = createGuidance(targetId, outputDir, maxDurationMs, log);

        String testClass;
        String testMethod;

        switch (targetId) {
            case "V1":
                testClass = "com.fuzzer.saml.SAMLRequestParserFuzzTest";
                testMethod = "fuzzSAMLRequestParserParseRequestRedirectBinding";
                break;
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }

        log.printf("[FuzzRunner] Target=%s testClass=%s method=%s duration=%ds%n",
                targetId, testClass, testMethod, durationSecs);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(testClass, testMethod, cl, guidance, System.out);

        log.printf("[FuzzRunner] Fuzzing complete for %s%n", targetId);
    }
}
