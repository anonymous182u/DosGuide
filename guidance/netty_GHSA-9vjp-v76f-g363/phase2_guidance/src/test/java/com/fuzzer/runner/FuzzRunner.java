package com.fuzzer.runner;

import com.fuzzer.guidance.V1Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the Netty Snappy DoS fuzzing campaign.
 *
 * <p>Usage: {@code java ... com.fuzzer.runner.FuzzRunner <targetId> [durationSeconds]}</p>
 *
 * <p>Supports CLI target selection ([R10]):
 * <ul>
 *   <li>{@code V1} — fuzzSnappyFrameDecoderDecode (Snappy preamble allocation exhaustion)</li>
 * </ul>
 * Duration of 0 or omitted means infinite ([R8]).</p>
 */
public class FuzzRunner {

    /**
     * Factory method required by DoSGuide validation contract.
     * Creates the appropriate Guidance for the given target.
     *
     * @param targetId     one of "V1"
     * @param outputDir    base directory for corpus and output files
     * @param maxDurationMs maximum run time in milliseconds; 0 = infinite
     * @param log          stream for structured logging
     * @return the Guidance instance
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
            System.err.println("  durationSeconds: 0 = infinite (default)");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = args.length > 1 ? Long.parseLong(args[1]) : 0;
        long durationMs = durationSec * 1000;

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.err);

        String testClass;
        String testMethod;
        switch (targetId) {
            case "V1":
                testClass = "com.fuzzer.harness.SnappyFuzzTest";
                testMethod = "fuzzSnappyFrameDecoderDecode";
                break;
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }

        System.err.printf("[FuzzRunner] target=%s test=%s#%s duration=%ds%n",
                targetId, testClass, testMethod, durationSec);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(testClass, testMethod, cl, guidance, System.out);

        System.err.println("[FuzzRunner] Finished.");
    }
}
