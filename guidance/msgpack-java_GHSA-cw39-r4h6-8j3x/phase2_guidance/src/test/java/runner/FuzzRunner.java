package runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import guidance.V1Guidance;
import guidance.V2Guidance;
import guidance.V3Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for DoS fuzzing of msgpack-java MessageUnpacker.
 * Usage: java [jvm-opts] runner.FuzzRunner <targetId> <durationSeconds> [outputDir]
 *
 * Factory method createGuidance(...) is the DoSGuide entry point.
 */
public class FuzzRunner {

    /** The fuzz test class containing @Fuzz methods */
    private static final String TEST_CLASS = "fuzzing.MsgpackFuzzTest";

    /** All three targets call the same @Fuzz method */
    private static final String TEST_METHOD = "fuzzMessageUnpackerUnpackValue";

    /**
     * DoSGuide entry point: create a Guidance for the given target.
     * Each Guidance also implements dosguide.validate.SignalSource.
     *
     * @param targetId       one of "V1", "V2", "V3"
     * @param outputDir      directory for corpus, saved inputs, etc.
     * @param maxDurationMs  maximum fuzzing duration in milliseconds (0 = unlimited)
     * @param log            stream for status logging
     * @return a Guidance (also a SignalSource) for the target
     */
    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            case "V2":
                return new V2Guidance(outputDir, maxDurationMs, log);
            case "V3":
                return new V3Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId
                        + ". Valid targets: V1, V2, V3");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <targetId> <durationSeconds> [outputDir]");
            System.err.println("  targetId: V1, V2, or V3");
            System.err.println("  durationSeconds: max time in seconds (0 for infinite)");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = Long.parseLong(args[1]);
        long durationMs = durationSec * 1000L;
        String outputPath = args.length >= 3 ? args[2] : "fuzz-output/" + targetId;
        File outputDir = new File(outputPath);
        outputDir.mkdirs();

        PrintStream log = System.err;
        log.printf("[FuzzRunner] Target=%s, duration=%ds, output=%s%n",
                targetId, durationSec, outputDir.getAbsolutePath());

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, log);

        // Run the fuzz test
        GuidedFuzzing.run(TEST_CLASS, TEST_METHOD,
                Thread.currentThread().getContextClassLoader(),
                guidance, log);

        log.println("[FuzzRunner] Done.");
    }
}
