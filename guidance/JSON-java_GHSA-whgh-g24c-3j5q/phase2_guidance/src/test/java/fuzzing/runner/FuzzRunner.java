package fuzzing.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import fuzzing.guidance.V1Guidance;
import fuzzing.guidance.V2Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for DoS fuzzing of JSON-java.
 *
 * Usage: java ... fuzzing.runner.FuzzRunner <targetId> <durationSecs>
 *
 * Target IDs:
 *   V1 — JSON recursive descent (fuzzJSONObjectAndJSONArrayConstructors)
 *   V2 — XML recursive parsing  (fuzzXMLToJSONObject)
 *
 * Duration: seconds to fuzz (0 = infinite).
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "fuzzing.harness.JsonFuzzTest";

    /**
     * Factory method required by DoSGuide validation contract.
     * Creates the Guidance for the given target ID.
     *
     * @param targetId     "V1" or "V2"
     * @param outputDir    base output directory
     * @param maxDurationMs maximum fuzzing duration in milliseconds (0 = infinite)
     * @param log          print stream for logging
     * @return the target's Guidance instance
     */
    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        File corpusDir = new File(outputDir, "corpus");
        switch (targetId) {
            case "V1":
                return new V1Guidance(corpusDir, maxDurationMs, log);
            case "V2":
                return new V2Guidance(corpusDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId
                        + ". Supported: V1, V2");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [durationSecs]");
            System.err.println("  targetId: V1 | V2");
            System.err.println("  durationSecs: seconds to fuzz (default: 0 = infinite)");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSecs = args.length >= 2 ? Long.parseLong(args[1]) : 0;
        long durationMs = durationSecs > 0 ? durationSecs * 1000L : 0;

        // Determine the fuzz method for each target
        String testMethod;
        switch (targetId) {
            case "V1":
                testMethod = "fuzzJSONObjectAndJSONArrayConstructors";
                break;
            case "V2":
                testMethod = "fuzzXMLToJSONObject";
                break;
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId
                        + ". Supported: V1, V2");
        }

        // Output directory
        File outputDir = new File("out", targetId);
        outputDir.mkdirs();

        System.out.printf("[FuzzRunner] Target=%s, Method=%s, Duration=%ds, MaxInput=%s%n",
                targetId, testMethod, durationSecs,
                System.getProperty("jqf.ei.MAX_INPUT_SIZE", "10240"));

        // Create guidance
        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.err);

        // Run fuzzing
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, guidance, System.out);

        System.out.printf("[FuzzRunner] Done. Corpus saved to %s%n", outputDir);
    }
}
