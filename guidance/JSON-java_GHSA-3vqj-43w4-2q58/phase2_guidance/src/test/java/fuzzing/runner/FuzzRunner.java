package fuzzing.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import fuzzing.guidance.V1Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for JQF fuzzing with custom DoS-targeted Guidance.
 *
 * Usage:
 *   java -cp ... -javaagent:target/v1-agent.jar fuzzing.runner.FuzzRunner V1 [durationSec] [outputDir]
 *
 * The factory method createGuidance(targetId, outputDir, maxDurationMs, log) is the
 * single entry point for constructing a Guidance instance.  DoSGuide calls it directly.
 */
public class FuzzRunner {

    /** Test class containing the @Fuzz methods. */
    private static final String TEST_CLASS = "fuzzing.harness.XmlFuzzTest";

    /**
     * Factory method: creates the appropriate Guidance for the given targetId.
     *
     * @param targetId       slot id, e.g. "V1"
     * @param outputDir      directory for corpus / logs
     * @param maxDurationMs  maximum fuzzing duration in milliseconds
     * @param log            stream for structured logging
     * @return a Guidance instance (also implements SignalSource)
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                           long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId
                        + ". Supported: V1");
        }
    }

    /** Map targetId to the @Fuzz method name in the test class. */
    private static String methodForTarget(String targetId) {
        switch (targetId) {
            case "V1":
                return "fuzzJSONMLToJSONArray";
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [durationSec] [outputDir]");
            System.err.println("  targetId:    V1");
            System.err.println("  durationSec: fuzzing duration in seconds (default: 120)");
            System.err.println("  outputDir:   output directory (default: fuzz-results/<targetId>)");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = args.length >= 2 ? Long.parseLong(args[1]) : 120;
        long maxDurationMs = durationSec * 1000L;
        String outputPath = args.length >= 3 ? args[2]
                : "fuzz-results" + File.separator + targetId;
        File outputDir = new File(outputPath);
        outputDir.mkdirs();

        PrintStream log = System.err;

        log.printf("[FuzzRunner] target=%s duration=%ds output=%s%n",
                targetId, durationSec, outputDir.getAbsolutePath());
        log.printf("[FuzzRunner] MAX_INPUT_SIZE=%d%n",
                Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 65536));

        Guidance guidance = createGuidance(targetId, outputDir, maxDurationMs, log);
        String method = methodForTarget(targetId);

        log.printf("[FuzzRunner] Starting: %s#%s%n", TEST_CLASS, method);

        GuidedFuzzing.run(TEST_CLASS, method,
                Thread.currentThread().getContextClassLoader(),
                guidance, System.out);

        log.println("[FuzzRunner] Done.");
    }
}
