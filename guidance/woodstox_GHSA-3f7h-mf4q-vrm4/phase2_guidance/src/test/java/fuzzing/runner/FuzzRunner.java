package fuzzing.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import fuzzing.guidance.V1Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the Woodstox fuzz targets.
 *
 * Usage: java fuzzing.runner.FuzzRunner <targetId> [durationMs]
 *
 * targetId:    V1  (unbounded DTD content spec recursion)
 * durationMs:  0 = infinite (default); positive = time-bounded in ms
 *
 * Example:
 *   java -Xmx1g -Xss1m -javaagent:target/v1-agent.jar \
 *        -cp <classpath> fuzzing.runner.FuzzRunner V1 60000
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "fuzzing.harness.WoodstoxFuzzTest";

    /**
     * Entry point for running the fuzzer from the command line.
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [durationMs]");
            System.err.println("  targetId: V1");
            System.err.println("  durationMs: 0=infinite (default), positive=time-bounded");
            System.exit(1);
        }

        String targetId = args[0];
        long durationMs = args.length > 1 ? Long.parseLong(args[1]) : 0;

        // Also check system property for duration (used by evaluation)
        String durProp = System.getProperty("jqf.ei.MAX_DURATION");
        if (durProp != null && !durProp.isEmpty()) {
            durationMs = Long.parseLong(durProp);
        }

        File outputDir = new File("out/" + targetId);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.out);

        String methodName = resolveMethod(targetId);
        System.out.printf("[FuzzRunner] Target=%s Method=%s Duration=%dms%n",
                targetId, methodName, durationMs);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, methodName, cl, guidance, System.out);

        System.out.println("[FuzzRunner] Fuzzing complete for target " + targetId);
    }

    /**
     * Factory method for creating a Guidance instance for the given target.
     * Called by the evaluation framework (DoSGuide).
     *
     * @param targetId     the target identifier (e.g., "V1")
     * @param outputDir    the output directory for corpus and logs
     * @param maxDurationMs maximum duration in milliseconds (0 = infinite)
     * @param log          the print stream for logging
     * @return a Guidance instance for the target
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                           long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException(
                    "Unknown target: " + targetId + ". Supported: V1");
        };
    }

    /**
     * Resolves a target ID to the corresponding fuzz method name.
     */
    private static String resolveMethod(String targetId) {
        return switch (targetId) {
            case "V1" -> "fuzzXMLStreamReaderNextNonValidating";
            default -> throw new IllegalArgumentException(
                    "Unknown target: " + targetId + ". Supported: V1");
        };
    }
}
