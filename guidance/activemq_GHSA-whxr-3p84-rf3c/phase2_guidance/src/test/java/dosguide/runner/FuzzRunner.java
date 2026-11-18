package dosguide.runner;

import java.io.File;
import java.io.PrintStream;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import dosguide.guidance.V1AllocGuidance;
import dosguide.guidance.V2ThrowableGuidance;
import dosguide.guidance.V3NestingGuidance;

/**
 * CLI runner for all DoS fuzz targets.
 *
 * Usage:
 *   java ... dosguide.runner.FuzzRunner <targetId> <maxDurationSec> [outputDir]
 *   java ... dosguide.runner.FuzzRunner replay <targetId> <inputFile>
 *
 * Target IDs: V1, V2, V3
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "com.fuzz.activemq.OpenWireFuzzTest";

    /**
     * Factory method for creating Guidance instances.
     * Called by DoSGuide validation and by this runner's main.
     *
     * @param targetId      V1, V2, or V3
     * @param outputDir     directory for corpus and best inputs
     * @param maxDurationMs maximum duration in milliseconds (0 = infinite)
     * @param log           log output stream
     * @return the target-specific Guidance
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                           long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1AllocGuidance(outputDir, maxDurationMs, log);
            case "V2":
                return new V2ThrowableGuidance(outputDir, maxDurationMs, log);
            case "V3":
                return new V3NestingGuidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId
                    + ". Valid targets: V1, V2, V3");
        }
    }

    /**
     * Map target ID to the fuzz method name in OpenWireFuzzTest.
     */
    private static String methodForTarget(String targetId) {
        switch (targetId) {
            case "V1": return "fuzzOpenWireFormatUnmarshal";
            case "V2": return "fuzzOpenWireFormatUnmarshalStackTraceEnabled";
            case "V3": return "fuzzOpenWireFormatUnmarshal";
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <V1|V2|V3> <maxDurationSec> [outputDir]");
            System.err.println("       FuzzRunner replay <V1|V2|V3> <inputFile>");
            System.exit(1);
        }

        if ("replay".equalsIgnoreCase(args[0])) {
            // Replay mode
            if (args.length < 3) {
                System.err.println("Usage: FuzzRunner replay <V1|V2|V3> <inputFile>");
                System.exit(1);
            }
            String targetId = args[1].toUpperCase();
            String inputFile = args[2];
            String method = methodForTarget(targetId);

            File replayFile = new File(inputFile);
            dosguide.replay.ReplayGuidance replayGuidance =
                new dosguide.replay.ReplayGuidance(replayFile, targetId, System.err);

            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            GuidedFuzzing.run(TEST_CLASS, method, cl, replayGuidance, System.err);
            return;
        }

        // Fuzz mode
        String targetId = args[0].toUpperCase();
        long maxDurationSec = Long.parseLong(args[1]);
        long maxDurationMs = maxDurationSec > 0 ? maxDurationSec * 1000 : 0;

        File outputDir = new File(args.length >= 3 ? args[2] : "out/" + targetId);

        String method = methodForTarget(targetId);

        System.err.printf("[FuzzRunner] target=%s method=%s duration=%ds output=%s%n",
            targetId, method, maxDurationSec, outputDir.getAbsolutePath());

        Guidance guidance = createGuidance(targetId, outputDir, maxDurationMs, System.err);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, method, cl, guidance, System.err);

        System.err.println("[FuzzRunner] Fuzzing complete for " + targetId);
    }
}
