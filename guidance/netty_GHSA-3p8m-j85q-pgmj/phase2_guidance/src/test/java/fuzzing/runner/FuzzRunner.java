package fuzzing.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import fuzzing.guidance.V1Guidance;
import fuzzing.guidance.V2Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the decompression fuzz tests.
 *
 * <p>Usage: {@code java fuzzing.runner.FuzzRunner <targetId> <durationSeconds>}
 * where targetId is V1 or V2.</p>
 *
 * <p>Also provides the static factory method {@code createGuidance} used by
 * DoSGuide validation.</p>
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "fuzzing.harness.DecompressionFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <V1|V2> <durationSeconds>");
            System.err.println("  V1 = BrotliDecoder decompression bomb");
            System.err.println("  V2 = ZstdDecoder decompression bomb");
            System.exit(1);
        }

        String targetId = args[0].toUpperCase();
        long durationSeconds = Long.parseLong(args[1]);
        long durationMs = durationSeconds <= 0 ? 0 : durationSeconds * 1000;

        File outputDir = new File("out");
        outputDir.mkdirs();

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.err);

        String testMethod;
        switch (targetId) {
            case "V1":
                testMethod = "fuzzBrotliDecoderDecode";
                break;
            case "V2":
                testMethod = "fuzzZstdDecoderDecode";
                break;
            default:
                System.err.println("Unknown target: " + targetId);
                System.exit(1);
                return;
        }

        System.err.printf("[FuzzRunner] Starting %s for %d seconds%n", targetId, durationSeconds);
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, guidance, System.out);
        System.err.printf("[FuzzRunner] %s finished%n", targetId);
    }

    /**
     * Factory method for creating a Guidance instance.
     * Required by DoSGuide validation contract.
     *
     * @param targetId      "V1" or "V2"
     * @param outputDir     directory for corpus and logs
     * @param maxDurationMs maximum fuzzing duration in milliseconds (0 = infinite)
     * @param log           print stream for structured logging
     * @return a Guidance instance for the target
     */
    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        switch (targetId.toUpperCase()) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            case "V2":
                return new V2Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }
    }
}
