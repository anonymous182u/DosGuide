package org.elasticsearch.compute.data.fuzz;

import java.io.File;
import java.io.PrintStream;
import java.util.Map;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import org.elasticsearch.compute.data.fuzz.guidance.V1Guidance;
import org.elasticsearch.compute.data.fuzz.guidance.V2Guidance;

/**
 * CLI runner for the block builder fuzz harness.
 *
 * <p>Usage: {@code java ... FuzzRunner <targetId> <durationSec> [outputDir]}
 *
 * <p>Target IDs:
 * <ul>
 *   <li>{@code V1} → IntBlockBuilder (fuzzBlockFactoryNewIntBlockBuilder)</li>
 *   <li>{@code V2} → LongBlockBuilder (fuzzBlockFactoryNewLongBlockBuilder)</li>
 * </ul>
 *
 * <p>Also exposes the factory method {@link #createGuidance} that DoSGuide's
 * validation framework calls to instantiate a Guidance.
 */
public class FuzzRunner {

    /** The JQF fuzz-test class containing the @Fuzz methods. */
    private static final Class<?> TEST_CLASS = BlockBuilderFuzzTest.class;

    /** Map from target ID to the @Fuzz method name in BlockBuilderFuzzTest. */
    private static final Map<String, String> TARGET_METHODS = Map.of(
            "V1", "fuzzBlockFactoryNewIntBlockBuilder",
            "V2", "fuzzBlockFactoryNewLongBlockBuilder"
    );

    /**
     * Factory method for creating a Guidance instance.
     *
     * <p>This is the entry point that DoSGuide's validation framework uses.
     * Signature: {@code (String targetId, File outputDir, long maxDurationMs, PrintStream log) → Guidance}
     *
     * @param targetId     "V1" or "V2"
     * @param outputDir    directory for saving best/crash inputs (may be null)
     * @param maxDurationMs maximum fuzzing duration in milliseconds
     * @param log          stream for periodic status logging
     * @return a Guidance that also implements {@link dosguide.validate.SignalSource}
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                          long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            case "V2" -> new V2Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException("Unknown target: " + targetId
                    + ". Valid targets: V1, V2");
        };
    }

    /**
     * CLI entry point.
     *
     * @param args [0] targetId (V1 or V2), [1] durationSec, [2] optional outputDir
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <targetId> <durationSec> [outputDir]");
            System.err.println("  targetId:    V1 (IntBlockBuilder) or V2 (LongBlockBuilder)");
            System.err.println("  durationSec: max fuzzing duration in seconds");
            System.err.println("  outputDir:   directory for saving results (default: fuzz-results/<targetId>)");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = Long.parseLong(args[1]);
        long maxDurationMs = durationSec * 1000L;

        String methodName = TARGET_METHODS.get(targetId);
        if (methodName == null) {
            System.err.println("Unknown target: " + targetId + ". Valid targets: " + TARGET_METHODS.keySet());
            System.exit(1);
        }

        File outputDir;
        if (args.length >= 3) {
            outputDir = new File(args[2]);
        } else {
            outputDir = new File("fuzz-results", targetId);
        }

        System.out.printf("=== FuzzRunner ===%n");
        System.out.printf("Target:   %s → %s%n", targetId, methodName);
        System.out.printf("Duration: %d seconds%n", durationSec);
        System.out.printf("Output:   %s%n", outputDir.getAbsolutePath());
        System.out.printf("MaxInput: %s bytes%n", System.getProperty("jqf.ei.MAX_INPUT_SIZE", "10240"));
        System.out.println();

        Guidance guidance = createGuidance(targetId, outputDir, maxDurationMs, System.out);

        // Run JQF with the custom guidance.
        // The test class name is passed as a string so JQF can load it through its
        // InstrumentingClassLoader if desired; we also pass the current classloader.
        GuidedFuzzing.run(TEST_CLASS, methodName, guidance, System.out);

        System.out.printf("%n=== FuzzRunner complete ===%n");
    }
}
