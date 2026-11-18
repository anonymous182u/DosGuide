package tech.kwik.fuzz.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import tech.kwik.fuzz.guidance.V1Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * Command-line runner for the kwik fuzz harness.
 * <p>
 * Resolves a target ID to the corresponding test class / method / guidance and
 * delegates to {@link GuidedFuzzing#run}.
 *
 * <h3>Usage</h3>
 * <pre>
 *   java ... FuzzRunner &lt;targetId&gt; [durationSeconds]
 * </pre>
 */
public final class FuzzRunner {

    /**
     * Factory method used by the validation harness (DoSGuide).
     *
     * @param targetId     one of the target IDs defined in launch.json ("V1")
     * @param outputDir    directory for corpus / stats output
     * @param maxDurationMs maximum fuzzing time in milliseconds (0 = unlimited)
     * @param log          stream for periodic progress logging
     * @return a configured Guidance instance
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                          long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId> [durationSeconds]");
            System.exit(1);
        }

        String targetId = args[0];
        long durationMs = args.length > 1 ? Long.parseLong(args[1]) * 1000L : 0L;

        String testClass;
        String testMethod;

        switch (targetId) {
            case "V1" -> {
                testClass = "tech.kwik.fuzz.harness.KwikFuzzTest";
                testMethod = "fuzzServerConnectionRegistryRegisterConnection";
            }
            default -> {
                System.err.println("Unknown target ID: " + targetId);
                System.exit(1);
                return;
            }
        }

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        System.out.printf("[FuzzRunner] target=%s test=%s#%s duration=%ds maxInput=%s%n",
                targetId, testClass, testMethod,
                durationMs / 1000,
                System.getProperty("jqf.ei.MAX_INPUT_SIZE", "1048576"));

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.out);
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(testClass, testMethod, cl, guidance, System.out);

        System.out.println("[FuzzRunner] Done.");
    }
}
