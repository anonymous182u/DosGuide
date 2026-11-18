package v1;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for V1 fuzzing.
 *
 * Usage: java v1.FuzzRunner <targetId> [durationSeconds]
 *   targetId: V1
 *   durationSeconds: 0 = infinite (default), >0 = time-bounded [R8]
 *
 * Supports CLI method selection [R10].
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "com.fuzz.snakeyaml.SnakeYamlFuzzTest";

    /**
     * Factory method for DoSGuide validation [Part D].
     *
     * @param targetId      the target identifier (e.g. "V1")
     * @param outputDir     the output directory for corpus/logs
     * @param maxDurationMs maximum duration in ms (0 = infinite)
     * @param log           print stream for logging
     * @return a configured Guidance instance
     */
    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        if (!"V1".equals(targetId)) {
            throw new IllegalArgumentException("Unknown target: " + targetId + ". Supported: V1");
        }
        return new V1Guidance(outputDir, maxDurationMs, log);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java v1.FuzzRunner <targetId> [durationSeconds]");
            System.err.println("  targetId: V1");
            System.err.println("  durationSeconds: 0=infinite (default)");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = args.length > 1 ? Long.parseLong(args[1]) : 0;
        long durationMs = durationSec > 0 ? durationSec * 1000 : 0;

        // Map target to fuzz method
        String method = resolveMethod(targetId);

        File outputDir = new File("out", targetId);
        outputDir.mkdirs();

        PrintStream log = System.err;

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, log);

        // Class Origin Check: prove we load from the vulnerable jar, not target/classes
        try {
            Class<?> composerClass = Class.forName("org.yaml.snakeyaml.composer.Composer");
            log.println("[FuzzRunner] Composer loaded from: " +
                    composerClass.getProtectionDomain().getCodeSource().getLocation());
        } catch (Exception e) {
            log.println("[FuzzRunner] WARNING: Could not verify Composer class origin: " + e);
        }

        log.printf("[FuzzRunner] Starting %s on %s#%s (duration=%s)%n",
                targetId, TEST_CLASS, method,
                durationMs > 0 ? durationMs + "ms" : "infinite");

        // Run guided fuzzing [R4 Step 4]
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, method, cl, guidance, System.out);

        log.println("[FuzzRunner] Fuzzing complete.");
    }

    private static String resolveMethod(String targetId) {
        return switch (targetId) {
            case "V1" -> "fuzzYamlLoad";
            default -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };
    }
}
