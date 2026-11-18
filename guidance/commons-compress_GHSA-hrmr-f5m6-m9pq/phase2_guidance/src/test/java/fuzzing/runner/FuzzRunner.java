package fuzzing.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import fuzzing.guidance.V1Guidance;
import fuzzing.guidance.PkgRisk1Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for fuzzing. Supports target selection [R10].
 *
 * Usage: java fuzzing.runner.FuzzRunner <targetId> [durationSeconds]
 *   targetId:         V1 | PkgRisk1
 *   durationSeconds:  optional, 0 = infinite [R8]
 */
public final class FuzzRunner {

    private static final String TEST_CLASS = "fuzzing.tests.ZipArchiveInputStreamFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <V1|PkgRisk1> [durationSeconds]");
            System.exit(1);
        }

        String targetId = args[0];
        long durationMs = 0; // infinite by default
        if (args.length >= 2) {
            durationMs = Long.parseLong(args[1]) * 1000L;
        }

        // Check system property for timeout as well
        String timeoutProp = System.getProperty("jqf.ei.timeout");
        if (timeoutProp != null && durationMs == 0) {
            durationMs = Long.parseLong(timeoutProp) * 1000L;
        }

        File outputDir = new File("out", targetId);
        outputDir.mkdirs();

        PrintStream logStream = System.out;
        Guidance guidance = createGuidance(targetId, outputDir, durationMs, logStream);

        String testMethod = getTestMethod(targetId);

        System.out.printf("Starting fuzzing: target=%s method=%s duration=%s%n",
                targetId, testMethod,
                durationMs > 0 ? durationMs + "ms" : "infinite");

        // Class origin check
        System.out.println("ZipArchiveInputStream loaded from: " +
            org.apache.commons.compress.archivers.zip.ZipArchiveInputStream.class
                .getProtectionDomain().getCodeSource().getLocation());

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, guidance, logStream);

        System.out.println("Fuzzing completed for target: " + targetId);
    }

    /**
     * Factory method required by DoSGuide validation contract.
     * Creates the appropriate Guidance for the given target.
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                           long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            case "PkgRisk1" -> new PkgRisk1Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException("Unknown target: " + targetId
                    + ". Valid targets: V1, PkgRisk1");
        };
    }

    private static String getTestMethod(String targetId) {
        return switch (targetId) {
            case "V1" -> "fuzzZipArchiveInputStreamReadText";
            case "PkgRisk1" -> "fuzzZipArchiveInputStreamReadBytes";
            default -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };
    }
}
