package com.googlecode.vfsjfilechooser2.fuzz.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import com.googlecode.vfsjfilechooser2.fuzz.guidance.V1Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the vfsjfilechooser2 fuzz targets.
 *
 * <p>Usage: {@code java ... FuzzRunner <targetId> <durationSeconds>}
 *
 * <p>Factory method {@link #createGuidance} is the entry point used by DoSGuide validation.
 */
public class FuzzRunner {

    /**
     * Factory method required by DoSGuide validation contract.
     *
     * @param targetId       target identifier (e.g. "V1")
     * @param outputDir      directory for corpus and logs
     * @param maxDurationMs  maximum fuzzing duration in milliseconds (0 = unlimited)
     * @param log            log stream for structured output
     * @return a fresh Guidance instance for the given target
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                          long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <targetId> <durationSeconds>");
            System.err.println("  targetId:        V1");
            System.err.println("  durationSeconds:  0 = infinite");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSeconds = Long.parseLong(args[1]);
        long durationMs = durationSeconds > 0 ? durationSeconds * 1000 : 0;

        // Verify the vulnerable artifact is loaded from the correct jar
        try {
            Class<?> cls = Class.forName(
                    "com.googlecode.vfsjfilechooser2.utils.VFSURIValidator");
            System.err.println("[FuzzRunner] VFSURIValidator loaded from: "
                    + cls.getProtectionDomain().getCodeSource().getLocation());
        } catch (ClassNotFoundException e) {
            System.err.println("[FuzzRunner] ERROR: VFSURIValidator not on classpath");
            System.exit(1);
        }

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        PrintStream log = System.err;
        Guidance guidance = createGuidance(targetId, outputDir, durationMs, log);

        String testClass;
        String testMethod;
        switch (targetId) {
            case "V1":
                testClass = "com.googlecode.vfsjfilechooser2.fuzz.harness.VFSURIValidatorFuzzTest";
                testMethod = "fuzzVFSURIValidatorIsValid";
                break;
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }

        log.println("[FuzzRunner] target=" + targetId
                + " method=" + testMethod
                + " duration=" + durationSeconds + "s"
                + " maxInputSize=" + Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240));

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(testClass, testMethod, cl, guidance, log);

        log.println("[FuzzRunner] Fuzzing complete for target=" + targetId);
    }
}
