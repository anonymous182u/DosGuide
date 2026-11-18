package dosguide;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import dosguide.guidance.V1Guidance;
import dosguide.guidance.V2Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for DoS-targeted fuzzing of the token-macro plugin.
 *
 * <p>Usage:
 * <pre>
 *   java dosguide.FuzzRunner &lt;targetId&gt; &lt;durationSeconds&gt;
 * </pre>
 *
 * <p>Supports CLI method selection (R10):
 * <ul>
 *   <li>{@code V1} — fuzzTokenMacroExpand (CWE-674)</li>
 *   <li>{@code V2} — fuzzBeginningOrEndMatchTransormTransform (CWE-1333)</li>
 * </ul>
 */
public class FuzzRunner {

    private static final String TEST_CLASS =
            "edu.berkeley.cs.jqf.examples.tokenmacro.TokenMacroFuzzTest";

    /**
     * Factory method used by DoSGuide validation (Part D).
     *
     * @param targetId     "V1" or "V2"
     * @param outputDir    directory for corpus and logs
     * @param maxDurationMs  fuzzing budget in ms (0 = infinite)
     * @param log          stream for structured logs
     * @return the target's Guidance (also implements SignalSource)
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                          long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1": return new V1Guidance(outputDir, maxDurationMs, log);
            case "V2": return new V2Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId
                        + " (valid: V1, V2)");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <V1|V2> <durationSeconds>");
            System.exit(1);
        }

        String targetId   = args[0];
        long durationSec  = Long.parseLong(args[1]);
        long durationMs   = durationSec > 0 ? durationSec * 1000 : 0;

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        PrintStream log = System.err;
        Guidance guidance = createGuidance(targetId, outputDir, durationMs, log);

        String testMethod;
        switch (targetId) {
            case "V1":
                testMethod = "fuzzTokenMacroExpand";
                break;
            case "V2":
                testMethod = "fuzzBeginningOrEndMatchTransormTransform";
                break;
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }

        log.printf("=== FuzzRunner  target=%s  method=%s  duration=%ds ===%n",
                targetId, testMethod, durationSec);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, guidance, log);

        log.println("=== FuzzRunner done ===");
    }
}
