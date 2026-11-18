package fuzzing.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import fuzzing.guidance.V1Guidance;
import fuzzing.guidance.V2Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner for the json-smart DoS fuzzing campaign.
 *
 * Usage: FuzzRunner <V1|V2> [durationSeconds]
 *
 * V1 → fuzzJSONParserParsePermissive (MODE_PERMISSIVE)
 * V2 → fuzzJSONParserParseRFC4627    (MODE_RFC4627)
 */
public class FuzzRunner {

    private static final String TEST_CLASS = "edu.berkeley.cs.jqf.examples.json.JsonSmartFuzzTest";

    /**
     * Factory method required by DoSGuide validation (Part D).
     * Creates the Guidance for the given target.
     */
    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            case "V2" -> new V2Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException("Unknown target: " + targetId
                    + ". Supported: V1, V2");
        };
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <V1|V2> [durationSeconds]");
            System.exit(1);
        }

        String targetId = args[0];
        long durationMs = 0; // infinite by default
        if (args.length >= 2) {
            durationMs = Long.parseLong(args[1]) * 1000L;
        }

        String testMethod = switch (targetId) {
            case "V1" -> "fuzzJSONParserParsePermissive";
            case "V2" -> "fuzzJSONParserParseRFC4627";
            default -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        // Class origin check: prove we're using the vulnerable jar
        try {
            Class<?> parserClass = Class.forName("net.minidev.json.parser.JSONParser");
            System.out.println("[FuzzRunner] JSONParser loaded from: "
                    + parserClass.getProtectionDomain().getCodeSource().getLocation());
        } catch (Exception e) {
            System.err.println("[FuzzRunner] WARNING: Could not verify class origin: " + e);
        }

        Guidance guidance = createGuidance(targetId, outputDir, durationMs, System.out);

        System.out.printf("[FuzzRunner] Starting %s fuzzing: target=%s method=%s duration=%s%n",
                targetId, TEST_CLASS, testMethod,
                durationMs > 0 ? (durationMs / 1000 + "s") : "infinite");

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, guidance, System.out);

        System.out.println("[FuzzRunner] Fuzzing complete for " + targetId);
    }
}
