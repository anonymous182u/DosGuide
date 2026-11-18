package org.keycloak.fuzzing;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI entry point for the fuzz campaign.
 * <p>
 * Usage: {@code java ... FuzzRunner <targetId> <durationSeconds>}
 * <p>
 * Target IDs:
 * <ul>
 *   <li>{@code V1} → {@link SearchQueryFuzzTest#fuzzSearchQueryUtilsGetFields}</li>
 * </ul>
 *
 * Also exposes the static factory
 * {@link #createGuidance(String, File, long, PrintStream)} required by the
 * validation harness (launch.json {@code guidance_factory}).
 */
public class FuzzRunner {

    // ── Factory method (launch.json guidance_factory) ──────────────────

    /**
     * Creates the Guidance for the given target.
     *
     * @param targetId      e.g. "V1"
     * @param outputDir     directory for corpus / artifacts
     * @param maxDurationMs 0 = infinite
     * @param log           where to print status lines
     * @return configured Guidance (also implements SignalSource)
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                          long maxDurationMs, PrintStream log) {
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, log);
            default -> throw new IllegalArgumentException(
                    "Unknown target: " + targetId);
        };
    }

    // ── CLI entry point ────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <targetId> <durationSeconds>");
            System.exit(1);
        }

        String targetId = args[0];
        long durationSec = Long.parseLong(args[1]);
        long durationMs = durationSec * 1000L;

        // Resolve test class + method from targetId.
        String testClassName;
        String testMethodName;
        switch (targetId) {
            case "V1" -> {
                testClassName = "org.keycloak.fuzzing.SearchQueryFuzzTest";
                testMethodName = "fuzzSearchQueryUtilsGetFields";
            }
            default -> {
                System.err.println("Unknown targetId: " + targetId);
                System.exit(1);
                return; // unreachable but needed for definite assignment
            }
        }

        File outputDir = new File("out/" + targetId);
        outputDir.mkdirs();

        PrintStream log = System.err;
        Guidance guidance = createGuidance(targetId, outputDir, durationMs, log);

        log.printf("[FuzzRunner] target=%s class=%s method=%s duration=%ds%n",
                targetId, testClassName, testMethodName, durationSec);

        GuidedFuzzing.run(testClassName, testMethodName,
                FuzzRunner.class.getClassLoader(), guidance, log);

        log.println("[FuzzRunner] Campaign finished.");
    }
}
