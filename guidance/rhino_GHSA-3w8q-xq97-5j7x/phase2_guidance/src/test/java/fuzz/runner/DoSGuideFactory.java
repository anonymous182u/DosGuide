package fuzz.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import fuzz.guidance.V1Guidance;
import fuzz.guidance.V2Guidance;
import fuzz.guidance.V3Guidance;

import java.io.File;
import java.io.PrintStream;
import java.util.Random;

/**
 * Factory class with the exact signature that DoSGuide expects.
 *
 * DoSGuide calls:
 *   createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log)
 *
 * This is separate from FuzzRunner (which is frozen) to avoid revert issues.
 */
public class DoSGuideFactory {

    /**
     * Factory method called by DoSGuide to create the appropriate Guidance.
     *
     * @param targetId       V1, V2, or V3
     * @param outputDir      directory for saving interesting inputs / artifacts
     * @param maxDurationMs  maximum fuzzing duration in milliseconds
     * @param log            print stream for logging
     * @return configured Guidance instance (also implements SignalSource)
     */
    public static Guidance createGuidance(String targetId, File outputDir,
                                          long maxDurationMs, PrintStream log) {
        Random random = new Random();
        return switch (targetId) {
            case "V1" -> new V1Guidance(outputDir, maxDurationMs, random, log);
            case "V2" -> new V2Guidance(outputDir, maxDurationMs, random, log);
            case "V3" -> new V3Guidance(outputDir, maxDurationMs, random, log);
            default -> throw new IllegalArgumentException("Unknown target: " + targetId
                    + ". Expected V1, V2, or V3.");
        };
    }
}
