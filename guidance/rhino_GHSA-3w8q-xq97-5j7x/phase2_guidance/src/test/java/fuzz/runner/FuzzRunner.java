package fuzz.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import fuzz.guidance.V1Guidance;
import fuzz.guidance.V2Guidance;
import fuzz.guidance.V3Guidance;
import fuzz.harness.NativeNumberFuzzTest;

import java.util.Random;

/**
 * CLI runner for DoS fuzz testing of Rhino NativeNumber formatting methods.
 *
 * Usage:
 *   java -javaagent:target/dos-agent.jar -cp <classpath> fuzz.runner.FuzzRunner <target> <maxTrials>
 *
 * Targets:
 *   V1 - fuzzNumberToFixed
 *   V2 - fuzzNumberToStringRadix
 *   V3 - fuzzNumberFormatMethods
 */
public class FuzzRunner {

    /**
     * Factory method: creates the appropriate Guidance for the given target.
     *
     * @param target    V1, V2, or V3
     * @param maxTrials maximum number of fuzzing trials
     * @param random    random seed source
     * @return configured Guidance instance (also implements SignalSource)
     */
    public static Guidance createGuidance(String target, long maxTrials, Random random) {
        return switch (target) {
            case "V1" -> new V1Guidance(maxTrials, random);
            case "V2" -> new V2Guidance(maxTrials, random);
            case "V3" -> new V3Guidance(maxTrials, random);
            default -> throw new IllegalArgumentException("Unknown target: " + target
                    + ". Expected V1, V2, or V3.");
        };
    }

    /**
     * Returns the @Fuzz method name corresponding to the target.
     */
    public static String methodName(String target) {
        return switch (target) {
            case "V1" -> "fuzzNumberToFixed";
            case "V2" -> "fuzzNumberToStringRadix";
            case "V3" -> "fuzzNumberFormatMethods";
            default -> throw new IllegalArgumentException("Unknown target: " + target);
        };
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: FuzzRunner <target V1|V2|V3> <maxTrials>");
            System.exit(1);
        }

        String target = args[0];
        long maxTrials = Long.parseLong(args[1]);

        // Set JQF max input size from system property or default
        if (System.getProperty("jqf.ei.MAX_INPUT_SIZE") == null) {
            System.setProperty("jqf.ei.MAX_INPUT_SIZE", "10240");
        }

        // Seed: use system property or current time
        long seed = Long.getLong("fuzz.seed", System.nanoTime());
        Random random = new Random(seed);

        System.out.printf("[FuzzRunner] target=%s maxTrials=%d seed=%d maxInput=%s%n",
                target, maxTrials, seed, System.getProperty("jqf.ei.MAX_INPUT_SIZE"));

        // Verify vulnerable artifact is loaded
        try {
            Class<?> dtoaClass = Class.forName("org.mozilla.javascript.DToA");
            System.out.printf("[FuzzRunner] DToA loaded from: %s%n",
                    dtoaClass.getProtectionDomain().getCodeSource().getLocation());
        } catch (Exception e) {
            System.err.println("[FuzzRunner] WARNING: Could not verify DToA class source: " + e);
        }

        Guidance guidance = createGuidance(target, maxTrials, random);
        String method = methodName(target);

        System.out.printf("[FuzzRunner] Starting fuzzing: %s.%s%n",
                NativeNumberFuzzTest.class.getSimpleName(), method);

        GuidedFuzzing.run(NativeNumberFuzzTest.class, method, guidance, System.out);

        System.out.println("[FuzzRunner] Fuzzing complete.");
    }
}
