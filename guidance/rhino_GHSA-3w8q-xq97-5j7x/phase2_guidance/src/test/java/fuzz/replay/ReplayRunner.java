package fuzz.replay;

import fuzz.agent.DToACounters;
import fuzz.harness.NativeNumberFuzzTest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Replay/reproduction runner for saved fuzzing inputs.
 *
 * Usage:
 *   java -javaagent:target/dos-agent.jar -cp <classpath> \
 *       fuzz.replay.ReplayRunner <inputFile> [methodName]
 *
 * methodName defaults to fuzzNumberToFixed (V1).
 * Valid method names:
 *   - fuzzNumberToFixed (V1)
 *   - fuzzNumberToStringRadix (V2)
 *   - fuzzNumberFormatMethods (V3)
 */
public class ReplayRunner {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ReplayRunner <inputFile> [methodName]");
            System.exit(1);
        }

        String inputFile = args[0];
        String methodName = args.length > 1 ? args[1] : "fuzzNumberToFixed";

        byte[] data = Files.readAllBytes(Path.of(inputFile));
        System.out.printf("[Replay] Input: %s (%d bytes)%n", inputFile, data.length);

        // Decode and display the input structure
        if (data.length >= 8) {
            double value = Double.longBitsToDouble(ByteBuffer.wrap(data, 0, 8).getLong());
            System.out.printf("[Replay] Double value: %s (0x%016X)%n",
                    value, Double.doubleToRawLongBits(value));
        }
        if (data.length >= 9) {
            int param = data[8] & 0xFF;
            System.out.printf("[Replay] Param byte: %d (0x%02X)%n", param, param);
        }
        if (data.length >= 10) {
            int sel = data[9] & 0xFF;
            System.out.printf("[Replay] Method selector byte: %d (0x%02X)%n", sel, sel);
        }

        // Verify vulnerable artifact source
        try {
            Class<?> dtoaClass = Class.forName("org.mozilla.javascript.DToA");
            System.out.printf("[Replay] DToA loaded from: %s%n",
                    dtoaClass.getProtectionDomain().getCodeSource().getLocation());
        } catch (Exception e) {
            System.err.println("[Replay] WARNING: Could not verify DToA class source: " + e);
        }

        // Reset counters and execute
        DToACounters.reset();
        NativeNumberFuzzTest test = new NativeNumberFuzzTest();

        long startNs = System.nanoTime();
        try {
            InputStream is = new ByteArrayInputStream(data);
            switch (methodName) {
                case "fuzzNumberToFixed":
                    test.fuzzNumberToFixed(is);
                    break;
                case "fuzzNumberToStringRadix":
                    test.fuzzNumberToStringRadix(is);
                    break;
                case "fuzzNumberFormatMethods":
                    test.fuzzNumberFormatMethods(is);
                    break;
                default:
                    System.err.println("Unknown method: " + methodName);
                    System.exit(1);
            }
        } catch (Throwable t) {
            System.out.printf("[Replay] Exception: %s: %s%n",
                    t.getClass().getSimpleName(), t.getMessage());
        }
        long elapsedNs = System.nanoTime() - startNs;

        // Report counters
        System.out.println("--- Replay Results ---");
        System.out.printf("  Method:          %s%n", methodName);
        System.out.printf("  Elapsed:         %.3f ms%n", elapsedNs / 1_000_000.0);
        System.out.printf("  BigIntOps:       %d%n", DToACounters.getBigIntOps());
        System.out.printf("  JS_dtoa time:    %.3f ms%n", DToACounters.getJsDtoaTimeNs() / 1_000_000.0);
        System.out.printf("  JS_dtobasestr:   %.3f ms%n", DToACounters.getJsDtobasestrTimeNs() / 1_000_000.0);
        System.out.printf("  JS_dtostr time:  %.3f ms%n", DToACounters.getJsDtostrTimeNs() / 1_000_000.0);
        System.out.printf("  pow5mult calls:  %d%n", DToACounters.getPow5multCalls());
    }
}
