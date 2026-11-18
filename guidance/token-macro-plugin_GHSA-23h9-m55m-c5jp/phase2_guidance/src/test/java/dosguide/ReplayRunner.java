package dosguide;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.agent.V1Counter;
import dosguide.agent.V2Counter;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.function.Consumer;

/**
 * Replays a saved input through the original fuzz harness and reports
 * the measured signals.  Deterministic reproduction (R7).
 *
 * <p>Usage:
 * <pre>
 *   java dosguide.ReplayRunner &lt;V1|V2&gt; &lt;inputFile&gt;
 * </pre>
 */
public class ReplayRunner {

    private static final String TEST_CLASS =
            "edu.berkeley.cs.jqf.examples.tokenmacro.TokenMacroFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <V1|V2> <inputFile>");
            System.exit(1);
        }
        String targetId = args[0];
        File inputFile  = new File(args[1]);

        byte[] data = Files.readAllBytes(inputFile.toPath());
        System.out.printf("Replaying %s (%d bytes) for target %s%n",
                inputFile, data.length, targetId);
        System.out.printf("Input (hex): %s%n", bytesToHex(data, 200));
        System.out.printf("Input (text): %s%n",
                new String(data, StandardCharsets.ISO_8859_1));

        String testMethod;
        switch (targetId) {
            case "V1": testMethod = "fuzzTokenMacroExpand"; break;
            case "V2": testMethod = "fuzzBeginningOrEndMatchTransormTransform"; break;
            default: throw new IllegalArgumentException("Unknown target: " + targetId);
        }

        V1Counter.reset();
        V2Counter.reset();

        // One-shot Guidance that serves the saved input exactly once.
        final byte[] inputData = data;
        Guidance replay = new Guidance() {
            private boolean served = false;
            @Override
            public InputStream getInput() {
                V1Counter.reset();
                V2Counter.reset();
                served = true;
                return new ByteArrayInputStream(inputData);
            }
            @Override
            public boolean hasInput() { return !served; }
            @Override
            public void handleResult(Result result, Throwable error) {
                System.out.printf("Result: %s%s%n", result,
                        error != null ? " (" + error.getClass().getSimpleName()
                                + ": " + error.getMessage() + ")" : "");
                System.out.printf("V1 processTokenCount = %d%n",
                        V1Counter.count.get()[0]);
                System.out.printf("V2 findNanos (charAtSteps) = %d%n",
                        V2Counter.findNanos.get()[0]);
            }
            @Override
            public Consumer<TraceEvent> generateCallBack(Thread t) {
                return e -> { };
            }
        };

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, replay, System.err);
    }

    private static String bytesToHex(byte[] data, int maxLen) {
        StringBuilder sb = new StringBuilder();
        int len = Math.min(data.length, maxLen);
        for (int i = 0; i < len; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", data[i] & 0xff));
        }
        if (len < data.length) sb.append("...");
        return sb.toString();
    }
}
