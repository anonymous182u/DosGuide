package tech.kwik.fuzz.replay;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import tech.kwik.fuzz.agent.V1Counters;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.function.Consumer;

/**
 * Replays a saved input file through the fuzz harness, printing metadata
 * (input size, connection ID count, equals count from the V1 agent).
 *
 * <h3>Usage</h3>
 * <pre>
 *   java -javaagent:target/agent/v1-measure-agent.jar \
 *        -cp ... MetadataReplay &lt;inputFile&gt; [testClass [testMethod]]
 * </pre>
 */
public final class MetadataReplay {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: MetadataReplay <inputFile> [testClass] [testMethod]");
            System.exit(1);
        }

        String inputFile = args[0];
        String testClass = args.length > 1 ? args[1]
                : "tech.kwik.fuzz.harness.KwikFuzzTest";
        String testMethod = args.length > 2 ? args[2]
                : "fuzzServerConnectionRegistryRegisterConnection";

        byte[] inputData = Files.readAllBytes(Paths.get(inputFile));
        System.out.printf("Replaying: %s (%d bytes)%n", inputFile, inputData.length);

        // Count and show the first few connection IDs
        int pos = 0;
        int idCount = 0;
        while (pos < inputData.length) {
            int len = ((inputData[pos] & 0xff) % 20) + 1;
            pos++;
            if (pos + len > inputData.length) break;
            if (idCount < 5) {
                StringBuilder hex = new StringBuilder();
                for (int i = 0; i < len; i++) {
                    hex.append(String.format("%02x", inputData[pos + i]));
                }
                System.out.printf("  ID[%d] len=%d: %s%n", idCount, len, hex);
            }
            pos += len;
            idCount++;
        }
        if (idCount > 5) {
            System.out.printf("  ... and %d more IDs%n", idCount - 5);
        }
        System.out.printf("Total connection IDs: %d%n", idCount);

        // Reset agent counter and replay the input once
        V1Counters.reset();

        Guidance replayGuidance = new Guidance() {
            private boolean hasRun = false;

            @Override
            public InputStream getInput() throws GuidanceException {
                return new ByteArrayInputStream(inputData);
            }

            @Override
            public boolean hasInput() {
                if (hasRun) return false;
                hasRun = true;
                return true;
            }

            @Override
            public void handleResult(Result result, Throwable error) {
                long equalsCount = V1Counters.getEqualsCount();
                System.out.printf("Result: %s  equalsCount: %d%n", result, equalsCount);
                if (error != null) {
                    System.err.printf("Error: %s: %s%n",
                            error.getClass().getName(), error.getMessage());
                }
            }

            @Override
            public Consumer<TraceEvent> generateCallBack(Thread thread) {
                return e -> { };
            }
        };

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(testClass, testMethod, cl, replayGuidance, System.out);
    }
}
