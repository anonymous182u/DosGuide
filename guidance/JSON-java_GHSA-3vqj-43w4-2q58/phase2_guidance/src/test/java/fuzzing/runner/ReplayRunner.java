package fuzzing.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import fuzzing.agent.V1DepthCounters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.function.Consumer;

/**
 * Replay a saved corpus entry (or any raw file) through the fuzz target,
 * printing the signal observed.
 *
 * Usage:
 *   java -cp ... -javaagent:target/v1-agent.jar fuzzing.runner.ReplayRunner V1 <inputFile>
 */
public class ReplayRunner {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <targetId> <inputFile>");
            System.exit(1);
        }

        String targetId = args[0];
        File inputFile = new File(args[1]);
        if (!inputFile.exists()) {
            System.err.println("Input file not found: " + inputFile);
            System.exit(1);
        }

        byte[] data = Files.readAllBytes(inputFile.toPath());
        System.err.printf("[Replay] target=%s file=%s size=%d bytes%n",
                targetId, inputFile, data.length);

        // Use JQF's GuidedFuzzing to replay
        String testClass = "fuzzing.harness.XmlFuzzTest";
        String method;
        switch (targetId) {
            case "V1":
                method = "fuzzJSONMLToJSONArray";
                break;
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }

        // Single-shot Guidance that feeds the file data exactly once
        Guidance replay = new Guidance() {
            private boolean consumed = false;

            @Override
            public InputStream getInput() throws IllegalStateException, GuidanceException {
                V1DepthCounters.reset();
                return new ByteArrayInputStream(data);
            }

            @Override
            public boolean hasInput() {
                if (consumed) return false;
                consumed = true;
                return true;
            }

            @Override
            public void handleResult(Result result, Throwable error) throws GuidanceException {
                long depth = V1DepthCounters.maxDepth();
                System.out.printf("result=%s maxDepth=%d inputSize=%d%n",
                        result, depth, data.length);
                if (error != null) {
                    System.out.printf("error=%s: %s%n",
                            error.getClass().getSimpleName(), error.getMessage());
                }
            }

            @Override
            public Consumer<TraceEvent> generateCallBack(Thread thread) {
                return (event) -> { };
            }
        };

        edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing.run(
                testClass, method,
                Thread.currentThread().getContextClassLoader(),
                replay, System.out);

        System.err.println("[Replay] Done.");
    }
}
