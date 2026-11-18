package fuzzing.replay;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import fuzzing.agent.DepthCounters;
import fuzzing.agent.XmlDepthCounters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.function.Consumer;

/**
 * Replay runner: replays a single saved input through the fuzz harness
 * and reports the measured signals and result.
 *
 * Usage: java ... fuzzing.replay.ReplayRunner <targetId> <inputFile>
 *
 * Reads the input file, feeds it to the fuzz harness, and prints
 * the result, any exception, and measured signals (maxDepth, nodeCount).
 */
public class ReplayRunner {

    private static final String TEST_CLASS = "fuzzing.harness.JsonFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <targetId> <inputFile>");
            System.err.println("  targetId: V1 | V2");
            System.err.println("  inputFile: path to .bin file");
            System.exit(1);
        }

        String targetId = args[0];
        File inputFile = new File(args[1]);

        if (!inputFile.exists()) {
            System.err.println("Input file not found: " + inputFile);
            System.exit(1);
        }

        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());
        String testMethod;

        switch (targetId) {
            case "V1":
                testMethod = "fuzzJSONObjectAndJSONArrayConstructors";
                break;
            case "V2":
                testMethod = "fuzzXMLToJSONObject";
                break;
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }

        System.out.printf("=== Replay: target=%s, file=%s, size=%d bytes ===%n",
                targetId, inputFile, inputBytes.length);

        // Print input content (truncated)
        String inputStr = new String(inputBytes, StandardCharsets.UTF_8);
        if (inputStr.length() > 200) {
            System.out.printf("Input (UTF-8, truncated): %s...%n", inputStr.substring(0, 200));
        } else {
            System.out.printf("Input (UTF-8): %s%n", inputStr);
        }

        // Print hex (truncated)
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < Math.min(inputBytes.length, 100); i++) {
            hex.append(String.format("%02x ", inputBytes[i]));
        }
        if (inputBytes.length > 100) hex.append("...");
        System.out.printf("Input (hex): %s%n", hex);

        // Reset counters
        DepthCounters.reset();
        XmlDepthCounters.reset();

        // Create a single-shot replay guidance
        ReplayGuidance replayGuidance = new ReplayGuidance(inputBytes, targetId);

        // Run
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, replayGuidance, System.out);

        // Print results
        System.out.printf("=== Result: %s ===%n", replayGuidance.lastResult);
        if (replayGuidance.lastError != null) {
            System.out.printf("Exception: %s%n", replayGuidance.lastError);
            replayGuidance.lastError.printStackTrace(System.out);
        }

        long maxDepth;
        long nodeCount;
        if ("V1".equals(targetId)) {
            maxDepth = DepthCounters.getMaxDepth();
            nodeCount = DepthCounters.getNodeCount();
        } else {
            maxDepth = XmlDepthCounters.getMaxDepth();
            nodeCount = XmlDepthCounters.getNodeCount();
        }

        System.out.printf("Signals: maxDepth=%d, nodeCount=%d%n", maxDepth, nodeCount);
    }

    /**
     * Minimal single-execution Guidance for replaying one input.
     */
    private static class ReplayGuidance implements Guidance {

        private final byte[] input;
        private final String targetId;
        private boolean hasRun = false;
        Result lastResult;
        Throwable lastError;

        ReplayGuidance(byte[] input, String targetId) {
            this.input = input;
            this.targetId = targetId;
        }

        @Override
        public InputStream getInput() throws GuidanceException {
            if ("V1".equals(targetId)) {
                DepthCounters.reset();
            } else {
                XmlDepthCounters.reset();
            }
            return new ByteArrayInputStream(input);
        }

        @Override
        public boolean hasInput() {
            if (hasRun) return false;
            hasRun = true;
            return true;
        }

        @Override
        public void handleResult(Result result, Throwable error) throws GuidanceException {
            this.lastResult = result;
            this.lastError = error;
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return (event) -> { };
        }
    }
}
