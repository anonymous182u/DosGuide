package com.fuzzing.replay;

import com.fuzzing.agent.V1Counters;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.*;
import java.nio.file.Files;
import java.util.function.Consumer;

/**
 * Replays a single saved input file against a fuzz target, printing the
 * measured signals and the execution result.
 *
 * Usage:
 *   java -cp &lt;classpath&gt; -javaagent:&lt;agent.jar&gt; \
 *        com.fuzzing.replay.ReplayRunner &lt;targetId&gt; &lt;inputFile&gt;
 */
public class ReplayRunner {

    private static final String TEST_CLASS = "com.fuzzing.harness.MultipartFuzzTest";

    private static String testMethodFor(String targetId) {
        return switch (targetId) {
            case "V1" -> "fuzzMultipartStreamReadHeaders";
            default   -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <targetId> <inputFile>");
            System.exit(1);
        }

        String targetId = args[0];
        File inputFile  = new File(args[1]);

        if (!inputFile.isFile()) {
            System.err.println("Input file not found: " + inputFile);
            System.exit(1);
        }

        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());
        System.out.printf("[Replay] target=%s input=%s (%d bytes)%n",
                targetId, inputFile, inputBytes.length);

        String testMethod = testMethodFor(targetId);

        // Single-shot guidance that provides the input exactly once.
        ReplayGuidance guidance = new ReplayGuidance(inputBytes);

        GuidedFuzzing.run(TEST_CLASS, testMethod, guidance, System.out);

        // Print results
        System.out.printf("[Replay] result=%s%n", guidance.lastResult);
        if (guidance.lastError != null) {
            System.out.printf("[Replay] error=%s: %s%n",
                    guidance.lastError.getClass().getName(),
                    guidance.lastError.getMessage());
        }
        System.out.printf("[Replay] boundaryIterations=%d%n",
                guidance.boundaryIterations);
        System.out.printf("[Replay] headerBytes=%d%n",
                guidance.headerBytes);
        System.out.printf("[Replay] multipartWork=%.6f%n",
                guidance.multipartWork);
    }

    /**
     * Minimal Guidance that feeds one input, records the result, then stops.
     */
    private static class ReplayGuidance implements Guidance {
        private final byte[] input;
        private boolean used = false;

        Result lastResult;
        Throwable lastError;
        long boundaryIterations;
        long headerBytes;
        double multipartWork;

        ReplayGuidance(byte[] input) {
            this.input = input;
        }

        @Override
        public InputStream getInput() throws IllegalStateException, GuidanceException {
            V1Counters.reset();
            used = true;
            return new ByteArrayInputStream(input);
        }

        @Override
        public boolean hasInput() {
            return !used;
        }

        @Override
        public void handleResult(Result result, Throwable error) throws GuidanceException {
            this.lastResult         = result;
            this.lastError          = error;
            this.boundaryIterations = V1Counters.getBoundaryIterations();
            this.headerBytes        = V1Counters.getHeaderBytes();
            this.multipartWork      = 0.5 * (boundaryIterations / 10.0)
                                    + 0.5 * (headerBytes / 512.0);
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return event -> { };
        }
    }
}
