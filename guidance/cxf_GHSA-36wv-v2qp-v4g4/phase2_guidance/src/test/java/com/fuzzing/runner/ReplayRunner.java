package com.fuzzing.runner;

import com.fuzzing.agent.V1Counters;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.function.Consumer;

/**
 * Replays a saved corpus file through the fuzz test and prints metadata.
 *
 * Usage: java ... ReplayRunner <targetId> <inputFile>
 */
public class ReplayRunner {

    private static final String TEST_CLASS = "org.apache.cxf.io.fuzz.CachedOutputStreamFuzzTest";

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

        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());
        System.out.println("[Replay] Target: " + targetId);
        System.out.println("[Replay] Input file: " + inputFile.getAbsolutePath());
        System.out.println("[Replay] Input size: " + inputBytes.length + " bytes");

        // Print hex dump of first 64 bytes
        System.out.print("[Replay] Input (hex): ");
        int dumpLen = Math.min(64, inputBytes.length);
        for (int i = 0; i < dumpLen; i++) {
            System.out.printf("%02x", inputBytes[i]);
            if (i % 4 == 3) System.out.print(" ");
        }
        if (inputBytes.length > 64) System.out.print("...");
        System.out.println();

        String method = switch (targetId) {
            case "V1" -> "fuzzCachedOutputStreamCleanerForceClean";
            default -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };

        Guidance replayGuidance = new ReplayGuidance(inputBytes);

        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            GuidedFuzzing.run(TEST_CLASS, method, cl, replayGuidance, System.out);
        } catch (Exception e) {
            System.out.println("[Replay] Exception during replay: " + e.getClass().getName() + ": " + e.getMessage());
        }

        System.out.println("[Replay] charsAppended: " + V1Counters.getCharsAppended());
        System.out.println("[Replay] Done.");
    }

    private static class ReplayGuidance implements Guidance {
        private final byte[] input;
        private boolean consumed = false;
        private Result lastResult;
        private Throwable lastError;

        ReplayGuidance(byte[] input) {
            this.input = input;
        }

        @Override
        public InputStream getInput() throws IllegalStateException, GuidanceException {
            V1Counters.reset();
            return new ByteArrayInputStream(input);
        }

        @Override
        public boolean hasInput() {
            if (!consumed) {
                consumed = true;
                return true;
            }
            return false;
        }

        @Override
        public void handleResult(Result result, Throwable error) throws GuidanceException {
            this.lastResult = result;
            this.lastError = error;
            System.out.println("[Replay] Result: " + result);
            if (error != null) {
                System.out.println("[Replay] Error: " + error.getClass().getName() + ": " + error.getMessage());
            }
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return (e) -> {};
        }
    }
}
