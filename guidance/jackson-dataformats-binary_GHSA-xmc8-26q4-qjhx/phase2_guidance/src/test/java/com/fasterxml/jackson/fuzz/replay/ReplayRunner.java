package com.fasterxml.jackson.fuzz.replay;

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
 * Replay runner: replays a saved input file against the fuzz harness
 * to reproduce failures deterministically.
 *
 * Usage: java ... ReplayRunner <testMethod> <inputFile>
 */
public final class ReplayRunner {

    private static final String TEST_CLASS_NAME =
            "com.fasterxml.jackson.fuzz.harness.CBORFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <testMethod> <inputFile>");
            System.err.println("  Methods: fuzzCBORParserNextTokenScalarValues, fuzzObjectMapperReadTree");
            System.exit(1);
        }

        String testMethod = args[0];
        File inputFile = new File(args[1]);

        if (!inputFile.exists()) {
            System.err.println("Input file not found: " + inputFile);
            System.exit(1);
        }

        byte[] inputData = Files.readAllBytes(inputFile.toPath());
        System.err.printf("[ReplayRunner] Method: %s, Input: %s (%d bytes)%n",
                testMethod, inputFile.getAbsolutePath(), inputData.length);
        System.err.printf("[ReplayRunner] Input hex: ");
        for (int i = 0; i < Math.min(inputData.length, 64); i++) {
            System.err.printf("%02x ", inputData[i] & 0xFF);
        }
        if (inputData.length > 64) {
            System.err.printf("... (%d more bytes)", inputData.length - 64);
        }
        System.err.println();

        Guidance replayGuidance = new SingleInputGuidance(inputData);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        try {
            GuidedFuzzing.run(TEST_CLASS_NAME, testMethod, cl, replayGuidance, System.out);
        } catch (Throwable t) {
            System.err.println("[ReplayRunner] Exception during replay:");
            t.printStackTrace(System.err);
        }

        System.err.println("[ReplayRunner] Replay complete.");
    }

    /**
     * A minimal Guidance that feeds exactly one input and then stops.
     */
    private static final class SingleInputGuidance implements Guidance {
        private final byte[] input;
        private boolean used = false;

        SingleInputGuidance(byte[] input) {
            this.input = input;
        }

        @Override
        public InputStream getInput() throws GuidanceException {
            return new ByteArrayInputStream(input);
        }

        @Override
        public boolean hasInput() {
            if (used) return false;
            used = true;
            return true;
        }

        @Override
        public void handleResult(Result result, Throwable error) {
            System.err.printf("[ReplayRunner] Result: %s%n", result);
            if (error != null) {
                System.err.printf("[ReplayRunner] Error: %s: %s%n",
                        error.getClass().getName(), error.getMessage());
                error.printStackTrace(System.err);
            }
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return e -> {};
        }
    }
}
