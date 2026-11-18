package org.xerial.snappy.fuzz;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.function.Consumer;

/**
 * Replay runner: loads a saved payload file and replays it through
 * the JQF pipeline to deterministically reproduce the execution.
 * <p>
 * Usage: java ... ReplayRunner &lt;input.bin&gt; &lt;fuzzMethod&gt;
 * <p>
 * Example: java ... ReplayRunner out/V1/corpus/id_000042.bin fuzzSnappyInputStreamRead
 */
public class ReplayRunner {

    private static final String TEST_CLASS = "org.xerial.snappy.fuzz.SnappyFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <input.bin> <fuzzMethodName>");
            System.exit(1);
        }

        String inputPath = args[0];
        String methodName = args[1];

        byte[] payload = Files.readAllBytes(new File(inputPath).toPath());
        System.err.printf("Replaying %s (%d payload bytes) via %s.%s%n",
                inputPath, payload.length, TEST_CLASS, methodName);

        // Print hex dump (first 64 bytes)
        StringBuilder hex = new StringBuilder("Input hex: ");
        for (int i = 0; i < Math.min(payload.length, 64); i++) {
            hex.append(String.format("%02x ", payload[i] & 0xFF));
        }
        if (payload.length > 64) hex.append("...");
        System.err.println(hex);

        // Read metadata JSON if present
        String metaPath = inputPath.replace(".bin", ".json");
        File metaFile = new File(metaPath);
        if (metaFile.exists()) {
            String meta = Files.readString(metaFile.toPath());
            System.err.println("Metadata: " + meta.trim());
        }

        // Create single-shot replay guidance
        Guidance replayGuidance = new ReplayGuidance(payload);

        AllocCounters.reset();
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, methodName, cl, replayGuidance, System.err);

        // Print signal values
        System.err.printf("Signal after replay: slot0=%d, slot1=%d, slot2=%d%n",
                AllocCounters.get(0), AllocCounters.get(1), AllocCounters.get(2));
    }

    /**
     * Single-input replay guidance: feeds the saved payload once, then stops.
     * Overrides run() to inject payload directly (same as the main guidances).
     */
    static class ReplayGuidance implements Guidance {
        private final byte[] payload;
        private boolean done = false;

        ReplayGuidance(byte[] payload) {
            this.payload = payload;
        }

        @Override
        public InputStream getInput() throws IllegalStateException, GuidanceException {
            AllocCounters.reset();
            return new ByteArrayInputStream(payload);
        }

        @Override
        public void run(org.junit.runners.model.TestClass testClass,
                        org.junit.runners.model.FrameworkMethod method,
                        Object[] args) throws Throwable {
            args[0] = new ByteArrayInputStream(payload);
            Guidance.super.run(testClass, method, args);
        }

        @Override
        public boolean hasInput() {
            return !done;
        }

        @Override
        public void handleResult(Result result, Throwable error) throws GuidanceException {
            this.done = true;
            System.err.printf("Result: %s%n", result);
            if (error != null) {
                System.err.printf("Error: %s: %s%n",
                        error.getClass().getName(), error.getMessage());
            }
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return null;
        }
    }
}
