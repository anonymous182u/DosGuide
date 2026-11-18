package org.jose4j.fuzz.replay;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import org.jose4j.fuzz.agent.InflateCounters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

/**
 * Replay runner: loads a saved input and replays it through the fuzz test.
 *
 * Usage: ReplayRunner <inputFile>
 *   inputFile: path to a .bin file from out/V1/corpus/
 *
 * Prints signal values and any exception raised ([R7]).
 */
public class ReplayRunner {

    private static final String TEST_CLASS = "org.jose4j.fuzz.JsonWebEncryptionFuzzTest";
    private static final String TEST_METHOD = "fuzzJsonWebEncryptionGetPlaintextBytes";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ReplayRunner <inputFile>");
            System.exit(1);
        }

        Path inputPath = Path.of(args[0]);
        if (!Files.exists(inputPath)) {
            System.err.println("Input file not found: " + inputPath);
            System.exit(1);
        }

        byte[] inputBytes = Files.readAllBytes(inputPath);
        System.out.println("[Replay] Input file: " + inputPath);
        System.out.println("[Replay] Input length: " + inputBytes.length + " bytes");

        // Print first 64 bytes as hex
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < Math.min(64, inputBytes.length); i++) {
            hex.append(String.format("%02x", inputBytes[i] & 0xFF));
            if (i < Math.min(63, inputBytes.length - 1)) hex.append(" ");
        }
        System.out.println("[Replay] Input hex (first 64 bytes): " + hex);

        // Check for metadata sidecar
        String baseName = inputPath.getFileName().toString();
        if (baseName.endsWith(".bin")) {
            Path metaPath = inputPath.resolveSibling(
                    baseName.substring(0, baseName.length() - 4) + ".json");
            if (Files.exists(metaPath)) {
                System.out.println("[Replay] Metadata: " + Files.readString(metaPath));
            }
        }

        // Reset counters and replay
        InflateCounters.reset();

        // Create a one-shot replay guidance
        ReplayGuidance replayGuidance = new ReplayGuidance(inputBytes);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, TEST_METHOD, cl, replayGuidance, System.out);

        // Print signal values
        long[] counters = InflateCounters.get();
        System.out.println("[Replay] inflatedBytes: " + counters[0]);
        System.out.println("[Replay] inflateCallCount: " + counters[1]);
        if (replayGuidance.lastError != null) {
            System.out.println("[Replay] Exception: " + replayGuidance.lastError.getClass().getName()
                    + ": " + replayGuidance.lastError.getMessage());
        } else {
            System.out.println("[Replay] Result: " + replayGuidance.lastResult);
        }
    }

    /** Minimal Guidance that replays a single input once. */
    private static final class ReplayGuidance implements Guidance {
        private final byte[] input;
        private boolean consumed = false;
        Result lastResult;
        Throwable lastError;

        ReplayGuidance(byte[] input) {
            this.input = input;
        }

        @Override
        public InputStream getInput() throws IllegalStateException, GuidanceException {
            InflateCounters.reset();
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
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return event -> {};
        }
    }
}
