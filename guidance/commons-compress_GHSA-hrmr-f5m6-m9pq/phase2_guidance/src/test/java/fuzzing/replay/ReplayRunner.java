package fuzzing.replay;

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
import java.nio.file.Path;
import java.util.function.Consumer;

/**
 * Replays a single saved input through the fuzz test [R7].
 *
 * Usage: java fuzzing.replay.ReplayRunner <V1|PkgRisk1> <inputFile>
 */
public final class ReplayRunner {

    private static final String TEST_CLASS = "fuzzing.tests.ZipArchiveInputStreamFuzzTest";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <V1|PkgRisk1> <inputFile>");
            System.exit(1);
        }

        String targetId = args[0];
        Path inputPath = Path.of(args[1]);

        byte[] inputBytes = Files.readAllBytes(inputPath);

        System.out.printf("Replaying: target=%s file=%s length=%d bytes%n",
                targetId, inputPath, inputBytes.length);

        // Print hex dump of first 64 bytes
        System.out.print("Hex: ");
        for (int i = 0; i < Math.min(inputBytes.length, 64); i++) {
            System.out.printf("%02x ", inputBytes[i] & 0xFF);
        }
        System.out.println();

        // Read metadata if available
        Path metaPath = Path.of(inputPath + ".meta.json");
        if (Files.exists(metaPath)) {
            System.out.println("Metadata: " + Files.readString(metaPath).trim());
        }

        String testMethod = switch (targetId) {
            case "V1" -> "fuzzZipArchiveInputStreamReadText";
            case "PkgRisk1" -> "fuzzZipArchiveInputStreamReadBytes";
            default -> throw new IllegalArgumentException("Unknown target: " + targetId);
        };

        // Single-input replay guidance
        Guidance replayGuidance = new SingleInputGuidance(inputBytes);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, testMethod, cl, replayGuidance, System.out);

        System.out.println("Replay completed.");
    }

    /**
     * A minimal Guidance that plays a single input once [R3].
     */
    private static final class SingleInputGuidance implements Guidance {

        private final byte[] input;
        private boolean played = false;
        private Result lastResult;
        private Throwable lastError;

        SingleInputGuidance(byte[] input) {
            this.input = input;
        }

        @Override
        public InputStream getInput() throws IllegalStateException, GuidanceException {
            return new ByteArrayInputStream(input);
        }

        @Override
        public boolean hasInput() {
            if (played) return false;
            played = true;
            return true;
        }

        @Override
        public void handleResult(Result result, Throwable error) throws GuidanceException {
            this.lastResult = result;
            this.lastError = error;
            System.out.printf("Result: %s%n", result);
            if (error != null) {
                System.out.printf("Error: %s: %s%n", error.getClass().getName(), error.getMessage());
                error.printStackTrace(System.out);
            }
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return e -> {};
        }
    }
}
