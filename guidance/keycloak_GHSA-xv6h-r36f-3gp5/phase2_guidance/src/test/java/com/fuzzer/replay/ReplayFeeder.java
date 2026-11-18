package com.fuzzer.replay;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.function.Consumer;

/**
 * Deterministic replay of a saved input artifact through the fuzz test [R7].
 * Reads a .bin file (raw DEFLATE bytes) and feeds it once through the harness.
 *
 * Usage: java ... ReplayFeeder &lt;targetId&gt; &lt;inputFile&gt;
 */
public class ReplayFeeder implements Guidance {

    private final byte[] inputBytes;
    private final String inputPath;
    private boolean consumed = false;

    public ReplayFeeder(File inputFile) throws IOException {
        this.inputPath = inputFile.getAbsolutePath();
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            this.inputBytes = fis.readAllBytes();
        }
        System.err.printf("[Replay] Loaded %d bytes from %s%n",
                inputBytes.length, inputPath);
        System.err.printf("[Replay] Base64: %s%n",
                Base64.getEncoder().encodeToString(inputBytes));
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        if (consumed) {
            throw new IllegalStateException("Input already consumed");
        }
        consumed = true;
        System.err.printf("[Replay] Feeding %d bytes%n", inputBytes.length);
        return new ByteArrayInputStream(inputBytes);
    }

    @Override
    public boolean hasInput() {
        return !consumed;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        System.err.printf("[Replay] Result: %s%n", result);
        if (error != null) {
            System.err.printf("[Replay] Error: %s: %s%n",
                    error.getClass().getName(), error.getMessage());
            error.printStackTrace(System.err);
        }
        System.err.printf("[Replay] Input file: %s%n", inputPath);
        System.err.printf("[Replay] Input size: %d bytes%n", inputBytes.length);
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return (event) -> { };
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayFeeder <targetId> <inputFile>");
            System.err.println("  targetId: V1");
            System.err.println("  inputFile: path to .bin artifact (raw DEFLATE bytes)");
            System.exit(1);
        }

        String targetId = args[0];
        File inputFile = new File(args[1]);

        if (!inputFile.exists()) {
            System.err.println("Input file not found: " + inputFile);
            System.exit(1);
        }

        ReplayFeeder feeder = new ReplayFeeder(inputFile);

        String testClass;
        String testMethod;

        switch (targetId) {
            case "V1":
                testClass = "com.fuzzer.saml.SAMLRequestParserFuzzTest";
                testMethod = "fuzzSAMLRequestParserParseRequestRedirectBinding";
                break;
            default:
                throw new IllegalArgumentException("Unknown target: " + targetId);
        }

        System.err.printf("[Replay] Replaying %s through %s#%s%n",
                inputFile, testClass, testMethod);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(testClass, testMethod, cl, feeder, System.out);

        System.err.println("[Replay] Done.");
    }
}
