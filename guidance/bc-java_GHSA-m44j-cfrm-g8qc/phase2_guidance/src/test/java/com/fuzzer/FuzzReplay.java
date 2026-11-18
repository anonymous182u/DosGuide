package com.fuzzer;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Replays a single saved input file through the Ed25519 fuzz harness
 * with instrumentation active, printing the measured signals.
 *
 * Usage: java ... FuzzReplay <inputFile>
 *
 * Output: prints loopIterations and execution time to stdout.
 */
public class FuzzReplay implements Guidance, SignalSource {

    private final byte[] inputData;
    private boolean consumed = false;
    private double lastSignalValue = 0.0;

    public FuzzReplay(byte[] data) {
        this.inputData = data;
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        V1Counters.reset();
        consumed = true;
        return new ByteArrayInputStream(inputData);
    }

    @Override
    public boolean hasInput() {
        return !consumed;
    }

    @Override
    public void handleResult(edu.berkeley.cs.jqf.fuzz.guidance.Result result, Throwable error) throws GuidanceException {
        long iterations = V1Counters.get();
        lastSignalValue = (double) iterations;
        System.out.printf("[FuzzReplay] result=%s, loopIterations=%d%n", result, iterations);
        if (error != null) {
            System.out.printf("[FuzzReplay] error=%s: %s%n", error.getClass().getSimpleName(), error.getMessage());
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return event -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        signals.put("loopIterations", lastSignalValue);
        return signals;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzReplay <inputFile>");
            System.exit(1);
        }

        File inputFile = new File(args[0]);
        if (!inputFile.exists()) {
            System.err.println("Input file not found: " + inputFile);
            System.exit(1);
        }

        byte[] data = Files.readAllBytes(inputFile.toPath());
        System.out.printf("[FuzzReplay] Replaying %s (%d bytes)%n", inputFile, data.length);

        FuzzReplay replay = new FuzzReplay(data);

        long startNs = System.nanoTime();
        try {
            GuidedFuzzing.run(
                    Ed25519FuzzTest.class,
                    "fuzzEd25519Verify",
                    replay,
                    System.out
            );
        } catch (Exception e) {
            System.err.printf("[FuzzReplay] Error: %s%n", e.getMessage());
        }
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
        System.out.printf("[FuzzReplay] elapsed=%dms%n", elapsedMs);

        // Print signals for validation
        Map<String, Double> signals = replay.lastSignals();
        System.out.printf("[FuzzReplay] signals=%s%n", signals);
    }
}
