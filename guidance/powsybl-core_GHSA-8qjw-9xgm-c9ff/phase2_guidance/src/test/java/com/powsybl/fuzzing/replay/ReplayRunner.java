package com.powsybl.fuzzing.replay;

import com.powsybl.fuzzing.counter.RegexStepCounter;
import com.powsybl.fuzzing.runner.FuzzRunner;
import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Replays a single saved input file through the fuzz target with signal
 * measurement, printing the resulting nfaSteps to stdout.
 *
 * <p>Usage: {@code java ... ReplayRunner <targetId> <inputFile>}</p>
 */
public class ReplayRunner {

    private static final String TEST_CLASS =
            "com.powsybl.fuzzing.tests.RegexCriterionFuzzTest";
    private static final String TEST_METHOD = "fuzzRegexCriterionFilter";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <targetId> <inputFile>");
            System.exit(1);
        }

        String targetId = args[0];
        Path inputPath = Path.of(args[1]);

        if (!Files.exists(inputPath)) {
            System.err.println("Input file not found: " + inputPath);
            System.exit(1);
        }

        byte[] inputBytes = Files.readAllBytes(inputPath);
        System.out.printf("[ReplayRunner] Replaying %s (%d bytes) for target %s%n",
                inputPath, inputBytes.length, targetId);

        // Create a single-shot guidance that serves the input once
        SingleInputGuidance guidance = new SingleInputGuidance(inputBytes);

        GuidedFuzzing.run(TEST_CLASS, TEST_METHOD,
                Thread.currentThread().getContextClassLoader(),
                guidance, System.out);

        Map<String, Double> signals = guidance.lastSignals();
        System.out.printf("[ReplayRunner] Result: %s | Signals: %s%n",
                guidance.lastResult, signals);
    }

    /**
     * A minimal Guidance that serves a single input and records the result.
     */
    private static class SingleInputGuidance implements Guidance, SignalSource {
        private final byte[] input;
        private boolean served = false;
        Result lastResult;
        private double lastNfaSteps = 0.0;

        SingleInputGuidance(byte[] input) {
            this.input = input;
        }

        @Override
        public InputStream getInput() throws GuidanceException {
            served = true;
            RegexStepCounter.reset();
            return new ByteArrayInputStream(input);
        }

        @Override
        public boolean hasInput() {
            return !served;
        }

        @Override
        public void handleResult(Result result, Throwable error) {
            this.lastResult = result;
            this.lastNfaSteps = (double) RegexStepCounter.get();
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return event -> { };
        }

        @Override
        public Map<String, Double> lastSignals() {
            return Map.of("nfaSteps", lastNfaSteps);
        }
    }
}
