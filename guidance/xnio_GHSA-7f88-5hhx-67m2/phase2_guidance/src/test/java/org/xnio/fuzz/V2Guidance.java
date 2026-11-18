package org.xnio.fuzz;

import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import org.xnio.fuzz.agent.RecursionCounters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance for target V2: hill-climbing recursion depth
 * in AbstractIoFuture$CancellableState.cancel.
 *
 * Implements Guidance (JQF 2.1) and SignalSource (validation contract).
 * Uses the RecursionCounters ThreadLocal signal injected by the Java agent.
 *
 * Retention: primary = maxDepth improvement; secondary (flat signal) = length growth [R46].
 * Mutation: byte-level + repetition [R45(a)] + dictionary [R45(b)].
 */
public final class V2Guidance implements Guidance, SignalSource {

    /** Read the maximum input size from the system property set by the evaluation harness. */
    private static int readMaxInputSize() {
        String prop = System.getProperty("jqf.ei.MAX_INPUT_SIZE");
        if (prop != null) {
            try {
                return Integer.parseInt(prop.trim());
            } catch (NumberFormatException ignored) {}
        }
        return 65_536; // default if property not set
    }

    private final int maxInputSize;
    private final File outputDir;
    private final File corpusDir;
    private final long maxDurationMs;
    private final PrintStream log;
    private final Random rng = new Random();
    private final long startTimeMs;

    // Corpus of retained inputs
    private final List<byte[]> corpus = new ArrayList<>();

    // Current execution state
    private byte[] currentInput;
    private long executionCount;
    private long bestMaxDepth;
    private int bestLength;

    // Per-execution signal for SignalSource
    private double lastMaxDepth;

    public V2Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = readMaxInputSize();
        this.outputDir = outputDir;
        this.corpusDir = new File(outputDir, "corpus");
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();

        corpusDir.mkdirs();

        // Initial seed: registration bytes, capped to maxInputSize
        int seedLen = Math.min(16, maxInputSize);
        byte[] seed = new byte[seedLen];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) 0xFF;
        }
        corpus.add(seed);
    }

    @Override
    public boolean hasInput() {
        long elapsed = System.currentTimeMillis() - startTimeMs;
        return elapsed < maxDurationMs;
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset recursion counter before each execution
        RecursionCounters.resetCancel();

        // Select a parent from corpus and mutate
        byte[] parent = corpus.get(rng.nextInt(corpus.size()));
        currentInput = Mutator.mutate(parent, maxInputSize, rng);
        executionCount++;

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        long depth = RecursionCounters.getCancelMaxDepth();
        lastMaxDepth = (double) depth;

        boolean retained = false;

        if (result == Result.SUCCESS || result == Result.FAILURE) {
            // Primary criterion: depth improvement
            if (depth > bestMaxDepth) {
                bestMaxDepth = depth;
                corpus.add(currentInput.clone());
                retained = true;
            }
            // Secondary criterion [R46]: length growth when signal is flat
            else if (depth == 0 || depth == bestMaxDepth) {
                if (currentInput.length > bestLength) {
                    bestLength = currentInput.length;
                    corpus.add(currentInput.clone());
                    retained = true;
                }
            }
        }

        // Save FAILURE inputs (potential DoS triggers)
        if (result == Result.FAILURE && error instanceof StackOverflowError) {
            saveInput(currentInput, "crash_" + executionCount);
        }

        // Periodic logging
        if (executionCount % 500 == 0) {
            long elapsed = System.currentTimeMillis() - startTimeMs;
            log.printf("[V2] exec=%d elapsed=%dms bestDepth=%d corpus=%d lastDepth=%d inputLen=%d%n",
                    executionCount, elapsed, bestMaxDepth, corpus.size(),
                    depth, currentInput.length);
        }

        // Save retained inputs to corpus directory
        if (retained) {
            saveInput(currentInput, "id_" + executionCount);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: signals come from the agent's ThreadLocal counters, not JQF tracing
        return (event) -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        return Collections.singletonMap("maxDepth", lastMaxDepth);
    }

    private void saveInput(byte[] data, String name) {
        try {
            Files.write(new File(corpusDir, name + ".bin").toPath(), data);
        } catch (IOException e) {
            // Best-effort save
        }
    }
}
