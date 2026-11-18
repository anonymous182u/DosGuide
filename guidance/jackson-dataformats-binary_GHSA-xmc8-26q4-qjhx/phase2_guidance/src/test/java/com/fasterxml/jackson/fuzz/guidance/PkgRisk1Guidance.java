package com.fasterxml.jackson.fuzz.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;
import com.fasterxml.jackson.fuzz.agent.NestingDepthCounters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Cost-Gradient Fuzzing guidance for PkgRisk1: Deep CBOR nesting causes
 * StackOverflowError in jackson-databind recursive tree deserialization.
 *
 * Signal: maxNestingDepth — the maximum recursion depth reached by
 * BaseNodeDeserializer.deserializeArray/deserializeObject, measured by
 * the PkgRisk1MeasureAgent via bytecode instrumentation (Tier 1).
 *
 * Strategy: hill-climb nesting depth using chunk repetition to build
 * deeply nested CBOR structures.
 * Input model: byte[] / InputStream (raw CBOR).
 */
public final class PkgRisk1Guidance implements Guidance, SignalSource {

    // --- Configuration ---
    private final int maxInputSize;
    private final long maxDurationMs;
    private final File corpusDir;
    private final PrintStream log;
    private final Random rng = new Random();

    // --- Corpus ---
    private final List<byte[]> corpus = new ArrayList<>();
    private long bestNestingDepth = -1;
    private int bestInputLen = 0;

    // --- Per-execution state ---
    private byte[] currentInput;
    private long currentNestingDepth;

    // --- Execution bookkeeping ---
    private long startTimeMs;
    private long totalTrials;
    private long lastLogMs;

    // --- Target input_bytes from the register ---
    private static final int TARGET_INPUT_BYTES = 4000;

    // --- CBOR dictionary tokens for nesting structures ---
    private static final byte[][] DICTIONARY = {
        {(byte) 0x81},       // 1-element array (most efficient: 1 byte per nesting level)
        {(byte) 0x82},       // 2-element array
        {(byte) 0xA1},       // 1-element map (triggers deserializeObject)
        {(byte) 0x9F},       // indefinite-length array
        {(byte) 0xBF},       // indefinite-length map
        {(byte) 0x00},       // integer 0 (leaf value)
        {(byte) 0xF6},       // null (leaf value)
        {(byte) 0xFF},       // break code (closes indefinite items)
        {(byte) 0x60},       // empty text string (leaf)
    };

    public PkgRisk1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();

        // Seed: a moderately nested CBOR array structure
        // 100 repetitions of 0x81 (1-element array) followed by 0x00 (integer 0 as leaf)
        // This creates [[[[...[[0]]...]]]] with 100 levels of nesting
        byte[] seed = new byte[101];
        Arrays.fill(seed, 0, 100, (byte) 0x81);
        seed[100] = 0x00;
        corpus.add(seed);

        this.startTimeMs = System.currentTimeMillis();
        this.lastLogMs = startTimeMs;
    }

    @Override
    public InputStream getInput() throws GuidanceException {
        // Reset the agent's depth counters before each execution
        NestingDepthCounters.reset();

        // Choose a parent and mutate
        byte[] parent = corpus.get(rng.nextInt(corpus.size()));
        currentInput = mutate(parent);
        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (startTimeMs == 0) {
            startTimeMs = System.currentTimeMillis();
        }
        if (maxDurationMs > 0) {
            return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
        }
        return true;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalTrials++;
        currentNestingDepth = NestingDepthCounters.maxDepth();

        boolean retained = false;

        // Primary retention: higher nesting depth
        if (currentNestingDepth > bestNestingDepth) {
            bestNestingDepth = currentNestingDepth;
            bestInputLen = currentInput.length;
            retained = true;
        }
        // Secondary retention ([R46]): while signal is flat, retain inputs
        // that grow toward TARGET_INPUT_BYTES
        else if (currentNestingDepth == bestNestingDepth
                && currentInput.length > bestInputLen
                && currentInput.length <= TARGET_INPUT_BYTES
                && corpus.size() < 64) {
            bestInputLen = currentInput.length;
            retained = true;
        }
        // Tertiary: retain inputs with zero signal if they are growing
        // (the signal may be zero before the structure is valid)
        else if (bestNestingDepth <= 0
                && currentInput.length > bestInputLen
                && corpus.size() < 64) {
            bestInputLen = currentInput.length;
            retained = true;
        }

        if (retained) {
            corpus.add(Arrays.copyOf(currentInput, currentInput.length));
            while (corpus.size() > 64) {
                corpus.remove(rng.nextInt(corpus.size() - 1));
            }
            saveCorpusInput(currentInput, "id_" + totalTrials);
        }

        // Periodic logging
        long now = System.currentTimeMillis();
        if (now - lastLogMs >= 1000) {
            log.printf("[PkgRisk1] trials=%d, bestNestingDepth=%d, bestInputLen=%d, corpusSize=%d, elapsed=%ds%n",
                    totalTrials, bestNestingDepth, bestInputLen, corpus.size(),
                    (now - startTimeMs) / 1000);
            lastLogMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // The signal comes from the bytecode agent, not JQF tracing
        return e -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        return Collections.singletonMap("maxNestingDepth", (double) currentNestingDepth);
    }

    // ==================== Mutation Operators ====================

    private byte[] mutate(byte[] parent) {
        byte[] result = Arrays.copyOf(parent, parent.length);
        double r = rng.nextDouble();

        if (r < 0.40) {
            result = chunkRepeat(result);
        } else if (r < 0.55) {
            result = dictionaryInsert(result);
        } else if (r < 0.70) {
            result = splice(result);
        } else if (r < 0.80) {
            result = byteFlip(result);
        } else if (r < 0.90) {
            result = havoc(result);
        } else if (r < 0.95) {
            result = byteInsert(result);
        } else {
            result = byteDelete(result);
        }

        // Enforce max input size
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        // Ensure non-empty
        if (result.length == 0) {
            result = new byte[] { (byte) 0x81, (byte) 0x00 };
        }
        return result;
    }

    /**
     * PRIMARY growth operator: select a contiguous chunk and repeat it k times.
     * This builds deeply nested CBOR structures by duplicating runs of nesting bytes.
     */
    private byte[] chunkRepeat(byte[] input) {
        if (input.length == 0) return input;

        // Select chunk boundaries
        int chunkStart = rng.nextInt(input.length);
        int maxChunkLen = Math.min(64, input.length - chunkStart);
        int chunkLen = 1 + rng.nextInt(Math.max(1, maxChunkLen));
        // Repetition count: 2..8
        int k = 2 + rng.nextInt(7);

        int newLen = Math.min(input.length + chunkLen * (k - 1), maxInputSize);
        byte[] result = new byte[newLen];

        // Copy prefix
        System.arraycopy(input, 0, result, 0, Math.min(chunkStart, newLen));

        // Repeat the chunk k times
        int pos = chunkStart;
        byte[] chunk = Arrays.copyOfRange(input, chunkStart,
                Math.min(chunkStart + chunkLen, input.length));
        for (int i = 0; i < k && pos + chunk.length <= newLen; i++) {
            System.arraycopy(chunk, 0, result, pos, chunk.length);
            pos += chunk.length;
        }

        // Copy suffix from original input after the chunk
        int srcAfter = chunkStart + chunkLen;
        if (srcAfter < input.length && pos < newLen) {
            int toCopy = Math.min(input.length - srcAfter, newLen - pos);
            System.arraycopy(input, srcAfter, result, pos, toCopy);
        }

        return result;
    }

    private byte[] dictionaryInsert(byte[] input) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(input.length + 1);
        int newLen = Math.min(input.length + token.length, maxInputSize);
        byte[] result = new byte[newLen];
        int prefixLen = Math.min(pos, newLen);
        System.arraycopy(input, 0, result, 0, prefixLen);
        int tokenLen = Math.min(token.length, newLen - prefixLen);
        if (tokenLen > 0) {
            System.arraycopy(token, 0, result, prefixLen, tokenLen);
        }
        int remaining = newLen - prefixLen - tokenLen;
        if (remaining > 0 && pos < input.length) {
            System.arraycopy(input, pos, result, prefixLen + tokenLen,
                    Math.min(remaining, input.length - pos));
        }
        return result;
    }

    /**
     * Splice: take a prefix from one corpus input and a suffix from another.
     */
    private byte[] splice(byte[] input) {
        if (corpus.size() < 2) return chunkRepeat(input); // fallback
        byte[] other = corpus.get(rng.nextInt(corpus.size()));
        int splitA = rng.nextInt(input.length + 1);
        int splitB = rng.nextInt(other.length + 1);
        int newLen = Math.min(splitA + (other.length - splitB), maxInputSize);
        if (newLen <= 0) return input;
        byte[] result = new byte[newLen];
        System.arraycopy(input, 0, result, 0, Math.min(splitA, newLen));
        int suffixLen = Math.min(other.length - splitB, newLen - Math.min(splitA, newLen));
        if (suffixLen > 0) {
            System.arraycopy(other, splitB, result, Math.min(splitA, newLen), suffixLen);
        }
        return result;
    }

    private byte[] byteFlip(byte[] input) {
        if (input.length == 0) return input;
        byte[] result = Arrays.copyOf(input, input.length);
        int pos = rng.nextInt(result.length);
        result[pos] ^= (byte) (1 << rng.nextInt(8));
        return result;
    }

    private byte[] byteInsert(byte[] input) {
        if (input.length >= maxInputSize) return input;
        byte[] result = new byte[input.length + 1];
        int pos = rng.nextInt(input.length + 1);
        System.arraycopy(input, 0, result, 0, pos);
        result[pos] = (byte) rng.nextInt(256);
        System.arraycopy(input, pos, result, pos + 1, input.length - pos);
        return result;
    }

    private byte[] byteDelete(byte[] input) {
        if (input.length <= 1) return input;
        byte[] result = new byte[input.length - 1];
        int pos = rng.nextInt(input.length);
        System.arraycopy(input, 0, result, 0, pos);
        System.arraycopy(input, pos + 1, result, pos, input.length - pos - 1);
        return result;
    }

    private byte[] havoc(byte[] input) {
        byte[] result = Arrays.copyOf(input, input.length);
        int count = 1 + rng.nextInt(4);
        for (int i = 0; i < count; i++) {
            int op = rng.nextInt(4);
            switch (op) {
                case 0: result = byteFlip(result); break;
                case 1: result = byteInsert(result); break;
                case 2: result = dictionaryInsert(result); break;
                case 3: result = chunkRepeat(result); break;
            }
        }
        return result;
    }

    // ==================== Corpus Management ====================

    private void saveCorpusInput(byte[] input, String name) {
        try {
            File f = new File(corpusDir, name + ".bin");
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(input);
            }
        } catch (IOException e) {
            // Non-fatal
        }
    }
}
