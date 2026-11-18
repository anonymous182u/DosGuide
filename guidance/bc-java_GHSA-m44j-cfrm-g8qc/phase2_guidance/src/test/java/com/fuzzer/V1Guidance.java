package com.fuzzer;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance for V1: Scalar25519.reduceBasisVar unbounded loop.
 *
 * Implements Guidance directly [R3]. Does not extend/delegate any existing guidance.
 *
 * Signal: loopIterations — number of iterations of the while loop in
 * reduceBasisVar, measured via bytecode instrumentation of
 * ScalarUtil.addShifted_NP and ScalarUtil.subShifted_NP [R36].
 *
 * Input model: byte[]/InputStream [R31]. The harness reads all bytes and
 * splits into sig(64) + pk(32) + msg(rest).
 *
 * The Guidance never decides that an execution failed [R6].
 */
public class V1Guidance implements Guidance, SignalSource {

    // --- Configuration ---
    private final int maxInputSize;
    private final long maxDurationMs;
    private final long startTimeMs;
    private final File corpusDir;
    private final PrintStream log;
    private final Random rng = new Random();

    // --- Corpus ---
    private final List<byte[]> corpus = new ArrayList<>();
    private static final int MAX_CORPUS_SIZE = 128;

    // --- State ---
    private byte[] currentInput;
    private long lastLogTimeMs;
    private long totalExecs;
    private long bestIterations;
    private double lastSignalValue;

    // --- Dictionary tokens from Ed25519 code path [R45(b)] ---
    private static final byte[][] DICTIONARY = {
        {0x58},             // base point y[0]
        {0x66},             // base point y repeated byte
        {(byte)0xED},       // low byte of prime p LE
        {(byte)0xFF},       // max byte, near-p values
        {0x7F},             // high-bit mask in checkPointVar
        {(byte)0x80},       // sign bit in point encoding
        {0x00},             // zero, valid scalar high bytes
        {0x10},             // boundary for S[31] near group order
        {0x01},             // identity / one values
    };

    // --- Seed: a minimal valid 97-byte input structure ---
    // sig[0..31] = R (base point encoding), sig[32..63] = S (=1),
    // pk[0..31] = A (base point encoding), msg[0] = 0x42
    private static byte[] createSeed() {
        byte[] seed = new byte[97];
        // R = base point y-coordinate encoding (little-endian)
        seed[0] = 0x58;
        for (int i = 1; i < 32; i++) seed[i] = 0x66;
        // S = 1 (valid scalar < L)
        seed[32] = 0x01;
        // pk = base point encoding
        seed[64] = 0x58;
        for (int i = 65; i < 96; i++) seed[i] = 0x66;
        // msg = single byte
        seed[96] = 0x42;
        return seed;
    }

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.maxDurationMs = maxDurationMs;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = startTimeMs;
        this.log = log;

        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();

        // Initialize corpus with seed
        corpus.add(createSeed());
        // Also add a random 97-byte input for diversity
        byte[] randomSeed = new byte[97];
        rng.nextBytes(randomSeed);
        // Make S valid (< L): clear high bits of S[31]
        randomSeed[63] = (byte)(randomSeed[63] & 0x0F);
        corpus.add(randomSeed);
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset counter before each execution
        V1Counters.reset();

        // Select parent from corpus
        byte[] parent = corpus.get(rng.nextInt(corpus.size()));

        // Mutate
        currentInput = mutate(parent);

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs <= 0) return true; // infinite
        return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;

        // Read the signal from instrumentation
        long iterations = V1Counters.get();
        lastSignalValue = (double) iterations;

        // Retention policy:
        // Primary: keep if iterations > best seen (hill-climb)
        // Secondary (flat): keep inputs with iterations > 0 (reached reduceBasisVar)
        //   and diverse iteration counts, plus growing inputs
        boolean retain = false;

        if (iterations > bestIterations) {
            bestIterations = iterations;
            retain = true;
        } else if (iterations > 0 && corpus.size() < MAX_CORPUS_SIZE) {
            // Keep inputs that reach the sink with some probability
            retain = rng.nextInt(10) == 0;
        } else if (iterations == 0 && currentInput.length >= 97 && corpus.size() < MAX_CORPUS_SIZE / 2) {
            // Keep some inputs that don't reach the sink (might mutate to pass checks)
            retain = rng.nextInt(50) == 0;
        }

        // Also retain if input is significantly longer (exploring hash space)
        if (!retain && iterations > 0 && currentInput.length > getMaxCorpusLength() && corpus.size() < MAX_CORPUS_SIZE) {
            retain = true;
        }

        if (retain) {
            corpus.add(currentInput.clone());
            // Evict weakest if over limit
            if (corpus.size() > MAX_CORPUS_SIZE) {
                evictWeakest();
            }
            // Save to disk
            saveCorpusEntry(currentInput, iterations);
        }

        // Log every 1 second [R5]
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            log.printf("[V1Guidance] execs=%d, best_iters=%d, last_iters=%d, corpus=%d, elapsed=%ds%n",
                    totalExecs, bestIterations, iterations, corpus.size(),
                    (now - startTimeMs) / 1000);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // We don't use JQF tracing events; we use our custom agent instead
        return event -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        signals.put("loopIterations", lastSignalValue);
        return signals;
    }

    // --- Mutation operators ---

    private byte[] mutate(byte[] parent) {
        // Copy parent
        byte[] input = parent.clone();

        // Apply 1-3 random mutations
        int numMutations = 1 + rng.nextInt(3);
        for (int m = 0; m < numMutations; m++) {
            int op = rng.nextInt(100);
            if (op < 25) {
                input = mutateBytesFlip(input);
            } else if (op < 45) {
                input = mutateBytesReplace(input);
            } else if (op < 55) {
                input = mutateBytesInsert(input);
            } else if (op < 65) {
                input = mutateBytesDelete(input);
            } else if (op < 80) {
                input = mutateRepetition(input);
            } else if (op < 95) {
                input = mutateDictionary(input);
            } else {
                // Generate completely fresh random input
                int len = 97 + rng.nextInt(Math.max(1, maxInputSize - 97));
                input = new byte[len];
                rng.nextBytes(input);
                // Make S valid
                input[63] = (byte)(input[63] & 0x0F);
            }
        }

        // Enforce max input size
        if (input.length > maxInputSize) {
            byte[] trimmed = new byte[maxInputSize];
            System.arraycopy(input, 0, trimmed, 0, maxInputSize);
            input = trimmed;
        }

        return input;
    }

    /** Flip 1-4 random bits */
    private byte[] mutateBytesFlip(byte[] input) {
        if (input.length == 0) return input;
        int count = 1 + rng.nextInt(4);
        for (int i = 0; i < count; i++) {
            int pos = rng.nextInt(input.length);
            int bit = 1 << rng.nextInt(8);
            input[pos] ^= (byte) bit;
        }
        return input;
    }

    /** Replace 1-8 bytes with random values */
    private byte[] mutateBytesReplace(byte[] input) {
        if (input.length == 0) return input;
        int count = 1 + rng.nextInt(Math.min(8, input.length));
        int start = rng.nextInt(input.length);
        for (int i = 0; i < count && (start + i) < input.length; i++) {
            input[start + i] = (byte) rng.nextInt(256);
        }
        return input;
    }

    /** Insert 1-16 random bytes at a random position */
    private byte[] mutateBytesInsert(byte[] input) {
        int count = 1 + rng.nextInt(16);
        if (input.length + count > maxInputSize) {
            count = maxInputSize - input.length;
        }
        if (count <= 0) return input;
        int pos = rng.nextInt(input.length + 1);
        byte[] result = new byte[input.length + count];
        System.arraycopy(input, 0, result, 0, pos);
        for (int i = 0; i < count; i++) {
            result[pos + i] = (byte) rng.nextInt(256);
        }
        System.arraycopy(input, pos, result, pos + count, input.length - pos);
        return result;
    }

    /** Delete 1-8 bytes */
    private byte[] mutateBytesDelete(byte[] input) {
        if (input.length <= 97) return input; // keep minimum size
        int count = 1 + rng.nextInt(Math.min(8, input.length - 97));
        int pos = rng.nextInt(input.length - count + 1);
        byte[] result = new byte[input.length - count];
        System.arraycopy(input, 0, result, 0, pos);
        System.arraycopy(input, pos + count, result, pos, input.length - pos - count);
        return result;
    }

    /**
     * Repetition [R45(a)]: Copy a random chunk and repeat it k times.
     * Also supports whole-input doubling.
     */
    private byte[] mutateRepetition(byte[] input) {
        if (input.length == 0) return input;

        // Sometimes double the entire input
        if (rng.nextInt(4) == 0 && input.length * 2 <= maxInputSize) {
            byte[] result = new byte[input.length * 2];
            System.arraycopy(input, 0, result, 0, input.length);
            System.arraycopy(input, 0, result, input.length, input.length);
            return result;
        }

        // Pick a chunk
        int chunkLen = 4 + rng.nextInt(Math.min(64, input.length));
        if (chunkLen > input.length) chunkLen = input.length;
        int chunkStart = rng.nextInt(input.length - chunkLen + 1);
        byte[] chunk = new byte[chunkLen];
        System.arraycopy(input, chunkStart, chunk, 0, chunkLen);

        // Repeat k times
        int maxK = (maxInputSize - input.length) / chunkLen;
        if (maxK <= 0) return input;
        int k = 1 + rng.nextInt(Math.min(maxK, 64));

        byte[] result = new byte[input.length + k * chunkLen];
        if (result.length > maxInputSize) {
            result = new byte[maxInputSize];
        }

        // Insert repetitions at the chunk position
        int insertPos = chunkStart + chunkLen;
        int copyLen = Math.min(insertPos, result.length);
        System.arraycopy(input, 0, result, 0, copyLen);
        int pos = copyLen;
        for (int i = 0; i < k && pos + chunkLen <= result.length; i++) {
            System.arraycopy(chunk, 0, result, pos, chunkLen);
            pos += chunkLen;
        }
        int remaining = Math.min(input.length - insertPos, result.length - pos);
        if (remaining > 0) {
            System.arraycopy(input, insertPos, result, pos, remaining);
        }
        return result;
    }

    /**
     * Dictionary [R45(b)]: Insert or overwrite with tokens from Ed25519 code path.
     */
    private byte[] mutateDictionary(byte[] input) {
        if (input.length == 0) return input;
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(input.length);

        if (rng.nextBoolean()) {
            // Overwrite at position
            for (int i = 0; i < token.length && pos + i < input.length; i++) {
                input[pos + i] = token[i];
            }
        } else {
            // Insert at position
            if (input.length + token.length <= maxInputSize) {
                byte[] result = new byte[input.length + token.length];
                System.arraycopy(input, 0, result, 0, pos);
                System.arraycopy(token, 0, result, pos, token.length);
                System.arraycopy(input, pos, result, pos + token.length, input.length - pos);
                return result;
            }
        }
        return input;
    }

    // --- Corpus management ---

    private int getMaxCorpusLength() {
        int max = 0;
        for (byte[] entry : corpus) {
            if (entry.length > max) max = entry.length;
        }
        return max;
    }

    private void evictWeakest() {
        // Remove a random entry from the second half (keep seeds/best)
        if (corpus.size() > 2) {
            int idx = 2 + rng.nextInt(corpus.size() - 2);
            corpus.remove(idx);
        }
    }

    private void saveCorpusEntry(byte[] input, long iterations) {
        try {
            String name = String.format("id_%06d_iters_%d.bin", totalExecs, iterations);
            Files.write(corpusDir.toPath().resolve(name), input);
        } catch (IOException e) {
            // Ignore save errors
        }
    }
}
