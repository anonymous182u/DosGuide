package com.fasterxml.jackson.fuzz.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;
import com.fasterxml.jackson.fuzz.agent.AllocationSizeCounters;

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
 * Value-Driven Fuzzing guidance for V1: Uncontrolled byte array allocation
 * via CBOR byte-string length field.
 *
 * Signal: declaredLen — the maximum allocation size parameter passed to
 * CBORParser._finishBytes(int len) during execution, measured by the
 * AllocationSizeTransformer bytecode agent (Tier 1).
 *
 * Strategy: hill-climb the CBOR 4-byte length field toward Integer.MAX_VALUE.
 * Input model: byte[] / InputStream (raw CBOR).
 */
public final class V1Guidance implements Guidance, SignalSource {

    // --- Configuration ---
    private final int maxInputSize;
    private final long maxDurationMs;
    private final File corpusDir;
    private final PrintStream log;
    private final Random rng = new Random();

    // --- Corpus ---
    private final List<byte[]> corpus = new ArrayList<>();
    private long bestDeclaredLen = -1;

    // --- Per-execution state ---
    private byte[] currentInput;
    private long currentDeclaredLen;

    // --- Execution bookkeeping ---
    private long startTimeMs;
    private long totalTrials;
    private long lastLogMs;

    // --- CBOR dictionary tokens from the attack path ---
    private static final byte[][] DICTIONARY = {
        {(byte) 0x5A},       // byte string with 4-byte length (the attack vector)
        {(byte) 0x5B},       // byte string with 8-byte length
        {(byte) 0x59},       // byte string with 2-byte length
        {(byte) 0x58},       // byte string with 1-byte length
        {(byte) 0xC2},       // tag 2 (bignum positive, triggers getBinaryValue)
        {(byte) 0xC3},       // tag 3 (bignum negative, triggers getBinaryValue)
        {(byte) 0xFF},       // break code
        {(byte) 0x00},       // integer 0
    };

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();

        // Seed: a valid CBOR byte-string header with a small length
        // 0x5A = major type 2 (bytes) + additional info 26 (4-byte length)
        // Length = 256 (0x00000100) — a small, non-triggering value
        byte[] seed = new byte[] {
            (byte) 0x5A, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00
        };
        corpus.add(seed);

        this.startTimeMs = System.currentTimeMillis();
        this.lastLogMs = startTimeMs;
    }

    @Override
    public InputStream getInput() throws GuidanceException {
        // Reset the agent's allocation counter before each execution
        AllocationSizeCounters.reset();

        // Choose a parent from corpus and mutate it
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
        return true; // infinite by default
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalTrials++;
        // Read the execution-measured signal from the bytecode agent
        currentDeclaredLen = AllocationSizeCounters.maxLen();

        // Retention: keep inputs with higher declaredLen
        if (currentDeclaredLen > bestDeclaredLen) {
            bestDeclaredLen = currentDeclaredLen;
            corpus.add(Arrays.copyOf(currentInput, currentInput.length));
            // Cap corpus size
            while (corpus.size() > 64) {
                corpus.remove(rng.nextInt(corpus.size() - 1)); // keep last added
            }
            saveCorpusInput(currentInput, "id_" + totalTrials);
        } else if (currentDeclaredLen == bestDeclaredLen && corpus.size() < 64) {
            // Flat signal: retain inputs that are closer to target input_bytes (5)
            if (currentInput.length <= 5) {
                corpus.add(Arrays.copyOf(currentInput, currentInput.length));
            }
        }

        // Periodic logging
        long now = System.currentTimeMillis();
        if (now - lastLogMs >= 1000) {
            log.printf("[V1] trials=%d, bestDeclaredLen=%d, corpusSize=%d, elapsed=%ds%n",
                    totalTrials, bestDeclaredLen, corpus.size(),
                    (now - startTimeMs) / 1000);
            lastLogMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // Signal comes from the bytecode agent, not JQF tracing
        return e -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        return Collections.singletonMap("declaredLen", (double) currentDeclaredLen);
    }

    // ==================== Mutation Operators ====================

    private byte[] mutate(byte[] parent) {
        byte[] result = Arrays.copyOf(parent, parent.length);
        double r = rng.nextDouble();

        if (r < 0.35) {
            result = mutateLengthField(result);
        } else if (r < 0.60) {
            result = dictionaryInsert(result);
        } else if (r < 0.75) {
            result = byteFlip(result);
        } else if (r < 0.85) {
            result = byteInsert(result);
        } else if (r < 0.95) {
            result = havoc(result);
        } else {
            result = byteDelete(result);
        }

        // Enforce max input size
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        // Ensure non-empty
        if (result.length == 0) {
            result = new byte[] { (byte) 0x5A, 0x00, 0x00, 0x01, 0x00 };
        }
        return result;
    }

    /**
     * If input starts with 0x5A (byte string, 4-byte length),
     * hill-climb one of the 4 length bytes toward 0xFF.
     */
    private byte[] mutateLengthField(byte[] input) {
        if (input.length < 5) {
            // Not a valid 4-byte-length header; construct one
            return new byte[] {
                (byte) 0x5A,
                (byte) rng.nextInt(256),
                (byte) rng.nextInt(256),
                (byte) rng.nextInt(256),
                (byte) rng.nextInt(256)
            };
        }
        byte[] result = Arrays.copyOf(input, input.length);
        if ((result[0] & 0xFF) == 0x5A) {
            int idx = 1 + rng.nextInt(4); // bytes 1..4
            int current = result[idx] & 0xFF;
            if (current < 0xFF) {
                // Increase toward 0xFF
                result[idx] = (byte) (current + 1 + rng.nextInt(0xFF - current));
            } else {
                // Already max, flip a random bit
                result[idx] = (byte) (current ^ (1 << rng.nextInt(8)));
            }
        } else {
            // Replace first byte with 0x5A to create a byte-string header
            result[0] = (byte) 0x5A;
        }
        return result;
    }

    private byte[] dictionaryInsert(byte[] input) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(input.length + 1);
        byte[] result = new byte[Math.min(input.length + token.length, maxInputSize)];
        System.arraycopy(input, 0, result, 0, Math.min(pos, result.length));
        if (pos < result.length) {
            int tokenLen = Math.min(token.length, result.length - pos);
            System.arraycopy(token, 0, result, pos, tokenLen);
            int remaining = result.length - pos - tokenLen;
            if (remaining > 0 && pos < input.length) {
                System.arraycopy(input, pos, result, pos + tokenLen,
                        Math.min(remaining, input.length - pos));
            }
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
            int op = rng.nextInt(3);
            switch (op) {
                case 0: result = byteFlip(result); break;
                case 1: result = byteInsert(result); break;
                case 2: result = dictionaryInsert(result); break;
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
            // Non-fatal; corpus save failure is not critical
        }
    }
}
