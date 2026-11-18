package org.elasticsearch.compute.data.fuzz.guidance;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import org.elasticsearch.compute.data.fuzz.agent.AllocCounter;

/**
 * VDF + CGF guidance for V2 (LongBlockBuilder, element size = 8).
 *
 * <p>Identical to {@link V1Guidance} except:
 * <ul>
 *   <li>Log prefix: {@code [V2]}</li>
 *   <li>Dictionary: uses {@code intToBytes(8)} instead of {@code intToBytes(4)} to reflect
 *       the long element size.</li>
 * </ul>
 *
 * <p>Signal: {@code allocRequestedBytes} — the number of bytes the NEWARRAY instruction
 * is asked to allocate, measured via the Java agent's instrumentation of the constructor.
 */
public class V2Guidance implements Guidance, SignalSource {

    // ---- Configuration ----
    private static final int MAX_INPUT_SIZE =
            Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
    private static final int MAX_CORPUS = 100;
    private static final String LOG_PREFIX = "[V2]";

    // ---- State ----
    private final Random rng = new Random();
    private final File outputDir;
    private final long maxDurationMs;
    private final PrintStream log;
    private final long startTimeMs;

    /** Corpus: each entry is (input bytes, signal value). */
    private final List<byte[]> corpusInputs = new ArrayList<>();
    private final List<Long> corpusSignals = new ArrayList<>();

    /** Seed queue, drained before mutating from the corpus. */
    private final List<byte[]> seeds = new ArrayList<>();
    private int seedIndex = 0;

    /** Per-execution state. */
    private byte[] currentInput;
    private long lastAllocRequestedBytes;
    private long bestAllocRequestedBytes;
    private long totalExecs;
    private long lastLogTimeMs;

    /** Best input seen so far (for saving). */
    private byte[] bestInput;

    // ---- Dictionary tokens (V2: long element, size=8) ----
    private static final byte[][] DICT_TOKENS = {
        intToBytes(2),
        intToBytes(8),       // element size for long
        intToBytes(16),
        intToBytes(0x7FFFFFFF),
        intToBytes(0),
    };

    public V2Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.outputDir = outputDir;
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = startTimeMs;

        // Create output directory
        if (outputDir != null) {
            outputDir.mkdirs();
        }

        // Initial seeds: (numAppends=0, estimatedSize=2), (0, 1024), (1, 100)
        seeds.add(makeInput(0, 2));
        seeds.add(makeInput(0, 1024));
        seeds.add(makeInput(1, 100));
    }

    // ========== Guidance interface ==========

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset the allocation counter before each execution
        AllocCounter.reset();

        if (seedIndex < seeds.size()) {
            currentInput = seeds.get(seedIndex++);
        } else if (corpusInputs.isEmpty()) {
            // No corpus yet — generate random input
            currentInput = makeInput(rng.nextInt(16), rng.nextInt(65536));
        } else {
            // Tournament selection: pick 2 random corpus entries, choose higher signal
            int idx1 = rng.nextInt(corpusInputs.size());
            int idx2 = rng.nextInt(corpusInputs.size());
            int parent = (corpusSignals.get(idx1) >= corpusSignals.get(idx2)) ? idx1 : idx2;
            currentInput = mutate(corpusInputs.get(parent));
        }

        // Clamp to MAX_INPUT_SIZE
        if (currentInput.length > MAX_INPUT_SIZE) {
            currentInput = Arrays.copyOf(currentInput, MAX_INPUT_SIZE);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        long elapsed = System.currentTimeMillis() - startTimeMs;
        return elapsed < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;

        // Read the signal from the agent's allocation counter
        lastAllocRequestedBytes = AllocCounter.getAlloc();

        // Check for OOM (the vulnerability we're looking for!)
        boolean isOOM = false;
        if (error != null) {
            Throwable t = error;
            while (t != null) {
                if (t instanceof OutOfMemoryError) {
                    isOOM = true;
                    break;
                }
                t = t.getCause();
            }
        }

        // Update best
        if (lastAllocRequestedBytes > bestAllocRequestedBytes) {
            bestAllocRequestedBytes = lastAllocRequestedBytes;
            bestInput = currentInput.clone();
            saveBest();
        }

        // Save crash-triggering inputs
        if (isOOM && outputDir != null) {
            saveCrash(currentInput);
        }

        // Retention policy: decide whether to add to corpus
        boolean retain = false;
        if (lastAllocRequestedBytes > 0) {
            // Hill-climb: keep if it's a new best or improves on some corpus entry
            if (lastAllocRequestedBytes >= bestAllocRequestedBytes) {
                retain = true;
            }
            // Random retention: 2% chance for any input with positive signal
            if (rng.nextDouble() < 0.02) {
                retain = true;
            }
        } else {
            // Zero-signal: 10% random retention for exploration diversity
            if (rng.nextDouble() < 0.10) {
                retain = true;
            }
        }

        if (retain) {
            addToCorpus(currentInput.clone(), lastAllocRequestedBytes);
        }

        // Periodic logging (every 1 second)
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            double elapsed = (now - startTimeMs) / 1000.0;
            log.printf("%s execs=%d best=%d last=%d corpus=%d elapsed=%.1fs%n",
                    LOG_PREFIX, totalExecs, bestAllocRequestedBytes,
                    lastAllocRequestedBytes, corpusInputs.size(), elapsed);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // We don't use JQF's coverage tracking; our signal comes from the agent.
        return event -> { /* no-op */ };
    }

    // ========== SignalSource interface ==========

    @Override
    public Map<String, Double> lastSignals() {
        return Map.of("allocRequestedBytes", (double) lastAllocRequestedBytes);
    }

    // ========== Corpus management ==========

    private void addToCorpus(byte[] input, long signal) {
        if (corpusInputs.size() < MAX_CORPUS) {
            corpusInputs.add(input);
            corpusSignals.add(signal);
        } else {
            // Replace the entry with the lowest signal
            int minIdx = 0;
            long minSignal = corpusSignals.get(0);
            for (int i = 1; i < corpusSignals.size(); i++) {
                if (corpusSignals.get(i) < minSignal) {
                    minSignal = corpusSignals.get(i);
                    minIdx = i;
                }
            }
            if (signal > minSignal) {
                corpusInputs.set(minIdx, input);
                corpusSignals.set(minIdx, signal);
            }
        }
    }

    // ========== Mutation operators ==========

    private byte[] mutate(byte[] parent) {
        byte[] child = parent.clone();
        // Apply 1-3 mutations
        int numMutations = 1 + rng.nextInt(3);
        for (int i = 0; i < numMutations; i++) {
            int op = rng.nextInt(6);
            switch (op) {
                case 0 -> child = bitFlip(child);
                case 1 -> child = byteOverwrite(child);
                case 2 -> child = arithmeticField(child);
                case 3 -> child = randomField(child);
                case 4 -> child = dictInsert(child);
                case 5 -> child = fieldCopy(child);
            }
        }
        return child;
    }

    /** Flip a random bit in the input. */
    private byte[] bitFlip(byte[] data) {
        if (data.length == 0) return data;
        int pos = rng.nextInt(data.length);
        int bit = rng.nextInt(8);
        data[pos] ^= (byte) (1 << bit);
        return data;
    }

    /** Overwrite a random byte with a random value. */
    private byte[] byteOverwrite(byte[] data) {
        if (data.length == 0) return data;
        int pos = rng.nextInt(data.length);
        data[pos] = (byte) rng.nextInt(256);
        return data;
    }

    /** Add or subtract a small delta from one of the 4-byte integer fields. */
    private byte[] arithmeticField(byte[] data) {
        if (data.length < 4) return data;
        // Pick field 0 (bytes 0-3) or field 1 (bytes 4-7) if long enough
        int fieldStart = (data.length >= 8 && rng.nextBoolean()) ? 4 : 0;
        ByteBuffer buf = ByteBuffer.wrap(data);
        int val = buf.getInt(fieldStart);
        int delta = (rng.nextInt(21) - 10); // -10 to +10
        if (delta == 0) delta = 1;
        val += delta;
        buf.putInt(fieldStart, val);
        return data;
    }

    /** Replace one of the 4-byte integer fields with a completely random value. */
    private byte[] randomField(byte[] data) {
        if (data.length < 4) return data;
        int fieldStart = (data.length >= 8 && rng.nextBoolean()) ? 4 : 0;
        ByteBuffer buf = ByteBuffer.wrap(data);
        buf.putInt(fieldStart, rng.nextInt());
        return data;
    }

    /** Overwrite a 4-byte field with a dictionary token. */
    private byte[] dictInsert(byte[] data) {
        if (data.length < 4) return data;
        int fieldStart = (data.length >= 8 && rng.nextBoolean()) ? 4 : 0;
        byte[] token = DICT_TOKENS[rng.nextInt(DICT_TOKENS.length)];
        System.arraycopy(token, 0, data, fieldStart, Math.min(token.length, data.length - fieldStart));
        return data;
    }

    /** Copy one 4-byte field to the other. */
    private byte[] fieldCopy(byte[] data) {
        if (data.length < 8) return data;
        if (rng.nextBoolean()) {
            // Copy field 0 → field 1
            System.arraycopy(data, 0, data, 4, 4);
        } else {
            // Copy field 1 → field 0
            System.arraycopy(data, 4, data, 0, 4);
        }
        return data;
    }

    // ========== Helpers ==========

    /** Create an 8-byte input: [numAppends (4 bytes BE)] [estimatedSize (4 bytes BE)]. */
    static byte[] makeInput(int numAppends, int estimatedSize) {
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.putInt(numAppends);
        buf.putInt(estimatedSize);
        return buf.array();
    }

    /** Convert an int to 4-byte big-endian array. */
    static byte[] intToBytes(int value) {
        ByteBuffer buf = ByteBuffer.allocate(4);
        buf.putInt(value);
        return buf.array();
    }

    /** Save the best input to the output directory. */
    private void saveBest() {
        if (outputDir == null) return;
        try {
            File f = new File(outputDir, "best_input.bin");
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(bestInput);
            }
        } catch (IOException e) {
            // best-effort
        }
    }

    /** Save a crash-triggering input. */
    private void saveCrash(byte[] input) {
        if (outputDir == null) return;
        try {
            File dir = new File(outputDir, "crashes");
            dir.mkdirs();
            File f = new File(dir, "crash_" + totalExecs + ".bin");
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(input);
            }
        } catch (IOException e) {
            // best-effort
        }
    }
}
