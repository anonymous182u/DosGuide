package org.xerial.snappy.fuzz;

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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance for V1: SnappyInputStream.hasNextChunk chunkSize allocation.
 * <p>
 * Signal: compressedAllocBytes (slot 0) — bytes requested by {@code new byte[chunkSize]}
 * in hasNextChunk, measured by the AllocationMeasureAgent.
 * <p>
 * Overrides {@code Guidance.run()} to inject crafted payload directly into
 * the test method, bypassing JQF's {@code StreamBackedRandom(input, 8)} which
 * forces 8 leading zero bytes that break the Snappy header magic.
 */
public class V1Guidance implements Guidance, SignalSource {

    // ---- Constants ----

    /** Snappy stream header: 8-byte magic + version(1) + compatible(1) */
    private static final byte[] SNAPPY_HEADER = {
        (byte) 0x82, 0x53, 0x4E, 0x41, 0x50, 0x50, 0x59, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01
    };

    /** Dictionary tokens from snappy source on the attack path. */
    private static final byte[][] DICTIONARY = {
        {(byte) 0x82, 0x53, 0x4E, 0x41, 0x50, 0x50, 0x59, 0x00},
        {0x00, 0x00, 0x00, 0x01},
        {0x7F},
        {(byte) 0xFF},
        {0x00},
        {0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
    };

    private static final int SLOT = 0;
    private static final String SIGNAL_NAME = "compressedAllocBytes";
    private static final int HEADER_LEN = 16;
    private static final int CHUNKSIZE_OFFSET = 16;
    private static final int SEED_PAYLOAD_LEN = 21; // header(16) + chunkSize(4) + 1 byte data

    // ---- State ----

    private final File corpusDir;
    private final long endTimeMs;
    private final int maxInputSize;
    private final PrintStream log;
    private final Random rng = new Random();

    private final List<byte[]> corpus = new ArrayList<>();
    private byte[] currentPayload;

    private long maxSignal = 0;
    private double lastSignalValue = 0.0;
    private long totalExecs = 0;
    private long savedInputs = 0;
    private long lastLogMs;

    // ---- Constructor ----

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.endTimeMs = maxDurationMs > 0
                ? System.currentTimeMillis() + maxDurationMs : Long.MAX_VALUE;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.log = log;
        this.lastLogMs = System.currentTimeMillis();

        // Seed: valid Snappy header + chunkSize=1 + 1 byte of data
        byte[] seed = createSeed();
        corpus.add(seed);
    }

    // ---- Seed ----

    private byte[] createSeed() {
        int len = Math.min(SEED_PAYLOAD_LEN, maxInputSize);
        byte[] payload = new byte[len];
        // Header
        int hLen = Math.min(SNAPPY_HEADER.length, len);
        System.arraycopy(SNAPPY_HEADER, 0, payload, 0, hLen);
        // chunkSize = 1 (big-endian) at offset 16
        if (len >= 20) {
            payload[16] = 0; payload[17] = 0; payload[18] = 0; payload[19] = 1;
        }
        // 1 byte of compressed data (snappy varint 0 + empty)
        if (len > 20) {
            payload[20] = 0x00;
        }
        return payload;
    }

    // ---- Encoder: fix header ----

    private void applyEncoder(byte[] payload) {
        int hLen = Math.min(SNAPPY_HEADER.length, payload.length);
        System.arraycopy(SNAPPY_HEADER, 0, payload, 0, hLen);
    }

    // ---- Mutation (operates on payload bytes) ----

    private byte[] mutate(byte[] parent) {
        byte[] child = Arrays.copyOf(parent, parent.length);
        if (child.length <= HEADER_LEN) return child;

        int op = rng.nextInt(10);
        switch (op) {
            case 0: case 1: // Bit flip in chunk-data region
                flipBit(child, HEADER_LEN);
                break;
            case 2: // Random byte in chunk-data region
                setRandom(child, HEADER_LEN);
                break;
            case 3: // Increment/decrement in chunk-data region
                incDec(child, HEADER_LEN);
                break;
            case 4: case 5: // Arithmetic on chunkSize (mechanism-specific)
                chunkSizeArithmetic(child);
                break;
            case 6: // Dictionary insertion
                dictInsert(child, HEADER_LEN);
                break;
            case 7: // Repetition
                child = repetition(child);
                break;
            case 8: // Byte insertion
                child = insertByte(child);
                break;
            case 9: // Byte deletion in chunk-data region
                child = deleteByte(child, HEADER_LEN);
                break;
        }

        // Clamp length
        if (child.length > maxInputSize) {
            child = Arrays.copyOf(child, maxInputSize);
        }

        // Re-apply encoder (fix header)
        applyEncoder(child);
        return child;
    }

    private void flipBit(byte[] data, int minPos) {
        if (data.length <= minPos) return;
        int pos = minPos + rng.nextInt(data.length - minPos);
        data[pos] ^= (byte) (1 << rng.nextInt(8));
    }

    private void setRandom(byte[] data, int minPos) {
        if (data.length <= minPos) return;
        int pos = minPos + rng.nextInt(data.length - minPos);
        data[pos] = (byte) rng.nextInt(256);
    }

    private void incDec(byte[] data, int minPos) {
        if (data.length <= minPos) return;
        int pos = minPos + rng.nextInt(data.length - minPos);
        data[pos] += (byte) (rng.nextBoolean() ? 1 : -1);
    }

    /** Mechanism-specific: arithmetic on the 4-byte big-endian chunkSize at payload[16..19]. */
    private void chunkSizeArithmetic(byte[] data) {
        if (data.length < 20) return;
        int cs = ((data[16] & 0xFF) << 24) | ((data[17] & 0xFF) << 16)
               | ((data[18] & 0xFF) << 8)  |  (data[19] & 0xFF);
        int op = rng.nextInt(5);
        switch (op) {
            case 0: cs = Math.max(1, cs * 2); break;
            case 1: cs = Math.max(1, cs + rng.nextInt(10_000_000) + 1); break;
            case 2: cs = Math.max(1, cs + (1 << rng.nextInt(28))); break;
            case 3: cs = rng.nextInt(Integer.MAX_VALUE / 2) + 1; break;
            case 4: cs = Math.max(1, cs | (0xFF << (rng.nextInt(4) * 8))); break;
        }
        if (cs < 0) cs = Integer.MAX_VALUE / 2;
        data[16] = (byte) ((cs >> 24) & 0xFF);
        data[17] = (byte) ((cs >> 16) & 0xFF);
        data[18] = (byte) ((cs >>  8) & 0xFF);
        data[19] = (byte) ( cs        & 0xFF);
    }

    private void dictInsert(byte[] data, int minPos) {
        if (data.length <= minPos) return;
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = minPos + rng.nextInt(data.length - minPos);
        int len = Math.min(token.length, data.length - pos);
        System.arraycopy(token, 0, data, pos, len);
    }

    private byte[] repetition(byte[] data) {
        if (data.length < HEADER_LEN + 2) return data;
        int start = HEADER_LEN + rng.nextInt(data.length - HEADER_LEN);
        int regionLen = rng.nextInt(Math.max(1, Math.min(data.length - start, 32))) + 1;
        int k = rng.nextInt(5) + 1;
        int addedLen = regionLen * k;
        int newLen = Math.min(data.length + addedLen, maxInputSize);
        byte[] result = new byte[newLen];
        System.arraycopy(data, 0, result, 0, Math.min(data.length, newLen));
        int cursor = data.length;
        for (int r = 0; r < k && cursor < newLen; r++) {
            int copyLen = Math.min(regionLen, newLen - cursor);
            if (start + copyLen <= data.length) {
                System.arraycopy(data, start, result, cursor, copyLen);
            }
            cursor += copyLen;
        }
        return result;
    }

    private byte[] insertByte(byte[] data) {
        if (data.length >= maxInputSize) return data;
        int pos = HEADER_LEN + (data.length > HEADER_LEN ? rng.nextInt(data.length - HEADER_LEN) : 0);
        byte[] result = new byte[data.length + 1];
        System.arraycopy(data, 0, result, 0, pos);
        result[pos] = (byte) rng.nextInt(256);
        System.arraycopy(data, pos, result, pos + 1, data.length - pos);
        return result;
    }

    private byte[] deleteByte(byte[] data, int minPos) {
        if (data.length <= minPos + 1) return data;
        int pos = minPos + rng.nextInt(data.length - minPos);
        byte[] result = new byte[data.length - 1];
        System.arraycopy(data, 0, result, 0, pos);
        System.arraycopy(data, pos + 1, result, pos, data.length - pos - 1);
        return result;
    }

    // ---- Guidance interface ----

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        AllocCounters.reset();
        byte[] parent = corpus.get(rng.nextInt(corpus.size()));
        currentPayload = mutate(parent);
        totalExecs++;
        // Return the payload as guidance bytes (length measured by validator).
        // The actual test input is injected in run() below.
        return new ByteArrayInputStream(currentPayload);
    }

    /**
     * Override run() to inject our crafted payload directly into the test,
     * bypassing JQF's StreamBackedRandom(input, 8) which forces 8 leading
     * zero bytes that break the Snappy stream header magic.
     */
    @Override
    public void run(org.junit.runners.model.TestClass testClass,
                    org.junit.runners.model.FrameworkMethod method,
                    Object[] args) throws Throwable {
        args[0] = new ByteArrayInputStream(currentPayload);
        Guidance.super.run(testClass, method, args);
    }

    @Override
    public boolean hasInput() {
        long now = System.currentTimeMillis();
        if (now - lastLogMs >= 1000) {
            log.printf("[V1] execs=%d saved=%d maxSignal=%d lastSignal=%.0f%n",
                    totalExecs, savedInputs, maxSignal, lastSignalValue);
            lastLogMs = now;
        }
        return now < endTimeMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        long signal = AllocCounters.get(SLOT);
        lastSignalValue = (double) signal;

        boolean save = false;
        if (signal > maxSignal) {
            maxSignal = signal;
            save = true;
        } else if (signal > 0 && corpus.size() < 100 && rng.nextInt(20) == 0) {
            save = true; // diversity
        } else if (signal == 0 && corpus.size() < 50 && rng.nextInt(10) == 0) {
            save = true; // progress while flat
        }

        if (save && currentPayload != null) {
            corpus.add(Arrays.copyOf(currentPayload, currentPayload.length));
            saveToFile(currentPayload, signal);
            savedInputs++;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return null; // measurement via custom agent, not JQF trace events
    }

    // ---- SignalSource ----

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> m = new LinkedHashMap<>();
        m.put(SIGNAL_NAME, lastSignalValue);
        return m;
    }

    // ---- Persistence ----

    private void saveToFile(byte[] payload, long signal) {
        try {
            String name = String.format("id_%06d", savedInputs);
            Files.write(corpusDir.toPath().resolve(name + ".bin"), payload);
            String meta = String.format(
                    "{\"signal\":%d,\"iteration\":%d,\"time\":%d}%n",
                    signal, totalExecs, System.currentTimeMillis());
            Files.writeString(corpusDir.toPath().resolve(name + ".json"), meta);
        } catch (IOException ignored) { }
    }
}
