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
 * Cost-Gradient Guidance for V3: Snappy.uncompress(byte[]) allocation.
 * <p>
 * Signal: resultAllocBytes (slot 2) — bytes requested by
 * {@code new byte[Snappy.uncompressedLength(input)]} in Snappy.uncompress,
 * measured by the AllocationMeasureAgent.
 * <p>
 * The input is raw snappy data: leading varint encodes the claimed uncompressed length.
 * No container format (no Snappy stream header).
 * <p>
 * Overrides {@code Guidance.run()} to inject crafted payload directly into the test.
 */
public class V3Guidance implements Guidance, SignalSource {

    // ---- Constants ----

    /** Dictionary tokens from Snappy source on the V3 attack path. */
    private static final byte[][] DICTIONARY = {
        {(byte) 0x80},         // varint continuation
        {0x7F},                 // max varint data byte (no continuation)
        {(byte) 0xFF},          // full byte (continuation + 7 bits all set)
        {(byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, 0x01}, // varint for 2^28
        {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x07}, // large varint
    };

    private static final int SLOT = 2;
    private static final String SIGNAL_NAME = "resultAllocBytes";
    private static final int SEED_PAYLOAD_LEN = 5; // varint(1) + padding

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

    public V3Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.endTimeMs = maxDurationMs > 0
                ? System.currentTimeMillis() + maxDurationMs : Long.MAX_VALUE;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.log = log;
        this.lastLogMs = System.currentTimeMillis();

        byte[] seed = createSeed();
        corpus.add(seed);
    }

    // ---- Seed ----

    private byte[] createSeed() {
        int len = Math.min(SEED_PAYLOAD_LEN, maxInputSize);
        byte[] payload = new byte[len];
        // Varint encoding of 1: single byte 0x01
        if (len > 0) payload[0] = 0x01;
        // Rest stays 0 (padding)
        return payload;
    }

    // ---- Varint helpers ----

    private static long[] decodeVarint(byte[] data, int offset) {
        long value = 0;
        int shift = 0;
        int bytesRead = 0;
        for (int i = offset; i < data.length && bytesRead < 5; i++) {
            int b = data[i] & 0xFF;
            value |= ((long) (b & 0x7F)) << shift;
            bytesRead++;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return new long[]{value, bytesRead};
    }

    private static byte[] encodeVarint(long value) {
        if (value < 0) value = 0;
        byte[] buf = new byte[5];
        int len = 0;
        while (value > 0x7F) {
            buf[len++] = (byte) ((value & 0x7F) | 0x80);
            value >>= 7;
        }
        buf[len++] = (byte) (value & 0x7F);
        return Arrays.copyOf(buf, len);
    }

    // ---- Mutation ----

    private byte[] mutate(byte[] parent) {
        byte[] child = Arrays.copyOf(parent, parent.length);
        if (child.length == 0) return child;

        int op = rng.nextInt(10);
        switch (op) {
            case 0: case 1: // Bit flip
                flipBit(child);
                break;
            case 2: // Random byte
                setRandomByte(child);
                break;
            case 3: // Increment/decrement
                incDec(child);
                break;
            case 4: case 5: case 6: // Varint arithmetic (mechanism-specific, higher weight)
                child = varintArithmetic(child);
                break;
            case 7: // Dictionary insertion
                dictInsert(child);
                break;
            case 8: // Repetition (prepend continuation bytes)
                child = repetition(child);
                break;
            case 9: // Byte insertion
                child = insertByte(child);
                break;
        }

        if (child.length > maxInputSize) {
            child = Arrays.copyOf(child, maxInputSize);
        }
        // No format encoder needed — raw snappy data accepts any bytes
        return child;
    }

    /** Mechanism-specific: increase the varint at the start of the input. */
    private byte[] varintArithmetic(byte[] data) {
        if (data.length == 0) return data;
        long[] decoded = decodeVarint(data, 0);
        long value = decoded[0];
        int oldLen = (int) decoded[1];

        int op = rng.nextInt(5);
        switch (op) {
            case 0: value = Math.max(1, value * 2); break;
            case 1: value = Math.max(1, value + rng.nextInt(10_000_000) + 1); break;
            case 2: value = Math.max(1, value + (1L << rng.nextInt(28))); break;
            case 3: value = rng.nextInt(Integer.MAX_VALUE / 2) + 1; break;
            case 4: value = Math.max(1, value | (0xFFL << (rng.nextInt(4) * 7))); break;
        }
        if (value > Integer.MAX_VALUE) value = Integer.MAX_VALUE / 2;

        byte[] newVarint = encodeVarint(value);
        int tailStart = oldLen;
        int tailLen = Math.max(0, data.length - tailStart);
        byte[] result = new byte[newVarint.length + tailLen];
        System.arraycopy(newVarint, 0, result, 0, newVarint.length);
        if (tailLen > 0) {
            System.arraycopy(data, tailStart, result, newVarint.length, tailLen);
        }
        return result;
    }

    private void flipBit(byte[] data) {
        int pos = rng.nextInt(data.length);
        data[pos] ^= (byte) (1 << rng.nextInt(8));
    }

    private void setRandomByte(byte[] data) {
        int pos = rng.nextInt(data.length);
        data[pos] = (byte) rng.nextInt(256);
    }

    private void incDec(byte[] data) {
        int pos = rng.nextInt(data.length);
        data[pos] += (byte) (rng.nextBoolean() ? 1 : -1);
    }

    private void dictInsert(byte[] data) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(data.length);
        int len = Math.min(token.length, data.length - pos);
        System.arraycopy(token, 0, data, pos, len);
    }

    private byte[] repetition(byte[] data) {
        if (data.length < 1) return data;
        int start = rng.nextInt(data.length);
        int regionLen = rng.nextInt(Math.max(1, Math.min(data.length - start, 16))) + 1;
        int k = rng.nextInt(5) + 1;
        int newLen = Math.min(data.length + regionLen * k, maxInputSize);
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
        int pos = rng.nextInt(data.length + 1);
        byte[] result = new byte[data.length + 1];
        System.arraycopy(data, 0, result, 0, pos);
        result[pos] = (byte) rng.nextInt(256);
        if (pos < data.length) {
            System.arraycopy(data, pos, result, pos + 1, data.length - pos);
        }
        return result;
    }

    // ---- Guidance interface ----

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        AllocCounters.reset();
        byte[] parent = corpus.get(rng.nextInt(corpus.size()));
        currentPayload = mutate(parent);
        totalExecs++;
        return new ByteArrayInputStream(currentPayload);
    }

    /**
     * Override run() to inject our crafted payload directly into the test,
     * bypassing JQF's StreamBackedRandom(input, 8) which forces 8 leading
     * zero bytes that corrupt the snappy varint at position 0.
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
            log.printf("[V3] execs=%d saved=%d maxSignal=%d lastSignal=%.0f%n",
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
            save = true;
        } else if (signal == 0 && corpus.size() < 50 && rng.nextInt(10) == 0) {
            save = true;
        }

        if (save && currentPayload != null) {
            corpus.add(Arrays.copyOf(currentPayload, currentPayload.length));
            saveToFile(currentPayload, signal);
            savedInputs++;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return null;
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
