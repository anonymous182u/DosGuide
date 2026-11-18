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
 * Cost-Gradient Guidance for V2: SnappyInputStream.hasNextChunk uncompressedLength allocation.
 * <p>
 * Signal: uncompressedAllocBytes (slot 1) — bytes requested by {@code new byte[uncompressedLength]}
 * in hasNextChunk (2nd NEWARRAY T_BYTE), measured by the AllocationMeasureAgent.
 * <p>
 * The payload format is: header(16) + chunkSize(4, big-endian) + compressed_data(chunkSize).
 * The compressed data starts with a snappy varint encoding the claimed uncompressed length.
 * The encoder maintains the header and synchronises chunkSize with actual compressed data length.
 * <p>
 * Overrides {@code Guidance.run()} to inject crafted payload directly into the test.
 */
public class V2Guidance implements Guidance, SignalSource {

    // ---- Constants ----

    private static final byte[] SNAPPY_HEADER = {
        (byte) 0x82, 0x53, 0x4E, 0x41, 0x50, 0x50, 0x59, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01
    };

    /** Dictionary tokens from snappy source code on the V2 attack path. */
    private static final byte[][] DICTIONARY = {
        {(byte) 0x82, 0x53, 0x4E, 0x41, 0x50, 0x50, 0x59, 0x00},
        {0x00, 0x00, 0x00, 0x01},
        {(byte) 0x80}, // varint continuation
        {0x7F},         // max varint data
        {(byte) 0xFF},  // full byte
        {(byte) 0x80, (byte) 0x80, (byte) 0x80, (byte) 0x80, 0x01}, // varint for 2^28
    };

    private static final int SLOT = 1;
    private static final String SIGNAL_NAME = "uncompressedAllocBytes";
    private static final int HEADER_LEN = 16;
    private static final int CHUNKSIZE_OFFSET = 16;
    private static final int DATA_OFFSET = 20; // compressed data starts here
    private static final int SEED_PAYLOAD_LEN = 25; // header(16) + chunkSize(4) + 5 bytes data

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

    public V2Guidance(File outputDir, long maxDurationMs, PrintStream log) {
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
        int hLen = Math.min(SNAPPY_HEADER.length, len);
        System.arraycopy(SNAPPY_HEADER, 0, payload, 0, hLen);
        // chunkSize = 5 (big-endian), compressed data = 5 bytes
        if (len >= 20) {
            payload[16] = 0; payload[17] = 0; payload[18] = 0; payload[19] = 5;
        }
        // Varint encoding of 1 (0x01) as compressed data byte 0
        if (len > DATA_OFFSET) {
            payload[DATA_OFFSET] = 0x01;
        }
        // Remaining compressed data bytes stay 0
        return payload;
    }

    // ---- Encoder ----

    /** Fix header and synchronise chunkSize with actual compressed data length. */
    private void applyEncoder(byte[] payload) {
        // Fix header
        int hLen = Math.min(SNAPPY_HEADER.length, payload.length);
        System.arraycopy(SNAPPY_HEADER, 0, payload, 0, hLen);

        // Set chunkSize = remaining bytes after header+chunkSize field
        if (payload.length >= 20) {
            int chunkSize = payload.length - DATA_OFFSET;
            if (chunkSize < 1) chunkSize = 1;
            payload[16] = (byte) ((chunkSize >> 24) & 0xFF);
            payload[17] = (byte) ((chunkSize >> 16) & 0xFF);
            payload[18] = (byte) ((chunkSize >>  8) & 0xFF);
            payload[19] = (byte) ( chunkSize        & 0xFF);
        }
    }

    // ---- Varint helpers (snappy/protobuf little-endian varint) ----

    /** Decode a snappy varint from data at the given offset. Returns {value, bytesConsumed}. */
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

    /** Encode a value as a snappy varint. Returns the varint bytes. */
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
        if (child.length <= DATA_OFFSET) return child;

        int op = rng.nextInt(10);
        switch (op) {
            case 0: case 1: // Bit flip in data region
                flipBit(child, DATA_OFFSET);
                break;
            case 2: // Random byte in data region
                setRandomByte(child, DATA_OFFSET);
                break;
            case 3: // Increment/decrement in data region
                incDec(child, DATA_OFFSET);
                break;
            case 4: case 5: // Varint arithmetic (mechanism-specific)
                child = varintArithmetic(child);
                break;
            case 6: // Dictionary insertion
                dictInsert(child, DATA_OFFSET);
                break;
            case 7: // Repetition
                child = repetition(child);
                break;
            case 8: // Byte insertion in data region
                child = insertByte(child);
                break;
            case 9: // Byte deletion in data region
                child = deleteByte(child, DATA_OFFSET);
                break;
        }

        if (child.length > maxInputSize) {
            child = Arrays.copyOf(child, maxInputSize);
        }
        applyEncoder(child);
        return child;
    }

    /** Mechanism-specific: increase the varint-encoded uncompressed length in compressed data. */
    private byte[] varintArithmetic(byte[] data) {
        if (data.length <= DATA_OFFSET) return data;
        long[] decoded = decodeVarint(data, DATA_OFFSET);
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
        // Replace old varint with new one, adjusting array size
        int tailStart = DATA_OFFSET + oldLen;
        int tailLen = Math.max(0, data.length - tailStart);
        int newDataStart = DATA_OFFSET + newVarint.length;
        byte[] result = new byte[newDataStart + tailLen];
        System.arraycopy(data, 0, result, 0, DATA_OFFSET);
        System.arraycopy(newVarint, 0, result, DATA_OFFSET, newVarint.length);
        if (tailLen > 0) {
            System.arraycopy(data, tailStart, result, newDataStart, tailLen);
        }
        return result;
    }

    private void flipBit(byte[] data, int minPos) {
        if (data.length <= minPos) return;
        int pos = minPos + rng.nextInt(data.length - minPos);
        data[pos] ^= (byte) (1 << rng.nextInt(8));
    }

    private void setRandomByte(byte[] data, int minPos) {
        if (data.length <= minPos) return;
        int pos = minPos + rng.nextInt(data.length - minPos);
        data[pos] = (byte) rng.nextInt(256);
    }

    private void incDec(byte[] data, int minPos) {
        if (data.length <= minPos) return;
        int pos = minPos + rng.nextInt(data.length - minPos);
        data[pos] += (byte) (rng.nextBoolean() ? 1 : -1);
    }

    private void dictInsert(byte[] data, int minPos) {
        if (data.length <= minPos) return;
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = minPos + rng.nextInt(data.length - minPos);
        int len = Math.min(token.length, data.length - pos);
        System.arraycopy(token, 0, data, pos, len);
    }

    private byte[] repetition(byte[] data) {
        if (data.length <= DATA_OFFSET + 1) return data;
        int start = DATA_OFFSET + rng.nextInt(data.length - DATA_OFFSET);
        int regionLen = rng.nextInt(Math.max(1, Math.min(data.length - start, 32))) + 1;
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
        int pos = DATA_OFFSET + (data.length > DATA_OFFSET
                ? rng.nextInt(data.length - DATA_OFFSET) : 0);
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
            log.printf("[V2] execs=%d saved=%d maxSignal=%d lastSignal=%.0f%n",
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
