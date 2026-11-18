package com.fuzzer.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Custom Guidance for V1: Snappy COMPRESSED_DATA preamble-driven allocation exhaustion.
 *
 * <p>Strategy: CGF + VDF hybrid. Hill-climbs the measured capacity growth of the
 * {@code out} ByteBuf inside {@code Snappy.decode()}, which directly correlates with
 * the attacker-controlled varint preamble value.</p>
 *
 * <p>Implements {@link Guidance} directly (no delegation to Zest or other guidances)
 * and {@link SignalSource} for DoSGuide validation.</p>
 *
 * <p>Input model: raw bytes via InputStream. The Guidance mutates byte arrays using
 * byte-level operators, chunk repetition, a dictionary of Snappy frame tokens, and
 * a well-formed Snappy frame encoder.</p>
 *
 * <p>The Guidance never decides failures and never writes failure files ([R6]).</p>
 */
public class V1Guidance implements Guidance, SignalSource {

    // ---- configuration ----
    private final int maxInputSize;
    private final long maxDurationMs;
    private final File corpusDir;
    private final PrintStream log;
    private final Random random = new Random();

    // ---- corpus ----
    private final List<byte[]> corpus = new ArrayList<>();
    private final List<Double> corpusSignals = new ArrayList<>();

    // ---- per-execution state ----
    private byte[] currentInput;
    private double lastCapacityGrowth;

    // ---- statistics ----
    private long totalExecs;
    private double bestCapacityGrowth;
    private int longestZeroSignalLen;
    private long startTimeMs;
    private long lastLogTimeMs;

    // ---- Snappy frame dictionary tokens ([R45b]) ----
    // Each is a single syntactic unit from the Snappy frame format source code.
    private static final byte[][] DICTIONARY = {
        {(byte) 0xFF},                                              // stream identifier chunk type
        {(byte) 0x00},                                              // compressed data chunk type
        {0x06, 0x00, 0x00},                                         // stream id length (LE, value 6)
        {0x73, 0x4E, 0x61, 0x50, 0x70, 0x59},                      // magic 'sNaPpY'
        {0x00, 0x00, 0x00, 0x00},                                   // zero checksum (4 bytes)
        {0x08, 0x00, 0x00},                                         // chunk length 8 (LE) = 4+4
        {(byte) 0x80},                                              // varint continuation byte
        {(byte) 0x01},                                              // minimal varint (value 1)
        {0x05, 0x00, 0x00},                                         // chunk length 5 (LE) = 4+1
    };

    // ---- stream identifier constant ----
    private static final byte[] STREAM_ID = {
        (byte) 0xFF, 0x06, 0x00, 0x00,
        0x73, 0x4E, 0x61, 0x50, 0x70, 0x59
    };

    /**
     * @param outputDir base output directory for this target
     * @param maxDurationMs maximum fuzzing duration in ms; 0 = infinite
     * @param log stream for structured logging
     */
    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.maxDurationMs = maxDurationMs;
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = startTimeMs;
    }

    // ================================================================
    //  Guidance interface
    // ================================================================

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset signal accumulator before each execution
        V1Signal.reset();

        if (corpus.isEmpty()) {
            // Initial seed: small random byte array
            currentInput = new byte[Math.min(16, maxInputSize)];
            random.nextBytes(currentInput);
        } else {
            // Select a parent from corpus and mutate
            int parentIdx = selectParent();
            byte[] parent = corpus.get(parentIdx);
            currentInput = mutate(parent);
        }

        // Enforce max input size limit
        if (currentInput.length > maxInputSize) {
            currentInput = Arrays.copyOf(currentInput, maxInputSize);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs > 0) {
            return System.currentTimeMillis() - startTimeMs < maxDurationMs;
        }
        return true; // infinite
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        // Read signal from this execution (not running total, not best-so-far)
        lastCapacityGrowth = (double) V1Signal.getCapacityGrowth();
        totalExecs++;

        // ---- retention decision ----
        boolean retain = false;

        if (corpus.isEmpty()) {
            // Always save first input
            retain = true;
        } else if (lastCapacityGrowth > bestCapacityGrowth) {
            // Strict improvement on primary signal
            retain = true;
        } else if (bestCapacityGrowth == 0.0 && lastCapacityGrowth == 0.0) {
            // Flat signal ([R46]): retain if this input is longer (growing toward input_bytes=58)
            if (currentInput.length > longestZeroSignalLen) {
                retain = true;
            }
        }
        // Length diversity: occasionally keep inputs at different lengths
        if (!retain && lastCapacityGrowth > 0 && corpus.size() < 20
                && random.nextDouble() < 0.05) {
            retain = true;
        }

        if (retain) {
            byte[] saved = currentInput.clone();
            corpus.add(saved);
            corpusSignals.add(lastCapacityGrowth);

            if (lastCapacityGrowth > bestCapacityGrowth) {
                bestCapacityGrowth = lastCapacityGrowth;
            }
            if (lastCapacityGrowth == 0.0 && currentInput.length > longestZeroSignalLen) {
                longestZeroSignalLen = currentInput.length;
            }

            saveToCorpus(saved);
        }

        // ---- structured logging every 1 second ([R5]) ----
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            logStats(now);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread executionThread) {
        // No-op: we use a custom javaagent, not JQF tracing
        return event -> { };
    }

    // ================================================================
    //  SignalSource interface (dosguide.validate)
    // ================================================================

    /**
     * Returns the signal values measured during the most recent execution.
     * This is the value of that execution only — not a running total or best-so-far.
     */
    @Override
    public Map<String, Double> lastSignals() {
        return Collections.singletonMap("capacityGrowth", lastCapacityGrowth);
    }

    // ================================================================
    //  Parent selection
    // ================================================================

    private int selectParent() {
        int n = corpus.size();
        if (n == 1) return 0;

        if (bestCapacityGrowth == 0.0) {
            // All signals flat — prefer longer inputs (weight by length)
            double total = 0;
            for (byte[] entry : corpus) {
                total += entry.length + 1.0;
            }
            double r = random.nextDouble() * total;
            double cumulative = 0;
            for (int i = 0; i < n; i++) {
                cumulative += corpus.get(i).length + 1.0;
                if (r <= cumulative) return i;
            }
            return n - 1;
        }

        // Weight by capacity growth (with +1 floor so zero-signal entries get a chance)
        double total = 0;
        for (Double s : corpusSignals) {
            total += s + 1.0;
        }
        double r = random.nextDouble() * total;
        double cumulative = 0;
        for (int i = 0; i < n; i++) {
            cumulative += corpusSignals.get(i) + 1.0;
            if (r <= cumulative) return i;
        }
        return n - 1;
    }

    // ================================================================
    //  Mutation operators
    // ================================================================

    private byte[] mutate(byte[] parent) {
        // Choose mutation operator by weighted random
        double p = random.nextDouble();
        byte[] result;
        if (p < 0.15) {
            result = byteFlip(parent);
        } else if (p < 0.25) {
            result = byteOverwrite(parent);
        } else if (p < 0.35) {
            result = byteInsert(parent);
        } else if (p < 0.40) {
            result = byteDelete(parent);
        } else if (p < 0.55) {
            result = dictionaryInsert(parent);
        } else if (p < 0.75) {
            result = chunkRepeat(parent);
        } else {
            result = snappyFrameEncode(parent);
        }
        // Enforce max size
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    /** Flip one random bit in a random byte. */
    private byte[] byteFlip(byte[] data) {
        if (data.length == 0) return data;
        byte[] out = data.clone();
        int pos = random.nextInt(out.length);
        out[pos] ^= (byte) (1 << random.nextInt(8));
        return out;
    }

    /** Overwrite one byte with a random value. */
    private byte[] byteOverwrite(byte[] data) {
        if (data.length == 0) return data;
        byte[] out = data.clone();
        int pos = random.nextInt(out.length);
        out[pos] = (byte) random.nextInt(256);
        return out;
    }

    /** Insert one random byte at a random position. */
    private byte[] byteInsert(byte[] data) {
        if (data.length >= maxInputSize) return byteFlip(data);
        byte[] out = new byte[data.length + 1];
        int pos = random.nextInt(data.length + 1);
        System.arraycopy(data, 0, out, 0, pos);
        out[pos] = (byte) random.nextInt(256);
        System.arraycopy(data, pos, out, pos + 1, data.length - pos);
        return out;
    }

    /** Delete one random byte. */
    private byte[] byteDelete(byte[] data) {
        if (data.length <= 1) return data;
        byte[] out = new byte[data.length - 1];
        int pos = random.nextInt(data.length);
        System.arraycopy(data, 0, out, 0, pos);
        System.arraycopy(data, pos + 1, out, pos, data.length - pos - 1);
        return out;
    }

    /**
     * Insert or overwrite a dictionary token at a random position ([R45b]).
     * Tokens are single syntactic units from the Snappy frame format source.
     */
    private byte[] dictionaryInsert(byte[] data) {
        byte[] token = DICTIONARY[random.nextInt(DICTIONARY.length)];

        if (data.length + token.length <= maxInputSize && random.nextBoolean()) {
            // Insert
            byte[] out = new byte[data.length + token.length];
            int pos = random.nextInt(data.length + 1);
            System.arraycopy(data, 0, out, 0, pos);
            System.arraycopy(token, 0, out, pos, token.length);
            System.arraycopy(data, pos, out, pos + token.length, data.length - pos);
            return out;
        } else {
            // Overwrite
            if (data.length < token.length) return data;
            byte[] out = data.clone();
            int pos = random.nextInt(data.length - token.length + 1);
            System.arraycopy(token, 0, out, pos, token.length);
            return out;
        }
    }

    /**
     * Duplicate a region of the input ([R45a]).
     *
     * <p>If the input looks like a Snappy frame (starts with 0xFF), attempts to
     * identify chunk boundaries at 12-byte intervals after the 10-byte stream
     * identifier. Otherwise, picks a random region. Repeats the region k times,
     * growing toward {@code input_bytes} (58) and the max input size.</p>
     */
    private byte[] chunkRepeat(byte[] data) {
        if (data.length == 0) return data;

        int regionStart;
        int regionLen;

        // Try to identify a chunk region in a Snappy frame
        if (data.length > 14 && (data[0] & 0xFF) == 0xFF) {
            regionStart = 10; // after stream identifier
            if (regionStart >= data.length) return data;
            // Read chunk length from header
            if (data.length >= regionStart + 4) {
                int chunkDataLen = (data[regionStart + 1] & 0xFF)
                        | ((data[regionStart + 2] & 0xFF) << 8)
                        | ((data[regionStart + 3] & 0xFF) << 16);
                regionLen = 4 + chunkDataLen; // type byte + 3 length bytes + payload
                if (regionLen <= 0 || regionStart + regionLen > data.length) {
                    regionLen = data.length - regionStart;
                }
            } else {
                regionLen = data.length - regionStart;
            }
        } else {
            // Unknown structure — pick random region
            regionStart = random.nextInt(data.length);
            regionLen = 1 + random.nextInt(Math.max(1, data.length - regionStart));
        }

        if (regionLen <= 0) return data;

        int space = maxInputSize - data.length;
        if (space < regionLen) {
            // No room — try whole-input doubling with truncation
            if (data.length < maxInputSize) {
                int newLen = Math.min(data.length * 2, maxInputSize);
                byte[] out = new byte[newLen];
                System.arraycopy(data, 0, out, 0, data.length);
                System.arraycopy(data, 0, out, data.length,
                        Math.min(data.length, newLen - data.length));
                return out;
            }
            return data;
        }

        int maxK = space / regionLen;
        int k = 1 + random.nextInt(Math.min(maxK, 10));

        int resultLen = data.length + k * regionLen;
        if (resultLen > maxInputSize) resultLen = maxInputSize;
        byte[] out = new byte[resultLen];

        // Copy prefix: everything up to end of the region
        int prefixEnd = Math.min(regionStart + regionLen, data.length);
        System.arraycopy(data, 0, out, 0, Math.min(prefixEnd, out.length));

        // Append k copies of the region
        int writePos = prefixEnd;
        for (int i = 0; i < k && writePos + regionLen <= out.length; i++) {
            System.arraycopy(data, regionStart, out, writePos, regionLen);
            writePos += regionLen;
        }

        // Copy suffix (data after the original region)
        int suffixStart = regionStart + regionLen;
        if (suffixStart < data.length) {
            int remaining = Math.min(data.length - suffixStart, out.length - writePos);
            if (remaining > 0) {
                System.arraycopy(data, suffixStart, out, writePos, remaining);
                writePos += remaining;
            }
        }

        return Arrays.copyOf(out, Math.min(writePos, maxInputSize));
    }

    /**
     * Well-formed Snappy frame encoder ([R45c]).
     *
     * <p>Parses the parent input as a Snappy frame (stream identifier + compressed
     * data chunks). Mutates the decoded representation (add/remove/modify chunks,
     * change varint preamble bytes). Re-encodes with correct chunk type byte and
     * 3-byte LE length, zero checksum.</p>
     *
     * <p>If the parent is not a valid frame, creates a minimal frame from the
     * parent's bytes as a payload seed.</p>
     */
    private byte[] snappyFrameEncode(byte[] parent) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.min(maxInputSize, 256));
        try {
            // Always write stream identifier
            bos.write(STREAM_ID);

            // Parse existing chunks
            List<byte[]> chunkPayloads = parseChunkPayloads(parent);

            // If no valid chunks, create one from parent bytes
            if (chunkPayloads.isEmpty()) {
                byte[] varint = randomVarint();
                byte[] payload = new byte[4 + varint.length]; // checksum + varint
                System.arraycopy(varint, 0, payload, 4, varint.length);
                chunkPayloads.add(payload);
            }

            // Apply one random structural mutation
            double m = random.nextDouble();
            if (m < 0.30) {
                // Add a new chunk with random varint
                byte[] varint = randomVarint();
                byte[] payload = new byte[4 + varint.length];
                System.arraycopy(varint, 0, payload, 4, varint.length);
                chunkPayloads.add(payload);
            } else if (m < 0.50 && chunkPayloads.size() > 1) {
                // Remove a random chunk
                chunkPayloads.remove(random.nextInt(chunkPayloads.size()));
            } else if (m < 0.70) {
                // Duplicate a random chunk
                int idx = random.nextInt(chunkPayloads.size());
                chunkPayloads.add(chunkPayloads.get(idx).clone());
            } else {
                // Mutate a byte in a random chunk's varint region
                int idx = random.nextInt(chunkPayloads.size());
                byte[] payload = chunkPayloads.get(idx);
                if (payload.length > 4) { // has varint after checksum
                    int varintPos = 4 + random.nextInt(payload.length - 4);
                    payload[varintPos] = (byte) random.nextInt(256);
                }
            }

            // Encode each chunk
            for (byte[] payload : chunkPayloads) {
                if (bos.size() + 4 + payload.length > maxInputSize) break;
                int len = payload.length;
                bos.write(0x00); // COMPRESSED_DATA type
                bos.write(len & 0xFF);
                bos.write((len >> 8) & 0xFF);
                bos.write((len >> 16) & 0xFF);
                bos.write(payload);
            }

        } catch (IOException e) {
            return parent; // fallback on error
        }

        byte[] result = bos.toByteArray();
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    /**
     * Parse the payload (checksum + compressed data) from each COMPRESSED_DATA
     * chunk in a Snappy frame.
     */
    private List<byte[]> parseChunkPayloads(byte[] data) {
        List<byte[]> chunks = new ArrayList<>();
        if (data.length < 10 || (data[0] & 0xFF) != 0xFF) return chunks;

        int pos = 10; // skip stream identifier
        while (pos + 4 <= data.length) {
            int type = data[pos] & 0xFF;
            int len = (data[pos + 1] & 0xFF)
                    | ((data[pos + 2] & 0xFF) << 8)
                    | ((data[pos + 3] & 0xFF) << 16);
            pos += 4;
            if (type == 0x00 && len > 0 && pos + len <= data.length) {
                chunks.add(Arrays.copyOfRange(data, pos, pos + len));
                pos += len;
            } else {
                break;
            }
        }
        return chunks;
    }

    /** Generate a random varint of 1–4 bytes. */
    private byte[] randomVarint() {
        int numBytes = 1 + random.nextInt(4);
        byte[] varint = new byte[numBytes];
        for (int i = 0; i < numBytes - 1; i++) {
            varint[i] = (byte) (0x80 | random.nextInt(128)); // continuation bit set
        }
        varint[numBytes - 1] = (byte) random.nextInt(128); // last byte: no continuation
        return varint;
    }

    // ================================================================
    //  Corpus persistence
    // ================================================================

    private void saveToCorpus(byte[] input) {
        try {
            Path dir = corpusDir.toPath();
            Files.createDirectories(dir);
            String name = String.format("id_%06d_cg_%.0f_len_%d",
                    totalExecs, lastCapacityGrowth, input.length);
            Files.write(dir.resolve(name), input);
        } catch (IOException ignored) {
            // best-effort save
        }
    }

    // ================================================================
    //  Logging
    // ================================================================

    private void logStats(long now) {
        long elapsedSec = (now - startTimeMs) / 1000;
        double eps = totalExecs * 1000.0 / Math.max(now - startTimeMs, 1);
        log.printf("[V1] %ds | execs=%d (%.0f/s) | corpus=%d | best_cg=%.0f | last_cg=%.0f%n",
                elapsedSec, totalExecs, eps, corpus.size(),
                bestCapacityGrowth, lastCapacityGrowth);
    }
}
