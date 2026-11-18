package guidance;

import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * V3Guidance: VDF Guidance targeting heap allocation via large BIN/EXT headers.
 * Signal: declaredPayloadBytes (byte count parsed from the first BIN/EXT header).
 * Tier 0 static signal — parsed directly from input bytes, no agent needed.
 * [R3] Implements Guidance directly, [R6] never decides failures, [R33] dedicated to V3.
 */
public class V3Guidance implements Guidance, SignalSource {

    private final int maxInputSize;
    private final File savedInputsDir;
    private final PrintStream log;
    private final long startTimeMs;
    private final long maxDurationMs;
    private final Random rng = new Random();

    // Corpus
    private final List<byte[]> corpus = new ArrayList<>();
    private long bestDeclaredLength = 0;
    private int bestInputLength = 0;

    // Current execution state
    private byte[] currentInput;
    private long lastDeclaredLength = 0;
    private long totalExecutions = 0;
    private long lastLogTimeMs;

    // Dictionary tokens [R45b]
    private static final byte[][] DICTIONARY = {
        {(byte) 0xC6},                                          // BIN32
        {(byte) 0xC5},                                          // BIN16
        {(byte) 0xC4},                                          // BIN8
        {(byte) 0xC9},                                          // EXT32
        {(byte) 0xC8},                                          // EXT16
        {(byte) 0xC7},                                          // EXT8
        {(byte) 0xC6, (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}, // BIN32 max positive
        {(byte) 0xC6, (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00}, // BIN32 ~256M
        {(byte) 0xC0},                                          // nil
        {(byte) 0xFF},                                          // max byte
    };

    public V3Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.savedInputsDir = new File(outputDir, "saved_inputs");
        this.savedInputsDir.mkdirs();
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();
        this.maxDurationMs = maxDurationMs;
        this.lastLogTimeMs = startTimeMs;

        // Seed: BIN32 header with size 1 + 1 byte payload
        byte[] seed = new byte[]{(byte) 0xC6, 0x00, 0x00, 0x00, 0x01, 0x41};
        corpus.add(seed);
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        lastDeclaredLength = 0;

        byte[] parent = corpus.get(rng.nextInt(corpus.size()));
        currentInput = mutate(parent);

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs > 0) {
            return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
        }
        return true;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecutions++;
        long declared = parseDeclaredLength(currentInput);
        lastDeclaredLength = declared;

        boolean retain = false;
        if (declared > bestDeclaredLength) {
            bestDeclaredLength = declared;
            retain = true;
        }
        // Secondary: while signal flat, retain longer/diverse inputs
        if (declared == 0 && currentInput.length > bestInputLength) {
            bestInputLength = currentInput.length;
            retain = true;
        }
        if (declared == bestDeclaredLength && declared > 0 && currentInput.length > bestInputLength) {
            bestInputLength = currentInput.length;
            retain = true;
        }

        if (retain) {
            byte[] copy = Arrays.copyOf(currentInput, currentInput.length);
            corpus.add(copy);
            saveInput(copy, declared);
        }

        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            log.printf("[V3] execs=%d, bestLen=%d, corpusSize=%d, bestInputLen=%d, elapsed=%.1fs%n",
                    totalExecutions, bestDeclaredLength, corpus.size(), bestInputLength,
                    (now - startTimeMs) / 1000.0);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return e -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> m = new HashMap<>();
        m.put("declaredPayloadBytes", (double) lastDeclaredLength);
        return m;
    }

    // ---- Static signal extraction (Tier 0) ----

    /**
     * Parse the declared payload byte count from the first BIN or EXT header in the input.
     * Returns 0 if no valid header is found.
     */
    static long parseDeclaredLength(byte[] data) {
        if (data == null || data.length == 0) return 0;
        int b = data[0] & 0xFF;

        // BIN8: 0xC4 + 1 byte length
        if (b == 0xC4 && data.length >= 2) {
            return data[1] & 0xFF;
        }
        // BIN16: 0xC5 + 2 bytes BE length
        if (b == 0xC5 && data.length >= 3) {
            return ((data[1] & 0xFF) << 8) | (data[2] & 0xFF);
        }
        // BIN32: 0xC6 + 4 bytes BE length
        if (b == 0xC6 && data.length >= 5) {
            return ((long)(data[1] & 0xFF) << 24) |
                   ((long)(data[2] & 0xFF) << 16) |
                   ((long)(data[3] & 0xFF) << 8)  |
                   ((long)(data[4] & 0xFF));
        }
        // EXT8: 0xC7 + 1 byte length + 1 byte type
        if (b == 0xC7 && data.length >= 3) {
            return data[1] & 0xFF;
        }
        // EXT16: 0xC8 + 2 bytes BE length + 1 byte type
        if (b == 0xC8 && data.length >= 4) {
            return ((data[1] & 0xFF) << 8) | (data[2] & 0xFF);
        }
        // EXT32: 0xC9 + 4 bytes BE length + 1 byte type
        if (b == 0xC9 && data.length >= 6) {
            return ((long)(data[1] & 0xFF) << 24) |
                   ((long)(data[2] & 0xFF) << 16) |
                   ((long)(data[3] & 0xFF) << 8)  |
                   ((long)(data[4] & 0xFF));
        }
        // STR32: 0xDB + 4 bytes BE length (also causes allocation)
        if (b == 0xDB && data.length >= 5) {
            return ((long)(data[1] & 0xFF) << 24) |
                   ((long)(data[2] & 0xFF) << 16) |
                   ((long)(data[3] & 0xFF) << 8)  |
                   ((long)(data[4] & 0xFF));
        }
        // STR16: 0xDA + 2 bytes BE length
        if (b == 0xDA && data.length >= 3) {
            return ((data[1] & 0xFF) << 8) | (data[2] & 0xFF);
        }
        return 0;
    }

    // ---- Mutation operators ----

    private byte[] mutate(byte[] parent) {
        int op = rng.nextInt(12);
        byte[] result;
        switch (op) {
            case 0: case 1: case 2:
                // Length-field targeted mutation (primary for this target)
                result = mutateLengthField(parent);
                break;
            case 3: case 4:
                // Dictionary insertion [R45b]
                result = mutateDictionary(parent);
                break;
            case 5: case 6:
                // Random byte flip
                result = mutateFlip(parent);
                break;
            case 7:
                // Random byte insert
                result = mutateInsert(parent);
                break;
            case 8:
                // Random byte delete
                result = mutateDelete(parent);
                break;
            case 9: case 10:
                // Repetition [R45a]
                result = mutateRepeat(parent);
                break;
            default:
                // Replace header with new large header
                result = mutateReplaceHeader(parent);
                break;
        }
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        if (result.length == 0) {
            result = new byte[]{(byte) 0xC6, 0x00, 0x00, 0x00, 0x01, 0x41};
        }
        return result;
    }

    /**
     * Targeted mutation of the length field for BIN32/EXT32/BIN16/EXT16 headers.
     */
    private byte[] mutateLengthField(byte[] parent) {
        if (parent.length < 5) return parent;
        byte[] result = parent.clone();
        int b = result[0] & 0xFF;

        if ((b == 0xC6 || b == 0xC9) && result.length >= 5) {
            // BIN32 or EXT32: mutate 4-byte length field at offsets 1-4
            int strategy = rng.nextInt(5);
            switch (strategy) {
                case 0: // Set to max positive
                    result[1] = 0x7F; result[2] = (byte) 0xFF;
                    result[3] = (byte) 0xFF; result[4] = (byte) 0xFF;
                    break;
                case 1: // Double current value
                    long current = parseDeclaredLength(result);
                    long doubled = Math.min(current * 2, 0x7FFFFFFFL);
                    if (doubled < 1) doubled = 0x10000000L;
                    result[1] = (byte) ((doubled >> 24) & 0xFF);
                    result[2] = (byte) ((doubled >> 16) & 0xFF);
                    result[3] = (byte) ((doubled >> 8) & 0xFF);
                    result[4] = (byte) (doubled & 0xFF);
                    break;
                case 2: // Random large value
                    long large = (long) rng.nextInt(Integer.MAX_VALUE) + 1;
                    result[1] = (byte) ((large >> 24) & 0xFF);
                    result[2] = (byte) ((large >> 16) & 0xFF);
                    result[3] = (byte) ((large >> 8) & 0xFF);
                    result[4] = (byte) (large & 0xFF);
                    break;
                case 3: // Flip one bit in length field
                    int byteIdx = 1 + rng.nextInt(4);
                    result[byteIdx] ^= (byte) (1 << rng.nextInt(8));
                    break;
                case 4: // ~256M (should exceed 1g heap)
                    result[1] = 0x10; result[2] = 0x00;
                    result[3] = 0x00; result[4] = 0x00;
                    break;
            }
        } else if ((b == 0xC5 || b == 0xC8) && result.length >= 3) {
            // BIN16 or EXT16: mutate 2-byte length field
            result[1] = (byte) rng.nextInt(256);
            result[2] = (byte) rng.nextInt(256);
        }
        return result;
    }

    private byte[] mutateReplaceHeader(byte[] parent) {
        // Replace/create a BIN32 header at the beginning
        byte[] result = new byte[Math.max(parent.length, 6)];
        result[0] = (byte) 0xC6;
        // Random large length
        long len = (long) rng.nextInt(Integer.MAX_VALUE) + 1;
        result[1] = (byte) ((len >> 24) & 0xFF);
        result[2] = (byte) ((len >> 16) & 0xFF);
        result[3] = (byte) ((len >> 8) & 0xFF);
        result[4] = (byte) (len & 0xFF);
        // Fill rest with data bytes
        for (int i = 5; i < result.length; i++) {
            result[i] = 0x41;
        }
        return result;
    }

    private byte[] mutateDictionary(byte[] parent) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[Math.min(parent.length + token.length, maxInputSize)];
        System.arraycopy(parent, 0, result, 0, Math.min(pos, result.length));
        if (pos < result.length) {
            int tokenCopy = Math.min(token.length, result.length - pos);
            System.arraycopy(token, 0, result, pos, tokenCopy);
            int suffixStart = pos + tokenCopy;
            int suffixLen = Math.min(parent.length - pos, result.length - suffixStart);
            if (suffixLen > 0 && suffixStart < result.length) {
                System.arraycopy(parent, pos, result, suffixStart, suffixLen);
            }
        }
        return result;
    }

    private byte[] mutateFlip(byte[] parent) {
        if (parent.length == 0) return parent;
        byte[] result = parent.clone();
        int pos = rng.nextInt(result.length);
        result[pos] ^= (byte) (1 << rng.nextInt(8));
        return result;
    }

    private byte[] mutateInsert(byte[] parent) {
        int pos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[Math.min(parent.length + 1, maxInputSize)];
        System.arraycopy(parent, 0, result, 0, Math.min(pos, result.length));
        if (pos < result.length) {
            result[pos] = (byte) rng.nextInt(256);
            int remaining = Math.min(parent.length - pos, result.length - pos - 1);
            if (remaining > 0) {
                System.arraycopy(parent, pos, result, pos + 1, remaining);
            }
        }
        return result;
    }

    private byte[] mutateDelete(byte[] parent) {
        if (parent.length <= 1) return parent;
        int pos = rng.nextInt(parent.length);
        byte[] result = new byte[parent.length - 1];
        System.arraycopy(parent, 0, result, 0, pos);
        System.arraycopy(parent, pos + 1, result, pos, parent.length - pos - 1);
        return result;
    }

    private byte[] mutateRepeat(byte[] parent) {
        if (parent.length == 0) return parent;
        int start = rng.nextInt(parent.length);
        int chunkLen = 1 + rng.nextInt(Math.min(parent.length - start, 32));
        int maxK = (maxInputSize - parent.length) / chunkLen + 1;
        if (maxK <= 1) maxK = 2;
        int k = 2 + rng.nextInt(Math.min(maxK, 64));
        byte[] chunk = Arrays.copyOfRange(parent, start, start + chunkLen);
        int newLen = Math.min(parent.length + chunkLen * k, maxInputSize);
        byte[] result = new byte[newLen];
        System.arraycopy(parent, 0, result, 0, Math.min(start, newLen));
        int pos = start;
        for (int i = 0; i < k && pos + chunkLen <= newLen; i++) {
            System.arraycopy(chunk, 0, result, pos, chunkLen);
            pos += chunkLen;
        }
        int remaining = parent.length - (start + chunkLen);
        if (remaining > 0 && pos < newLen) {
            int toCopy = Math.min(remaining, newLen - pos);
            System.arraycopy(parent, start + chunkLen, result, pos, toCopy);
        }
        return result;
    }

    private void saveInput(byte[] input, long declaredLen) {
        try {
            String name = String.format("id_%06d_len_%d.bin", totalExecutions, declaredLen);
            Files.write(new File(savedInputsDir, name).toPath(), input);
        } catch (IOException e) {
            // best effort
        }
    }
}
