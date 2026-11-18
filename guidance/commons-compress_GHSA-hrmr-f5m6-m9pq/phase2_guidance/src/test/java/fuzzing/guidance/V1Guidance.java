package fuzzing.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;
import fuzzing.agent.V1Counters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * V1Guidance — Vulnerability-Directed + Cost-Gradient Guidance for
 * ZipArchiveInputStream STORED entry stale-buffer re-serving (CWE-835).
 *
 * Signal: storedBytesRead (total bytes returned by readStored, measured by V1MeasureAgent).
 * Input model: raw bytes (InputStream) [R25][R31].
 * Does NOT decide failures or write failure files [R6].
 */
public final class V1Guidance implements Guidance, SignalSource {

    private final File corpusDir;
    private final PrintStream log;
    private final long startTime;
    private final long maxDurationMs;
    private final Random rng = new Random();
    private final int maxInputSize;

    // Corpus: list of (input bytes, signal value)
    private final List<byte[]> corpus = new ArrayList<>();
    private final List<Long> corpusSignals = new ArrayList<>();

    // Current execution state
    private byte[] currentInput;
    private long lastSignalValue;
    private long bestSignal;
    private long totalExecs;
    private long lastLogTime;
    private int savedCount;

    // Dictionary tokens from the attack path [R45b]
    private static final byte[][] DICTIONARY = {
        {0x50, 0x4B, 0x03, 0x04},               // LFH_SIG
        {0x50, 0x4B, 0x01, 0x02},               // CFH_SIG
        {0x50, 0x4B, 0x05, 0x06},               // EOCD_SIG
        {0x00},                                   // STORED method
        {0x08},                                   // DEFLATED method
        {(byte) 0xC0},                           // UTF-8 2-byte lead
        {(byte) 0xC2},                           // UTF-8 2-byte lead (valid start)
        {(byte) 0xE0},                           // UTF-8 3-byte lead
        {(byte) 0xF0},                           // UTF-8 4-byte lead
        {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}, // max 32-bit size
    };

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.log = log;
        this.startTime = System.currentTimeMillis();
        this.maxDurationMs = maxDurationMs;
        this.lastLogTime = startTime;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);

        // Initial seed: minimal valid STORED entry. The search must discover the
        // specific byte values that trigger the vulnerability [R23].
        byte[] seed = new byte[32];
        // LFH signature
        seed[0] = 0x50; seed[1] = 0x4B; seed[2] = 0x03; seed[3] = 0x04;
        // version needed = 20
        seed[4] = 20; seed[5] = 0;
        // general purpose bit flag = 0 (no data descriptor)
        seed[6] = 0; seed[7] = 0;
        // compression method = 0 (STORED)
        seed[8] = 0; seed[9] = 0;
        // last mod time + date
        seed[10] = 0; seed[11] = 0; seed[12] = 0x21; seed[13] = 0;
        // CRC32 = 0 (not checked for STORED entries at read time in this version)
        seed[14] = 0; seed[15] = 0; seed[16] = 0; seed[17] = 0;
        // compressed size = 1
        seed[18] = 1; seed[19] = 0; seed[20] = 0; seed[21] = 0;
        // uncompressed size = 1
        seed[22] = 1; seed[23] = 0; seed[24] = 0; seed[25] = 0;
        // filename length = 1
        seed[26] = 1; seed[27] = 0;
        // extra field length = 0
        seed[28] = 0; seed[29] = 0;
        // filename 'a'
        seed[30] = 0x61;
        // 1 data byte (arbitrary, the search will mutate this)
        seed[31] = 0x41;

        corpus.add(seed);
        corpusSignals.add(0L);
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        V1Counters.reset();

        // Select parent from corpus, biased toward higher signal
        byte[] parent = selectParent();

        // Mutate
        currentInput = mutate(parent);

        // Enforce max input size
        if (currentInput.length > maxInputSize) {
            currentInput = Arrays.copyOf(currentInput, maxInputSize);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs > 0) {
            return (System.currentTimeMillis() - startTime) < maxDurationMs;
        }
        return true; // infinite by default [R8]
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;
        lastSignalValue = V1Counters.get();

        // Retention logic
        boolean dominated = false;
        if (lastSignalValue > 0) {
            // Signal is non-zero: retain if it exceeds the best or adds diversity
            if (lastSignalValue > bestSignal || corpus.size() < 10) {
                retainInput(currentInput, lastSignalValue);
                if (lastSignalValue > bestSignal) {
                    bestSignal = lastSignalValue;
                }
            }
        } else {
            // Signal is flat [R46]: keep inputs that have different structure
            // to explore the input space toward valid STORED entries
            if (corpus.size() < 10 && currentInput.length >= 4 &&
                currentInput[0] == 0x50 && currentInput[1] == 0x4B &&
                currentInput[2] == 0x03 && currentInput[3] == 0x04) {
                retainInput(currentInput, 0);
            }
        }

        // Log every 1 second [R5]
        long now = System.currentTimeMillis();
        if (now - lastLogTime >= 1000) {
            log.printf("[V1] t=%ds execs=%d corpus=%d best_signal=%d last_signal=%d saved=%d%n",
                    (now - startTime) / 1000, totalExecs, corpus.size(),
                    bestSignal, lastSignalValue, savedCount);
            lastLogTime = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: measurement is via javaagent, not JQF tracing
        return e -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> m = new HashMap<>();
        m.put("storedBytesRead", (double) lastSignalValue);
        return m;
    }

    // ---- Mutation operators ----

    private byte[] mutate(byte[] parent) {
        byte[] input = parent.clone();

        // Apply 1-3 mutations
        int nMutations = 1 + rng.nextInt(3);
        for (int i = 0; i < nMutations; i++) {
            int op = rng.nextInt(7);
            switch (op) {
                case 0 -> input = mutateFlipByte(input);
                case 1 -> input = mutateOverwriteByte(input);
                case 2 -> input = mutateInsertByte(input);
                case 3 -> input = mutateDeleteByte(input);
                case 4 -> input = mutateRepeatChunk(input);        // [R45a]
                case 5 -> input = mutateDictionaryInsert(input);   // [R45b]
                case 6 -> input = mutateSizeField(input);          // V1-specific [R19]
            }
        }
        return input;
    }

    private byte[] mutateFlipByte(byte[] input) {
        if (input.length == 0) return input;
        int pos = rng.nextInt(input.length);
        input[pos] ^= (byte) (1 << rng.nextInt(8));
        return input;
    }

    private byte[] mutateOverwriteByte(byte[] input) {
        if (input.length == 0) return input;
        int pos = rng.nextInt(input.length);
        input[pos] = (byte) rng.nextInt(256);
        return input;
    }

    private byte[] mutateInsertByte(byte[] input) {
        if (input.length >= maxInputSize) return input;
        int pos = rng.nextInt(input.length + 1);
        byte[] out = new byte[input.length + 1];
        System.arraycopy(input, 0, out, 0, pos);
        out[pos] = (byte) rng.nextInt(256);
        System.arraycopy(input, pos, out, pos + 1, input.length - pos);
        return out;
    }

    private byte[] mutateDeleteByte(byte[] input) {
        if (input.length <= 1) return input;
        int pos = rng.nextInt(input.length);
        byte[] out = new byte[input.length - 1];
        System.arraycopy(input, 0, out, 0, pos);
        System.arraycopy(input, pos + 1, out, pos, input.length - pos - 1);
        return out;
    }

    /** [R45a] Repetition: copy a chunk and repeat it k times. */
    private byte[] mutateRepeatChunk(byte[] input) {
        if (input.length == 0) return input;
        int chunkStart = rng.nextInt(input.length);
        int chunkLen = 1 + rng.nextInt(Math.min(input.length - chunkStart, 64));
        int k = 2 + rng.nextInt(5); // repeat 2-6 times
        int newLen = Math.min(input.length + chunkLen * (k - 1), maxInputSize);
        byte[] out = new byte[newLen];
        // copy up to chunkStart
        System.arraycopy(input, 0, out, 0, Math.min(chunkStart, newLen));
        // repeat the chunk
        int pos = chunkStart;
        for (int i = 0; i < k && pos + chunkLen <= newLen; i++) {
            System.arraycopy(input, chunkStart, out, pos, chunkLen);
            pos += chunkLen;
        }
        // copy remainder
        int srcPos = chunkStart + chunkLen;
        if (srcPos < input.length && pos < newLen) {
            int toCopy = Math.min(input.length - srcPos, newLen - pos);
            System.arraycopy(input, srcPos, out, pos, toCopy);
        }
        return out;
    }

    /** [R45b] Dictionary insertion: insert or overwrite with a token from the source. */
    private byte[] mutateDictionaryInsert(byte[] input) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        if (input.length == 0) return token.clone();

        if (rng.nextBoolean() && input.length >= token.length) {
            // Overwrite at a random position
            int pos = rng.nextInt(input.length - token.length + 1);
            byte[] out = input.clone();
            System.arraycopy(token, 0, out, pos, token.length);
            return out;
        } else {
            // Insert
            if (input.length + token.length > maxInputSize) return input;
            int pos = rng.nextInt(input.length + 1);
            byte[] out = new byte[input.length + token.length];
            System.arraycopy(input, 0, out, 0, pos);
            System.arraycopy(token, 0, out, pos, token.length);
            System.arraycopy(input, pos, out, pos + token.length, input.length - pos);
            return out;
        }
    }

    /**
     * V1-specific mutation [R19]: mutate the size fields at LFH offsets 18-25
     * (compressed size at 18-21, uncompressed size at 22-25) to explore large declared sizes.
     */
    private byte[] mutateSizeField(byte[] input) {
        if (input.length < 26) return input;
        byte[] out = input.clone();
        // Target either compressed size (18-21) or uncompressed size (22-25)
        int fieldOffset = rng.nextBoolean() ? 18 : 22;
        // Set to a random large value or max
        if (rng.nextInt(3) == 0) {
            // Max 32-bit
            out[fieldOffset] = (byte) 0xFF;
            out[fieldOffset + 1] = (byte) 0xFF;
            out[fieldOffset + 2] = (byte) 0xFF;
            out[fieldOffset + 3] = (byte) 0xFF;
        } else {
            // Random large value
            int val = rng.nextInt(Integer.MAX_VALUE);
            out[fieldOffset]     = (byte) (val & 0xFF);
            out[fieldOffset + 1] = (byte) ((val >> 8) & 0xFF);
            out[fieldOffset + 2] = (byte) ((val >> 16) & 0xFF);
            out[fieldOffset + 3] = (byte) ((val >> 24) & 0xFF);
        }
        return out;
    }

    // ---- Corpus management ----

    private byte[] selectParent() {
        if (corpus.isEmpty()) {
            return new byte[0];
        }
        // Bias toward higher signal: pick from top-10 by signal
        int topN = Math.min(corpus.size(), 10);

        // Simple approach: sort indices by signal descending
        Integer[] indices = new Integer[corpus.size()];
        for (int i = 0; i < indices.length; i++) indices[i] = i;
        Arrays.sort(indices, (a, b) -> Long.compare(corpusSignals.get(b), corpusSignals.get(a)));

        int pick = indices[rng.nextInt(topN)];
        return corpus.get(pick);
    }

    private void retainInput(byte[] input, long signal) {
        // Keep corpus bounded
        if (corpus.size() >= 100) {
            // Remove worst
            int worstIdx = 0;
            long worstSig = corpusSignals.get(0);
            for (int i = 1; i < corpus.size(); i++) {
                if (corpusSignals.get(i) < worstSig) {
                    worstSig = corpusSignals.get(i);
                    worstIdx = i;
                }
            }
            if (signal <= worstSig) return; // not better than worst
            corpus.remove(worstIdx);
            corpusSignals.remove(worstIdx);
        }

        byte[] copy = input.clone();
        corpus.add(copy);
        corpusSignals.add(signal);

        // Save to disk
        try {
            savedCount++;
            String fname = String.format("id_%06d_sig_%d", savedCount, signal);
            Path p = corpusDir.toPath().resolve(fname);
            Files.write(p, copy);
            // Write metadata
            Path meta = corpusDir.toPath().resolve(fname + ".meta.json");
            Files.writeString(meta, String.format(
                "{\"id\":\"%s\",\"signal\":%d,\"length\":%d}%n",
                fname, signal, copy.length));
        } catch (IOException e) {
            // best-effort save
        }
    }
}
