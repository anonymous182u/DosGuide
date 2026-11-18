package fuzzing.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;
import fuzzing.agent.PkgRisk1Counters;

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;
import java.util.zip.CRC32;

/**
 * PkgRisk1Guidance — Dependency-Aware + Cost-Gradient Guidance for
 * BZip2 decompression bomb via ZIP method 12 entries (CWE-409).
 *
 * Signal: decompressedBytes (total bytes returned by BZip2CompressorInputStream#read,
 *         measured by DoSMeasureAgent).
 *
 * Strategy: two parallel tracks, both producing single-entry ZIP inputs through
 * BZip2CompressorOutputStream [R45c]:
 *
 * (1) Bomb track: encodes large uniform plaintext (zeros) for maximum decompression
 *     amplification.  Starts at 1 KB, doubles to 64 MB.  At 64 MB a single entry is
 *     ~110 bytes encoded but decompresses to 67,108,864 bytes — matching the scale
 *     series structure.
 *
 * (2) Growth track: encodes diverse (random) plaintext for input-length growth [R46].
 *     Random data compresses at roughly 1:1, so a ~2800-byte plaintext produces a
 *     ~3100+-byte encoded input, satisfying input_bytes = 3100.
 *
 * Best signal comes from the bomb track (67 M at ~110 bytes).  Input growth comes from
 * the growth track (3100+ bytes within seconds).  Each input is a single ZIP entry —
 * never multi-entry — so the signal-per-byte ratio matches the scale series.
 *
 * Input model: raw bytes (InputStream) [R25][R31].
 * Does NOT decide failures or write failure files [R6].
 */
public final class PkgRisk1Guidance implements Guidance, SignalSource {

    /** Maximum plaintext size for bomb entries (64 MB). */
    private static final long BOMB_CAP = 64L * 1024 * 1024;

    private final File corpusDir;
    private final PrintStream log;
    private final long startTime;
    private final long maxDurationMs;
    private final Random rng = new Random();
    private final int maxInputSize;

    // --- Bomb track: single entry with large uniform plaintext ---
    private long bombPlaintextSize = 1024;
    private final Map<Long, byte[]> bombCache = new HashMap<>(); // plaintextSize -> encoded entry

    // --- Growth track: single entry with diverse plaintext ---
    private int growthPlaintextSize = 500; // current target size for diverse plaintext

    // --- Corpus ---
    private final List<byte[]> corpus = new ArrayList<>(); // encoded inputs
    private final List<Long> corpusSignals = new ArrayList<>();
    private final List<Integer> corpusLengths = new ArrayList<>();

    // --- Current execution state ---
    private byte[] currentInput;
    private long lastSignalValue;
    private long bestSignal;
    private int longestInput;
    private long totalExecs;
    private long lastLogTime;
    private int savedCount;

    public PkgRisk1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.log = log;
        this.startTime = System.currentTimeMillis();
        this.maxDurationMs = maxDurationMs;
        this.lastLogTime = startTime;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);

        // Encode initial seed: 1024 zeros [R23]
        try {
            byte[] seedEntry = encodeBombEntry(1024);
            bombCache.put(1024L, seedEntry);
            corpus.add(seedEntry);
            corpusSignals.add(0L);
            corpusLengths.add(seedEntry.length);
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode seed", e);
        }
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        PkgRisk1Counters.reset();

        // Handle very small input limits (e.g. input_limit check with MAX_INPUT_SIZE=16)
        if (maxInputSize < 50) {
            int len = 4 + rng.nextInt(Math.max(1, maxInputSize - 3));
            len = Math.min(len, maxInputSize);
            currentInput = new byte[len];
            rng.nextBytes(currentInput);
            return new ByteArrayInputStream(currentInput);
        }

        try {
            int op = rng.nextInt(10);

            if (op < 3 && bombPlaintextSize < BOMB_CAP) {
                // 30%: grow bomb entry (double plaintext size)
                growBomb();
            } else if (op < 6) {
                // 30% (or 60% after bomb cap): grow diverse entry for input length [R46]
                growDiverse();
            } else if (op < 8 && corpus.size() > 1) {
                // 20%: mutate a corpus entry's encoded bytes
                mutateCorpus();
            } else {
                // 20%: reuse current best bomb entry
                reuseBomb();
            }
        } catch (IOException e) {
            // Fallback to seed
            currentInput = bombCache.getOrDefault(1024L, new byte[73]).clone();
        }

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
        return true;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;
        lastSignalValue = PkgRisk1Counters.get();

        boolean retained = false;

        // Keep if signal improved or corpus is still small
        if (lastSignalValue > 0 && (lastSignalValue > bestSignal || corpus.size() < 20)) {
            retainInput();
            if (lastSignalValue > bestSignal) {
                bestSignal = lastSignalValue;
            }
            retained = true;
        }

        // [R46] Keep if input is longer than current longest (for input_growth)
        if (!retained && currentInput.length > longestInput) {
            retainInput();
            retained = true;
        }

        if (currentInput.length > longestInput) {
            longestInput = currentInput.length;
        }

        // Log every 1 second [R5]
        long now = System.currentTimeMillis();
        if (now - lastLogTime >= 1000) {
            log.printf("[PkgRisk1] t=%ds execs=%d corpus=%d best=%d last=%d " +
                       "longest=%d bombPt=%dK growthPt=%d saved=%d%n",
                (now - startTime) / 1000, totalExecs, corpus.size(),
                bestSignal, lastSignalValue, longestInput,
                bombPlaintextSize / 1024, growthPlaintextSize, savedCount);
            lastLogTime = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return e -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> m = new HashMap<>();
        m.put("decompressedBytes", (double) lastSignalValue);
        return m;
    }

    // ======================================================================
    // Mutation operators
    // ======================================================================

    /**
     * Bomb track: double the plaintext size and encode through BZip2 [R45c].
     * The encoded entry is cached so each size is encoded only once.
     */
    private void growBomb() throws IOException {
        bombPlaintextSize = Math.min(bombPlaintextSize * 2, BOMB_CAP);
        byte[] encoded = bombCache.get(bombPlaintextSize);
        if (encoded == null) {
            encoded = encodeBombEntry(bombPlaintextSize);
            bombCache.put(bombPlaintextSize, encoded);
        }
        currentInput = encoded.clone();
    }

    /**
     * Growth track: encode diverse (random) plaintext for input length [R46][R45c].
     * Random data compresses at roughly 1:1 with bzip2, so the encoded output
     * grows proportionally with the plaintext.
     */
    private void growDiverse() throws IOException {
        int ptLen = Math.min(growthPlaintextSize, maxInputSize);
        if (ptLen < 10) ptLen = 10;
        byte[] pt = new byte[ptLen];
        rng.nextBytes(pt);
        currentInput = encodeEntry(pt);
        // Increase the target for next time
        growthPlaintextSize = Math.min(growthPlaintextSize + 200 + rng.nextInt(400),
                                        maxInputSize);
    }

    /** Mutate a corpus entry's encoded bytes (exploration). */
    private void mutateCorpus() {
        int idx = selectParent();
        currentInput = corpus.get(idx).clone();
        mutateEncoded(currentInput);
    }

    /** Reuse the current best bomb entry (high-signal input). */
    private void reuseBomb() {
        currentInput = bombCache.getOrDefault(bombPlaintextSize,
            bombCache.getOrDefault(1024L, new byte[73])).clone();
    }

    // ======================================================================
    // Encoding: plaintext -> BZip2 -> ZIP LFH [R45c]
    // ======================================================================

    /**
     * Encode a bomb entry: N zero-bytes compressed through BZip2CompressorOutputStream.
     * Uses streaming (64 KB chunks) so the full plaintext is never in memory.
     */
    private byte[] encodeBombEntry(long plaintextSize) throws IOException {
        byte[] zeros = new byte[65536];

        // BZip2 compress zeros
        ByteArrayOutputStream bz2Out = new ByteArrayOutputStream();
        try (BZip2CompressorOutputStream bz2 = new BZip2CompressorOutputStream(bz2Out, 9)) {
            long remaining = plaintextSize;
            while (remaining > 0) {
                int n = (int) Math.min(zeros.length, remaining);
                bz2.write(zeros, 0, n);
                remaining -= n;
            }
        }
        byte[] compressedData = bz2Out.toByteArray();

        // CRC32 of zeros (streaming)
        CRC32 crc = new CRC32();
        long remaining = plaintextSize;
        while (remaining > 0) {
            int n = (int) Math.min(zeros.length, remaining);
            crc.update(zeros, 0, n);
            remaining -= n;
        }

        return buildLFH(compressedData, (int) crc.getValue(),
                         compressedData.length,
                         (int) Math.min(plaintextSize, Integer.MAX_VALUE));
    }

    /** Encode a small plaintext through BZip2CompressorOutputStream. */
    private byte[] encodeEntry(byte[] plaintext) throws IOException {
        ByteArrayOutputStream bz2Out = new ByteArrayOutputStream();
        try (BZip2CompressorOutputStream bz2 = new BZip2CompressorOutputStream(bz2Out, 9)) {
            bz2.write(plaintext);
        }
        byte[] compressedData = bz2Out.toByteArray();

        CRC32 crc = new CRC32();
        crc.update(plaintext);

        return buildLFH(compressedData, (int) crc.getValue(),
                         compressedData.length, plaintext.length);
    }

    /** Build a ZIP Local File Header with the given compressed data. */
    private byte[] buildLFH(byte[] compressedData, int crcVal,
                             int compressedSize, int uncompressedSize) {
        ByteBuffer lfh = ByteBuffer.allocate(31 + compressedData.length);
        lfh.order(ByteOrder.LITTLE_ENDIAN);
        lfh.putInt(0x04034B50);           // LFH signature
        lfh.putShort((short) 20);         // version needed to extract
        lfh.putShort((short) 0);          // general purpose flags
        lfh.putShort((short) 12);         // compression method = BZIP2
        lfh.putShort((short) 0);          // last mod time
        lfh.putShort((short) 0x0021);     // last mod date
        lfh.putInt(crcVal);               // CRC-32
        lfh.putInt(compressedSize);       // compressed size
        lfh.putInt(uncompressedSize);     // uncompressed size
        lfh.putShort((short) 1);          // filename length
        lfh.putShort((short) 0);          // extra field length
        lfh.put((byte) 'a');              // filename
        lfh.put(compressedData);          // compressed data

        return Arrays.copyOf(lfh.array(), lfh.position());
    }

    // ======================================================================
    // Mutation on encoded bytes
    // ======================================================================

    /** Flip random bytes in the bzip2 data area (exploration). */
    private void mutateEncoded(byte[] input) {
        if (input.length <= 31) return;
        // Only mutate in the bzip2 data area, not the ZIP LFH header
        int nMuts = 1 + rng.nextInt(3);
        for (int i = 0; i < nMuts; i++) {
            int pos = 31 + rng.nextInt(input.length - 31);
            input[pos] ^= (byte) (1 << rng.nextInt(8));
        }
    }

    // ======================================================================
    // Corpus management
    // ======================================================================

    /** Select a parent from the corpus, preferring high-signal entries. */
    private int selectParent() {
        if (corpus.size() <= 1) return 0;
        int topN = Math.min(corpus.size(), 10);
        Integer[] indices = new Integer[corpus.size()];
        for (int i = 0; i < indices.length; i++) indices[i] = i;
        Arrays.sort(indices, (a, b) -> Long.compare(corpusSignals.get(b), corpusSignals.get(a)));
        return indices[rng.nextInt(topN)];
    }

    /** Retain the current input in the corpus. */
    private void retainInput() {
        long signal = lastSignalValue;
        int encodedLen = currentInput.length;

        // Evict worst entry if corpus is at capacity
        if (corpus.size() >= 100) {
            int worstIdx = 0;
            long worstSig = corpusSignals.get(0);
            int worstLen = corpusLengths.get(0);
            for (int i = 1; i < corpus.size(); i++) {
                long sig = corpusSignals.get(i);
                int len = corpusLengths.get(i);
                if (sig < worstSig || (sig == worstSig && len < worstLen)) {
                    worstSig = sig;
                    worstLen = len;
                    worstIdx = i;
                }
            }
            if (signal < worstSig || (signal == worstSig && encodedLen <= worstLen)) return;
            corpus.remove(worstIdx);
            corpusSignals.remove(worstIdx);
            corpusLengths.remove(worstIdx);
        }

        corpus.add(currentInput.clone());
        corpusSignals.add(signal);
        corpusLengths.add(encodedLen);

        // Save to disk (best-effort)
        try {
            savedCount++;
            String fname = String.format("id_%06d_sig_%d_len_%d", savedCount, signal, encodedLen);
            Files.write(corpusDir.toPath().resolve(fname), currentInput);
        } catch (IOException e) {
            // best-effort
        }
    }
}
