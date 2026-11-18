package org.jose4j.fuzz.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;
import org.jose4j.fuzz.agent.InflateCounters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * V1Guidance: Cost-Gradient + Dependency-Aware Hybrid Guidance for
 * the Decompression Bomb vulnerability (CWE-409) in jose4j.
 *
 * Implements Guidance directly ([R3]), NOT extending any existing guidance.
 * Implements SignalSource for DoSGuide validation.
 *
 * Strategy:
 * - Hill-climbs on inflatedBytes (total decompressed output from DeflateRFC1951CompressionAlgorithm.decompress)
 * - Mutates at the plaintext level, then compresses via Deflater to produce valid
 *   raw DEFLATE streams ([R45c])
 * - Uses repetition ([R45a]) and dictionary tokens ([R45b])
 * - Never decides failures or writes failure files ([R6])
 *
 * Input model: byte[]/InputStream — the fuzz test receives raw DEFLATE bytes ([R25],[R31])
 */
public class V1Guidance implements Guidance, SignalSource {

    // --- Configuration ---
    private final int maxInputSize;
    private final File corpusDir;
    private final PrintStream log;
    private final long maxDurationMs;
    private final long startTimeMs;
    private final Random rng = new Random();

    // --- Corpus ---
    private static final int MAX_CORPUS_SIZE = 32;
    private final List<CorpusEntry> corpus = new ArrayList<>();

    // --- Per-execution state ---
    private byte[] currentPlaintext;
    private byte[] currentDeflateInput;
    private long executionCount;
    private long lastLogTimeMs;

    // --- Signal from last execution (for SignalSource) ---
    private double lastInflatedBytes;
    private double lastInflateCallCount;

    // --- Best-so-far tracking ---
    private long bestInflatedBytes;
    private int maxPlaintextLen;
    private int savedCount;

    // --- Dictionary tokens from attack path source ([R45b]) ---
    private static final byte[][] DICTIONARY = {
        {0x00},                                    // zero byte (maximally compressible)
        {0x01},                                    // DEFLATE BFINAL marker
        {0x03},                                    // DEFLATE fixed Huffman block header
        {0x78},                                    // zlib magic byte
        {(byte)0xFF},                              // common binary byte
        {0x44, 0x45, 0x46},                        // "DEF" — CompressionAlgorithmIdentifiers.DEFLATE
        {0x7A, 0x69, 0x70},                        // "zip" — HeaderParameterNames.ZIP
        {0x61, 0x6C, 0x67},                        // "alg" — header field name
        {0x65, 0x6E, 0x63},                        // "enc" — header field name
    };

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.log = log;
        this.maxDurationMs = maxDurationMs;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = this.startTimeMs;
        this.executionCount = 0;
        this.bestInflatedBytes = 0;
        this.maxPlaintextLen = 0;
        this.savedCount = 0;

        // Seed: start with a single-byte plaintext
        byte[] seedPlain = new byte[]{0x00};
        corpus.add(new CorpusEntry(seedPlain, 0));
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset the agent counters before each execution
        InflateCounters.reset();

        // Generate new input via mutation
        currentPlaintext = generatePlaintext();

        // Encode to valid raw DEFLATE ([R45c])
        currentDeflateInput = compressToRawDeflate(currentPlaintext);

        // Ensure within max input size
        if (currentDeflateInput.length > maxInputSize) {
            // Truncate plaintext and retry
            int maxPlain = Math.max(1, currentPlaintext.length / 2);
            byte[] truncated = new byte[maxPlain];
            System.arraycopy(currentPlaintext, 0, truncated, 0, maxPlain);
            currentPlaintext = truncated;
            currentDeflateInput = compressToRawDeflate(currentPlaintext);

            // If still too large, reduce further
            while (currentDeflateInput.length > maxInputSize && maxPlain > 1) {
                maxPlain = maxPlain / 2;
                truncated = new byte[maxPlain];
                System.arraycopy(currentPlaintext, 0, truncated, 0, maxPlain);
                currentPlaintext = truncated;
                currentDeflateInput = compressToRawDeflate(currentPlaintext);
            }
        }

        return new ByteArrayInputStream(currentDeflateInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs > 0) {
            return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
        }
        return true; // infinite by default ([R8])
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        executionCount++;

        // Read signals from agent counters ([R26])
        long[] counters = InflateCounters.get();
        long inflatedBytes = counters[0];
        long inflateCallCount = counters[1];

        // Store for SignalSource — value of THIS execution only, not cumulative
        lastInflatedBytes = (double) inflatedBytes;
        lastInflateCallCount = (double) inflateCallCount;

        // Retention: primary signal = inflatedBytes, secondary = plaintext growth ([R46])
        boolean retain = false;

        if (inflatedBytes > bestInflatedBytes) {
            bestInflatedBytes = inflatedBytes;
            retain = true;
        }

        if (currentPlaintext.length > maxPlaintextLen) {
            maxPlaintextLen = currentPlaintext.length;
            retain = true; // growth toward higher decompression output ([R46])
        }

        if (retain) {
            addToCorpus(currentPlaintext, inflatedBytes);
        }

        // Structured logging every 1 second ([R5])
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            long elapsedSec = (now - startTimeMs) / 1000;
            long execsPerSec = elapsedSec > 0 ? executionCount / elapsedSec : executionCount;
            log.printf("[V1] t=%ds | execs=%d (%d/s) | bestInflated=%d | corpus=%d | maxPlain=%d | lastInflated=%d%n",
                    elapsedSec, executionCount, execsPerSec, bestInflatedBytes,
                    corpus.size(), maxPlaintextLen, inflatedBytes);
            lastLogTimeMs = now;
        }

        // Note: Guidance never decides failures and never writes failure files ([R6])
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // We do not use JQF tracing — our signals come from the custom agent ([R43])
        return event -> {};
    }

    // --- SignalSource implementation ---

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        signals.put("inflatedBytes", lastInflatedBytes);
        signals.put("inflateCallCount", lastInflateCallCount);
        return signals;
    }

    // --- Plaintext generation and mutation ---

    private byte[] generatePlaintext() {
        if (corpus.isEmpty()) {
            return new byte[]{0x00};
        }

        // Select parent weighted by signal rank (higher inflatedBytes = higher priority)
        CorpusEntry parent = selectParent();
        byte[] plain = parent.plaintext.clone();

        // Apply mutations
        int mutationType = rng.nextInt(100);

        if (mutationType < 35) {
            // Repetition: whole-input doubling ([R45a]) — primary growth operator
            plain = doublePlaintext(plain);
        } else if (mutationType < 55) {
            // Repetition: chunk repeat ([R45a])
            plain = chunkRepeat(plain);
        } else if (mutationType < 70) {
            // Dictionary token insertion ([R45b])
            plain = dictionaryInsert(plain);
        } else if (mutationType < 85) {
            // Byte-level: random insert
            plain = randomInsert(plain);
        } else if (mutationType < 92) {
            // Byte-level: bit flip
            plain = bitFlip(plain);
        } else {
            // Byte-level: replace
            plain = randomReplace(plain);
        }

        return plain;
    }

    /** [R45a] Double the entire plaintext — maximizes compressibility and output growth. */
    private byte[] doublePlaintext(byte[] plain) {
        // Cap at a reasonable upper bound that still compresses within maxInputSize
        // DEFLATE can compress highly repetitive data at very high ratios,
        // so we can grow the plaintext quite large
        int maxPlainLen = 1024 * 1024; // 1MB of plaintext still compresses to ~1KB
        if (plain.length * 2 > maxPlainLen) {
            return plain;
        }
        byte[] doubled = new byte[plain.length * 2];
        System.arraycopy(plain, 0, doubled, 0, plain.length);
        System.arraycopy(plain, 0, doubled, plain.length, plain.length);
        return doubled;
    }

    /** [R45a] Select a chunk and repeat it k times. */
    private byte[] chunkRepeat(byte[] plain) {
        if (plain.length < 1) return plain;

        int chunkStart = rng.nextInt(plain.length);
        int chunkLen = 1 + rng.nextInt(Math.max(1, Math.min(plain.length - chunkStart, plain.length / 2)));
        int k = 2 + rng.nextInt(31); // k in [2, 32]

        int maxPlainLen = 1024 * 1024;
        int newLen = Math.min(plain.length + chunkLen * (k - 1), maxPlainLen);

        byte[] result = new byte[newLen];
        // Copy prefix
        System.arraycopy(plain, 0, result, 0, Math.min(chunkStart, newLen));
        // Repeat chunk
        int pos = chunkStart;
        for (int i = 0; i < k && pos + chunkLen <= newLen; i++) {
            System.arraycopy(plain, chunkStart, result, pos, chunkLen);
            pos += chunkLen;
        }
        // Copy remainder
        int afterChunk = chunkStart + chunkLen;
        if (afterChunk < plain.length && pos < newLen) {
            int toCopy = Math.min(plain.length - afterChunk, newLen - pos);
            System.arraycopy(plain, afterChunk, result, pos, toCopy);
        }
        return result;
    }

    /** [R45b] Insert a dictionary token at a random position. */
    private byte[] dictionaryInsert(byte[] plain) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = plain.length == 0 ? 0 : rng.nextInt(plain.length + 1);
        byte[] result = new byte[plain.length + token.length];
        System.arraycopy(plain, 0, result, 0, pos);
        System.arraycopy(token, 0, result, pos, token.length);
        if (pos < plain.length) {
            System.arraycopy(plain, pos, result, pos + token.length, plain.length - pos);
        }
        return result;
    }

    /** Byte-level: insert 1-4 random bytes. */
    private byte[] randomInsert(byte[] plain) {
        int count = 1 + rng.nextInt(4);
        int pos = plain.length == 0 ? 0 : rng.nextInt(plain.length + 1);
        byte[] insert = new byte[count];
        rng.nextBytes(insert);
        byte[] result = new byte[plain.length + count];
        System.arraycopy(plain, 0, result, 0, pos);
        System.arraycopy(insert, 0, result, pos, count);
        if (pos < plain.length) {
            System.arraycopy(plain, pos, result, pos + count, plain.length - pos);
        }
        return result;
    }

    /** Byte-level: flip a random bit. */
    private byte[] bitFlip(byte[] plain) {
        if (plain.length == 0) return plain;
        byte[] result = plain.clone();
        int byteIdx = rng.nextInt(result.length);
        int bitIdx = rng.nextInt(8);
        result[byteIdx] ^= (byte) (1 << bitIdx);
        return result;
    }

    /** Byte-level: replace 1-4 bytes at a random position. */
    private byte[] randomReplace(byte[] plain) {
        if (plain.length == 0) return plain;
        byte[] result = plain.clone();
        int count = 1 + rng.nextInt(Math.min(4, result.length));
        int pos = rng.nextInt(result.length);
        for (int i = 0; i < count && pos + i < result.length; i++) {
            result[pos + i] = (byte) rng.nextInt(256);
        }
        return result;
    }

    /** [R45c] Compress plaintext to a valid raw DEFLATE stream using Deflater(true). */
    private byte[] compressToRawDeflate(byte[] plaintext) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater);
            dos.write(plaintext);
            dos.finish();
            dos.close();
            return baos.toByteArray();
        } catch (IOException e) {
            // Fallback: return a minimal valid deflate stream (empty)
            deflater.end();
            return new byte[]{0x03, 0x00}; // BFINAL=1, BTYPE=00 (stored), LEN=0, NLEN=0xFFFF
        } finally {
            deflater.end();
        }
    }

    /** Select a parent from the corpus weighted by rank (higher inflatedBytes = more likely). */
    private CorpusEntry selectParent() {
        if (corpus.size() == 1) {
            return corpus.get(0);
        }
        // Sort by signal (descending) and select weighted by rank
        // Higher-ranked (higher inflatedBytes) parents get more weight
        int totalWeight = corpus.size() * (corpus.size() + 1) / 2;
        int pick = rng.nextInt(totalWeight);
        int cumulative = 0;
        // Sort corpus by inflatedBytes descending for weighted selection
        List<CorpusEntry> sorted = new ArrayList<>(corpus);
        sorted.sort((a, b) -> Long.compare(b.inflatedBytes, a.inflatedBytes));
        for (int i = 0; i < sorted.size(); i++) {
            cumulative += (sorted.size() - i); // higher rank = more weight
            if (pick < cumulative) {
                return sorted.get(i);
            }
        }
        return sorted.get(0);
    }

    /** Add a new entry to the corpus, evicting the lowest-signal entry if full. */
    private void addToCorpus(byte[] plaintext, long inflatedBytes) {
        CorpusEntry entry = new CorpusEntry(plaintext.clone(), inflatedBytes);

        if (corpus.size() < MAX_CORPUS_SIZE) {
            corpus.add(entry);
        } else {
            // Evict the entry with the lowest signal
            int worstIdx = 0;
            long worstSignal = corpus.get(0).inflatedBytes;
            for (int i = 1; i < corpus.size(); i++) {
                if (corpus.get(i).inflatedBytes < worstSignal) {
                    worstSignal = corpus.get(i).inflatedBytes;
                    worstIdx = i;
                }
            }
            if (inflatedBytes > worstSignal) {
                corpus.set(worstIdx, entry);
            }
        }

        // Save to disk with metadata
        saveCorpusEntry(entry);
    }

    /** Save a corpus entry and its metadata sidecar. */
    private void saveCorpusEntry(CorpusEntry entry) {
        try {
            savedCount++;
            String baseName = String.format("input_%04d", savedCount);
            Path inputPath = corpusDir.toPath().resolve(baseName + ".bin");
            Path metaPath = corpusDir.toPath().resolve(baseName + ".json");

            // Save the DEFLATE-encoded input (what the fuzz test receives)
            byte[] deflateBytes = compressToRawDeflate(entry.plaintext);
            Files.write(inputPath, deflateBytes);

            // Save metadata
            String meta = String.format(
                    "{\"index\": %d, \"inflatedBytes\": %d, \"inflateCallCount\": %d, "
                    + "\"plaintextLen\": %d, \"deflateLen\": %d, \"timestamp\": %d}",
                    savedCount, entry.inflatedBytes, (long) lastInflateCallCount,
                    entry.plaintext.length, deflateBytes.length, System.currentTimeMillis());
            Files.writeString(metaPath, meta);
        } catch (IOException e) {
            // Non-fatal: log and continue
            log.println("[V1] Warning: could not save corpus entry: " + e.getMessage());
        }
    }

    /** Corpus entry: plaintext and the observed signal. */
    private static final class CorpusEntry {
        final byte[] plaintext;
        final long inflatedBytes;

        CorpusEntry(byte[] plaintext, long inflatedBytes) {
            this.plaintext = plaintext;
            this.inflatedBytes = inflatedBytes;
        }
    }
}
