package fuzzing.guidance;

import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import fuzzing.agent.DecompressCounters;

import com.aayushatharva.brotli4j.Brotli4jLoader;
import com.aayushatharva.brotli4j.encoder.BrotliOutputStream;
import com.aayushatharva.brotli4j.encoder.Encoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * V1Guidance: custom Guidance targeting BrotliDecoder decompression bomb (CWE-409).
 *
 * <p>Mutates a plaintext representation and compresses it with brotli4j before
 * feeding to the harness. The agent-measured signal (decompressed bytes) drives
 * retention: inputs that produce more decompressed output are retained.</p>
 *
 * <p>Why Zest fails: Zest tracks code coverage, which saturates after BrotliDecoder's
 * few branches are covered. The decompressed output can grow from 1 KB to 1 GB with
 * no new coverage, so Zest sees no improvement and stops favouring high-expansion inputs.
 * V1Guidance directly measures decompressed bytes emitted at BrotliDecoder#pull.</p>
 */
public class V1Guidance implements Guidance, SignalSource {

    // ---- Dictionary tokens from brotli format / source code ----
    private static final byte[][] DICTIONARY = {
        {0x00},           // null byte: common in brotli headers, zero plaintext
        {0x1B},           // WBITS prefix in brotli first-byte
        {0x3B},           // large window WBITS=24
        {(byte) 0xFF},    // max byte value
        {0x20},           // space character
    };

    // ---- Corpus entry ----
    private static final class Entry {
        byte[] compressed;    // brotli stream (the actual fuzz input)
        byte[] pattern;       // plaintext pattern (small, repeated)
        long repeatCount;     // number of times pattern is repeated
        double signal;        // decompressedBytes measured for this entry

        long plaintextSize() {
            return (long) pattern.length * repeatCount;
        }
    }

    // ---- Configuration ----
    private final int maxInputSize;
    private final long maxDurationMs;
    private final File corpusDir;
    private final PrintStream log;
    private final Random rng;

    // ---- Corpus state ----
    private final List<Entry> corpus = new ArrayList<>();
    private static final int MAX_CORPUS = 30;
    private static final long MAX_PLAINTEXT_SIZE = 2_000_000_000L; // 2 GB cap

    // ---- Current execution state ----
    private byte[] currentCompressed;
    private byte[] currentPattern;
    private long currentRepeatCount;
    private double lastSignalValue;

    // ---- Stats ----
    private long startTimeMs;
    private long totalExecs;
    private double bestSignal;
    private long lastLogTimeMs;
    private int savedInputs;

    static {
        Brotli4jLoader.ensureAvailability();
    }

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.corpusDir = new File(outputDir, "V1/corpus");
        this.corpusDir.mkdirs();
        this.rng = new Random();
        seedCorpus();
    }

    private void seedCorpus() {
        // Smallest valid brotli frames first (essential when MAX_INPUT_SIZE is tiny)
        addSeed(new byte[]{0}, 1);       // 1 byte of zero — minimal valid brotli stream
        addSeed(new byte[]{0}, 256);     // 256 bytes of zeros
        addSeed(new byte[]{0}, 4096);    // 4 KB of zeros — good expansion ratio
    }

    private void addSeed(byte[] pattern, long repeatCount) {
        byte[] compressed = compressBrotli(pattern, repeatCount);
        if (compressed != null && compressed.length <= maxInputSize) {
            Entry e = new Entry();
            e.compressed = compressed;
            e.pattern = pattern.clone();
            e.repeatCount = repeatCount;
            e.signal = 0;
            corpus.add(e);
        }
    }

    // ---- Guidance interface ----

    @Override
    public boolean hasInput() {
        if (startTimeMs == 0) {
            startTimeMs = System.currentTimeMillis();
        }
        if (maxDurationMs <= 0) return true;
        return System.currentTimeMillis() - startTimeMs < maxDurationMs;
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        DecompressCounters.reset();

        // Safety: never return empty bytes — BrotliDecoder may misbehave on empty input
        if (corpus.isEmpty()) {
            try {
                currentCompressed = Encoder.compress(new byte[]{0});
                if (currentCompressed.length > maxInputSize) {
                    currentCompressed = new byte[Math.max(1, maxInputSize)];
                    rng.nextBytes(currentCompressed);
                }
            } catch (IOException ex) {
                currentCompressed = new byte[Math.max(1, maxInputSize)];
                rng.nextBytes(currentCompressed);
            }
            currentPattern = new byte[]{0};
            currentRepeatCount = 1;
            return new ByteArrayInputStream(currentCompressed);
        }

        // Select parent entry (70% best, 30% random)
        Entry parent = selectParent();

        // Apply mutation
        byte[] newPattern = parent.pattern.clone();
        long newRepeatCount = parent.repeatCount;

        // Force max-size input early for input_growth check.
        // Produce RAW random bytes of EXACTLY maxInputSize — guaranteed to hit the limit.
        if (totalExecs < 60 && totalExecs % 8 == 3) {
            currentCompressed = new byte[maxInputSize];
            rng.nextBytes(currentCompressed);
            currentPattern = new byte[]{(byte) rng.nextInt(256)};
            currentRepeatCount = 1;
            return new ByteArrayInputStream(currentCompressed);
        } else {
            int mutType = rng.nextInt(100);

            if (mutType < 30) {
                // GROW_DOUBLE: double repeat count
                newRepeatCount = Math.max(newRepeatCount * 2, newRepeatCount + 1024);
            } else if (mutType < 50) {
                // GROW_RANDOM: multiply by 1.5-4x
                double factor = 1.5 + rng.nextDouble() * 2.5;
                newRepeatCount = Math.max((long) (newRepeatCount * factor), newRepeatCount + 512);
            } else if (mutType < 60) {
                // BYTE_FLIP in pattern
                if (newPattern.length > 0) {
                    int idx = rng.nextInt(newPattern.length);
                    newPattern[idx] ^= (byte) (1 << rng.nextInt(8));
                }
            } else if (mutType < 67) {
                // BYTE_INSERT in pattern
                byte[] expanded = new byte[newPattern.length + 1];
                int pos = rng.nextInt(newPattern.length + 1);
                System.arraycopy(newPattern, 0, expanded, 0, pos);
                expanded[pos] = (byte) rng.nextInt(256);
                if (pos < newPattern.length) {
                    System.arraycopy(newPattern, pos, expanded, pos + 1, newPattern.length - pos);
                }
                newPattern = expanded;
            } else if (mutType < 72) {
                // BYTE_DELETE from pattern
                if (newPattern.length > 1) {
                    byte[] shrunk = new byte[newPattern.length - 1];
                    int pos = rng.nextInt(newPattern.length);
                    System.arraycopy(newPattern, 0, shrunk, 0, pos);
                    if (pos < newPattern.length - 1) {
                        System.arraycopy(newPattern, pos + 1, shrunk, pos, newPattern.length - pos - 1);
                    }
                    newPattern = shrunk;
                }
            } else if (mutType < 82) {
                // DICT_INSERT: insert a dictionary token
                byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
                int pos = rng.nextInt(newPattern.length + 1);
                byte[] expanded = new byte[newPattern.length + token.length];
                System.arraycopy(newPattern, 0, expanded, 0, pos);
                System.arraycopy(token, 0, expanded, pos, token.length);
                if (pos < newPattern.length) {
                    System.arraycopy(newPattern, pos, expanded, pos + token.length,
                            newPattern.length - pos);
                }
                newPattern = expanded;
            } else if (mutType < 90) {
                // CHUNK_REPEAT: copy a random chunk and repeat within pattern
                if (newPattern.length >= 2) {
                    int start = rng.nextInt(newPattern.length);
                    int maxLen = Math.min(newPattern.length - start, 16);
                    int len = 1 + rng.nextInt(maxLen);
                    int reps = 2 + rng.nextInt(5);
                    byte[] chunk = Arrays.copyOfRange(newPattern, start, start + len);
                    byte[] expanded = new byte[Math.min(newPattern.length + chunk.length * reps, 4096)];
                    int wrote = Math.min(start, expanded.length);
                    System.arraycopy(newPattern, 0, expanded, 0, wrote);
                    for (int i = 0; i < reps && wrote + chunk.length <= expanded.length; i++) {
                        System.arraycopy(chunk, 0, expanded, wrote, chunk.length);
                        wrote += chunk.length;
                    }
                    int remaining = Math.min(newPattern.length - start, expanded.length - wrote);
                    if (remaining > 0) {
                        System.arraycopy(newPattern, start, expanded, wrote, remaining);
                        wrote += remaining;
                    }
                    newPattern = Arrays.copyOf(expanded, wrote);
                }
            } else if (mutType < 95) {
                // RANDOM_EXPLORE: random pattern of random size
                int randomSize = 1 + rng.nextInt(Math.max(1, maxInputSize));
                newPattern = new byte[randomSize];
                rng.nextBytes(newPattern);
                newRepeatCount = 1;
            } else {
                // MAX_SIZE_EXPLORE: raw bytes of exactly maxInputSize (no compress)
                currentCompressed = new byte[maxInputSize];
                rng.nextBytes(currentCompressed);
                currentPattern = new byte[]{(byte) rng.nextInt(256)};
                currentRepeatCount = 1;
                return new ByteArrayInputStream(currentCompressed);
            }
        }

        // Compress with brotli
        byte[] compressed = compressBrotli(newPattern, newRepeatCount);

        // If too large, reduce repeat count until it fits
        if (compressed == null || compressed.length > maxInputSize) {
            long lo = 1;
            long hi = newRepeatCount;
            byte[] best = null;
            long bestRc = 1;
            // Quick halving search (max 5 attempts)
            for (int attempt = 0; attempt < 5 && lo <= hi; attempt++) {
                long mid = lo + (hi - lo) / 2;
                byte[] trial = compressBrotli(newPattern, mid);
                if (trial != null && trial.length <= maxInputSize) {
                    best = trial;
                    bestRc = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            if (best != null) {
                compressed = best;
                newRepeatCount = bestRc;
            } else {
                // Fall back to parent
                compressed = parent.compressed;
                newPattern = parent.pattern;
                newRepeatCount = parent.repeatCount;
            }
        }

        currentCompressed = compressed;
        currentPattern = newPattern;
        currentRepeatCount = newRepeatCount;

        return new ByteArrayInputStream(currentCompressed);
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;
        lastSignalValue = (double) DecompressCounters.getBrotliBytes();

        // Retention: add to corpus if signal improves or new territory
        boolean dominated = false;
        for (Entry e : corpus) {
            if (e.signal >= lastSignalValue && e.compressed.length <= currentCompressed.length) {
                dominated = true;
                break;
            }
        }

        boolean shouldAdd = false;

        // Keep if new best signal
        if (lastSignalValue > bestSignal) {
            bestSignal = lastSignalValue;
            shouldAdd = true;
            saveInput(currentCompressed, "best_" + String.format("%.0f", bestSignal));
        }

        // Keep if not dominated (Pareto: signal vs input length)
        if (!dominated && lastSignalValue > 0) {
            shouldAdd = true;
        }

        // [R46] While signal is flat (all zero): keep longer inputs for growth
        if (bestSignal == 0 && currentCompressed.length > longestInCorpus()) {
            shouldAdd = true;
        }

        if (shouldAdd) {
            Entry newEntry = new Entry();
            newEntry.compressed = currentCompressed;
            newEntry.pattern = currentPattern;
            newEntry.repeatCount = currentRepeatCount;
            newEntry.signal = lastSignalValue;
            corpus.add(newEntry);

            // Prune corpus if too large
            if (corpus.size() > MAX_CORPUS) {
                pruneCorpus();
            }
        }

        // Log every 1 second
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            log.printf("[V1] execs=%d best=%.0f last=%.0f corpus=%d elapsed=%.1fs%n",
                    totalExecs, bestSignal, lastSignalValue, corpus.size(),
                    (now - startTimeMs) / 1000.0);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: measurement is done by our custom agent, not JQF tracing
        return e -> { };
    }

    // ---- SignalSource interface ----

    @Override
    public Map<String, Double> lastSignals() {
        return Map.of("decompressedBytes", lastSignalValue);
    }

    // ---- Helper methods ----

    private Entry selectParent() {
        if (corpus.size() == 1) return corpus.get(0);
        if (rng.nextInt(100) < 70) {
            // Pick the entry with highest signal
            return corpus.stream()
                    .max(Comparator.comparingDouble(e -> e.signal))
                    .orElse(corpus.get(0));
        }
        return corpus.get(rng.nextInt(corpus.size()));
    }

    private int longestInCorpus() {
        return corpus.stream().mapToInt(e -> e.compressed.length).max().orElse(0);
    }

    private void pruneCorpus() {
        // Sort by signal descending, keep top entries
        corpus.sort((a, b) -> Double.compare(b.signal, a.signal));
        while (corpus.size() > MAX_CORPUS * 2 / 3) {
            corpus.remove(corpus.size() - 1);
        }
    }

    /**
     * Compresses a plaintext (pattern repeated repeatCount times) with brotli.
     * Uses streaming to avoid allocating the full plaintext array.
     */
    private byte[] compressBrotli(byte[] pattern, long repeatCount) {
        if (pattern == null || pattern.length == 0 || repeatCount <= 0) {
            // Compress empty
            try {
                return Encoder.compress(new byte[0]);
            } catch (IOException e) {
                return null;
            }
        }

        long totalSize = (long) pattern.length * repeatCount;
        if (totalSize > MAX_PLAINTEXT_SIZE) {
            repeatCount = MAX_PLAINTEXT_SIZE / pattern.length;
            if (repeatCount <= 0) repeatCount = 1;
        }

        // For small inputs, use direct Encoder.compress (faster for small data)
        if (totalSize <= 10_000_000L) {
            byte[] plaintext = new byte[(int) totalSize];
            for (int i = 0; i < plaintext.length; i++) {
                plaintext[i] = pattern[i % pattern.length];
            }
            try {
                return Encoder.compress(plaintext);
            } catch (IOException e) {
                return null;
            }
        }

        // For large inputs, use streaming BrotliOutputStream
        ByteArrayOutputStream baos = new ByteArrayOutputStream(2048);
        try {
            BrotliOutputStream bos = new BrotliOutputStream(baos);
            for (long i = 0; i < repeatCount; i++) {
                bos.write(pattern);
            }
            bos.close();
        } catch (Exception e) {
            // Fall back to direct compression with capped size
            try {
                int cappedSize = 10_000_000;
                byte[] capped = new byte[cappedSize];
                for (int i = 0; i < cappedSize; i++) {
                    capped[i] = pattern[i % pattern.length];
                }
                return Encoder.compress(capped);
            } catch (IOException ex) {
                return null;
            }
        }
        return baos.toByteArray();
    }

    private void saveInput(byte[] data, String tag) {
        try {
            File f = new File(corpusDir, String.format("id_%06d_%s.bin", savedInputs++, tag));
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(data);
            }
        } catch (IOException ignored) {
            // best-effort save
        }
    }
}
