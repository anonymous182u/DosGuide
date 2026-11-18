package com.fuzzer.guidance;

import com.fuzzer.agent.V1Counters;
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
import java.nio.charset.StandardCharsets;
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
 * Cost-Gradient Guidance for V1: QuotedQualityCSV.sort() cubic-time DoS (CWE-407).
 *
 * Implements Guidance directly — does NOT extend ZestGuidance or any other.
 * Implements SignalSource for DoSGuide validation.
 *
 * Signal: sortComparisons — count of Double.compareTo calls in sort(), measured
 *         by V1MeasureAgent's bytecode instrumentation.
 *
 * Input model: byte[]/InputStream. The fuzz test decodes as ISO-8859-1.
 *
 * CSV-aware mutations: the guidance generates complete well-formed MIME value
 * constructs at all four specificity levels of MOST_SPECIFIC_MIME_ORDERING (0–3),
 * including short 1–2 byte values for maximum density. The dense pair generator
 * creates alternating patterns from random vocabulary pairs; hill-climbing on
 * sortComparisons naturally selects pairs with mixed specificity orders and
 * short values (highest density → most values → cubic comparisons).
 */
public class V1Guidance implements Guidance, SignalSource {

    // ----- Configuration -----
    private final int maxInputSize;
    private final File corpusDir;
    private final PrintStream log;
    private final long startTimeMs;
    private final long maxDurationMs; // 0 = infinite
    private final Random rng = new Random();

    // ----- Corpus -----
    private final List<byte[]> corpus = new ArrayList<>();
    private long bestSortComparisons = 0;
    private int bestInputLength = 0;

    // ----- Per-execution state -----
    private byte[] currentInput;
    private long lastSortComparisons = 0;
    private long totalExecs = 0;
    private long lastLogTimeMs;

    /**
     * MIME value vocabulary covering all 4 specificity levels of
     * MOST_SPECIFIC_MIME_ORDERING. Includes short (1–2 byte) values at
     * orders 2 and 3 to enable discovery of maximally dense inputs.
     *
     * Order 0: wildcard — equals "*&#47;*"
     * Order 1: wildcard subtype — ends with "/*"
     * Order 2: specific type — no semicolon, no wildcard pattern
     * Order 3: type with parameters — contains semicolon
     */
    private static final String[] MIME_VOCAB = {
        "*/*",               // order 0, 3 bytes
        "text/*",            // order 1, 6 bytes
        "image/*",           // order 1, 7 bytes
        "b/*",               // order 1, 3 bytes
        "b",                 // order 2, 1 byte
        "c",                 // order 2, 1 byte
        "text/html",         // order 2, 9 bytes
        "image/png",         // order 2, 9 bytes
        ";d",                // order 3, 2 bytes — short parameterized value
        ";e",                // order 3, 2 bytes
        ";f",                // order 3, 2 bytes
        ";g",                // order 3, 2 bytes
        "b;y",               // order 3, 3 bytes
        "c;z=1",             // order 3, 5 bytes
        "text/html;level=1", // order 3, 18 bytes
    };

    /** Byte-level dictionary tokens from the CSV format syntax. */
    private static final byte[][] DICTIONARY = {
        {0x2C},              // comma — value separator
        {0x3B},              // semicolon — param separator
        {0x3D},              // equals — param value separator
        {0x71},              // 'q' — quality param name
        {0x22},              // quote — quoted string delimiter
        {0x5C},              // backslash — escape character
        {0x09},              // tab — OWS character
    };

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.corpusDir = new File(outputDir, "V1/corpus");
        this.corpusDir.mkdirs();
        this.log = log;
        this.maxDurationMs = maxDurationMs;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = this.startTimeMs;

        // Seeds: ordinary Accept header values with multiple MIME types at
        // different specificity levels. Lower-specificity values placed first
        // to create inversions in the gnome sort, producing non-trivial sort
        // comparisons from the very first execution.
        corpus.add("text/*, text/html".getBytes(StandardCharsets.ISO_8859_1));
        corpus.add("*/*,text/html".getBytes(StandardCharsets.ISO_8859_1));
        corpus.add("text/html, text/html;level=1".getBytes(StandardCharsets.ISO_8859_1));
        corpus.add("*/*,text/*,text/html".getBytes(StandardCharsets.ISO_8859_1));
    }

    // ===== Guidance interface =====

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset the agent counter before each execution
        V1Counters.resetComparisons();

        // Pick a parent from corpus and mutate
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
        totalExecs++;

        // Read the signal from the agent counter
        lastSortComparisons = V1Counters.getComparisons();

        boolean retained = false;

        // Primary retention: signal improved — hill-climb toward cubic cost
        if (lastSortComparisons > bestSortComparisons) {
            bestSortComparisons = lastSortComparisons;
            retained = true;
        }

        // Secondary retention: grow inputs when signal is flat
        if (currentInput.length > bestInputLength) {
            bestInputLength = currentInput.length;
            retained = true;
        }

        // Probabilistic retention for diversity (non-zero signal)
        if (!retained && lastSortComparisons > 0 && rng.nextDouble() < 0.05) {
            retained = true;
        }

        if (retained) {
            byte[] saved = Arrays.copyOf(currentInput, currentInput.length);
            corpus.add(saved);
            saveToCorpus(saved);
        }

        // Structured logging every 1 second
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            lastLogTimeMs = now;
            long elapsed = (now - startTimeMs) / 1000;
            log.printf("[V1] %ds | execs=%d | corpus=%d | bestComparisons=%d | bestLen=%d | lastComparisons=%d | lastLen=%d%n",
                    elapsed, totalExecs, corpus.size(), bestSortComparisons,
                    bestInputLength, lastSortComparisons,
                    currentInput != null ? currentInput.length : 0);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // We use bytecode instrumentation via V1MeasureAgent, not JQF tracing.
        return event -> { };
    }

    // ===== SignalSource interface =====

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        signals.put("sortComparisons", (double) lastSortComparisons);
        return signals;
    }

    // ===== Mutation operators =====

    /**
     * Mutate a parent input. Uses a mix of:
     *   - Dense pair generator: creates fresh alternating MIME value patterns
     *     from vocabulary pairs, enabling discovery of max-density inputs
     *   - CSV-structure-aware operators: value insert, tile, replace
     *   - Byte-level operators: repetition, dictionary, flip, insert, delete
     *
     * Weights:
     *   25% densePair       — fresh alternating patterns from random vocab pairs
     *   15% csvTile          — repeat existing CSV to grow it
     *   15% csvValueInsert   — insert a complete MIME value at a CSV boundary
     *    5% csvReplace       — replace a random segment with a MIME value
     *   10% repetition       — byte-level chunk repetition
     *   10% dictionaryInsert — single token byte insert
     *    8% byteFlip         — flip a random bit
     *    6% byteInsert       — insert a random byte
     *    6% byteDelete       — delete a random byte
     */
    private byte[] mutate(byte[] parent) {
        double choice = rng.nextDouble();

        byte[] result;
        if (choice < 0.25) {
            result = mutateDensePair(parent);
        } else if (choice < 0.40) {
            result = mutateCsvTile(parent);
        } else if (choice < 0.55) {
            result = mutateCsvValueInsert(parent);
        } else if (choice < 0.60) {
            result = mutateCsvReplace(parent);
        } else if (choice < 0.70) {
            result = mutateRepetition(parent);
        } else if (choice < 0.80) {
            result = mutateDictionaryInsert(parent);
        } else if (choice < 0.88) {
            result = mutateByteFlip(parent);
        } else if (choice < 0.94) {
            result = mutateByteInsert(parent);
        } else {
            result = mutateByteDelete(parent);
        }

        // Enforce max input size — truncate at last comma to keep values intact
        if (result.length > maxInputSize) {
            result = truncateAtComma(result, maxInputSize);
        }
        // Ensure non-empty
        if (result.length == 0) {
            result = "b".getBytes(StandardCharsets.ISO_8859_1);
        }
        return result;
    }

    /**
     * Truncate byte array at the last comma before maxLen to avoid
     * garbled partial values at the end.
     */
    private byte[] truncateAtComma(byte[] data, int maxLen) {
        if (data.length <= maxLen) return data;
        int lastComma = -1;
        for (int i = maxLen - 1; i >= maxLen / 2; i--) {
            if (data[i] == 0x2C) { // comma
                lastComma = i;
                break;
            }
        }
        int cutAt = lastComma > 0 ? lastComma : maxLen;
        return Arrays.copyOf(data, cutAt);
    }

    // ----- Dense pair generator -----

    /**
     * Dense pair: pick two random MIME values from the vocabulary and create
     * an alternating pattern "v1,v2,v1,v2,..." up to a random target size.
     *
     * This generator explores ALL combinations of specificity levels. The
     * hill-climbing on sortComparisons naturally selects:
     * 1. Mixed-order pairs (creates inversions → swaps → cubic comparisons)
     * 2. Short values (higher density → more values per byte → more comparisons)
     *
     * The specific attack pair emerges from the search, not from hard-coding.
     */
    private byte[] mutateDensePair(byte[] parent) {
        String v1 = MIME_VOCAB[rng.nextInt(MIME_VOCAB.length)];
        String v2 = MIME_VOCAB[rng.nextInt(MIME_VOCAB.length)];

        // Target size: random within [maxInputSize/4 .. min(maxInputSize, 6000)]
        // Capped at 6000 to keep execution time manageable (~15s at max density)
        int upperBound = Math.min(maxInputSize, 6000);
        int lowerBound = Math.max(4, maxInputSize / 4);
        lowerBound = Math.min(lowerBound, upperBound);
        int targetSize;
        if (upperBound <= lowerBound) {
            targetSize = upperBound;
        } else {
            targetSize = lowerBound + rng.nextInt(upperBound - lowerBound + 1);
        }

        // Build alternating pattern
        int pairBytes = v1.length() + 1 + v2.length() + 1; // "v1,v2,"
        StringBuilder sb = new StringBuilder(targetSize + pairBytes);
        while (sb.length() + v1.length() + 1 + v2.length() <= targetSize) {
            if (sb.length() > 0) sb.append(',');
            sb.append(v1);
            sb.append(',');
            sb.append(v2);
        }
        // Fit one more v1 if space allows
        if (sb.length() > 0 && sb.length() + 1 + v1.length() <= targetSize) {
            sb.append(',');
            sb.append(v1);
        }
        if (sb.length() == 0) {
            sb.append(v1);
        }

        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    // ----- CSV-structure-aware mutations -----

    /**
     * CSV value insert: split input on commas, insert a complete MIME value
     * from the vocabulary at a random position, rejoin with commas.
     */
    private byte[] mutateCsvValueInsert(byte[] parent) {
        String s = new String(parent, StandardCharsets.ISO_8859_1);
        String newVal = MIME_VOCAB[rng.nextInt(MIME_VOCAB.length)];

        String[] parts = s.split(",", -1);
        List<String> list = new ArrayList<>(Arrays.asList(parts));
        list.add(rng.nextInt(list.size() + 1), newVal);
        return String.join(",", list).getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * CSV tile: repeat the entire comma-separated input N times, rapidly
     * growing the number of values toward the input size limit. Preserves
     * whatever pattern the current input has.
     */
    private byte[] mutateCsvTile(byte[] parent) {
        if (parent.length == 0) return parent;
        String s = new String(parent, StandardCharsets.ISO_8859_1);

        int tileUnit = s.length() + 1; // +1 for joining comma
        int maxTiles = Math.max(2, maxInputSize / Math.max(1, tileUnit));
        int tiles = 2 + rng.nextInt(Math.min(maxTiles, 256));

        StringBuilder sb = new StringBuilder(Math.min(maxInputSize + 100, tileUnit * tiles));
        sb.append(s);
        for (int i = 1; i < tiles && sb.length() + tileUnit <= maxInputSize + 100; i++) {
            sb.append(',');
            sb.append(s);
        }

        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * CSV replace: replace a random comma-separated segment with a MIME
     * value from the vocabulary. Can change specificity order and density.
     */
    private byte[] mutateCsvReplace(byte[] parent) {
        String s = new String(parent, StandardCharsets.ISO_8859_1);
        String[] parts = s.split(",", -1);
        if (parts.length == 0) return parent;

        parts[rng.nextInt(parts.length)] = MIME_VOCAB[rng.nextInt(MIME_VOCAB.length)];
        return String.join(",", parts).getBytes(StandardCharsets.ISO_8859_1);
    }

    // ----- Byte-level mutations -----

    /**
     * Repetition: copy a random chunk and repeat it k times.
     */
    private byte[] mutateRepetition(byte[] parent) {
        if (parent.length == 0) return parent;

        int chunkStart = rng.nextInt(parent.length);
        int maxChunkLen = Math.max(1, Math.min(parent.length - chunkStart, parent.length / 2));
        int chunkLen = 1 + rng.nextInt(maxChunkLen);

        int maxRepeats = Math.max(2, maxInputSize / Math.max(1, chunkLen));
        int repeats = 2 + rng.nextInt(Math.min(maxRepeats, 64));

        byte[] chunk = Arrays.copyOfRange(parent, chunkStart, chunkStart + chunkLen);

        int prefixLen = chunkStart;
        int suffixStart = chunkStart + chunkLen;
        int suffixLen = parent.length - suffixStart;
        int totalLen = Math.min(prefixLen + chunkLen * repeats + suffixLen, maxInputSize);

        byte[] result = new byte[totalLen];
        int pos = 0;
        int copyLen = Math.min(prefixLen, totalLen);
        System.arraycopy(parent, 0, result, 0, copyLen);
        pos += copyLen;

        for (int i = 0; i < repeats && pos < totalLen; i++) {
            int toCopy = Math.min(chunkLen, totalLen - pos);
            System.arraycopy(chunk, 0, result, pos, toCopy);
            pos += toCopy;
        }

        if (pos < totalLen && suffixLen > 0) {
            int toCopy = Math.min(suffixLen, totalLen - pos);
            System.arraycopy(parent, suffixStart, result, pos, toCopy);
        }

        return result;
    }

    /**
     * Dictionary insert: insert a token from the CSV format syntax
     * at a random position.
     */
    private byte[] mutateDictionaryInsert(byte[] parent) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[Math.min(parent.length + token.length, maxInputSize)];

        int copyLen = Math.min(pos, result.length);
        System.arraycopy(parent, 0, result, 0, copyLen);

        int tokenCopy = Math.min(token.length, result.length - copyLen);
        if (tokenCopy > 0) {
            System.arraycopy(token, 0, result, copyLen, tokenCopy);
        }

        int remaining = result.length - copyLen - tokenCopy;
        if (remaining > 0 && pos < parent.length) {
            System.arraycopy(parent, pos, result, copyLen + tokenCopy, remaining);
        }

        return result;
    }

    /** Byte flip: flip a random bit in a random byte. */
    private byte[] mutateByteFlip(byte[] parent) {
        byte[] result = parent.clone();
        if (result.length == 0) return result;
        int idx = rng.nextInt(result.length);
        result[idx] ^= (byte) (1 << rng.nextInt(8));
        return result;
    }

    /** Byte insert: insert a random byte at a random position. */
    private byte[] mutateByteInsert(byte[] parent) {
        if (parent.length >= maxInputSize) return parent.clone();
        byte[] result = new byte[parent.length + 1];
        int pos = rng.nextInt(parent.length + 1);
        System.arraycopy(parent, 0, result, 0, pos);
        result[pos] = (byte) rng.nextInt(256);
        System.arraycopy(parent, pos, result, pos + 1, parent.length - pos);
        return result;
    }

    /** Byte delete: remove a random byte. */
    private byte[] mutateByteDelete(byte[] parent) {
        if (parent.length <= 1) return parent.clone();
        byte[] result = new byte[parent.length - 1];
        int pos = rng.nextInt(parent.length);
        System.arraycopy(parent, 0, result, 0, pos);
        System.arraycopy(parent, pos + 1, result, pos, parent.length - pos - 1);
        return result;
    }

    // ===== Corpus persistence =====

    private int savedCount = 0;

    private void saveToCorpus(byte[] input) {
        try {
            int id = savedCount++;
            Path inputPath = corpusDir.toPath().resolve("id_" + String.format("%06d", id) + ".bin");
            Files.write(inputPath, input);

            Path metaPath = corpusDir.toPath().resolve("id_" + String.format("%06d", id) + ".meta");
            String meta = String.format(
                    "{\"id\":%d,\"sortComparisons\":%d,\"inputLength\":%d,\"timestamp\":%d}",
                    id, lastSortComparisons, input.length, System.currentTimeMillis());
            Files.writeString(metaPath, meta);
        } catch (IOException e) {
            // Non-fatal: corpus save failure doesn't stop fuzzing
        }
    }
}
