package org.keycloak.fuzzing;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.validate.SignalSource;
import org.keycloak.fuzzing.agent.RegexStepCounter;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance (CGF) for V1: cubic ReDoS in
 * {@code SearchQueryUtils.queryPattern}.
 * <p>
 * Signal: {@code regexSteps} — total calls to {@code Pattern$Node.match()},
 * measured by the custom Java agent ({@link RegexStepCounter}).
 * <p>
 * Mutation: byte-level + repetition (doubling) + dictionary of tokens from
 * the regex pattern source.  Retention: favors higher step counts; secondary
 * criterion: longer inputs (growth while signal is flat, [R46]).
 * <p>
 * Never decides failures or writes failure files ([R6]).
 */
public class V1Guidance implements Guidance, SignalSource {

    // ── Configuration ──────────────────────────────────────────────────
    private final int maxInputSize;
    private final File corpusDir;
    private final long maxDurationMs;   // 0 = infinite
    private final PrintStream log;

    // ── State ──────────────────────────────────────────────────────────
    private final long startTimeMs;
    private int totalTrials;
    private long bestSteps;
    private int bestInputLen;
    private final List<byte[]> corpus = new ArrayList<>();
    private final List<Long> corpusSteps = new ArrayList<>();
    private final Random rng = new Random();

    private byte[] currentInput;
    private long lastLogMs;
    private double lastRegexSteps;      // for lastSignals()

    // ── Dictionary [R45(b)] ────────────────────────────────────────────
    // Tokens from SearchQueryUtils.queryPattern regex literal:
    //   \s*(?:(?<name>[^"][^: ]+|.)|"(?<nameEsc>(?:\\.|[^\\"])+)"):
    //   (?:(?<value>[^"][^ ]*)|"(?<valueEsc>(?:\\.|[^\\"])+)")\s*
    private static final byte[][] DICTIONARY = {
            {0x09},   // TAB    — matches \s AND [^: ] → cubic trigger
            {0x0B},   // VT     — same property
            {0x0C},   // FF     — same property
            {0x0D},   // CR     — same property
            {0x22},   // "      — quoted name/value delimiter
            {0x3A},   // :      — name:value separator
            {0x5C},   // \      — escape character
            {0x20},   // SPACE  — part of \s but excluded by [^: ]
    };

    private static final int MAX_CORPUS = 128;
    private static final int SEED_SIZE = 16;

    // ── Constructor ────────────────────────────────────────────────────
    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogMs = startTimeMs;
    }

    // ── Guidance interface ─────────────────────────────────────────────

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset counter before the execution.
        RegexStepCounter.getAndReset();

        if (corpus.isEmpty()) {
            // First trial: random seed.
            currentInput = new byte[SEED_SIZE];
            rng.nextBytes(currentInput);
        } else {
            // Pick a parent and mutate.
            int parentIdx = selectParent();
            byte[] parent = corpus.get(parentIdx);
            currentInput = mutate(parent);
        }
        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs > 0) {
            return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
        }
        return true; // infinite by default [R8]
    }

    @Override
    public void handleResult(Result result, Throwable error)
            throws GuidanceException {
        long steps = RegexStepCounter.get();
        lastRegexSteps = (double) steps;
        totalTrials++;

        // ── Retention decision ─────────────────────────────────
        boolean retain = false;

        // Primary: new best step count.
        if (steps > bestSteps) {
            bestSteps = steps;
            retain = true;
        }
        // Secondary ([R46]): grow toward input_bytes while signal is flat.
        if (currentInput.length > bestInputLen
                && currentInput.length <= maxInputSize) {
            bestInputLen = currentInput.length;
            retain = true;
        }
        // Always keep the first input (bootstrap the corpus).
        if (corpus.isEmpty()) {
            retain = true;
        }
        // Diversity: occasionally retain a random input.
        if (!retain && rng.nextInt(50) == 0) {
            retain = true;
        }

        if (retain) {
            byte[] copy = currentInput.clone();
            addToCorpus(copy, steps);
            saveToCorpus(copy, steps);
        }

        // ── Logging every 1 second [R5] ───────────────────────
        long now = System.currentTimeMillis();
        if (now - lastLogMs >= 1000) {
            log.printf("[V1] trials=%d corpus=%d bestSteps=%d bestLen=%d "
                            + "lastSteps=%d lastLen=%d elapsed=%.1fs%n",
                    totalTrials, corpus.size(), bestSteps, bestInputLen,
                    steps, currentInput.length,
                    (now - startTimeMs) / 1000.0);
            lastLogMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: measurement via custom agent, not JQF tracing [R43].
        return e -> { };
    }

    // ── SignalSource interface ──────────────────────────────────────────

    @Override
    public Map<String, Double> lastSignals() {
        return Collections.singletonMap("regexSteps", lastRegexSteps);
    }

    // ── Corpus management ──────────────────────────────────────────────

    private void addToCorpus(byte[] input, long steps) {
        if (corpus.size() < MAX_CORPUS) {
            corpus.add(input);
            corpusSteps.add(steps);
        } else {
            // Replace the entry with the lowest step count.
            int minIdx = 0;
            long minSteps = corpusSteps.get(0);
            for (int i = 1; i < corpusSteps.size(); i++) {
                if (corpusSteps.get(i) < minSteps) {
                    minSteps = corpusSteps.get(i);
                    minIdx = i;
                }
            }
            if (steps > minSteps || input.length > corpus.get(minIdx).length) {
                corpus.set(minIdx, input);
                corpusSteps.set(minIdx, steps);
            }
        }
    }

    private void saveToCorpus(byte[] input, long steps) {
        try {
            String name = String.format("id_%06d_steps_%d_len_%d.bin",
                    totalTrials, steps, input.length);
            Files.write(new File(corpusDir, name).toPath(), input);
        } catch (IOException e) {
            // Best-effort save; do not crash the guidance.
        }
    }

    // ── Parent selection ───────────────────────────────────────────────

    private int selectParent() {
        if (corpus.size() == 1) return 0;

        // Weight by step count; fall back to length when all steps are 0.
        long totalWeight = 0;
        for (int i = 0; i < corpus.size(); i++) {
            long w = corpusSteps.get(i);
            if (w <= 0) w = corpus.get(i).length;
            totalWeight += Math.max(w, 1);
        }
        long pick = rng.nextLong(totalWeight);
        long cumulative = 0;
        for (int i = 0; i < corpus.size(); i++) {
            long w = corpusSteps.get(i);
            if (w <= 0) w = corpus.get(i).length;
            cumulative += Math.max(w, 1);
            if (pick < cumulative) return i;
        }
        return corpus.size() - 1;
    }

    // ── Mutation [R45] ─────────────────────────────────────────────────

    private byte[] mutate(byte[] parent) {
        // Choose mutation operator.
        int choice = rng.nextInt(100);
        byte[] result;

        if (choice < 25) {
            // 25%: double the entire input (repetition [R45a]).
            result = doubleInput(parent);
        } else if (choice < 40) {
            // 15%: repeat a random chunk k times [R45a].
            result = chunkRepeat(parent);
        } else if (choice < 65) {
            // 25%: dictionary insertion [R45b].
            result = dictInsert(parent);
        } else if (choice < 80) {
            // 15%: random byte flip.
            result = byteFlip(parent);
        } else if (choice < 92) {
            // 12%: random byte insertion.
            result = byteInsert(parent);
        } else {
            // 8%: random byte deletion.
            result = byteDel(parent);
        }

        // Enforce size limit [R41].
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        // Ensure non-empty.
        if (result.length == 0) {
            result = new byte[]{DICTIONARY[rng.nextInt(DICTIONARY.length)][0]};
        }
        return result;
    }

    /** Double the entire input. */
    private byte[] doubleInput(byte[] src) {
        int newLen = Math.min(src.length * 2, maxInputSize);
        if (newLen <= src.length) return src.clone();
        byte[] out = new byte[newLen];
        System.arraycopy(src, 0, out, 0, src.length);
        System.arraycopy(src, 0, out, src.length,
                Math.min(src.length, newLen - src.length));
        return out;
    }

    /** Repeat a random chunk k times. */
    private byte[] chunkRepeat(byte[] src) {
        if (src.length < 2) return doubleInput(src);
        int start = rng.nextInt(src.length);
        int end = start + 1 + rng.nextInt(Math.max(1, src.length - start));
        if (end > src.length) end = src.length;
        int chunkLen = end - start;
        int maxK = Math.max(2, (maxInputSize - src.length) / chunkLen + 1);
        int k = 2 + rng.nextInt(Math.min(maxK, 16));
        int insertLen = chunkLen * k;
        int newLen = Math.min(src.length + insertLen, maxInputSize);

        byte[] out = new byte[newLen];
        // Copy prefix before the chunk.
        System.arraycopy(src, 0, out, 0, start);
        // Write the repeated chunk.
        int pos = start;
        for (int i = 0; i < k && pos < newLen; i++) {
            int toCopy = Math.min(chunkLen, newLen - pos);
            System.arraycopy(src, start, out, pos, toCopy);
            pos += toCopy;
        }
        // Copy suffix after the original chunk.
        int remaining = Math.min(src.length - end, newLen - pos);
        if (remaining > 0) {
            System.arraycopy(src, end, out, pos, remaining);
        }
        return out;
    }

    /** Insert a dictionary token at a random position. */
    private byte[] dictInsert(byte[] src) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = src.length == 0 ? 0 : rng.nextInt(src.length + 1);
        byte[] out = new byte[Math.min(src.length + token.length, maxInputSize)];
        System.arraycopy(src, 0, out, 0, Math.min(pos, out.length));
        int tokenCopy = Math.min(token.length, out.length - pos);
        if (tokenCopy > 0) {
            System.arraycopy(token, 0, out, pos, tokenCopy);
        }
        int suffixStart = pos + tokenCopy;
        int suffixLen = Math.min(src.length - pos, out.length - suffixStart);
        if (suffixLen > 0) {
            System.arraycopy(src, pos, out, suffixStart, suffixLen);
        }
        return out;
    }

    /** Flip a random bit in a random byte. */
    private byte[] byteFlip(byte[] src) {
        if (src.length == 0) return src.clone();
        byte[] out = src.clone();
        int pos = rng.nextInt(out.length);
        out[pos] ^= (byte) (1 << rng.nextInt(8));
        return out;
    }

    /** Insert a random byte at a random position. */
    private byte[] byteInsert(byte[] src) {
        int pos = src.length == 0 ? 0 : rng.nextInt(src.length + 1);
        byte[] out = new byte[Math.min(src.length + 1, maxInputSize)];
        System.arraycopy(src, 0, out, 0, Math.min(pos, out.length));
        if (pos < out.length) {
            out[pos] = (byte) rng.nextInt(256);
        }
        int suffixLen = Math.min(src.length - pos, out.length - pos - 1);
        if (suffixLen > 0) {
            System.arraycopy(src, pos, out, pos + 1, suffixLen);
        }
        return out;
    }

    /** Delete a random byte. */
    private byte[] byteDel(byte[] src) {
        if (src.length <= 1) return src.clone();
        int pos = rng.nextInt(src.length);
        byte[] out = new byte[src.length - 1];
        System.arraycopy(src, 0, out, 0, pos);
        System.arraycopy(src, pos + 1, out, pos, src.length - pos - 1);
        return out;
    }
}
