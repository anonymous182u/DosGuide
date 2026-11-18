package com.vaadin.fuzz;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.validate.SignalSource;

/**
 * Cost-Gradient Guidance for V1: Vaadin v7 EmailValidator ReDoS.
 *
 * Signal: regexSteps — count of Pattern$Node.match() invocations,
 * measured by the RegexStepAgent java agent.
 *
 * Retention: maximize regexSteps (primary); favor longer inputs when
 * the signal is flat (secondary), ensuring growth toward input_bytes.
 *
 * Mutation: byte flip/insert/delete/overwrite, whole-input and chunk
 * repetition, dictionary insertion/overwrite using email-regex tokens.
 */
public final class V1Guidance implements Guidance, SignalSource {

    private static final String TARGET_ID = "V1";
    private static final int MAX_CORPUS_SIZE = 20;
    private static final byte[] SEED = "a@b.cc".getBytes(StandardCharsets.UTF_8);

    /** Dictionary tokens from the v7 regex on the attack path. */
    private static final byte[] DICT_TOKENS = {
        (byte) '@',  // 0x40 email separator
        (byte) '.',  // 0x2E domain label separator
        (byte) '-',  // 0x2D valid in domain [a-zA-Z0-9-]
        (byte) '+',  // 0x2B valid in local part
        (byte) '_',  // 0x5F valid in local part
        (byte) '\n', // 0x0A affects $ anchor behaviour
    };

    private final File outputDir;
    private final long maxDurationMs;
    private final PrintStream log;
    private final int maxInputSize;
    private final Random random;

    // Corpus: list of (input, regexSteps) pairs
    private final List<CorpusEntry> corpus = new ArrayList<>();

    // Execution state
    private long startTime;
    private long totalExecs;
    private long bestSteps;
    private long lastLogTimeMs;
    private byte[] currentInput;
    private long lastRegexSteps;
    private int savedCount;
    private boolean started;

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.outputDir = outputDir;
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.random = new Random();
        this.startTime = 0;
        this.totalExecs = 0;
        this.bestSteps = 0;
        this.lastLogTimeMs = 0;
        this.savedCount = 0;
        this.started = false;
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        if (!started) {
            started = true;
            startTime = System.currentTimeMillis();
            lastLogTimeMs = startTime;
        }

        // Reset the step counter before each execution
        RegexStepCounter.reset();

        // Generate the next input
        if (corpus.isEmpty()) {
            // First execution: use the seed (capped to maxInputSize)
            currentInput = Arrays.copyOf(SEED, Math.min(SEED.length, maxInputSize));
        } else {
            // Select a parent from the corpus and mutate it
            byte[] parent = selectParent();
            currentInput = mutate(parent);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (!started) return true; // Haven't started yet
        long elapsed = System.currentTimeMillis() - startTime;
        return elapsed < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        // Read the step count from the agent-instrumented counter
        lastRegexSteps = RegexStepCounter.get();
        totalExecs++;

        // Update corpus
        addToCorpus(currentInput, lastRegexSteps);

        // Track best
        if (lastRegexSteps > bestSteps) {
            bestSteps = lastRegexSteps;
        }

        // Log every 1 second
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            log.printf("[%s] execs=%d best_steps=%d corpus=%d max_len=%d elapsed=%.1fs%n",
                    TARGET_ID, totalExecs, bestSteps, corpus.size(),
                    getMaxCorpusLength(), (now - startTime) / 1000.0);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: we use the RegexStepAgent for measurement, not JQF tracing
        return event -> { };
    }

    @Override
    public Map<String, Double> lastSignals() {
        return Collections.singletonMap("regexSteps", (double) lastRegexSteps);
    }

    // ---- Corpus management ----

    private void addToCorpus(byte[] input, long steps) {
        CorpusEntry entry = new CorpusEntry(input.clone(), steps);

        if (corpus.size() < MAX_CORPUS_SIZE) {
            corpus.add(entry);
            saveEntry(entry);
            return;
        }

        // Find the worst entry (lowest steps, then shortest length)
        int worstIdx = 0;
        for (int i = 1; i < corpus.size(); i++) {
            if (isWorse(corpus.get(i), corpus.get(worstIdx))) {
                worstIdx = i;
            }
        }

        CorpusEntry worst = corpus.get(worstIdx);

        // Replace if the new entry is better
        if (isBetter(entry, worst)) {
            corpus.set(worstIdx, entry);
            saveEntry(entry);
        }
    }

    /** Returns true if a is strictly better than b. */
    private boolean isBetter(CorpusEntry a, CorpusEntry b) {
        if (a.steps != b.steps) return a.steps > b.steps;
        return a.input.length > b.input.length;
    }

    /** Returns true if a is strictly worse than b. */
    private boolean isWorse(CorpusEntry a, CorpusEntry b) {
        if (a.steps != b.steps) return a.steps < b.steps;
        return a.input.length < b.input.length;
    }

    private int getMaxCorpusLength() {
        int max = 0;
        for (CorpusEntry e : corpus) {
            if (e.input.length > max) max = e.input.length;
        }
        return max;
    }

    private byte[] selectParent() {
        return corpus.get(random.nextInt(corpus.size())).input;
    }

    private void saveEntry(CorpusEntry entry) {
        try {
            File corpusDir = new File(outputDir, "corpus");
            corpusDir.mkdirs();
            int id = savedCount++;
            Files.write(new File(corpusDir, String.format("id_%06d.bin", id)).toPath(), entry.input);
            String meta = String.format("steps=%d%nlength=%d%ntimestamp=%d%n",
                    entry.steps, entry.input.length, System.currentTimeMillis());
            Files.writeString(new File(corpusDir, String.format("id_%06d.meta", id)).toPath(), meta);
        } catch (IOException e) {
            // Ignore save errors — corpus saving is best-effort
        }
    }

    // ---- Mutation operators ----

    private byte[] mutate(byte[] parent) {
        byte[] result = parent.clone();
        int numMutations = 1 + random.nextInt(2); // 1-2 mutations per round

        for (int i = 0; i < numMutations; i++) {
            int op = random.nextInt(10);
            switch (op) {
                case 0:            result = mutateBitFlip(result); break;
                case 1:            result = mutateByteInsert(result); break;
                case 2:            result = mutateByteDelete(result); break;
                case 3:            result = mutateByteOverwrite(result); break;
                case 4: case 5: case 6: result = mutateRepetition(result); break;
                case 7: case 8:    result = mutateDictInsert(result); break;
                case 9:            result = mutateDictOverwrite(result); break;
            }
        }

        // Enforce size limit
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        // Never produce empty input
        if (result.length == 0) {
            result = new byte[]{ (byte) 'a' };
        }
        return result;
    }

    private byte[] mutateBitFlip(byte[] input) {
        if (input.length == 0) return input;
        byte[] out = input.clone();
        int pos = random.nextInt(out.length);
        out[pos] ^= (byte) (1 << random.nextInt(8));
        return out;
    }

    private byte[] mutateByteInsert(byte[] input) {
        if (input.length >= maxInputSize) return input;
        int pos = random.nextInt(input.length + 1);
        byte[] out = new byte[input.length + 1];
        System.arraycopy(input, 0, out, 0, pos);
        out[pos] = (byte) random.nextInt(256);
        System.arraycopy(input, pos, out, pos + 1, input.length - pos);
        return out;
    }

    private byte[] mutateByteDelete(byte[] input) {
        if (input.length <= 1) return input;
        int pos = random.nextInt(input.length);
        byte[] out = new byte[input.length - 1];
        System.arraycopy(input, 0, out, 0, pos);
        System.arraycopy(input, pos + 1, out, pos, input.length - pos - 1);
        return out;
    }

    private byte[] mutateByteOverwrite(byte[] input) {
        if (input.length == 0) return input;
        byte[] out = input.clone();
        int pos = random.nextInt(out.length);
        out[pos] = (byte) random.nextInt(256);
        return out;
    }

    /**
     * Repetition operator (R45a): 50% whole-input doubling, 50% chunk repetition.
     * Grows input toward maxInputSize in a few steps.
     */
    private byte[] mutateRepetition(byte[] input) {
        if (input.length == 0 || input.length >= maxInputSize) return input;

        if (random.nextBoolean()) {
            // Whole-input doubling
            int newLen = Math.min(input.length * 2, maxInputSize);
            byte[] out = new byte[newLen];
            int pos = 0;
            while (pos < newLen) {
                int toCopy = Math.min(input.length, newLen - pos);
                System.arraycopy(input, 0, out, pos, toCopy);
                pos += toCopy;
            }
            return out;
        } else {
            // Chunk repetition: pick a random chunk, repeat it in place
            int start = random.nextInt(input.length);
            int chunkEnd = start + 1 + random.nextInt(
                    Math.max(1, Math.min(input.length - start, input.length / 2)));
            if (chunkEnd > input.length) chunkEnd = input.length;
            int chunkLen = chunkEnd - start;

            int prefixLen = start;
            int suffixLen = input.length - chunkEnd;
            int budget = maxInputSize - prefixLen - suffixLen;
            int k = Math.max(2, budget / chunkLen);

            int newLen = Math.min(prefixLen + chunkLen * k + suffixLen, maxInputSize);
            byte[] out = new byte[newLen];
            int pos = 0;

            // Prefix
            int pCopy = Math.min(prefixLen, newLen);
            System.arraycopy(input, 0, out, 0, pCopy);
            pos = pCopy;

            // Repeated chunk
            for (int i = 0; i < k && pos + chunkLen <= newLen; i++) {
                System.arraycopy(input, start, out, pos, chunkLen);
                pos += chunkLen;
            }

            // Suffix
            int sCopy = Math.min(suffixLen, newLen - pos);
            if (sCopy > 0) {
                System.arraycopy(input, chunkEnd, out, pos, sCopy);
                pos += sCopy;
            }

            return Arrays.copyOf(out, pos);
        }
    }

    /** Dictionary insertion (R45b): insert a token from the regex source at a random position. */
    private byte[] mutateDictInsert(byte[] input) {
        if (input.length >= maxInputSize) return input;
        byte token = DICT_TOKENS[random.nextInt(DICT_TOKENS.length)];
        int pos = random.nextInt(input.length + 1);
        byte[] out = new byte[input.length + 1];
        System.arraycopy(input, 0, out, 0, pos);
        out[pos] = token;
        System.arraycopy(input, pos, out, pos + 1, input.length - pos);
        return out;
    }

    /** Dictionary overwrite (R45b): overwrite a byte with a token from the regex source. */
    private byte[] mutateDictOverwrite(byte[] input) {
        if (input.length == 0) return input;
        byte[] out = input.clone();
        int pos = random.nextInt(out.length);
        out[pos] = DICT_TOKENS[random.nextInt(DICT_TOKENS.length)];
        return out;
    }

    // ---- Inner class ----

    private static final class CorpusEntry {
        final byte[] input;
        final long steps;

        CorpusEntry(byte[] input, long steps) {
            this.input = input;
            this.steps = steps;
        }
    }
}
