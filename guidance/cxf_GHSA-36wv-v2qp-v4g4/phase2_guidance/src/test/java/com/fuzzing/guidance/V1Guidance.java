package com.fuzzing.guidance;

import com.fuzzing.agent.V1Counters;
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
 * Cost-Gradient Guidance for V1: Unbounded CachedOutputStream.toString() in cleaner log messages.
 *
 * Implements Guidance directly ([R3]). Tracks charsAppended signal from V1Counters ([R24]/[R30]).
 * Mutation: byte-level + repetition + dictionary ([R45]). Input model: raw bytes ([R31]).
 * Does NOT decide failures or write failure files ([R6]).
 */
public class V1Guidance implements Guidance, SignalSource {

    // --- Dictionary tokens from the code on the attack path [R45(b)] ---
    private static final byte[][] DICTIONARY = {
        {0x0A},                           // '\n' newline
        {0x0D},                           // '\r' carriage return
        {0x5B},                           // '[' from toString() bracket
        {0x5D},                           // ']' from toString() bracket
        "Content: ".getBytes(),           // toString() prefix
        "cos".getBytes(),                 // temp file prefix
        "tmp".getBytes(),                 // temp file suffix
    };

    private final File corpusDir;
    private final long deadlineMs;        // 0 = infinite
    private final int maxInputSize;
    private final PrintStream log;
    private final Random random = new Random();

    // Corpus: list of saved inputs
    private final List<byte[]> corpus = new ArrayList<>();

    // Current execution state
    private byte[] currentInput;
    private long lastCharsAppended;

    // Best-so-far tracking for retention
    private long bestCharsAppended;
    private int longestSaved;             // secondary criterion while signal is flat [R46]

    // Stats
    private long totalExecs;
    private long lastLogTimeMs;
    private long startTimeMs;

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream logOut) {
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.deadlineMs = maxDurationMs > 0 ? System.currentTimeMillis() + maxDurationMs : 0;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.log = logOut;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = this.startTimeMs;

        // Seed: a small buffer of 16 random bytes. The fuzzer will grow it.
        byte[] seed = new byte[16];
        random.nextBytes(seed);
        corpus.add(seed);
        longestSaved = seed.length;
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        V1Counters.reset();

        if (corpus.isEmpty()) {
            currentInput = new byte[16];
            random.nextBytes(currentInput);
        } else {
            // Pick a random corpus entry and mutate it
            byte[] parent = corpus.get(random.nextInt(corpus.size()));
            currentInput = mutate(parent);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (deadlineMs > 0 && System.currentTimeMillis() >= deadlineMs) {
            return false;
        }
        return true;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;
        lastCharsAppended = V1Counters.getCharsAppended();

        // Retention policy:
        // Primary: if charsAppended > bestCharsAppended => save
        // Secondary (flat signal): if charsAppended == 0 and input is longer than longestSaved => save [R46]
        boolean save = false;
        if (lastCharsAppended > bestCharsAppended) {
            bestCharsAppended = lastCharsAppended;
            save = true;
        } else if (lastCharsAppended == 0 && bestCharsAppended == 0
                   && currentInput.length > longestSaved) {
            longestSaved = currentInput.length;
            save = true;
        }

        if (save) {
            corpus.add(Arrays.copyOf(currentInput, currentInput.length));
            saveToCorpus(currentInput);
        }

        // Structured logging every 1 second [R5]
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            long elapsed = now - startTimeMs;
            double execsPerSec = totalExecs * 1000.0 / Math.max(1, elapsed);
            log.printf("[V1] %d ms | execs=%d | corpus=%d | best_chars=%d | longest=%d | eps=%.1f%n",
                       elapsed, totalExecs, corpus.size(), bestCharsAppended, longestSaved, execsPerSec);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // We use the javaagent for measurement, not trace events
        return (e) -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        signals.put("charsAppended", (double) lastCharsAppended);
        return signals;
    }

    // ======================== Mutation Operators ========================

    private byte[] mutate(byte[] parent) {
        // Choose a mutation operator
        int op = random.nextInt(100);
        byte[] result;
        if (op < 20) {
            result = mutateByteFlip(parent);
        } else if (op < 35) {
            result = mutateByteInsert(parent);
        } else if (op < 45) {
            result = mutateByteDelete(parent);
        } else if (op < 75) {
            result = mutateRepeat(parent);       // [R45(a)] — most common to grow input
        } else {
            result = mutateDictionaryInsert(parent); // [R45(b)]
        }
        // Enforce max input size
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    /** Flip a random byte. */
    private byte[] mutateByteFlip(byte[] parent) {
        if (parent.length == 0) return parent;
        byte[] result = Arrays.copyOf(parent, parent.length);
        int pos = random.nextInt(result.length);
        result[pos] = (byte) (result[pos] ^ (1 << random.nextInt(8)));
        return result;
    }

    /** Insert 1-8 random bytes at a random position. */
    private byte[] mutateByteInsert(byte[] parent) {
        int count = 1 + random.nextInt(8);
        int newLen = Math.min(parent.length + count, maxInputSize);
        count = newLen - parent.length;
        if (count <= 0) return Arrays.copyOf(parent, parent.length);

        byte[] result = new byte[newLen];
        int pos = random.nextInt(parent.length + 1);
        System.arraycopy(parent, 0, result, 0, pos);
        for (int i = 0; i < count; i++) {
            result[pos + i] = (byte) random.nextInt(256);
        }
        System.arraycopy(parent, pos, result, pos + count, parent.length - pos);
        return result;
    }

    /** Delete 1-8 bytes from a random position. */
    private byte[] mutateByteDelete(byte[] parent) {
        if (parent.length <= 1) return parent;
        int count = Math.min(1 + random.nextInt(8), parent.length - 1);
        int pos = random.nextInt(parent.length - count + 1);
        byte[] result = new byte[parent.length - count];
        System.arraycopy(parent, 0, result, 0, pos);
        System.arraycopy(parent, pos + count, result, pos, parent.length - pos - count);
        return result;
    }

    /**
     * Repetition [R45(a)]: select a random region and repeat it k times,
     * growing toward maxInputSize. Special case: double the entire input.
     */
    private byte[] mutateRepeat(byte[] parent) {
        if (parent.length == 0) {
            byte[] r = new byte[1];
            random.nextBytes(r);
            return r;
        }

        int start, len;
        if (random.nextInt(3) == 0) {
            // Double the entire input
            start = 0;
            len = parent.length;
        } else {
            // Pick a random region
            start = random.nextInt(parent.length);
            len = 1 + random.nextInt(Math.max(1, parent.length - start));
        }

        // How many times to repeat the region (fill up to maxInputSize)
        int available = maxInputSize - parent.length;
        if (available <= 0) {
            // Already at max; just return a copy
            return Arrays.copyOf(parent, parent.length);
        }
        int k = Math.min(1 + random.nextInt(Math.max(1, available / Math.max(1, len))), available / Math.max(1, len));
        if (k < 1) k = 1;

        int insertLen = Math.min(k * len, available);
        byte[] result = new byte[parent.length + insertLen];
        // Copy everything before the insertion point (after the region)
        int insertPos = start + len;
        System.arraycopy(parent, 0, result, 0, insertPos);
        // Insert the repeated region
        for (int i = 0; i < insertLen; i++) {
            result[insertPos + i] = parent[start + (i % len)];
        }
        // Copy the rest of the parent after the region
        int remaining = parent.length - insertPos;
        if (remaining > 0 && insertPos + insertLen + remaining <= result.length) {
            System.arraycopy(parent, insertPos, result, insertPos + insertLen, remaining);
        }
        return result;
    }

    /**
     * Dictionary insertion [R45(b)]: insert or overwrite a dictionary token at a random position.
     */
    private byte[] mutateDictionaryInsert(byte[] parent) {
        byte[] token = DICTIONARY[random.nextInt(DICTIONARY.length)];

        if (random.nextBoolean() && parent.length > 0) {
            // Overwrite at random position
            byte[] result = Arrays.copyOf(parent, parent.length);
            int pos = random.nextInt(result.length);
            int copyLen = Math.min(token.length, result.length - pos);
            System.arraycopy(token, 0, result, pos, copyLen);
            return result;
        } else {
            // Insert at random position
            int newLen = Math.min(parent.length + token.length, maxInputSize);
            int actualTokenLen = newLen - parent.length;
            if (actualTokenLen <= 0) return Arrays.copyOf(parent, parent.length);

            byte[] result = new byte[newLen];
            int pos = random.nextInt(parent.length + 1);
            System.arraycopy(parent, 0, result, 0, pos);
            System.arraycopy(token, 0, result, pos, actualTokenLen);
            System.arraycopy(parent, pos, result, pos + actualTokenLen, parent.length - pos);
            return result;
        }
    }

    // ======================== Corpus Persistence ========================

    private void saveToCorpus(byte[] input) {
        try {
            String name = String.format("id_%06d_%d.bin", totalExecs, input.length);
            Files.write(new File(corpusDir, name).toPath(), input);
        } catch (IOException e) {
            // best-effort
        }
    }
}
