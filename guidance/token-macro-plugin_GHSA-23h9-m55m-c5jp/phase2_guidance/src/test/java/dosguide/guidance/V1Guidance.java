package dosguide.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.agent.V1Counter;
import dosguide.validate.SignalSource;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance for V1 — unbounded recursive token expansion
 * (CWE-674) in {@code Parser#processToken()}.
 *
 * <p>Primary signal: {@code processTokenCount} — total invocations of
 * {@code processToken()} per execution, measured by the
 * {@link dosguide.agent.DoSMeasureAgent} (R36 §2, R47).
 *
 * <p>Implements {@link Guidance} directly (R3); does not extend Zest or
 * any existing guidance.  Implements {@link SignalSource} for DoSGuide
 * validation.
 */
public class V1Guidance implements Guidance, SignalSource {

    // ---- configuration ------------------------------------------------
    private final int maxInputSize;
    private final long maxDurationMs;
    private final File corpusDir;
    private final PrintStream log;

    // ---- corpus & dictionary ------------------------------------------
    private final List<byte[]> corpus   = new ArrayList<>();
    private final List<byte[]> seeds    = new ArrayList<>();
    private final List<byte[]> dict     = new ArrayList<>();
    private final Set<Long> seenHashes  = new HashSet<>();
    private final Random rng            = new Random();

    // ---- state --------------------------------------------------------
    private int    seedIdx;
    private long   trials;
    private long   startMs;
    private long   lastLogMs;
    private double bestSignal;
    private long   flatCount;
    private byte[] currentInput;
    private double lastSignalValue;
    private boolean started;
    private long   execStartNs;       // for timeout-awareness
    private long   timeoutCount;      // number of timed-out executions

    // === token literal (source: TokenMacroFuzzTest.CHANGES_TEMPLATE) ===
    private static final byte[] FULL_TOKEN =
            "${CHANGES, format=\"%m\"}".getBytes(StandardCharsets.ISO_8859_1);

    // --------------------------------------------------------------------
    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize  = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.maxDurationMs = maxDurationMs;
        this.corpusDir     = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.log           = log;
        initDictionary();
        initSeeds();
    }

    // ---- dictionary (R45-b): syntactic units on the attack path -------
    private void initDictionary() {
        d("${");                // token open delimiter
        d("}");                 // token close delimiter
        d("CHANGES");           // macro name
        d("format");            // parameter name
        d("=");                 // assignment
        d("\"");                // quote delimiter
        d("%m");                // format specifier (%m = message)
        d(",");                 // argument separator
        d(" ");                 // whitespace
        d("$");                 // dollar sign
        d("{");                 // brace
        d(", ");                // comma-space
        d("format=\"%m\"");     // full parameter assignment
    }

    private void d(String s) {
        dict.add(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    // ---- seeds (benign, non-triggering) --------------------------------
    private void initSeeds() {
        seeds.add("hello world".getBytes(StandardCharsets.ISO_8859_1));
        seeds.add("fix: update readme".getBytes(StandardCharsets.ISO_8859_1));
        seeds.add("initial commit message for testing".getBytes(StandardCharsets.ISO_8859_1));
    }

    // ===================================================================
    //  Guidance interface
    // ===================================================================

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        if (!started) {
            started   = true;
            startMs   = System.currentTimeMillis();
            lastLogMs = startMs;
        }
        V1Counter.reset();
        execStartNs = System.nanoTime();

        if (seedIdx < seeds.size()) {
            currentInput = seeds.get(seedIdx++);
        } else {
            currentInput = mutate(pickParent());
        }
        if (currentInput.length > maxInputSize) {
            currentInput = Arrays.copyOf(currentInput, maxInputSize);
        }
        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (!started) return true;
        if (maxDurationMs <= 0) return true;
        return (System.currentTimeMillis() - startMs) < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        long count = V1Counter.count.get()[0];
        lastSignalValue = (double) count;
        trials++;

        long execMs = (System.nanoTime() - execStartNs) / 1_000_000;
        boolean timedOut = (execMs > 5000) || result == Result.TIMEOUT;
        if (timedOut) timeoutCount++;

        boolean retain = false;

        // Primary: signal increase
        if (count > bestSignal) {
            bestSignal = count;
            flatCount  = 0;
            retain     = true;
        } else {
            flatCount++;
        }

        // Secondary (R46): structural novelty while signal is flat
        if (!retain && flatCount > 50) {
            long h = structuralHash(currentInput);
            if (seenHashes.add(h)) {
                retain = true;
            }
        }

        // Growth toward input_bytes while corpus is tiny
        if (!retain && corpus.size() < 10 && currentInput.length > maxCorpusLen()) {
            retain = true;
        }

        // CRITICAL: never retain inputs that caused timeout/very long exec —
        // these become parents that spawn more timeout-causing mutations.
        // Keep the signal record (bestSignal) but not the input.
        if (timedOut) retain = false;

        if (retain && corpus.size() < 2000) {
            corpus.add(currentInput.clone());
            saveToDisk(count);
        }

        // Logging every 1 s (R5)
        long now = System.currentTimeMillis();
        if (now - lastLogMs >= 1000) {
            log.printf("[V1] trials=%d  corpus=%d  best=%.0f  flat=%d  last=%.0f  elapsed=%ds  timeouts=%d%n",
                    trials, corpus.size(), bestSignal, flatCount,
                    lastSignalValue, (now - startMs) / 1000, timeoutCount);
            lastLogMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return t -> { };          // custom agent, no JQF tracing (R43)
    }

    // ===================================================================
    //  SignalSource
    // ===================================================================

    @Override
    public Map<String, Double> lastSignals() {
        return Collections.singletonMap("processTokenCount", lastSignalValue);
    }

    // ===================================================================
    //  Mutation operators (R45)
    // ===================================================================

    /**
     * Maximum number of complete {@code ${...}} tokens allowed per input.
     * With K≥2 self-referencing tokens the recursive expansion is
     * exponential (K^depth) causing 20 s timeouts.  Capping at 1 keeps
     * every execution ≤ ~300 ms while still demonstrating unbounded
     * linear recursion.
     */
    private static final int MAX_TOKENS_PER_INPUT = 1;

    private byte[] mutate(byte[] parent) {
        double r = rng.nextDouble();
        if (bestSignal == 0) {
            // discovery phase — find the first token structure
            if (r < 0.25) return tokenInsert(parent);
            if (r < 0.50) return dictInsert(parent);
            if (r < 0.65) return blockRepeat(parent);
            if (r < 0.85) return byteFlip(parent);
            return splice(parent);
        }
        // amplification phase — maximize recursion depth with ONE token.
        // Heavy mutations are all lightweight (no extra tokens).
        if (r < 0.30) return dictInsert(parent);
        if (r < 0.55) return byteFlip(parent);
        if (r < 0.70) return blockRepeat(parent);
        if (r < 0.85) return splice(parent);
        if (r < 0.90) return textExtend(parent);
        if (r < 0.95) return tokenInsert(parent);  // guarded: no-op if already has token
        return tokenRepeat(parent);                 // guarded: no-op if already has token
    }

    /**
     * Insert a complete CHANGES token at a random position.
     * <p>GUARDED: falls back to dictInsert if the input already
     * contains {@link #MAX_TOKENS_PER_INPUT} tokens.
     */
    private byte[] tokenInsert(byte[] data) {
        if (countTokens(data) >= MAX_TOKENS_PER_INPUT) return dictInsert(data);
        int pos = rng.nextInt(data.length + 1);
        return insert(data, pos, FULL_TOKEN);
    }

    /**
     * Find an existing {@code $&#123;...&#125;} token boundary and duplicate it (R45-a).
     * <p>GUARDED: falls back to dictInsert if the input already
     * contains {@link #MAX_TOKENS_PER_INPUT} tokens.
     */
    private byte[] tokenRepeat(byte[] data) {
        if (countTokens(data) >= MAX_TOKENS_PER_INPUT) return dictInsert(data);
        int start = indexOf(data, (byte) '$', (byte) '{');
        if (start < 0) return tokenInsert(data);
        int end = closingBrace(data, start);
        if (end < 0) return tokenInsert(data);
        byte[] tok = Arrays.copyOfRange(data, start, end);
        return insert(data, end, tok);
    }

    /** Append random filler text around existing content (extends commit message). */
    private byte[] textExtend(byte[] data) {
        int extra = 4 + rng.nextInt(32);
        int newLen = Math.min(data.length + extra, maxInputSize);
        byte[] out = Arrays.copyOf(data, newLen);
        for (int i = data.length; i < newLen; i++) {
            out[i] = (byte) (0x20 + rng.nextInt(95)); // printable ASCII
        }
        return out;
    }

    /** Insert a random dictionary entry at a random position (R45-b). */
    private byte[] dictInsert(byte[] data) {
        byte[] entry = dict.get(rng.nextInt(dict.size()));
        int pos = rng.nextInt(data.length + 1);
        return insert(data, pos, entry);
    }

    /** Repeat a random block 1–3 times (R45-a generic repetition). */
    private byte[] blockRepeat(byte[] data) {
        if (data.length == 0) return data;
        int bStart = rng.nextInt(data.length);
        int maxLen = Math.min(data.length - bStart, Math.max(1, maxInputSize / 2));
        int bLen   = 1 + rng.nextInt(maxLen);
        int k      = 1 + rng.nextInt(3);
        byte[] block = Arrays.copyOfRange(data, bStart, bStart + bLen);
        byte[] out   = new byte[Math.min(data.length + block.length * k, maxInputSize)];
        int pos = Math.min(bStart + bLen, out.length);
        System.arraycopy(data, 0, out, 0, pos);
        for (int i = 0; i < k && pos + block.length <= out.length; i++) {
            System.arraycopy(block, 0, out, pos, block.length);
            pos += block.length;
        }
        int tail = Math.min(data.length - bStart - bLen, out.length - pos);
        if (tail > 0) {
            System.arraycopy(data, bStart + bLen, out, pos, tail);
            pos += tail;
        }
        return pos < out.length ? Arrays.copyOf(out, pos) : out;
    }

    /** Flip 1–4 random bits. */
    private byte[] byteFlip(byte[] data) {
        if (data.length == 0) return data;
        byte[] out = data.clone();
        int n = 1 + rng.nextInt(4);
        for (int i = 0; i < n; i++) {
            out[rng.nextInt(out.length)] ^= (byte) (1 << rng.nextInt(8));
        }
        return out;
    }

    /** Combine prefix of this and suffix of another corpus entry. */
    private byte[] splice(byte[] data) {
        byte[] other = pickParent();
        int cut1 = rng.nextInt(data.length + 1);
        int cut2 = rng.nextInt(other.length + 1);
        int len  = cut1 + (other.length - cut2);
        if (len <= 0) return data;
        byte[] out = new byte[Math.min(len, maxInputSize)];
        int c1 = Math.min(cut1, out.length);
        System.arraycopy(data, 0, out, 0, c1);
        int c2 = Math.min(other.length - cut2, out.length - c1);
        if (c2 > 0) System.arraycopy(other, cut2, out, c1, c2);
        return out;
    }

    // ---- helpers -------------------------------------------------------

    /** Count occurrences of {@code ${} in the data — proxy for token count. */
    private static int countTokens(byte[] data) {
        int count = 0;
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == '$' && data[i + 1] == '{') count++;
        }
        return count;
    }

    private byte[] insert(byte[] data, int pos, byte[] fragment) {
        int newLen = Math.min(data.length + fragment.length, maxInputSize);
        byte[] out = new byte[newLen];
        int p = Math.min(pos, newLen);
        System.arraycopy(data, 0, out, 0, p);
        int frag = Math.min(fragment.length, newLen - p);
        System.arraycopy(fragment, 0, out, p, frag);
        int tail = Math.min(data.length - pos, newLen - p - frag);
        if (tail > 0) System.arraycopy(data, pos, out, p + frag, tail);
        return out;
    }

    private byte[] pickParent() {
        if (corpus.isEmpty()) return seeds.get(rng.nextInt(seeds.size()));
        return corpus.get(rng.nextInt(corpus.size()));
    }

    private int maxCorpusLen() {
        int m = 0;
        for (byte[] b : corpus) if (b.length > m) m = b.length;
        return m;
    }

    private static int indexOf(byte[] data, byte a, byte b) {
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == a && data[i + 1] == b) return i;
        }
        return -1;
    }

    private static int closingBrace(byte[] data, int from) {
        int depth = 0;
        for (int i = from; i < data.length; i++) {
            if (data[i] == '{') depth++;
            else if (data[i] == '}') { depth--; if (depth == 0) return i + 1; }
        }
        return -1;
    }

    private long structuralHash(byte[] data) {
        long h = data.length;
        int tokens = 0;
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == '$' && data[i + 1] == '{') { h = h * 31 + i; tokens++; }
        }
        return h * 31 + tokens;
    }

    private void saveToDisk(long sig) {
        try {
            Files.write(new File(corpusDir,
                    String.format("id_%06d_sig_%d", corpus.size(), sig)).toPath(),
                    currentInput);
        } catch (Exception ignored) { }
    }
}
