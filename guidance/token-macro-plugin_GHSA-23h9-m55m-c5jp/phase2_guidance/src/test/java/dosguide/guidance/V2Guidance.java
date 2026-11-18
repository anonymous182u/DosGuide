package dosguide.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.agent.V2Counter;
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
 * Vulnerability-Directed Guidance for V2 — ReDoS in
 * {@code BeginningOrEndMatchTransorm#transform()} via
 * {@code Matcher.find()} (CWE-1333).
 *
 * <p>Primary signal: {@code findNanos} — number of
 * {@code CharSequence.charAt()} accesses made by the regex engine during
 * {@code Matcher.find()}, approximating backtracking-step count (R36 §1).
 * Measured by {@link dosguide.agent.CharSequenceProxy} injected by
 * {@link dosguide.agent.DoSMeasureAgent}.
 *
 * <p>Input model (R31): raw {@code byte[]} / {@code InputStream}.
 * The harness splits at the first NUL byte: pattern (before) and subject
 * (after).
 */
public class V2Guidance implements Guidance, SignalSource {

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

    // ---- constants ----------------------------------------------------
    private static final byte NUL = 0x00;

    // ===================================================================
    public V2Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize  = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.maxDurationMs = maxDurationMs;
        this.corpusDir     = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.log           = log;
        initDictionary();
        initSeeds();
    }

    // ---- dictionary (R45-b): regex metacharacters + source tokens ------
    private void initDictionary() {
        d("(");   d(")");    // group delimiters
        d("+");   d("*");    // quantifiers
        d("|");              // alternation — key to resisting JDK 17 opt
        d(".");              // any-char
        d("[");   d("]");    // character class
        d("^");   d("$");    // anchors
        d("?");              // optional quantifier
        d("a");   d("b");    // common test characters
        d("(a");  d("|a");   // useful 2-char fragments
        d("a)");  d(")+");   // useful 2-char fragments
    }

    private void d(String s) {
        dict.add(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    // ---- seeds: well-formed, non-triggering (R23) ---------------------
    private void initSeeds() {
        // seed 1: simple quantifier, short subject
        seeds.add(buildInput("a+", "aa"));
        // seed 2: character class
        seeds.add(buildInput("[ab]+", "abba"));
        // seed 3: group with quantifier — exercises group parsing
        seeds.add(buildInput("(a)+", "aaa"));
    }

    private byte[] buildInput(String pattern, String subject) {
        byte[] p = pattern.getBytes(StandardCharsets.ISO_8859_1);
        byte[] s = subject.getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = new byte[p.length + 1 + s.length];
        System.arraycopy(p, 0, out, 0, p.length);
        out[p.length] = NUL;
        System.arraycopy(s, 0, out, p.length + 1, s.length);
        return out;
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
        V2Counter.reset();

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
        long steps = V2Counter.findNanos.get()[0];
        lastSignalValue = (double) steps;
        trials++;

        boolean retain = false;

        if (steps > bestSignal) {
            bestSignal = steps;
            flatCount  = 0;
            retain     = true;
        } else {
            flatCount++;
        }

        // R46: structural novelty while signal is flat
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

        // Discard inputs that never reached the sink (e.g. PatternSyntaxException → steps=0)
        // but keep them during flat phase if they are structurally novel
        if (retain && corpus.size() < 2000) {
            corpus.add(currentInput.clone());
            saveToDisk(steps);
        }

        long now = System.currentTimeMillis();
        if (now - lastLogMs >= 1000) {
            log.printf("[V2] trials=%d  corpus=%d  best=%.0f  flat=%d  last=%.0f  elapsed=%ds%n",
                    trials, corpus.size(), bestSignal, flatCount,
                    lastSignalValue, (now - startMs) / 1000);
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
        return Collections.singletonMap("findNanos", lastSignalValue);
    }

    // ===================================================================
    //  Mutation operators (R45)
    // ===================================================================

    private byte[] mutate(byte[] parent) {
        double r = rng.nextDouble();
        if (bestSignal < 100) {
            // discovery: build regex structure
            if (r < 0.20) return alternationInsert(parent);
            if (r < 0.40) return patternNest(parent);
            if (r < 0.55) return dictInsert(parent);
            if (r < 0.70) return subjectExtend(parent);
            if (r < 0.85) return patternMutate(parent);
            return byteFlip(parent);
        }
        // amplification: extend subject, deepen pattern
        if (r < 0.35) return subjectExtend(parent);
        if (r < 0.50) return patternNest(parent);
        if (r < 0.60) return alternationInsert(parent);
        if (r < 0.72) return crossover(parent);
        if (r < 0.84) return patternMutate(parent);
        if (r < 0.92) return dictInsert(parent);
        return byteFlip(parent);
    }

    /** Extend the subject portion by appending 'a' chars (R45-a repetition). */
    private byte[] subjectExtend(byte[] data) {
        int nul = findNul(data);
        if (nul < 0) return byteFlip(data);
        int count = 1 + rng.nextInt(Math.max(1, maxInputSize / 4));
        int newLen = Math.min(data.length + count, maxInputSize);
        byte[] out = Arrays.copyOf(data, newLen);
        for (int i = data.length; i < newLen; i++) out[i] = (byte) 'a';
        return out;
    }

    /** Insert '|<char>' in an existing group to create ambiguous alternation. */
    private byte[] alternationInsert(byte[] data) {
        int nul = findNul(data);
        if (nul <= 1) return dictInsert(data);
        // find ')' in pattern portion
        for (int i = nul - 1; i >= 1; i--) {
            if (data[i] == ')') {
                byte[] insert = {(byte) '|', (byte) 'a'};
                return insertAt(data, i, insert);
            }
        }
        return dictInsert(data);
    }

    /** Wrap existing group in '(' ... ')+' nesting. */
    private byte[] patternNest(byte[] data) {
        int nul = findNul(data);
        if (nul <= 0) return dictInsert(data);
        // wrap the whole pattern: ( <pattern> )+
        byte[] prefix = {(byte) '('};
        byte[] suffix = {(byte) ')', (byte) '+'};
        int newLen = Math.min(data.length + 3, maxInputSize);
        byte[] out = new byte[newLen];
        out[0] = prefix[0];
        int pLen = Math.min(nul, newLen - 3);
        System.arraycopy(data, 0, out, 1, pLen);
        int pos = 1 + pLen;
        if (pos < newLen) out[pos++] = suffix[0];
        if (pos < newLen) out[pos++] = suffix[1];
        // NUL + subject
        int remaining = Math.min(data.length - nul, newLen - pos);
        if (remaining > 0) System.arraycopy(data, nul, out, pos, remaining);
        pos += remaining;
        return pos < newLen ? Arrays.copyOf(out, pos) : out;
    }

    /** Mutate a random byte in the pattern portion. */
    private byte[] patternMutate(byte[] data) {
        int nul = findNul(data);
        if (nul <= 0) return byteFlip(data);
        byte[] out = data.clone();
        int idx = rng.nextInt(nul);
        // bias 70% toward regex metacharacters
        if (rng.nextDouble() < 0.7) {
            byte[] metas = {(byte) '(', (byte) ')', (byte) '+', (byte) '*',
                    (byte) '|', (byte) '.', (byte) '[', (byte) ']',
                    (byte) '?', (byte) 'a', (byte) 'b'};
            out[idx] = metas[rng.nextInt(metas.length)];
        } else {
            out[idx] ^= (byte) (1 << rng.nextInt(8));
        }
        return out;
    }

    /** Insert a dictionary entry at a random position in the pattern. */
    private byte[] dictInsert(byte[] data) {
        byte[] entry = dict.get(rng.nextInt(dict.size()));
        int nul = findNul(data);
        int pos = nul > 0 ? rng.nextInt(nul + 1) : rng.nextInt(data.length + 1);
        return insertAt(data, pos, entry);
    }

    /** Combine pattern from one input with subject from another (R45-a). */
    private byte[] crossover(byte[] data) {
        byte[] other = pickParent();
        int nul1 = findNul(data);
        int nul2 = findNul(other);
        if (nul1 < 0 || nul2 < 0) return subjectExtend(data);
        // pattern from data, subject from other
        byte[] pattern = Arrays.copyOfRange(data, 0, nul1);
        byte[] subject = Arrays.copyOfRange(other, nul2 + 1, other.length);
        byte[] out = new byte[Math.min(pattern.length + 1 + subject.length, maxInputSize)];
        int pLen = Math.min(pattern.length, out.length - 2);
        System.arraycopy(pattern, 0, out, 0, pLen);
        out[pLen] = NUL;
        int sLen = Math.min(subject.length, out.length - pLen - 1);
        if (sLen > 0) System.arraycopy(subject, 0, out, pLen + 1, sLen);
        return Arrays.copyOf(out, pLen + 1 + sLen);
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

    // ---- helpers -------------------------------------------------------

    private byte[] insertAt(byte[] data, int pos, byte[] fragment) {
        int newLen = Math.min(data.length + fragment.length, maxInputSize);
        byte[] out = new byte[newLen];
        int p = Math.min(pos, newLen);
        System.arraycopy(data, 0, out, 0, p);
        int f = Math.min(fragment.length, newLen - p);
        System.arraycopy(fragment, 0, out, p, f);
        int t = Math.min(data.length - pos, newLen - p - f);
        if (t > 0) System.arraycopy(data, pos, out, p + f, t);
        return out;
    }

    private int findNul(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            if (data[i] == NUL) return i;
        }
        return -1;
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

    private long structuralHash(byte[] data) {
        int nul = findNul(data);
        long h = 0;
        if (nul > 0) {
            for (int i = 0; i < nul; i++) {
                byte b = data[i];
                if (b == '(' || b == ')' || b == '+' || b == '*'
                        || b == '|' || b == '.' || b == '[' || b == ']') {
                    h = h * 31 + b;
                }
            }
            h = h * 31 + (data.length - nul - 1); // subject length
        } else {
            h = data.length;
        }
        return h;
    }

    private void saveToDisk(long sig) {
        try {
            Files.write(new File(corpusDir,
                    String.format("id_%06d_sig_%d", corpus.size(), sig)).toPath(),
                    currentInput);
        } catch (Exception ignored) { }
    }
}
