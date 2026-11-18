package fuzzing.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.validate.SignalSource;
import fuzzing.agent.V1Counters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * V1Guidance: Cost-Gradient + Vulnerability-Directed Guidance for
 * FullDTDReader#readContentSpec unbounded recursion (CWE-674).
 *
 * Signal: maxDepth — maximum recursion depth of readContentSpec,
 * measured by the V1MeasureAgent via bytecode instrumentation.
 *
 * Strategy: Hill-climb recursion depth using structure-aware mutations
 * (parenthesis doubling, DTD token dictionary, well-formed encoding)
 * combined with byte-level mutations for exploration.
 *
 * The Guidance never decides an execution failed and never writes failure files [R6].
 */
public class V1Guidance implements Guidance, SignalSource {

    // ---- Configuration ----
    private final int maxInputSize;
    private final long maxDurationMs;
    private final File corpusDir;
    private final PrintStream log;
    private final Random rng;

    // ---- State ----
    private long totalExecs;
    private long startTimeMs;
    private long lastLogTimeMs;
    private byte[] currentInput;
    private double lastMaxDepth;
    private double bestMaxDepth;
    private int bestInputLength;
    private final List<CorpusEntry> corpus;
    private static final int MAX_CORPUS_SIZE = 100;

    // ---- Dictionary of DTD tokens from the source ----
    private static final byte[][] DICTIONARY = {
        // XML declaration tokens
        "<?xml".getBytes(),
        "version".getBytes(),
        "\"1.0\"".getBytes(),
        "?>".getBytes(),
        // DTD declaration tokens
        "<!DOCTYPE".getBytes(),
        "<!ELEMENT".getBytes(),
        // Content spec tokens (the recursion triggers)
        "(".getBytes(),
        ")".getBytes(),
        "|".getBytes(),
        ",".getBytes(),
        // Arity markers
        "?".getBytes(),
        "*".getBytes(),
        "+".getBytes(),
        // Mixed content
        "#PCDATA".getBytes(),
        // Structural tokens
        ">".getBytes(),
        "]".getBytes(),
        "<".getBytes(),
        "/>".getBytes(),
        " ".getBytes(),
        "[".getBytes(),
        "EMPTY".getBytes(),
        "ANY".getBytes(),
    };

    // ---- Seed: a minimal well-formed XML with small DTD content spec ----
    // Not a triggering input; just enough structure to reach the parser.
    // The search must grow this to the triggering depth via mutations.
    private static final byte[] INITIAL_SEED =
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ELEMENT r (a)>]><r/>".getBytes();

    /** A corpus entry with its measured signal. */
    private static final class CorpusEntry {
        final byte[] input;
        final double maxDepth;
        final long execNum;

        CorpusEntry(byte[] input, double maxDepth, long execNum) {
            this.input = input;
            this.maxDepth = maxDepth;
            this.execNum = execNum;
        }
    }

    /**
     * Creates a new V1Guidance.
     *
     * @param outputDir  the base output directory (corpus stored under outputDir/corpus)
     * @param maxDurationMs  maximum duration in ms (0 = infinite)
     * @param log  the print stream for logging
     */
    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.maxDurationMs = maxDurationMs;
        this.corpusDir = new File(outputDir, "corpus");
        this.log = log;
        this.rng = new Random();
        this.corpus = new ArrayList<>();
        this.totalExecs = 0;
        this.bestMaxDepth = 0;
        this.bestInputLength = 0;
        this.lastMaxDepth = 0;

        // Ensure corpus directory exists
        if (!corpusDir.exists()) {
            corpusDir.mkdirs();
        }
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset the agent counters before each execution
        V1Counters.reset();

        if (totalExecs == 0) {
            // First execution: use the initial seed
            currentInput = truncate(INITIAL_SEED);
        } else if (corpus.isEmpty()) {
            // No corpus yet: generate random well-formed DTD input
            currentInput = truncate(generateRandomWellFormedDTD());
        } else {
            // Pick a parent from corpus and mutate
            CorpusEntry parent = selectParent();
            currentInput = truncate(mutate(parent.input));
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (startTimeMs == 0) {
            startTimeMs = System.currentTimeMillis();
            lastLogTimeMs = startTimeMs;
        }

        // Check time bound
        if (maxDurationMs > 0) {
            long elapsed = System.currentTimeMillis() - startTimeMs;
            if (elapsed >= maxDurationMs) {
                return false;
            }
        }

        return true;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;

        // Read the signal from V1Counters (measured by the agent)
        lastMaxDepth = (double) V1Counters.getMaxDepth();

        boolean retain = false;

        // Primary criterion: new best maxDepth
        if (lastMaxDepth > bestMaxDepth) {
            bestMaxDepth = lastMaxDepth;
            retain = true;
        }
        // Secondary criterion: depth matches best, keep for diversity (50%)
        else if (lastMaxDepth > 0 && lastMaxDepth == bestMaxDepth && rng.nextBoolean()) {
            retain = true;
        }
        // Flat-signal progress [R46]: while maxDepth is low, retain longer inputs
        // that are growing toward the target input_bytes (7056)
        else if (lastMaxDepth <= 1 && currentInput.length > bestInputLength) {
            bestInputLength = currentInput.length;
            retain = true;
        }

        if (retain) {
            CorpusEntry entry = new CorpusEntry(
                    currentInput.clone(), lastMaxDepth, totalExecs);
            addToCorpus(entry);
            saveCorpusEntry(entry);
        }

        // Log every 1 second
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            lastLogTimeMs = now;
            long elapsed = now - startTimeMs;
            log.printf("[V1] t=%ds | execs=%d | lastDepth=%.0f | bestDepth=%.0f | " +
                            "corpusSize=%d | inputLen=%d%n",
                    elapsed / 1000, totalExecs, lastMaxDepth, bestMaxDepth,
                    corpus.size(), currentInput.length);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // We don't use JQF tracing; our measurement is via the custom agent.
        // Return a no-op consumer.
        return (event) -> { };
    }

    // ---- SignalSource implementation ----

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        signals.put("maxDepth", lastMaxDepth);
        return signals;
    }

    // ---- Mutation operators ----

    /**
     * Mutates a parent input using one of several operators.
     * Weighted toward structure-aware mutations that increase nesting depth.
     */
    private byte[] mutate(byte[] parent) {
        int choice = rng.nextInt(100);

        if (choice < 30) {
            // 30% - Parenthesis doubling (directly increases nesting)
            return mutateParenDoubling(parent);
        } else if (choice < 50) {
            // 20% - Region repetition
            return mutateRegionRepetition(parent);
        } else if (choice < 70) {
            // 20% - Dictionary insert
            return mutateDictionaryInsert(parent);
        } else if (choice < 80) {
            // 10% - Structure-aware encode with increased depth
            return mutateStructureAwareEncode(parent);
        } else if (choice < 90) {
            // 10% - Byte flip
            return mutateByteFlip(parent);
        } else if (choice < 95) {
            // 5% - Byte insert
            return mutateByteInsert(parent);
        } else {
            // 5% - Byte delete
            return mutateByteDelete(parent);
        }
    }

    /**
     * Parenthesis doubling: find a run of '(' characters and double it,
     * adding matching ')' characters. This directly doubles the nesting depth.
     */
    private byte[] mutateParenDoubling(byte[] input) {
        // Find the first run of '(' characters
        int openStart = -1;
        int openEnd = -1;
        for (int i = 0; i < input.length; i++) {
            if (input[i] == '(') {
                if (openStart < 0) openStart = i;
                openEnd = i + 1;
            } else if (openStart >= 0) {
                break;
            }
        }

        if (openStart < 0) {
            // No parens found, fall back to structure-aware encode
            return mutateStructureAwareEncode(input);
        }

        int openCount = openEnd - openStart;

        // Find the matching run of ')' characters
        int closeStart = -1;
        int closeEnd = -1;
        for (int i = input.length - 1; i >= 0; i--) {
            if (input[i] == ')') {
                if (closeEnd < 0) closeEnd = i + 1;
                closeStart = i;
            } else if (closeEnd >= 0) {
                break;
            }
        }

        if (closeStart < 0) {
            return mutateStructureAwareEncode(input);
        }

        int closeCount = closeEnd - closeStart;

        // Calculate how many extra parens we can add (each paren pair = 2 bytes)
        int available = maxInputSize - input.length;
        // We add k open parens and k close parens, so 2k bytes total
        int k = Math.min(openCount, available / 2); // double the current run
        if (k <= 0) {
            // Can't grow anymore, return with a small mutation
            return mutateByteFlip(input);
        }

        // Build new input: prefix + (original opens + k more opens) + middle + (k more closes + original closes) + suffix
        byte[] prefix = new byte[openStart];
        System.arraycopy(input, 0, prefix, 0, openStart);

        byte[] middle = new byte[closeStart - openEnd];
        System.arraycopy(input, openEnd, middle, 0, middle.length);

        byte[] suffix = new byte[input.length - closeEnd];
        System.arraycopy(input, closeEnd, suffix, 0, suffix.length);

        int newLen = prefix.length + (openCount + k) + middle.length + (closeCount + k) + suffix.length;
        if (newLen > maxInputSize) {
            k = (maxInputSize - prefix.length - openCount - middle.length - closeCount - suffix.length) / 2;
            if (k <= 0) return mutateByteFlip(input);
            newLen = prefix.length + (openCount + k) + middle.length + (closeCount + k) + suffix.length;
        }

        byte[] result = new byte[newLen];
        int pos = 0;

        // Copy prefix
        System.arraycopy(prefix, 0, result, pos, prefix.length);
        pos += prefix.length;

        // Write open parens (original + k more)
        for (int i = 0; i < openCount + k; i++) {
            result[pos++] = '(';
        }

        // Copy middle (element name, separators, etc.)
        System.arraycopy(middle, 0, result, pos, middle.length);
        pos += middle.length;

        // Write close parens (original + k more)
        for (int i = 0; i < closeCount + k; i++) {
            result[pos++] = ')';
        }

        // Copy suffix
        System.arraycopy(suffix, 0, result, pos, suffix.length);

        return result;
    }

    /**
     * Region repetition: select a contiguous region and repeat it.
     */
    private byte[] mutateRegionRepetition(byte[] input) {
        if (input.length < 2) return mutateStructureAwareEncode(input);

        int start = rng.nextInt(input.length);
        int maxLen = Math.min(input.length - start, input.length / 2 + 1);
        if (maxLen < 1) maxLen = 1;
        int len = 1 + rng.nextInt(maxLen);

        int available = maxInputSize - input.length;
        if (available <= 0) return mutateByteFlip(input);

        int reps = 1 + rng.nextInt(Math.min(available / Math.max(len, 1), 10) + 1);
        int insertBytes = len * reps;
        if (insertBytes > available) {
            reps = available / len;
            if (reps <= 0) return mutateByteFlip(input);
            insertBytes = len * reps;
        }

        byte[] result = new byte[input.length + insertBytes];
        int insertPos = start + len; // insert after the selected region
        System.arraycopy(input, 0, result, 0, insertPos);
        for (int r = 0; r < reps; r++) {
            System.arraycopy(input, start, result, insertPos + r * len, len);
        }
        System.arraycopy(input, insertPos, result, insertPos + insertBytes,
                input.length - insertPos);
        return result;
    }

    /**
     * Dictionary insert: insert or overwrite a dictionary token at a random position.
     */
    private byte[] mutateDictionaryInsert(byte[] input) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];

        if (rng.nextBoolean() && input.length + token.length <= maxInputSize) {
            // Insert
            int pos = rng.nextInt(input.length + 1);
            byte[] result = new byte[input.length + token.length];
            System.arraycopy(input, 0, result, 0, pos);
            System.arraycopy(token, 0, result, pos, token.length);
            System.arraycopy(input, pos, result, pos + token.length, input.length - pos);
            return result;
        } else {
            // Overwrite
            if (input.length < token.length) return input.clone();
            int pos = rng.nextInt(input.length - token.length + 1);
            byte[] result = input.clone();
            System.arraycopy(token, 0, result, pos, token.length);
            return result;
        }
    }

    /**
     * Structure-aware encode: construct a well-formed DTD content spec with
     * a mutated nesting depth. The depth is derived from the current input
     * (counting open parens) and then increased.
     */
    private byte[] mutateStructureAwareEncode(byte[] input) {
        // Count current depth from the input
        int currentDepth = 0;
        for (byte b : input) {
            if (b == '(') currentDepth++;
        }

        // Mutate the depth: increase
        int newDepth;
        int action = rng.nextInt(4);
        if (action == 0) {
            // Double
            newDepth = Math.max(currentDepth * 2, 2);
        } else if (action == 1) {
            // Add random amount
            newDepth = currentDepth + 1 + rng.nextInt(Math.max(currentDepth, 10));
        } else if (action == 2) {
            // Grow to fill available space
            int availableForParens = (maxInputSize - 54) / 2; // 54 bytes overhead
            newDepth = availableForParens;
        } else {
            // Small increment
            newDepth = currentDepth + 1 + rng.nextInt(5);
        }

        // Encode as well-formed DTD
        return encodeDTD(newDepth);
    }

    /**
     * Encodes a well-formed XML document with a DTD ELEMENT declaration
     * having the given nesting depth of parenthesized content specs.
     */
    private byte[] encodeDTD(int depth) {
        // Prefix: "<?xml version="1.0"?><!DOCTYPE r [<!ELEMENT r "
        byte[] prefix = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ELEMENT r ".getBytes();
        // Element name in the innermost spec
        byte[] elemName = "a".getBytes();
        // Suffix: ">]><r/>"
        byte[] suffix = ">]><r/>".getBytes();

        // Total size: prefix + depth open parens + elemName + depth close parens + suffix
        int totalSize = prefix.length + depth + elemName.length + depth + suffix.length;

        // Cap depth to fit within maxInputSize
        if (totalSize > maxInputSize) {
            depth = (maxInputSize - prefix.length - elemName.length - suffix.length) / 2;
            if (depth < 1) depth = 1;
            totalSize = prefix.length + depth + elemName.length + depth + suffix.length;
        }

        byte[] result = new byte[totalSize];
        int pos = 0;

        System.arraycopy(prefix, 0, result, pos, prefix.length);
        pos += prefix.length;

        for (int i = 0; i < depth; i++) {
            result[pos++] = '(';
        }

        System.arraycopy(elemName, 0, result, pos, elemName.length);
        pos += elemName.length;

        for (int i = 0; i < depth; i++) {
            result[pos++] = ')';
        }

        System.arraycopy(suffix, 0, result, pos, suffix.length);
        return result;
    }

    /**
     * Generates a random well-formed DTD input with a small nesting depth.
     * Used when the corpus is empty.
     */
    private byte[] generateRandomWellFormedDTD() {
        int depth = 1 + rng.nextInt(10);
        return encodeDTD(depth);
    }

    /** Flip a random byte in the input. */
    private byte[] mutateByteFlip(byte[] input) {
        if (input.length == 0) return input.clone();
        byte[] result = input.clone();
        int pos = rng.nextInt(result.length);
        result[pos] ^= (byte) (1 << rng.nextInt(8));
        return result;
    }

    /** Insert a random byte at a random position. */
    private byte[] mutateByteInsert(byte[] input) {
        if (input.length >= maxInputSize) return mutateByteFlip(input);
        byte[] result = new byte[input.length + 1];
        int pos = rng.nextInt(input.length + 1);
        System.arraycopy(input, 0, result, 0, pos);
        result[pos] = (byte) rng.nextInt(256);
        System.arraycopy(input, pos, result, pos + 1, input.length - pos);
        return result;
    }

    /** Delete a random byte from the input. */
    private byte[] mutateByteDelete(byte[] input) {
        if (input.length <= 1) return input.clone();
        byte[] result = new byte[input.length - 1];
        int pos = rng.nextInt(input.length);
        System.arraycopy(input, 0, result, 0, pos);
        System.arraycopy(input, pos + 1, result, pos, input.length - pos - 1);
        return result;
    }

    // ---- Corpus management ----

    /** Select a parent from the corpus for mutation, weighted by maxDepth^2. */
    private CorpusEntry selectParent() {
        if (corpus.size() == 1) return corpus.get(0);

        // Weighted selection by maxDepth^2 (with a floor of 1)
        double totalWeight = 0;
        for (CorpusEntry e : corpus) {
            double w = Math.max(e.maxDepth, 1);
            totalWeight += w * w;
        }

        double pick = rng.nextDouble() * totalWeight;
        double cumulative = 0;
        for (CorpusEntry e : corpus) {
            double w = Math.max(e.maxDepth, 1);
            cumulative += w * w;
            if (cumulative >= pick) return e;
        }

        return corpus.get(corpus.size() - 1);
    }

    /** Add an entry to the corpus, evicting the lowest-depth entry if full. */
    private void addToCorpus(CorpusEntry entry) {
        if (corpus.size() >= MAX_CORPUS_SIZE) {
            // Find and remove the entry with the lowest maxDepth
            int minIdx = 0;
            double minDepth = corpus.get(0).maxDepth;
            for (int i = 1; i < corpus.size(); i++) {
                if (corpus.get(i).maxDepth < minDepth) {
                    minDepth = corpus.get(i).maxDepth;
                    minIdx = i;
                }
            }
            if (entry.maxDepth > minDepth) {
                corpus.set(minIdx, entry);
            }
            // else: entry is worse than all existing, don't add
        } else {
            corpus.add(entry);
        }
    }

    /** Save a corpus entry to disk with a JSON metadata sidecar. */
    private void saveCorpusEntry(CorpusEntry entry) {
        try {
            String baseName = String.format("id_%06d", entry.execNum);
            Path inputFile = corpusDir.toPath().resolve(baseName + ".bin");
            Path metaFile = corpusDir.toPath().resolve(baseName + ".meta.json");

            Files.write(inputFile, entry.input);

            String meta = String.format(
                    "{\"execNum\": %d, \"maxDepth\": %.0f, \"inputBytes\": %d, \"timestamp\": %d}",
                    entry.execNum, entry.maxDepth, entry.input.length,
                    System.currentTimeMillis());
            Files.writeString(metaFile, meta);
        } catch (IOException e) {
            // Best-effort save; don't crash the fuzzer
            log.println("[V1] WARNING: Failed to save corpus entry: " + e.getMessage());
        }
    }

    /** Truncate input to maxInputSize. */
    private byte[] truncate(byte[] input) {
        if (input.length <= maxInputSize) return input;
        byte[] result = new byte[maxInputSize];
        System.arraycopy(input, 0, result, 0, maxInputSize);
        return result;
    }
}
