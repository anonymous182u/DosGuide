package fuzzing.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;
import fuzzing.agent.V1DepthCounters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
 * V1Guidance: targets JSONML.parse() unbounded recursive descent (CWE-674).
 *
 * Strategy: VDF + CGF (Vulnerability-Directed + Cost-Gradient).
 * Hill-climbs on recursion depth measured by V1MeasureAgent bytecode instrumentation.
 *
 * Key insight: JSONML.parse() recurses on every XML open tag {@code <X>}.
 * Each 3-byte {@code <X>} (single-char tag name) adds one recursion level.
 * The guidance generates XML-structured inputs from the start (not random bytes)
 * and uses signal feedback to discover that more nested open tags = higher depth.
 *
 * Signal: maxDepth — peak recursion depth of JSONML.parse() per execution.
 *
 * Mutation operators:
 *   - XML tag insert: insert a complete {@code <X>} open tag at a random position
 *   - XML tag block insert: insert multiple {@code <X>} tags at once for fast growth
 *   - Chunk repetition [R45a]: repeat a random chunk (often a tag sequence)
 *   - Dictionary insert/overwrite [R45b]: XML structural tokens
 *   - Byte-level: flip, insert, delete, overwrite (low probability, for diversity)
 *
 * Retention [R46]: retain inputs with higher maxDepth (primary) or longer length
 * at equal depth (secondary / flat-signal growth toward input_bytes).
 */
public class V1Guidance implements Guidance, SignalSource {

    // ---- Configuration ----
    private final int maxInputSize;
    private final File corpusDir;
    private final long maxDurationMs;
    private final PrintStream log;

    // ---- State ----
    private final Random rng = new Random();
    private final List<CorpusEntry> corpus = new ArrayList<>();
    private long bestDepth = 0;
    private int bestLength = 0;
    private long totalExecs = 0;
    private long startTimeMs = 0;
    private long lastLogTimeMs = 0;
    private byte[] currentInput;
    private double lastMaxDepth = 0.0;
    private long savedCount = 0;
    private int bootstrapIndex = 0;

    // ---- Tag names for generating XML open tags ----
    // Using varied single-character tag names to generate diverse XML structures.
    // These are ordinary XML tag names, not failure-inducing inputs.
    private static final char[] TAG_CHARS =
            "abcdefghijklmnopqrstuvwxyz".toCharArray();

    // ---- Dictionary: XML structural tokens [R45b] ----
    // Includes complete open tags <X> so that single insertions produce
    // valid XML structure that triggers recursion.
    private static final byte[][] DICTIONARY;
    static {
        List<byte[]> tokens = new ArrayList<>();
        // Complete XML open tags with various single-char tag names
        for (char c : TAG_CHARS) {
            tokens.add(("<" + c + ">").getBytes(StandardCharsets.UTF_8));
        }
        // Structural XML tokens from the parser's code paths
        tokens.add("<".getBytes(StandardCharsets.UTF_8));
        tokens.add(">".getBytes(StandardCharsets.UTF_8));
        tokens.add("/".getBytes(StandardCharsets.UTF_8));
        tokens.add("=".getBytes(StandardCharsets.UTF_8));
        tokens.add("</".getBytes(StandardCharsets.UTF_8));
        tokens.add("/>".getBytes(StandardCharsets.UTF_8));
        tokens.add("<!--".getBytes(StandardCharsets.UTF_8));
        tokens.add("-->".getBytes(StandardCharsets.UTF_8));
        tokens.add("<?".getBytes(StandardCharsets.UTF_8));
        tokens.add("?>".getBytes(StandardCharsets.UTF_8));
        tokens.add("\"".getBytes(StandardCharsets.UTF_8));
        tokens.add("'".getBytes(StandardCharsets.UTF_8));
        tokens.add("!".getBytes(StandardCharsets.UTF_8));
        tokens.add("<![CDATA[".getBytes(StandardCharsets.UTF_8));
        tokens.add("]]>".getBytes(StandardCharsets.UTF_8));
        DICTIONARY = tokens.toArray(new byte[0][]);
    }

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 65536);
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.maxDurationMs = maxDurationMs;
        this.log = log;
    }

    // ====================  Guidance interface  ====================

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        V1DepthCounters.reset();

        if (corpus.isEmpty()) {
            currentInput = generateBootstrapInput();
        } else {
            CorpusEntry parent = selectParent();
            currentInput = mutate(parent.data);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        long now = System.currentTimeMillis();
        if (startTimeMs == 0) {
            startTimeMs = now;
            lastLogTimeMs = now;
        }
        return (now - startTimeMs) < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;
        long depth = V1DepthCounters.maxDepth();
        lastMaxDepth = (double) depth;

        boolean retain = false;

        if (corpus.isEmpty()) {
            retain = true;
        } else if (depth > bestDepth) {
            retain = true;
        } else if (depth == bestDepth && currentInput.length > bestLength) {
            retain = true;
        } else if (depth > 0 && corpus.size() < 30) {
            retain = true;
        } else if (currentInput.length > bestLength) {
            retain = true;
        }

        if (retain) {
            if (depth > bestDepth) bestDepth = depth;
            if (currentInput.length > bestLength) bestLength = currentInput.length;
            CorpusEntry entry = new CorpusEntry(currentInput.clone(), depth, totalExecs);
            corpus.add(entry);
            if (corpus.size() > 200) pruneCorpus();
            saveCorpusEntry(entry);
        }

        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            log.printf("[V1] execs=%d bestDepth=%d corpusSize=%d lastDepth=%d lastLen=%d elapsed=%.1fs%n",
                    totalExecs, bestDepth, corpus.size(), depth,
                    currentInput.length, (now - startTimeMs) / 1000.0);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return (event) -> { };
    }

    // ==================== SignalSource interface ====================

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> m = new HashMap<>();
        m.put("maxDepth", lastMaxDepth);
        return m;
    }

    // ====================  Bootstrap  ====================

    /**
     * Generate well-formed XML fragments as bootstrap inputs.
     * Each bootstrap input is a small sequence of XML open tags with
     * varied tag names — ordinary well-formed XML, not a specific
     * failure-inducing pattern.
     *
     * The first few bootstraps systematically vary the structure:
     *   - Single tags: {@code <a>}, {@code <b>}
     *   - A few nested tags: {@code <c><d><e>}
     *   - Slightly larger: sequences of 5-10 tags
     * After that, generate random XML fragments of varied sizes.
     */
    private byte[] generateBootstrapInput() {
        bootstrapIndex++;
        StringBuilder sb = new StringBuilder();

        if (bootstrapIndex <= 26) {
            // First 26 bootstraps: single open tags with each letter
            char c = TAG_CHARS[(bootstrapIndex - 1) % TAG_CHARS.length];
            sb.append('<').append(c).append('>');
        } else if (bootstrapIndex <= 36) {
            // Next 10: small groups of 2-5 nested tags with varied names
            int count = 2 + rng.nextInt(4);
            count = Math.min(count, maxInputSize / 3);
            for (int i = 0; i < count; i++) {
                char c = TAG_CHARS[rng.nextInt(TAG_CHARS.length)];
                sb.append('<').append(c).append('>');
            }
        } else {
            // After that: random sequences of 3-20 open tags
            int count = 3 + rng.nextInt(18);
            count = Math.min(count, maxInputSize / 3);
            for (int i = 0; i < count; i++) {
                char c = TAG_CHARS[rng.nextInt(TAG_CHARS.length)];
                sb.append('<').append(c).append('>');
            }
        }

        byte[] result = sb.toString().getBytes(StandardCharsets.UTF_8);
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    // ====================  Mutation operators  ====================

    private byte[] mutate(byte[] parent) {
        int op = rng.nextInt(100);
        byte[] result;

        if (op < 30) {
            // [R45a] Tag-aligned chunk repetition — 30%
            // Repeats a chunk of the parent, often a sequence of <X> tags
            result = mutateChunkRepeat(parent);
        } else if (op < 55) {
            // XML tag block insert — 25%
            // Inserts 1-many complete <X> tags at a random position
            result = mutateTagBlockInsert(parent);
        } else if (op < 70) {
            // [R45b] Dictionary insert — 15%
            result = mutateDictionaryInsert(parent);
        } else if (op < 80) {
            // [R45b] Dictionary overwrite — 10%
            result = mutateDictionaryOverwrite(parent);
        } else if (op < 86) {
            // Byte flip — 6%
            result = mutateByteFlip(parent);
        } else if (op < 91) {
            // Byte insert — 5%
            result = mutateByteInsert(parent);
        } else if (op < 94) {
            // Byte delete — 3%
            result = mutateByteDelete(parent);
        } else if (op < 97) {
            // Byte overwrite — 3%
            result = mutateByteOverwrite(parent);
        } else {
            // Tag name randomization — 3%
            // Change tag names in existing <X> patterns
            result = mutateTagNames(parent);
        }

        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    /**
     * Insert 1 to many complete XML open tags {@code <X>} at a random position.
     * The number of tags to insert grows aggressively: we insert enough to
     * approximately double the input, up to maxInputSize.
     */
    private byte[] mutateTagBlockInsert(byte[] data) {
        int spaceLeft = maxInputSize - data.length;
        if (spaceLeft < 3) {
            // No room for even one tag: flip instead
            return mutateByteFlip(data);
        }

        // How many tags to insert? 1 to (spaceLeft/3), biased toward large
        int maxTags = spaceLeft / 3;
        int numTags;
        if (maxTags <= 1) {
            numTags = 1;
        } else if (rng.nextInt(100) < 60) {
            // 60% of the time: aggressive growth (insert many tags)
            numTags = Math.max(1, maxTags / (1 + rng.nextInt(4)));
        } else {
            // 40% of the time: moderate (1-10 tags)
            numTags = 1 + rng.nextInt(Math.min(10, maxTags));
        }

        // Build the tag bytes
        byte[] tags = new byte[numTags * 3];
        for (int i = 0; i < numTags; i++) {
            char c = TAG_CHARS[rng.nextInt(TAG_CHARS.length)];
            tags[i * 3] = '<';
            tags[i * 3 + 1] = (byte) c;
            tags[i * 3 + 2] = '>';
        }

        // Insert at a random position (prefer appending to existing tag sequences)
        int pos = data.length == 0 ? 0 : rng.nextInt(data.length + 1);
        int newLen = Math.min(data.length + tags.length, maxInputSize);
        byte[] r = new byte[newLen];
        int copied = Math.min(pos, newLen);
        System.arraycopy(data, 0, r, 0, copied);
        int tagLen = Math.min(tags.length, newLen - copied);
        System.arraycopy(tags, 0, r, copied, tagLen);
        int remain = newLen - copied - tagLen;
        if (remain > 0 && pos < data.length) {
            System.arraycopy(data, pos, r, copied + tagLen,
                    Math.min(remain, data.length - pos));
        }
        return r;
    }

    /**
     * [R45a] Chunk repetition: select a random chunk and repeat it k times.
     * On XML-structured inputs, this naturally repeats sequences of {@code <X>}
     * tags, amplifying nesting depth.
     */
    private byte[] mutateChunkRepeat(byte[] data) {
        if (data.length == 0) {
            return generateBootstrapInput();
        }

        // Try to align chunk to 3-byte tag boundaries when input looks tag-structured
        int chunkStart;
        int chunkLen;

        if (data.length >= 3 && rng.nextInt(100) < 70) {
            // 70% of the time: try to pick a tag-aligned chunk
            // Find a '<' character and use it as the chunk start
            int attempts = 10;
            int start = -1;
            for (int a = 0; a < attempts; a++) {
                int idx = rng.nextInt(data.length);
                if (data[idx] == '<') {
                    start = idx;
                    break;
                }
            }
            if (start >= 0 && start + 3 <= data.length) {
                chunkStart = start;
                // Chunk length: a multiple of 3 for tag alignment
                int maxUnits = (data.length - chunkStart) / 3;
                if (maxUnits <= 0) maxUnits = 1;
                int units = 1 + rng.nextInt(Math.min(maxUnits, 64));
                chunkLen = Math.min(units * 3, data.length - chunkStart);
            } else {
                // Fallback to random chunk
                chunkStart = rng.nextInt(data.length);
                int maxLen = Math.min(128, data.length - chunkStart);
                chunkLen = maxLen <= 0 ? 1 : 1 + rng.nextInt(maxLen);
            }
        } else {
            chunkStart = rng.nextInt(data.length);
            int maxLen = Math.min(128, data.length - chunkStart);
            chunkLen = maxLen <= 0 ? 1 : 1 + rng.nextInt(maxLen);
        }

        if (chunkLen <= 0) chunkLen = 1;

        int spaceLeft = maxInputSize - data.length;
        if (spaceLeft <= 0) {
            return mutateByteFlip(data);
        }

        int maxAdditional = spaceLeft / chunkLen;
        if (maxAdditional <= 0) maxAdditional = 1;
        int additionalCopies = 1 + rng.nextInt(Math.min(maxAdditional, 256));

        ByteArrayOutputStream bos = new ByteArrayOutputStream(
                Math.min(data.length + additionalCopies * chunkLen, maxInputSize));
        bos.write(data, 0, chunkStart);
        for (int i = 0; i < 1 + additionalCopies && bos.size() + chunkLen <= maxInputSize; i++) {
            bos.write(data, chunkStart, chunkLen);
        }
        int suffixStart = chunkStart + chunkLen;
        int suffixLen = data.length - suffixStart;
        if (suffixLen > 0) {
            int toWrite = Math.min(suffixLen, maxInputSize - bos.size());
            if (toWrite > 0) bos.write(data, suffixStart, toWrite);
        }

        byte[] result = bos.toByteArray();
        return result.length > 0 ? result : data.clone();
    }

    /** [R45b] Insert a random dictionary token at a random position. */
    private byte[] mutateDictionaryInsert(byte[] data) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = data.length == 0 ? 0 : rng.nextInt(data.length + 1);
        int newLen = Math.min(data.length + token.length, maxInputSize);
        byte[] r = new byte[newLen];
        int copied = Math.min(pos, newLen);
        System.arraycopy(data, 0, r, 0, copied);
        int tokenLen = Math.min(token.length, newLen - copied);
        System.arraycopy(token, 0, r, copied, tokenLen);
        int remain = newLen - copied - tokenLen;
        if (remain > 0 && pos < data.length) {
            System.arraycopy(data, pos, r, copied + tokenLen,
                    Math.min(remain, data.length - pos));
        }
        return r;
    }

    /** [R45b] Overwrite bytes at a random position with a dictionary token. */
    private byte[] mutateDictionaryOverwrite(byte[] data) {
        if (data.length == 0) return mutateDictionaryInsert(data);
        byte[] r = data.clone();
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(r.length);
        int len = Math.min(token.length, r.length - pos);
        System.arraycopy(token, 0, r, pos, len);
        return r;
    }

    /**
     * Randomize tag names in existing {@code <X>} patterns.
     * Preserves the XML structure while varying the tag names for diversity.
     */
    private byte[] mutateTagNames(byte[] data) {
        if (data.length < 3) return data.clone();
        byte[] r = data.clone();
        int changes = 1 + rng.nextInt(Math.min(8, r.length / 3));
        for (int i = 0; i < changes; i++) {
            int pos = rng.nextInt(r.length - 2);
            if (r[pos] == '<' && r[pos + 2] == '>' && isTagChar(r[pos + 1])) {
                r[pos + 1] = (byte) TAG_CHARS[rng.nextInt(TAG_CHARS.length)];
            }
        }
        return r;
    }

    /** Flip 1-8 random bits. */
    private byte[] mutateByteFlip(byte[] data) {
        if (data.length == 0) return data;
        byte[] r = data.clone();
        int count = rng.nextInt(8) + 1;
        for (int i = 0; i < count; i++) {
            int pos = rng.nextInt(r.length);
            r[pos] ^= (byte) (1 << rng.nextInt(8));
        }
        return r;
    }

    /** Insert 1-4 random bytes at a random position. */
    private byte[] mutateByteInsert(byte[] data) {
        int count = rng.nextInt(4) + 1;
        if (data.length + count > maxInputSize) {
            count = maxInputSize - data.length;
            if (count <= 0) return data.clone();
        }
        int pos = data.length == 0 ? 0 : rng.nextInt(data.length + 1);
        byte[] ins = new byte[count];
        rng.nextBytes(ins);
        byte[] r = new byte[data.length + count];
        System.arraycopy(data, 0, r, 0, pos);
        System.arraycopy(ins, 0, r, pos, count);
        System.arraycopy(data, pos, r, pos + count, data.length - pos);
        return r;
    }

    /** Delete 1-4 bytes from a random position. */
    private byte[] mutateByteDelete(byte[] data) {
        if (data.length <= 1) return data.clone();
        int count = Math.min(rng.nextInt(4) + 1, data.length - 1);
        int pos = rng.nextInt(data.length - count + 1);
        byte[] r = new byte[data.length - count];
        System.arraycopy(data, 0, r, 0, pos);
        System.arraycopy(data, pos + count, r, pos, data.length - pos - count);
        return r;
    }

    /** Overwrite 1-4 bytes at a random position with random values. */
    private byte[] mutateByteOverwrite(byte[] data) {
        if (data.length == 0) return data;
        byte[] r = data.clone();
        int count = Math.min(rng.nextInt(4) + 1, r.length);
        int pos = rng.nextInt(r.length - count + 1);
        for (int i = 0; i < count; i++) {
            r[pos + i] = (byte) rng.nextInt(256);
        }
        return r;
    }

    // ====================  Helpers  ====================

    private static boolean isTagChar(byte b) {
        return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z');
    }

    // ====================  Corpus management  ====================

    private CorpusEntry selectParent() {
        if (corpus.size() == 1) return corpus.get(0);
        if (rng.nextInt(100) < 70) {
            long maxD = 0;
            for (CorpusEntry e : corpus) {
                if (e.depth > maxD) maxD = e.depth;
            }
            List<CorpusEntry> best = new ArrayList<>();
            for (CorpusEntry e : corpus) {
                if (e.depth >= maxD) best.add(e);
            }
            return best.get(rng.nextInt(best.size()));
        }
        return corpus.get(rng.nextInt(corpus.size()));
    }

    private void pruneCorpus() {
        corpus.sort((a, b) -> {
            int dc = Long.compare(b.depth, a.depth);
            if (dc != 0) return dc;
            return Integer.compare(b.data.length, a.data.length);
        });
        while (corpus.size() > 100) {
            corpus.remove(corpus.size() - 1);
        }
    }

    private void saveCorpusEntry(CorpusEntry entry) {
        try {
            savedCount++;
            String name = String.format("id_%06d", savedCount);
            Path binPath = corpusDir.toPath().resolve(name + ".bin");
            Path metaPath = corpusDir.toPath().resolve(name + ".meta.json");
            Files.write(binPath, entry.data);
            String meta = String.format(
                    "{\"id\":%d,\"depth\":%d,\"length\":%d,\"execNum\":%d,\"timestamp\":%d}",
                    savedCount, entry.depth, entry.data.length,
                    entry.execNum, System.currentTimeMillis());
            Files.writeString(metaPath, meta, StandardCharsets.UTF_8);
        } catch (IOException e) {
            // best-effort
        }
    }

    // ====================  Inner types  ====================

    private static final class CorpusEntry {
        final byte[] data;
        final long depth;
        final long execNum;

        CorpusEntry(byte[] data, long depth, long execNum) {
            this.data = data;
            this.depth = depth;
            this.execNum = execNum;
        }
    }
}
