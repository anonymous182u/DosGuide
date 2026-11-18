package fuzzing.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.validate.SignalSource;
import fuzzing.agent.DepthCounters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance for V1: Deep JSON array nesting → StackOverflowError
 * via fuzzJSONParserParsePermissive (MODE_PERMISSIVE).
 *
 * Primary signal: maxDepth (parser recursion depth, measured by agent)
 * Secondary signal: nodeCount (total parser node entries)
 *
 * Implements Guidance directly ([R3]). Never decides failures ([R6]).
 */
public class V1Guidance implements Guidance, SignalSource {

    private final Random rng = new Random();
    private final int maxInputSize;
    private final File corpusDir;
    private final PrintStream log;
    private final long startTimeMs;
    private final long maxDurationMs;

    // Corpus: list of saved inputs with their scores
    private final List<byte[]> corpus = new ArrayList<>();
    private final List<Long> corpusDepths = new ArrayList<>();

    // Current execution state
    private byte[] currentInput;
    private long lastMaxDepth;
    private long lastNodeCount;

    // Best-so-far tracking for retention
    private long bestMaxDepth = 0;
    private long bestNodeCount = 0;
    private int bestInputLen = 0;

    // Logging
    private long totalExecs = 0;
    private long lastLogTimeMs;

    // Dictionary tokens from the parser source ([R45b])
    private static final byte[][] DICT_TOKENS = {
        { '[' }, { ']' }, { '{' }, { '}' },
        { ':' }, { ',' }, { '"' }, { '\'' },
        "null".getBytes(), "true".getBytes(),
        "false".getBytes(), "NaN".getBytes()
    };

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.log = log;
        this.maxDurationMs = maxDurationMs;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = this.startTimeMs;

        // Seed with ordinary well-formed JSON examples so the parser enters
        // readArray/readObject from the very first execution.  These are NOT
        // failure-inducing inputs – they are the smallest valid JSON structures.
        corpus.add(new byte[]{ '[', ']' });           // empty array
        corpusDepths.add(0L);
        corpus.add(new byte[]{ '[', '0', ']' });      // array with one element
        corpusDepths.add(0L);
        corpus.add(new byte[]{ '[', '[', ']', ']' }); // nested array (depth 2)
        corpusDepths.add(0L);
    }

    @Override
    public InputStream getInput() {
        // Reset agent counters before each execution
        DepthCounters.reset();

        if (corpus.isEmpty()) {
            currentInput = new byte[]{ '[', ']' };
        } else {
            // Prioritize higher-depth inputs for selection
            byte[] parent = selectParent();
            currentInput = mutate(parent);
        }

        // Enforce max input size ([R41])
        if (currentInput.length > maxInputSize) {
            byte[] trimmed = new byte[maxInputSize];
            System.arraycopy(currentInput, 0, trimmed, 0, maxInputSize);
            currentInput = trimmed;
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs > 0) {
            return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
        }
        return true; // infinite by default ([R8])
    }

    @Override
    public void handleResult(Result result, Throwable error) {
        // Read signals from agent counters
        lastMaxDepth = DepthCounters.getMaxDepth();
        lastNodeCount = DepthCounters.getNodeCount();
        totalExecs++;

        // Retention decision — never writes failure files ([R6])
        boolean keep = false;

        // Primary: new depth record
        if (lastMaxDepth > bestMaxDepth) {
            bestMaxDepth = lastMaxDepth;
            keep = true;
        }

        // Secondary: new node count record
        if (lastNodeCount > bestNodeCount) {
            bestNodeCount = lastNodeCount;
            keep = true;
        }

        // [R46] Progress while signal is flat: keep inputs growing toward input_bytes
        if (currentInput.length > bestInputLen) {
            bestInputLen = currentInput.length;
            keep = true;
        }

        if (keep) {
            byte[] saved = currentInput.clone();
            corpus.add(saved);
            corpusDepths.add(lastMaxDepth);
            saveToCorpus(saved);
        }

        // Structured logging every 1 second ([R5])
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            long elapsed = (now - startTimeMs) / 1000;
            log.printf("[V1Guidance] executions=%d | maxDepth=%d | nodeCount=%d | corpusSize=%d | bestDepth=%d | inputLen=%d | elapsed=%ds%n",
                    totalExecs, lastMaxDepth, lastNodeCount, corpus.size(),
                    bestMaxDepth, currentInput.length, elapsed);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // We use agent-based instrumentation, not JQF tracing callbacks
        return (e) -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> m = new HashMap<>();
        m.put("maxDepth", (double) lastMaxDepth);
        m.put("nodeCount", (double) lastNodeCount);
        return m;
    }

    // ----- Selection -----

    private byte[] selectParent() {
        // Weighted selection: prefer inputs with higher depth
        if (corpus.size() == 1) {
            return corpus.get(0);
        }
        // 70% chance: pick from top 20% by depth; 30% random
        if (rng.nextDouble() < 0.7) {
            // Find max depth in corpus
            long maxD = 0;
            for (long d : corpusDepths) {
                if (d > maxD) maxD = d;
            }
            // Pick randomly from entries with depth >= 80% of max
            long threshold = (long)(maxD * 0.8);
            List<Integer> candidates = new ArrayList<>();
            for (int i = 0; i < corpus.size(); i++) {
                if (corpusDepths.get(i) >= threshold) {
                    candidates.add(i);
                }
            }
            if (!candidates.isEmpty()) {
                return corpus.get(candidates.get(rng.nextInt(candidates.size())));
            }
        }
        return corpus.get(rng.nextInt(corpus.size()));
    }

    // ----- Mutation -----

    private byte[] mutate(byte[] parent) {
        // Choose mutation operator
        int op = rng.nextInt(100);
        if (op < 25) {
            return mutateRepeat(parent);      // [R45a] Repetition
        } else if (op < 50) {
            return mutateDictInsert(parent);  // [R45b] Dictionary
        } else if (op < 65) {
            return mutateFlip(parent);        // byte flip
        } else if (op < 80) {
            return mutateInsertByte(parent);  // byte insert
        } else if (op < 90) {
            return mutateDeleteByte(parent);  // byte delete
        } else {
            return mutateOverwrite(parent);   // byte overwrite
        }
    }

    /** [R45a] Repetition: copy a chunk and repeat it to fill toward maxInputSize. */
    private byte[] mutateRepeat(byte[] src) {
        if (src.length == 0) return new byte[]{ '[' };
        int offset = rng.nextInt(src.length);
        int maxLen = Math.max(1, src.length - offset);
        int chunkLen = 1 + rng.nextInt(maxLen);
        // How many times to repeat
        int space = maxInputSize - src.length;
        if (space <= 0) {
            // If already at max, replace a region with repeated chunk
            int k = 2 + rng.nextInt(3);
            int totalChunk = chunkLen * k;
            if (totalChunk > maxInputSize) totalChunk = maxInputSize;
            byte[] result = new byte[Math.min(offset + totalChunk, maxInputSize)];
            System.arraycopy(src, 0, result, 0, Math.min(offset, result.length));
            for (int i = offset; i < result.length; i++) {
                result[i] = src[offset + ((i - offset) % chunkLen)];
            }
            return result;
        }
        int k = Math.max(2, space / Math.max(1, chunkLen));
        k = Math.min(k, maxInputSize / Math.max(1, chunkLen));
        int insertLen = chunkLen * k;
        int newLen = Math.min(src.length + insertLen, maxInputSize);
        byte[] result = new byte[newLen];
        System.arraycopy(src, 0, result, 0, offset);
        for (int i = 0; i < newLen - offset; i++) {
            result[offset + i] = src[offset + (i % chunkLen)];
        }
        return result;
    }

    /** [R45b] Dictionary token insertion/overwrite at random position. */
    private byte[] mutateDictInsert(byte[] src) {
        byte[] token = DICT_TOKENS[rng.nextInt(DICT_TOKENS.length)];
        if (src.length == 0) return token.clone();

        if (rng.nextBoolean()) {
            // Insert
            int pos = rng.nextInt(src.length + 1);
            int newLen = Math.min(src.length + token.length, maxInputSize);
            byte[] result = new byte[newLen];
            System.arraycopy(src, 0, result, 0, Math.min(pos, newLen));
            int tokenCopy = Math.min(token.length, newLen - pos);
            if (tokenCopy > 0) {
                System.arraycopy(token, 0, result, pos, tokenCopy);
            }
            int remaining = newLen - pos - tokenCopy;
            if (remaining > 0 && pos < src.length) {
                System.arraycopy(src, pos, result, pos + tokenCopy, Math.min(remaining, src.length - pos));
            }
            return result;
        } else {
            // Overwrite
            int pos = rng.nextInt(src.length);
            byte[] result = src.clone();
            for (int i = 0; i < token.length && pos + i < result.length; i++) {
                result[pos + i] = token[i];
            }
            return result;
        }
    }

    private byte[] mutateFlip(byte[] src) {
        if (src.length == 0) return new byte[]{ '[' };
        byte[] result = src.clone();
        int pos = rng.nextInt(result.length);
        result[pos] ^= (byte)(1 << rng.nextInt(8));
        return result;
    }

    private byte[] mutateInsertByte(byte[] src) {
        if (src.length >= maxInputSize) return src.clone();
        int pos = rng.nextInt(src.length + 1);
        byte[] result = new byte[src.length + 1];
        System.arraycopy(src, 0, result, 0, pos);
        result[pos] = (byte) rng.nextInt(256);
        System.arraycopy(src, pos, result, pos + 1, src.length - pos);
        return result;
    }

    private byte[] mutateDeleteByte(byte[] src) {
        if (src.length <= 1) return src.clone();
        int pos = rng.nextInt(src.length);
        byte[] result = new byte[src.length - 1];
        System.arraycopy(src, 0, result, 0, pos);
        System.arraycopy(src, pos + 1, result, pos, src.length - pos - 1);
        return result;
    }

    private byte[] mutateOverwrite(byte[] src) {
        if (src.length == 0) return new byte[]{ '[' };
        byte[] result = src.clone();
        int pos = rng.nextInt(result.length);
        result[pos] = (byte) rng.nextInt(256);
        return result;
    }

    // ----- Corpus persistence -----

    private int savedCount = 0;

    private void saveToCorpus(byte[] data) {
        try {
            Path p = corpusDir.toPath().resolve("input_" + savedCount + ".bin");
            Files.write(p, data);
            // Save metadata
            Path meta = corpusDir.toPath().resolve("input_" + savedCount + ".meta");
            String json = String.format("{\"maxDepth\":%d,\"nodeCount\":%d,\"length\":%d,\"timestamp\":%d}",
                    lastMaxDepth, lastNodeCount, data.length, System.currentTimeMillis());
            Files.writeString(meta, json);
            savedCount++;
        } catch (IOException e) {
            // Ignore save errors
        }
    }
}
