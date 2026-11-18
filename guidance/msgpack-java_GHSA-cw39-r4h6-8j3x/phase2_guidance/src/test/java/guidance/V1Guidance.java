package guidance;

import agent.V1Counters;
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
 * V1Guidance: Cost-Gradient Guidance targeting stack overflow via nested containers.
 * Signal: maxDepth (recursion depth of MessageUnpacker.unpackValue(), measured by V1 agent).
 * [R3] Implements Guidance directly, [R6] never decides failures, [R33] dedicated to V1.
 */
public class V1Guidance implements Guidance, SignalSource {

    private final int maxInputSize;
    private final File corpusDir;
    private final File savedInputsDir;
    private final PrintStream log;
    private final long startTimeMs;
    private final long maxDurationMs;
    private final Random rng = new Random();

    // Corpus: list of (input, maxDepth)
    private final List<byte[]> corpus = new ArrayList<>();
    private final List<Long> corpusDepths = new ArrayList<>();
    private long bestMaxDepth = 0;
    private int bestInputLength = 0;

    // Current execution state
    private byte[] currentInput;
    private long lastSignalMaxDepth = 0;
    private long totalExecutions = 0;
    private long lastLogTimeMs;

    // Dictionary tokens from the source on the attack path [R45b]
    private static final byte[][] DICTIONARY = {
        {(byte) 0x91},  // fixarray(1) - one nesting level per byte
        {(byte) 0x81},  // fixmap(1) - nesting alternative
        {(byte) 0xC0},  // nil - terminal value
        {(byte) 0xC2},  // false - terminal
        {(byte) 0xC3},  // true - terminal
        {(byte) 0xDD},  // ARRAY32 format byte
        {(byte) 0xDC},  // ARRAY16 format byte
        {(byte) 0xDF},  // MAP32 format byte
        {(byte) 0x00},  // fixint 0 - terminal value
    };

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.corpusDir = new File(outputDir, "corpus");
        this.savedInputsDir = new File(outputDir, "saved_inputs");
        this.corpusDir.mkdirs();
        this.savedInputsDir.mkdirs();
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();
        this.maxDurationMs = maxDurationMs;
        this.lastLogTimeMs = startTimeMs;

        // Seed: a small valid nesting input [R23: no concrete exploit, just a small seed]
        byte[] seed = new byte[]{(byte) 0x91, (byte) 0xC0};
        corpus.add(seed);
        corpusDepths.add(0L);
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        V1Counters.reset();

        byte[] parent = corpus.get(rng.nextInt(corpus.size()));
        currentInput = mutate(parent);

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
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecutions++;
        long depth = V1Counters.getMaxDepth();
        lastSignalMaxDepth = depth;

        boolean retain = false;
        // Primary: retain if depth improves [R46, R47]
        if (depth > bestMaxDepth) {
            bestMaxDepth = depth;
            retain = true;
        }
        // Secondary: while signal flat, retain longer inputs growing toward input_bytes [R46]
        if (depth == 0 && currentInput.length > bestInputLength) {
            bestInputLength = currentInput.length;
            retain = true;
        }
        // Also retain if same best depth but longer input (more room to grow)
        if (depth == bestMaxDepth && depth > 0 && currentInput.length > bestInputLength) {
            bestInputLength = currentInput.length;
            retain = true;
        }

        if (retain) {
            byte[] copy = Arrays.copyOf(currentInput, currentInput.length);
            corpus.add(copy);
            corpusDepths.add(depth);
            saveInput(copy, depth);
        }

        // Log every 1 second [R5]
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            log.printf("[V1] execs=%d, bestDepth=%d, corpusSize=%d, bestLen=%d, elapsed=%.1fs%n",
                    totalExecutions, bestMaxDepth, corpus.size(), bestInputLength,
                    (now - startTimeMs) / 1000.0);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return e -> {}; // No-op: we use the agent for measurement, not JQF tracing
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> m = new HashMap<>();
        m.put("maxDepth", (double) lastSignalMaxDepth);
        return m;
    }

    // ---- Mutation operators ----

    private byte[] mutate(byte[] parent) {
        int op = rng.nextInt(10);
        byte[] result;
        switch (op) {
            case 0: case 1: case 2:
                // Repetition [R45a]: duplicate a chunk and repeat it
                result = mutateRepeat(parent);
                break;
            case 3: case 4:
                // Dictionary insertion [R45b]
                result = mutateDictionary(parent);
                break;
            case 5: case 6:
                // Random byte flip
                result = mutateFlip(parent);
                break;
            case 7:
                // Random byte insert
                result = mutateInsert(parent);
                break;
            case 8:
                // Random byte delete
                result = mutateDelete(parent);
                break;
            default:
                // Block copy
                result = mutateBlockCopy(parent);
                break;
        }
        // Enforce max input size
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        if (result.length == 0) {
            result = new byte[]{(byte) 0x91, (byte) 0xC0};
        }
        return result;
    }

    private byte[] mutateRepeat(byte[] parent) {
        if (parent.length == 0) return parent;
        // Pick a chunk start and length
        int start = rng.nextInt(parent.length);
        int chunkLen = 1 + rng.nextInt(Math.min(parent.length - start, 64));
        // Repeat k times to fill up to maxInputSize
        int maxK = (maxInputSize - parent.length) / chunkLen + 1;
        if (maxK <= 1) maxK = 2;
        int k = 2 + rng.nextInt(Math.min(maxK, 128));

        byte[] chunk = Arrays.copyOfRange(parent, start, start + chunkLen);
        int newLen = Math.min(parent.length + chunkLen * k, maxInputSize);
        byte[] result = new byte[newLen];
        // Copy prefix
        System.arraycopy(parent, 0, result, 0, Math.min(start, newLen));
        int pos = start;
        for (int i = 0; i < k && pos + chunkLen <= newLen; i++) {
            System.arraycopy(chunk, 0, result, pos, chunkLen);
            pos += chunkLen;
        }
        // Copy suffix
        int remaining = parent.length - (start + chunkLen);
        if (remaining > 0 && pos < newLen) {
            int toCopy = Math.min(remaining, newLen - pos);
            System.arraycopy(parent, start + chunkLen, result, pos, toCopy);
        }
        return result;
    }

    private byte[] mutateDictionary(byte[] parent) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[Math.min(parent.length + token.length, maxInputSize)];
        System.arraycopy(parent, 0, result, 0, Math.min(pos, result.length));
        if (pos < result.length) {
            int tokenCopy = Math.min(token.length, result.length - pos);
            System.arraycopy(token, 0, result, pos, tokenCopy);
            int suffixStart = pos + tokenCopy;
            int suffixLen = Math.min(parent.length - pos, result.length - suffixStart);
            if (suffixLen > 0 && suffixStart < result.length) {
                System.arraycopy(parent, pos, result, suffixStart, suffixLen);
            }
        }
        return result;
    }

    private byte[] mutateFlip(byte[] parent) {
        if (parent.length == 0) return parent;
        byte[] result = parent.clone();
        int pos = rng.nextInt(result.length);
        result[pos] ^= (byte) (1 << rng.nextInt(8));
        return result;
    }

    private byte[] mutateInsert(byte[] parent) {
        int pos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[Math.min(parent.length + 1, maxInputSize)];
        System.arraycopy(parent, 0, result, 0, Math.min(pos, result.length));
        if (pos < result.length) {
            result[pos] = (byte) rng.nextInt(256);
            int remaining = Math.min(parent.length - pos, result.length - pos - 1);
            if (remaining > 0) {
                System.arraycopy(parent, pos, result, pos + 1, remaining);
            }
        }
        return result;
    }

    private byte[] mutateDelete(byte[] parent) {
        if (parent.length <= 1) return parent;
        int pos = rng.nextInt(parent.length);
        byte[] result = new byte[parent.length - 1];
        System.arraycopy(parent, 0, result, 0, pos);
        System.arraycopy(parent, pos + 1, result, pos, parent.length - pos - 1);
        return result;
    }

    private byte[] mutateBlockCopy(byte[] parent) {
        if (parent.length < 2) return parent;
        int srcStart = rng.nextInt(parent.length);
        int srcLen = 1 + rng.nextInt(Math.min(parent.length - srcStart, 32));
        int dstPos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[Math.min(parent.length + srcLen, maxInputSize)];
        System.arraycopy(parent, 0, result, 0, Math.min(dstPos, result.length));
        if (dstPos < result.length) {
            int toCopy = Math.min(srcLen, result.length - dstPos);
            System.arraycopy(parent, srcStart, result, dstPos, toCopy);
            int suffixLen = Math.min(parent.length - dstPos, result.length - dstPos - toCopy);
            if (suffixLen > 0) {
                System.arraycopy(parent, dstPos, result, dstPos + toCopy, suffixLen);
            }
        }
        return result;
    }

    private void saveInput(byte[] input, long depth) {
        try {
            String name = String.format("id_%06d_depth_%d.bin", totalExecutions, depth);
            Files.write(new File(savedInputsDir, name).toPath(), input);
        } catch (IOException e) {
            // best effort
        }
    }
}
