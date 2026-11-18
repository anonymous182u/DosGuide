package dosguide.guidance;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.agent.SignalCollector;
import dosguide.validate.SignalSource;

/**
 * V3 Guidance: targets unbounded recursive nested DataResponse deserialization
 * via looseUnmarsalNestedObject → OpenWireFormat.looseUnmarshalNestedObject.
 *
 * Signal: nestingDepth — the max nesting depth, measured by the custom Java agent
 * instrumenting entry/exit of looseUnmarsalNestedObject.
 *
 * Strategy: signal-maximizing (VDF). Constructs valid DataResponse frames (type 0x20)
 * with recursive nesting.
 *
 * Frame layout for DataResponse:
 *   [0..3]   frameLength (int32 BE)
 *   [4]      dataType = 0x20 (DataResponse = 32)
 *   [5..8]   commandId (int32 BE)
 *   [9]      responseRequired (boolean)
 *   [10..13] correlationId (int32 BE)
 *
 * Each nesting level via looseUnmarshalNestedObject:
 *   [0]      present: boolean true (0x01)
 *   [1]      nested dataType = 0x20 (DataResponse)
 *   [2..5]   commandId (int32 BE)
 *   [6]      responseRequired (boolean)
 *   [7..10]  correlationId (int32 BE)
 *   Total: 11 bytes per level.
 *
 * Nesting termination: boolean false (0x00) = 1 byte (no nested object).
 */
public class V3NestingGuidance implements Guidance, SignalSource {

    private static final int HEADER_SIZE = 14; // first DataResponse header
    private static final int BYTES_PER_LEVEL = 11; // nested DataResponse per level
    private static final byte TYPE_DATA_RESPONSE = 0x20;

    // Dictionary tokens from the attack path
    private static final byte[][] DICTIONARY = {
        {0x20},       // DataResponse type byte (32)
        {0x01},       // boolean true (nested object present)
        {0x00},       // boolean false (no nested object / terminator)
        {0x00, 0x00, 0x00, 0x01}, // commandId = 1
        {0x00, 0x00, 0x00, 0x00}, // correlationId = 0
    };

    private final Random rng;
    private final File outputDir;
    private final PrintStream log;
    private final long maxDurationMs;
    private final int maxInputSize;
    private final long startTime;

    private final List<byte[]> corpus = new ArrayList<>();
    private byte[] currentInput;
    private long trialCount = 0;
    private long lastLogTime;

    private double lastNestingDepth = 0.0;
    private int bestNestingDepth = 0;
    private byte[] bestInput;
    private int bestInputLength = 0;

    public V3NestingGuidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.rng = new Random();
        this.outputDir = outputDir;
        this.log = log;
        this.maxDurationMs = maxDurationMs;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.startTime = System.currentTimeMillis();
        this.lastLogTime = startTime;

        if (outputDir != null) {
            outputDir.mkdirs();
            new File(outputDir, "corpus").mkdirs();
        }

        // Seed: DataResponse with 16 nesting levels
        byte[] seed = buildNestingChain(16);
        corpus.add(seed);
        bestInput = seed;
        bestInputLength = seed.length;
    }

    /**
     * Build a valid DataResponse frame with the given number of nesting levels.
     */
    private byte[] buildNestingChain(int levels) {
        int totalSize = HEADER_SIZE + levels * BYTES_PER_LEVEL + 1; // +1 for terminator
        totalSize = Math.min(totalSize, maxInputSize);
        byte[] frame = new byte[totalSize];

        // Header (first DataResponse)
        putInt(frame, 0, totalSize - 4); // frame length
        frame[4] = TYPE_DATA_RESPONSE;
        putInt(frame, 5, 1);    // commandId
        frame[9] = 0x00;       // responseRequired = false
        putInt(frame, 10, 0);  // correlationId

        // Nested DataResponse chain
        int offset = HEADER_SIZE;
        int actualLevels = (totalSize - HEADER_SIZE - 1) / BYTES_PER_LEVEL;
        for (int i = 0; i < actualLevels && offset + BYTES_PER_LEVEL < totalSize; i++) {
            frame[offset] = 0x01;                    // nested object present = true
            frame[offset + 1] = TYPE_DATA_RESPONSE;  // nested type = DataResponse
            putInt(frame, offset + 2, i + 2);        // commandId (unique per level)
            frame[offset + 6] = 0x00;                // responseRequired = false
            putInt(frame, offset + 7, 0);            // correlationId = 0
            offset += BYTES_PER_LEVEL;
        }
        // Terminator: no more nesting
        if (offset < totalSize) {
            frame[offset] = 0x00;
        }

        return frame;
    }

    private static void putInt(byte[] buf, int offset, int value) {
        buf[offset]     = (byte) (value >>> 24);
        buf[offset + 1] = (byte) (value >>> 16);
        buf[offset + 2] = (byte) (value >>> 8);
        buf[offset + 3] = (byte) (value);
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        SignalCollector.reset();
        trialCount++;

        if (trialCount == 1) {
            currentInput = corpus.get(0).clone();
        } else {
            byte[] base = corpus.get(rng.nextInt(corpus.size())).clone();
            currentInput = mutate(base);
        }

        if (currentInput.length > maxInputSize) {
            currentInput = Arrays.copyOf(currentInput, maxInputSize);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs > 0 && (System.currentTimeMillis() - startTime) >= maxDurationMs) {
            return false;
        }
        return true;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        int depth = SignalCollector.getNestingDepth();
        this.lastNestingDepth = (double) depth;

        boolean improved = false;
        if (depth > bestNestingDepth) {
            bestNestingDepth = depth;
            bestInput = currentInput.clone();
            improved = true;
        }

        // Secondary: input length growth [R46]
        if (currentInput.length > bestInputLength) {
            bestInputLength = currentInput.length;
            if (!improved) {
                corpus.add(currentInput.clone());
            }
        }

        if (improved) {
            corpus.add(currentInput.clone());
            if (outputDir != null) {
                saveToDisk(currentInput, "best_input.bin");
                saveCorpusEntry(currentInput);
            }
        }

        if (corpus.size() > 50) {
            corpus.remove(1 + rng.nextInt(corpus.size() - 1));
        }

        long now = System.currentTimeMillis();
        if (now - lastLogTime >= 1000) {
            lastLogTime = now;
            log.printf("[V3] trial=%d depth=%d bestDepth=%d inputLen=%d result=%s elapsed=%.1fs%n",
                trialCount, depth, bestNestingDepth, currentInput.length,
                result, (now - startTime) / 1000.0);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return event -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        signals.put("nestingDepth", lastNestingDepth);
        return signals;
    }

    // ── Mutation operators ──

    private byte[] mutate(byte[] input) {
        int op = rng.nextInt(100);

        if (op < 30) {
            return mutateExtendNesting(input);
        } else if (op < 50) {
            return mutateMaximizeDepth(input);
        } else if (op < 65) {
            return mutateRepetition(input);
        } else if (op < 78) {
            return mutateRandomBytes(input);
        } else if (op < 88) {
            return mutateDictionary(input);
        } else {
            return mutateTruncate(input);
        }
    }

    /** Extend the nesting chain by adding more 11-byte nesting blocks. */
    private byte[] mutateExtendNesting(byte[] input) {
        int levelsToAdd = 1 + rng.nextInt(64);
        int addBytes = levelsToAdd * BYTES_PER_LEVEL;
        int newLen = Math.min(input.length + addBytes, maxInputSize);
        if (newLen <= input.length) return input.clone();

        // Rebuild the full chain at the new size
        int levels = (newLen - HEADER_SIZE - 1) / BYTES_PER_LEVEL;
        return buildNestingChain(levels);
    }

    /** Build maximum-depth nesting chain filling the entire input budget. */
    private byte[] mutateMaximizeDepth(byte[] input) {
        int levels = (maxInputSize - HEADER_SIZE - 1) / BYTES_PER_LEVEL;
        return buildNestingChain(levels);
    }

    /** [R45] Repetition: duplicate region of nesting blocks. */
    private byte[] mutateRepetition(byte[] input) {
        if (input.length <= HEADER_SIZE + BYTES_PER_LEVEL) {
            return mutateExtendNesting(input);
        }
        int bodyStart = HEADER_SIZE;
        int bodyLen = input.length - bodyStart;
        int newLen = Math.min(input.length + bodyLen, maxInputSize);
        byte[] result = new byte[newLen];
        System.arraycopy(input, 0, result, 0, input.length);
        for (int i = input.length; i < newLen; i++) {
            result[i] = input[bodyStart + ((i - input.length) % bodyLen)];
        }
        // Fix terminator and frame length
        result[newLen - 1] = 0x00;
        putInt(result, 0, newLen - 4);
        // Ensure each nested block starts with 0x01 and has the right type
        repairNestingBlocks(result);
        return result;
    }

    private byte[] mutateRandomBytes(byte[] input) {
        byte[] result = input.clone();
        int numMutations = 1 + rng.nextInt(3);
        for (int i = 0; i < numMutations; i++) {
            int idx = HEADER_SIZE + rng.nextInt(Math.max(1, result.length - HEADER_SIZE));
            if (idx < result.length) {
                result[idx] = (byte) rng.nextInt(256);
            }
        }
        result[4] = TYPE_DATA_RESPONSE;
        putInt(result, 0, result.length - 4);
        return result;
    }

    private byte[] mutateDictionary(byte[] input) {
        byte[] result = input.clone();
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        if (result.length > HEADER_SIZE + token.length) {
            int pos = HEADER_SIZE + rng.nextInt(result.length - HEADER_SIZE - token.length + 1);
            pos = Math.min(pos, result.length - token.length);
            System.arraycopy(token, 0, result, pos, token.length);
        }
        result[4] = TYPE_DATA_RESPONSE;
        putInt(result, 0, result.length - 4);
        return result;
    }

    private byte[] mutateTruncate(byte[] input) {
        if (input.length <= HEADER_SIZE + BYTES_PER_LEVEL + 1) return input.clone();
        int removeLevels = 1 + rng.nextInt(16);
        int newLen = Math.max(HEADER_SIZE + BYTES_PER_LEVEL + 1,
                              input.length - removeLevels * BYTES_PER_LEVEL);
        byte[] result = Arrays.copyOf(input, newLen);
        result[newLen - 1] = 0x00;
        putInt(result, 0, newLen - 4);
        return result;
    }

    /** Repair nesting blocks after repetition to ensure valid structure. */
    private void repairNestingBlocks(byte[] frame) {
        int offset = HEADER_SIZE;
        while (offset + BYTES_PER_LEVEL < frame.length - 1) {
            frame[offset] = 0x01; // nested present
            frame[offset + 1] = TYPE_DATA_RESPONSE;
            offset += BYTES_PER_LEVEL;
        }
        frame[4] = TYPE_DATA_RESPONSE;
    }

    private void saveToDisk(byte[] data, String filename) {
        try {
            File f = new File(outputDir, filename);
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(data);
            }
        } catch (IOException e) {
            log.println("[V3] Warning: could not save " + filename + ": " + e.getMessage());
        }
    }

    private void saveCorpusEntry(byte[] data) {
        try {
            File corpusDir = new File(outputDir, "corpus");
            File f = new File(corpusDir, String.format("id_%06d.bin", trialCount));
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(data);
            }
        } catch (IOException e) { /* ignore */ }
    }
}
