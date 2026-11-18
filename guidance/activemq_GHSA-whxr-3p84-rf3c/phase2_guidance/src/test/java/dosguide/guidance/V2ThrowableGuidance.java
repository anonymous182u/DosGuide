package dosguide.guidance;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
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
 * V2 Guidance: targets unbounded throwable recursion in
 * BaseDataStreamMarshaller.looseUnmarsalThrowable.
 *
 * Signal: throwableDepth — the max recursion depth, measured by the custom Java agent
 * instrumenting entry/exit of looseUnmarsalThrowable.
 *
 * Strategy: signal-maximizing (VDF). Constructs valid ExceptionResponse frames (type 0x1F)
 * with stackTraceEnabled=true, building recursive throwable cause chains.
 *
 * Frame layout for ExceptionResponse:
 *   [0..3]  frameLength (int32 BE)
 *   [4]     dataType = 0x1F (ExceptionResponse = 31)
 *   [5..8]  commandId (int32 BE)
 *   [9]     responseRequired (boolean)
 *   [10..13] correlationId (int32 BE)
 *   [14..]  throwable chain via looseUnmarsalThrowable
 *
 * Each throwable level (minimal, with stackTraceEnabled=true):
 *   [0]     present: boolean true (0x01)
 *   [1]     classString null: boolean false (0x00)
 *   [2]     messageString null: boolean false (0x00)
 *   [3..4]  stackTraceCount: short 0 (0x00 0x00)
 *   Then recurse for cause chain.
 *   Total: 5 bytes per level.
 *
 * Chain termination: boolean false (0x00) = 1 byte.
 */
public class V2ThrowableGuidance implements Guidance, SignalSource {

    private static final int HEADER_SIZE = 14; // frame prefix through correlationId
    private static final int BYTES_PER_LEVEL = 5;
    private static final byte TYPE_EXCEPTION_RESPONSE = 0x1F;

    // Dictionary tokens from the attack path source code
    private static final byte[][] DICTIONARY = {
        {0x1F},             // ExceptionResponse type byte (31)
        {0x01},             // boolean true (throwable present / cause present)
        {0x00},             // boolean false (null string / no more cause)
        {0x00, 0x00},       // zero stack trace count
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

    private double lastThrowableDepth = 0.0;
    private int bestThrowableDepth = 0;
    private byte[] bestInput;
    private int bestInputLength = 0;

    public V2ThrowableGuidance(File outputDir, long maxDurationMs, PrintStream log) {
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

        // Seed: ExceptionResponse with 16 recursion levels
        byte[] seed = buildThrowableChain(16);
        corpus.add(seed);
        bestInput = seed;
        bestInputLength = seed.length;
    }

    /**
     * Build a valid ExceptionResponse frame with the given number of throwable recursion levels.
     */
    private byte[] buildThrowableChain(int levels) {
        int totalSize = HEADER_SIZE + levels * BYTES_PER_LEVEL + 1; // +1 for terminator
        totalSize = Math.min(totalSize, maxInputSize);
        byte[] frame = new byte[totalSize];

        // Header
        putInt(frame, 0, totalSize - 4); // frame length
        frame[4] = TYPE_EXCEPTION_RESPONSE;
        putInt(frame, 5, 1);     // commandId
        frame[9] = 0x00;        // responseRequired = false
        putInt(frame, 10, 0);   // correlationId

        // Throwable chain
        int offset = HEADER_SIZE;
        int actualLevels = (totalSize - HEADER_SIZE - 1) / BYTES_PER_LEVEL;
        for (int i = 0; i < actualLevels && offset + BYTES_PER_LEVEL < totalSize; i++) {
            frame[offset] = 0x01;      // throwable present = true
            frame[offset + 1] = 0x00;  // class string = null
            frame[offset + 2] = 0x00;  // message string = null
            frame[offset + 3] = 0x00;  // stack trace count high byte
            frame[offset + 4] = 0x00;  // stack trace count low byte
            offset += BYTES_PER_LEVEL;
        }
        // Terminator: no more cause
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
        int depth = SignalCollector.getThrowableDepth();
        this.lastThrowableDepth = (double) depth;

        boolean improved = false;
        if (depth > bestThrowableDepth) {
            bestThrowableDepth = depth;
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
            log.printf("[V2] trial=%d depth=%d bestDepth=%d inputLen=%d result=%s elapsed=%.1fs%n",
                trialCount, depth, bestThrowableDepth, currentInput.length,
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
        signals.put("throwableDepth", lastThrowableDepth);
        return signals;
    }

    // ── Mutation operators ──

    private byte[] mutate(byte[] input) {
        int op = rng.nextInt(100);

        if (op < 30) {
            // Op 1: Extend chain — add more recursion levels
            return mutateExtendChain(input);
        } else if (op < 50) {
            // Op 2: Maximize depth — build max-depth input
            return mutateMaximizeDepth(input);
        } else if (op < 65) {
            // Op 3: Repetition [R45] — duplicate throwable blocks
            return mutateRepetition(input);
        } else if (op < 78) {
            // Op 4: Byte-level random mutations
            return mutateRandomBytes(input);
        } else if (op < 88) {
            // Op 5: Dictionary token insertion [R45]
            return mutateDictionary(input);
        } else {
            // Op 6: Truncate chain (explore shorter chains)
            return mutateTruncate(input);
        }
    }

    /** Extend the throwable chain by inserting more 5-byte blocks. */
    private byte[] mutateExtendChain(byte[] input) {
        int levelsToAdd = 1 + rng.nextInt(64);
        int addBytes = levelsToAdd * BYTES_PER_LEVEL;
        int newLen = Math.min(input.length + addBytes, maxInputSize);
        int actualAdd = newLen - input.length;
        if (actualAdd <= 0) return input.clone();

        byte[] result = new byte[newLen];
        // Copy header
        int headerEnd = Math.min(HEADER_SIZE, input.length);
        System.arraycopy(input, 0, result, 0, headerEnd);

        // Build a full chain in the body
        int offset = HEADER_SIZE;
        int maxLevels = (newLen - HEADER_SIZE - 1) / BYTES_PER_LEVEL;
        for (int i = 0; i < maxLevels && offset + BYTES_PER_LEVEL < newLen; i++) {
            result[offset] = 0x01;
            result[offset + 1] = 0x00;
            result[offset + 2] = 0x00;
            result[offset + 3] = 0x00;
            result[offset + 4] = 0x00;
            offset += BYTES_PER_LEVEL;
        }
        if (offset < newLen) {
            result[offset] = 0x00; // terminator
        }
        putInt(result, 0, newLen - 4);
        return result;
    }

    /** Build maximum-depth chain filling the entire input budget. */
    private byte[] mutateMaximizeDepth(byte[] input) {
        int levels = (maxInputSize - HEADER_SIZE - 1) / BYTES_PER_LEVEL;
        return buildThrowableChain(levels);
    }

    /** [R45] Repetition: duplicate a region of throwable blocks. */
    private byte[] mutateRepetition(byte[] input) {
        if (input.length <= HEADER_SIZE + BYTES_PER_LEVEL) {
            return mutateExtendChain(input);
        }
        // Double the throwable body region
        int bodyStart = HEADER_SIZE;
        int bodyLen = input.length - bodyStart;
        int newLen = Math.min(input.length + bodyLen, maxInputSize);
        byte[] result = new byte[newLen];
        System.arraycopy(input, 0, result, 0, input.length);
        // Repeat body
        int src = bodyStart;
        for (int i = input.length; i < newLen; i++) {
            result[i] = input[src + ((i - input.length) % bodyLen)];
        }
        // Fix: ensure last byte is terminator and frame length is correct
        result[newLen - 1] = 0x00;
        putInt(result, 0, newLen - 4);
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
        // Repair header
        result[4] = TYPE_EXCEPTION_RESPONSE;
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
        result[4] = TYPE_EXCEPTION_RESPONSE;
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

    private void saveToDisk(byte[] data, String filename) {
        try {
            File f = new File(outputDir, filename);
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(data);
            }
        } catch (IOException e) {
            log.println("[V2] Warning: could not save " + filename + ": " + e.getMessage());
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
