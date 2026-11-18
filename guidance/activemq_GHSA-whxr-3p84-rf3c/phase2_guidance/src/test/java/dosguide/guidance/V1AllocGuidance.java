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
 * V1 Guidance: targets unchecked allocation in BaseDataStreamMarshaller.looseUnmarshalByteArray.
 *
 * Signal: allocBytes — the size argument passed to new byte[size], measured by the custom
 * Java agent instrumenting the NEWARRAY bytecode instruction.
 *
 * Strategy: signal-maximizing (VDF + CGF). Constructs valid PartialCommand (type 0x3C) frames
 * and mutates the 4-byte allocation size field to maximize allocBytes.
 *
 * Input model: byte[]/InputStream only ([R31]).
 * No generators, no coverage guidance.
 */
public class V1AllocGuidance implements Guidance, SignalSource {

    // ── Frame layout for PartialCommand ──
    // [0..3]  frameLength (int32 BE): total payload length (bytes after this field)
    // [4]     dataType = 0x3C (PartialCommand = 60)
    // [5..8]  commandId (int32 BE)
    // [9]     data present: boolean (0x01 = true)
    // [10..13] allocSize (int32 BE): the 4-byte size passed to new byte[size]
    private static final int FRAME_SIZE = 14;
    private static final int TYPE_OFFSET = 4;
    private static final int BOOL_OFFSET = 9;
    private static final int ALLOC_OFFSET = 10;

    // Dictionary tokens from the attack path source code
    private static final byte[][] DICTIONARY = {
        {0x3C},       // PartialCommand type byte (60)
        {0x01},       // boolean true
        {0x00},       // boolean false / zero
        {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF}, // max int (-1 → NegativeArraySizeException)
    };

    private final Random rng;
    private final File outputDir;
    private final PrintStream log;
    private final long maxDurationMs;
    private final int maxInputSize;
    private final long startTime;

    // Corpus: list of inputs; best is always at index 0
    private final List<byte[]> corpus = new ArrayList<>();
    private byte[] currentInput;
    private long trialCount = 0;
    private long lastLogTime;

    // Signal tracking
    private double lastAllocBytes = 0.0;
    private long bestAllocBytes = 0;
    private byte[] bestInput;

    // Secondary: track best input length (for input_growth when signal is flat)
    private int bestInputLength = 0;

    public V1AllocGuidance(File outputDir, long maxDurationMs, PrintStream log) {
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

        // Seed: a valid PartialCommand frame with a moderate allocation (1 MB)
        byte[] seed = buildPartialCommandFrame(0x00100000); // 1 MB
        corpus.add(seed);
        bestInput = seed;
        bestInputLength = seed.length;
    }

    /**
     * Build a valid PartialCommand frame with the given allocation size.
     */
    private byte[] buildPartialCommandFrame(int allocSize) {
        byte[] frame = new byte[FRAME_SIZE];
        // frameLength = 10 (payload after the 4-byte length prefix)
        putInt(frame, 0, FRAME_SIZE - 4);
        frame[TYPE_OFFSET] = 0x3C; // PartialCommand type
        putInt(frame, 5, 1);       // commandId = 1
        frame[BOOL_OFFSET] = 0x01; // data present = true
        putInt(frame, ALLOC_OFFSET, allocSize);
        return frame;
    }

    private static void putInt(byte[] buf, int offset, int value) {
        buf[offset]     = (byte) (value >>> 24);
        buf[offset + 1] = (byte) (value >>> 16);
        buf[offset + 2] = (byte) (value >>> 8);
        buf[offset + 3] = (byte) (value);
    }

    private static int getInt(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 24)
             | ((buf[offset + 1] & 0xFF) << 16)
             | ((buf[offset + 2] & 0xFF) << 8)
             | (buf[offset + 3] & 0xFF);
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        SignalCollector.reset();
        trialCount++;

        if (trialCount == 1) {
            // First trial: use seed directly
            currentInput = corpus.get(0).clone();
        } else {
            // Pick a base from corpus and mutate
            byte[] base = corpus.get(rng.nextInt(corpus.size())).clone();
            currentInput = mutate(base);
        }

        // Enforce max input size
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
        return true; // run until time limit
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        long allocBytes = SignalCollector.getAllocBytes();
        this.lastAllocBytes = (double) allocBytes;

        boolean improved = false;

        if (allocBytes > bestAllocBytes) {
            bestAllocBytes = allocBytes;
            bestInput = currentInput.clone();
            improved = true;
        }

        // Secondary retention: input length growth (for [R46] flat signal progress)
        if (currentInput.length > bestInputLength && allocBytes >= 0) {
            bestInputLength = currentInput.length;
        }

        // Retain in corpus if improved or if we're still exploring structure
        if (improved || (corpus.size() < 20 && currentInput.length > bestInputLength - 2)) {
            corpus.add(currentInput.clone());
            if (corpus.size() > 50) {
                // Keep best + recent diverse inputs
                corpus.remove(1 + rng.nextInt(corpus.size() - 1));
            }
        }

        // Save best input to disk
        if (improved && outputDir != null) {
            saveToDisk(currentInput, "best_input.bin");
            saveCorpusEntry(currentInput);
        }

        // Logging every 1 second
        long now = System.currentTimeMillis();
        if (now - lastLogTime >= 1000) {
            lastLogTime = now;
            log.printf("[V1] trial=%d allocBytes=%d bestAlloc=%d inputLen=%d result=%s elapsed=%.1fs%n",
                trialCount, allocBytes, bestAllocBytes, currentInput.length,
                result, (now - startTime) / 1000.0);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: we use our custom agent, not JQF trace events
        return event -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        signals.put("allocBytes", lastAllocBytes);
        return signals;
    }

    // ── Mutation operators ──

    private byte[] mutate(byte[] input) {
        // Ensure the input is at least a valid PartialCommand frame
        if (input.length < FRAME_SIZE) {
            input = buildPartialCommandFrame(0x00100000);
        }

        int op = rng.nextInt(100);

        if (op < 30) {
            // Op 1: Double the allocation size
            return mutateDoubleAllocSize(input);
        } else if (op < 55) {
            // Op 2: Set alloc size to a specific large value
            return mutateSetLargeAllocSize(input);
        } else if (op < 70) {
            // Op 3: Random large int for allocation size
            return mutateRandomLargeAllocSize(input);
        } else if (op < 82) {
            // Op 4: Bit flip on alloc size field
            return mutateBitFlipAllocSize(input);
        } else if (op < 90) {
            // Op 5: Byte-level random mutations
            return mutateRandomBytes(input);
        } else if (op < 95) {
            // Op 6: Dictionary token insertion
            return mutateDictionaryInsert(input);
        } else {
            // Op 7: Repetition — duplicate region of input ([R45])
            return mutateRepetition(input);
        }
    }

    private byte[] mutateDoubleAllocSize(byte[] input) {
        byte[] result = input.clone();
        if (result.length >= FRAME_SIZE) {
            int currentSize = getInt(result, ALLOC_OFFSET);
            int newSize;
            if (currentSize <= 0 || currentSize > 0x3FFFFFFF) {
                newSize = 0x00100000; // reset to 1MB
            } else {
                newSize = currentSize * 2;
                if (newSize < 0 || newSize > 0x3FFFFFFF) {
                    newSize = 0x3C000000; // cap at 960 MB
                }
            }
            putInt(result, ALLOC_OFFSET, newSize);
            ensureFrameValid(result);
        }
        return result;
    }

    private byte[] mutateSetLargeAllocSize(byte[] input) {
        byte[] result = input.clone();
        if (result.length >= FRAME_SIZE) {
            int[] targets = {
                0x08000000,  // 128 MB
                0x10000000,  // 256 MB
                0x20000000,  // 512 MB
                0x30000000,  // 768 MB
                0x38000000,  // 896 MB
                0x3A000000,  // 928 MB
                0x3C000000,  // 960 MB
                0x3E000000,  // 1024 MB - 32 MB
                0x3FFFFFFF,  // max positive ~1023 MB
            };
            putInt(result, ALLOC_OFFSET, targets[rng.nextInt(targets.length)]);
            ensureFrameValid(result);
        }
        return result;
    }

    private byte[] mutateRandomLargeAllocSize(byte[] input) {
        byte[] result = input.clone();
        if (result.length >= FRAME_SIZE) {
            // Random int in [1MB, 1023MB]
            int allocSize = 0x00100000 + rng.nextInt(0x3FF00000);
            putInt(result, ALLOC_OFFSET, allocSize);
            ensureFrameValid(result);
        }
        return result;
    }

    private byte[] mutateBitFlipAllocSize(byte[] input) {
        byte[] result = input.clone();
        if (result.length >= FRAME_SIZE) {
            int byteIdx = ALLOC_OFFSET + rng.nextInt(4);
            int bitIdx = rng.nextInt(8);
            result[byteIdx] ^= (byte)(1 << bitIdx);
            // Ensure the value stays positive
            result[ALLOC_OFFSET] &= 0x7F;
            ensureFrameValid(result);
        }
        return result;
    }

    private byte[] mutateRandomBytes(byte[] input) {
        byte[] result = input.clone();
        int numMutations = 1 + rng.nextInt(3);
        for (int i = 0; i < numMutations; i++) {
            int idx = rng.nextInt(result.length);
            result[idx] = (byte) rng.nextInt(256);
        }
        // Repair critical frame fields to keep it valid
        ensureFrameValid(result);
        return result;
    }

    private byte[] mutateDictionaryInsert(byte[] input) {
        byte[] result = input.clone();
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        if (result.length >= token.length) {
            int pos = rng.nextInt(result.length - token.length + 1);
            System.arraycopy(token, 0, result, pos, token.length);
            ensureFrameValid(result);
        }
        return result;
    }

    /** [R45] Repetition operator: duplicate a region of the input. */
    private byte[] mutateRepetition(byte[] input) {
        if (input.length < 2) return input;
        // For V1, the frame is fixed at 14 bytes, so repetition is mostly
        // about generating longer inputs that still start with a valid frame.
        // We can duplicate the entire frame, but the parser only reads the first one.
        // Better: just return the input with a padded tail.
        int newLen = Math.min(input.length * 2, maxInputSize);
        byte[] result = new byte[newLen];
        System.arraycopy(input, 0, result, 0, Math.min(input.length, newLen));
        // Fill remainder with copies of the input
        for (int i = input.length; i < newLen; i++) {
            result[i] = input[i % input.length];
        }
        ensureFrameValid(result);
        return result;
    }

    /** Ensure the frame header bytes are valid for PartialCommand parsing. */
    private void ensureFrameValid(byte[] frame) {
        if (frame.length >= FRAME_SIZE) {
            // Fix frame length prefix
            putInt(frame, 0, frame.length - 4);
            // Ensure type is PartialCommand
            frame[TYPE_OFFSET] = 0x3C;
            // Ensure data-present boolean is true
            frame[BOOL_OFFSET] = 0x01;
            // Ensure allocSize is positive
            frame[ALLOC_OFFSET] &= 0x7F;
        }
    }

    private void saveToDisk(byte[] data, String filename) {
        try {
            File f = new File(outputDir, filename);
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(data);
            }
        } catch (IOException e) {
            log.println("[V1] Warning: could not save " + filename + ": " + e.getMessage());
        }
    }

    private void saveCorpusEntry(byte[] data) {
        try {
            File corpusDir = new File(outputDir, "corpus");
            File f = new File(corpusDir, String.format("id_%06d.bin", trialCount));
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(data);
            }
        } catch (IOException e) {
            // ignore
        }
    }
}
