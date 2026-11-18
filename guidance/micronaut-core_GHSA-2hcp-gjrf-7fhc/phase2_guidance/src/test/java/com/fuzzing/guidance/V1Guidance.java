package com.fuzzing.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance (CGF) for V1: hill-climbs totalAllocatedChars to maximise
 * unbounded ConcurrentHashMap cache growth in DefaultHtmlErrorResponseBodyProvider.
 *
 * Strategy:
 *   1. Start from a small seed corpus of line-delimited text.
 *   2. Mutate the current best input using byte-level, line-level, and dictionary operators.
 *   3. After each execution, read agent counters via System.getProperties().get("V1_COUNTERS").
 *   4. If totalAllocatedChars exceeds the current best, retain the input.
 *   5. Secondary: retain on new-max htmlCallCount.
 *   6. Tertiary (flat signal): retain if input is longer than current best (drives growth).
 *
 * Implements Guidance (JQF) and SignalSource (DoSGuide validation).
 */
public class V1Guidance implements Guidance, SignalSource {

    private static final int DEFAULT_MAX_INPUT_SIZE = 10240;

    private final int maxInputSize;
    private final long maxDurationMs;
    private final long startTimeMs;
    private final PrintStream log;
    private final File outputDir;
    private final Random random = new Random();

    // Agent counters: [0]=htmlCallCount, [1]=totalAllocatedChars
    private final long[] counters;

    // Hill-climbing state
    private byte[] bestInput;
    private double bestCost = -1;
    private long bestHtmlCalls = 0;
    private int bestLength = 0;
    private byte[] currentInput;
    private long totalExecs = 0;
    private long lastLogTimeMs;

    // Per-execution signal values (for SignalSource.lastSignals())
    private double lastTotalAllocatedChars = 0;
    private double lastHtmlCallCount = 0;

    // Dictionary tokens from the attack surface
    private static final byte[][] DICTIONARY = {
        "\n".getBytes(),
        "&".getBytes(),
        "<".getBytes(),
        ">".getBytes(),
        "\"".getBytes(),
        "'".getBytes(),
        ".error".getBytes(),
        ".".getBytes(),
        "Bad Request".getBytes(),
        "\r\n".getBytes(),
    };

    // Seed corpus (consumed before mutation begins)
    private final List<byte[]> seeds = new ArrayList<>();
    private int seedIndex = 0;

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.outputDir = outputDir;
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", DEFAULT_MAX_INPUT_SIZE);
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = startTimeMs;

        // Retrieve shared counters installed by the V1MeasureAgent
        Object obj = System.getProperties().get("V1_COUNTERS");
        if (obj instanceof long[]) {
            this.counters = (long[]) obj;
        } else {
            this.counters = new long[2];
            log.println("[V1Guidance] WARNING: V1_COUNTERS not found in System.getProperties() — agent may not be loaded");
        }

        // Ensure output directory exists
        outputDir.mkdirs();

        // Build seed corpus: diversity of unique-line inputs.
        // All seeds are truncated to maxInputSize.
        addSeed("abc\n".getBytes());
        addSeed("aa\nbb\ncc\ndd\nee\n".getBytes());

        // 100 unique 3-char lines
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sb.append(String.format("%03d", i)).append('\n');
        }
        addSeed(sb.toString().getBytes());

        bestInput = seeds.get(0);
        bestLength = bestInput.length;
    }

    /** Add a seed, truncating to maxInputSize. Seeds longer than maxInputSize are still
     *  added (truncated) so there is always at least one seed. */
    private void addSeed(byte[] raw) {
        if (raw.length > maxInputSize) {
            raw = Arrays.copyOf(raw, maxInputSize);
        }
        seeds.add(raw);
    }

    // ==================== Guidance interface ====================

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset counters before each execution
        counters[0] = 0;
        counters[1] = 0;

        if (seedIndex < seeds.size()) {
            currentInput = seeds.get(seedIndex++);
        } else {
            currentInput = mutate(bestInput);
        }

        // Hard enforcement: never exceed maxInputSize
        if (currentInput.length > maxInputSize) {
            currentInput = Arrays.copyOf(currentInput, maxInputSize);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        long elapsed = System.currentTimeMillis() - startTimeMs;
        return elapsed < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;

        long htmlCalls = counters[0];
        long totalChars = counters[1];

        // Store per-execution values for SignalSource
        lastTotalAllocatedChars = (double) totalChars;
        lastHtmlCallCount = (double) htmlCalls;

        // Retention logic (multi-criteria hill-climbing):
        double cost = totalChars;
        boolean retained = false;

        // Primary: higher totalAllocatedChars
        if (cost > bestCost) {
            bestCost = cost;
            bestHtmlCalls = htmlCalls;
            bestLength = currentInput.length;
            bestInput = Arrays.copyOf(currentInput, currentInput.length);
            retained = true;
        }
        // Secondary: new-max htmlCallCount
        else if (htmlCalls > bestHtmlCalls) {
            bestHtmlCalls = htmlCalls;
            bestLength = currentInput.length;
            bestInput = Arrays.copyOf(currentInput, currentInput.length);
            retained = true;
        }
        // Tertiary (growth): keep longer inputs even when signal is flat.
        // This drives the input toward input_bytes when the signal hasn't risen yet
        // (e.g. duplicated lines that don't create new cache entries but grow the input).
        else if (currentInput.length > bestLength) {
            bestLength = currentInput.length;
            bestInput = Arrays.copyOf(currentInput, currentInput.length);
            retained = true;
        }

        if (retained) {
            saveBestInput();
        }

        // Log every 1 second
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            long elapsedSec = (now - startTimeMs) / 1000;
            log.printf("[V1Guidance] %ds | execs=%d | best_cost=%.0f | cur_cost=%.0f | " +
                       "cur_htmlCalls=%d | best_htmlCalls=%d | best_len=%d | cur_len=%d%n",
                       elapsedSec, totalExecs, bestCost, cost,
                       htmlCalls, bestHtmlCalls, bestInput.length, currentInput.length);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: we use our own bytecode instrumentation via the Java agent,
        // not JQF's coverage-guided tracing.
        return e -> {};
    }

    // ==================== SignalSource interface ====================

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new LinkedHashMap<>();
        signals.put("totalAllocatedChars", lastTotalAllocatedChars);
        signals.put("htmlCallCount", lastHtmlCallCount);
        return signals;
    }

    // ==================== Persistence ====================

    private void saveBestInput() {
        try {
            Files.write(outputDir.toPath().resolve("best_input.bin"), bestInput);
        } catch (IOException e) {
            // best-effort save; ignore failures
        }
    }

    // ==================== Mutation operators ====================

    /**
     * Select and apply a random mutation operator to the given input.
     * Growth operators are heavily weighted and scale with remaining capacity
     * to reach maxInputSize quickly.
     */
    private byte[] mutate(byte[] input) {
        // If far from maxInputSize, strongly favour growth operators
        double fillRatio = (double) input.length / maxInputSize;
        int op = random.nextInt(100);
        byte[] result;

        if (fillRatio < 0.8) {
            // Growth phase: heavily favour operators that increase size
            if (op < 5) {
                result = mutateByteFlip(input);           // 5%
            } else if (op < 8) {
                result = mutateByteInsert(input);          // 3%
            } else if (op < 10) {
                result = mutateByteDelete(input);          // 2%
            } else if (op < 14) {
                result = mutateBlockOverwrite(input);      // 4%
            } else if (op < 24) {
                result = mutateLineDuplicate(input);       // 10%
            } else if (op < 44) {
                result = mutateDoubleInput(input);         // 20%
            } else if (op < 50) {
                result = mutateDictionary(input);          // 6%
            } else if (op < 80) {
                result = mutateNewUniqueLines(input);      // 30%
            } else {
                result = mutateSpliceNewLines(input);      // 20%
            }
        } else {
            // Refinement phase: input is near max, diversify content
            if (op < 12) {
                result = mutateByteFlip(input);           // 12%
            } else if (op < 18) {
                result = mutateByteInsert(input);          // 6%
            } else if (op < 22) {
                result = mutateByteDelete(input);          // 4%
            } else if (op < 34) {
                result = mutateBlockOverwrite(input);      // 12%
            } else if (op < 50) {
                result = mutateLineDuplicate(input);       // 16%
            } else if (op < 62) {
                result = mutateDictionary(input);          // 12%
            } else if (op < 80) {
                result = mutateNewUniqueLines(input);      // 18%
            } else {
                result = mutateSpliceNewLines(input);      // 20%
            }
        }

        // Enforce max input size
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        // Ensure non-empty
        if (result.length == 0) {
            result = "a\n".getBytes();
        }

        return result;
    }

    /** Flip a random bit in a random byte. */
    private byte[] mutateByteFlip(byte[] input) {
        if (input.length == 0) return input;
        byte[] out = Arrays.copyOf(input, input.length);
        int pos = random.nextInt(out.length);
        out[pos] ^= (byte) (1 << random.nextInt(8));
        return out;
    }

    /** Insert one random byte at a random position. */
    private byte[] mutateByteInsert(byte[] input) {
        if (input.length >= maxInputSize) return input;
        byte[] out = new byte[input.length + 1];
        int pos = random.nextInt(input.length + 1);
        System.arraycopy(input, 0, out, 0, pos);
        out[pos] = (byte) random.nextInt(256);
        System.arraycopy(input, pos, out, pos + 1, input.length - pos);
        return out;
    }

    /** Delete one random byte. */
    private byte[] mutateByteDelete(byte[] input) {
        if (input.length <= 1) return input;
        byte[] out = new byte[input.length - 1];
        int pos = random.nextInt(input.length);
        System.arraycopy(input, 0, out, 0, pos);
        System.arraycopy(input, pos + 1, out, pos, input.length - pos - 1);
        return out;
    }

    /** Overwrite a contiguous block of 1-16 bytes with random data. */
    private byte[] mutateBlockOverwrite(byte[] input) {
        if (input.length < 2) return input;
        byte[] out = Arrays.copyOf(input, input.length);
        int len = 1 + random.nextInt(Math.min(16, out.length));
        int pos = random.nextInt(out.length - len + 1);
        for (int i = 0; i < len; i++) {
            out[pos + i] = (byte) random.nextInt(256);
        }
        return out;
    }

    /**
     * Pick a random line and duplicate it k times.
     * Duplicated lines are identical → same cache key → no cost increase,
     * but they grow the input toward maxInputSize. Byte-level mutations on
     * duplicated lines later create new unique keys.
     */
    private byte[] mutateLineDuplicate(byte[] input) {
        List<int[]> lines = findLines(input);
        if (lines.isEmpty()) return input;

        int[] line = lines.get(random.nextInt(lines.size()));
        int lineLen = line[1] - line[0];
        if (lineLen == 0) return input;

        // Fill as much remaining space as possible with copies
        int remaining = maxInputSize - input.length;
        if (remaining <= 0) return input;
        int k = Math.min(1 + random.nextInt(Math.max(1, remaining / lineLen)),
                         remaining / lineLen);
        if (k <= 0) return input;

        int newLen = input.length + lineLen * k;
        byte[] out = new byte[newLen];
        System.arraycopy(input, 0, out, 0, line[1]);
        int pos = line[1];
        for (int i = 0; i < k; i++) {
            System.arraycopy(input, line[0], out, pos, lineLen);
            pos += lineLen;
        }
        System.arraycopy(input, line[1], out, pos, input.length - line[1]);
        return out;
    }

    /**
     * Double (or extend) the entire input by repeating it, up to maxInputSize.
     * Does NOT give up when 2*len > maxInputSize — fills to the limit instead.
     */
    private byte[] mutateDoubleInput(byte[] input) {
        if (input.length >= maxInputSize) return input;
        if (input.length == 0) return input;
        int newLen = (int) Math.min((long) input.length * 2, maxInputSize);
        byte[] out = new byte[newLen];
        int pos = 0;
        while (pos < newLen) {
            int toCopy = Math.min(input.length, newLen - pos);
            System.arraycopy(input, 0, out, pos, toCopy);
            pos += toCopy;
        }
        return out;
    }

    /** Insert a random dictionary token at a random position. */
    private byte[] mutateDictionary(byte[] input) {
        byte[] token = DICTIONARY[random.nextInt(DICTIONARY.length)];
        if ((long) input.length + token.length > maxInputSize) return input;
        int pos = random.nextInt(input.length + 1);
        byte[] out = new byte[input.length + token.length];
        System.arraycopy(input, 0, out, 0, pos);
        System.arraycopy(token, 0, out, pos, token.length);
        System.arraycopy(input, pos, out, pos + token.length, input.length - pos);
        return out;
    }

    /**
     * Append new random unique printable-ASCII lines to fill a large portion
     * of the remaining capacity. Each line is 2-6 chars of ASCII 0x21..0x7E + '\n'.
     * These create new, distinct cache keys → immediate cost increase.
     *
     * The amount added scales with remaining capacity: fills 10-100% of
     * (maxInputSize - input.length), so a single application can grow the
     * input from near-empty to near-max.
     */
    private byte[] mutateNewUniqueLines(byte[] input) {
        int remaining = maxInputSize - input.length;
        if (remaining <= 0) return input;

        // Fill between 10% and 100% of remaining capacity
        int targetBytes = Math.max(20, remaining / (1 + random.nextInt(10)));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length + targetBytes);
        baos.writeBytes(input);
        int added = 0;
        while (added < targetBytes && baos.size() < maxInputSize) {
            int lineLen = 2 + random.nextInt(5);
            for (int j = 0; j < lineLen; j++) {
                baos.write(0x21 + random.nextInt(0x5E)); // printable ASCII ! through ~
            }
            baos.write('\n');
            added += lineLen + 1;
        }
        byte[] result = baos.toByteArray();
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    /**
     * Replace the middle of the input with fresh unique lines, filling
     * up to maxInputSize.
     */
    private byte[] mutateSpliceNewLines(byte[] input) {
        if (input.length < 4) return mutateNewUniqueLines(input);

        int spliceStart = random.nextInt(input.length / 2);
        int spliceEnd = input.length / 2 + random.nextInt(input.length / 2);
        int tailLen = input.length - spliceEnd;

        // Target filling to maxInputSize
        int targetMid = maxInputSize - spliceStart - tailLen;
        if (targetMid <= 0) targetMid = 100;
        // Fill 10-100% of the target middle
        int fillBytes = Math.max(20, targetMid / (1 + random.nextInt(10)));

        ByteArrayOutputStream baos = new ByteArrayOutputStream(spliceStart + fillBytes + tailLen);
        baos.writeBytes(Arrays.copyOfRange(input, 0, spliceStart));
        int added = 0;
        while (added < fillBytes && baos.size() + tailLen < maxInputSize) {
            int lineLen = 2 + random.nextInt(5);
            for (int j = 0; j < lineLen; j++) {
                baos.write(0x21 + random.nextInt(0x5E));
            }
            baos.write('\n');
            added += lineLen + 1;
        }
        if (spliceEnd < input.length) {
            // Only append tail if it fits
            int remaining = maxInputSize - baos.size();
            int toCopy = Math.min(tailLen, remaining);
            if (toCopy > 0) {
                baos.writeBytes(Arrays.copyOfRange(input, spliceEnd, spliceEnd + toCopy));
            }
        }
        byte[] result = baos.toByteArray();
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    /** Find [start, end) byte ranges of lines (delimited by '\n'). */
    private List<int[]> findLines(byte[] input) {
        List<int[]> lines = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < input.length; i++) {
            if (input[i] == '\n') {
                lines.add(new int[]{start, i + 1});
                start = i + 1;
            }
        }
        if (start < input.length) {
            lines.add(new int[]{start, input.length});
        }
        return lines;
    }
}
