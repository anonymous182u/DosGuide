package com.googlecode.vfsjfilechooser2.fuzz.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;
import regexmeasure.RegexStepCounter;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance for V1 (ReDoS in VFSURIValidator.isValid via p_ftp2).
 *
 * <p>Hill-climbs the {@code regexSteps} signal (total Pattern$Node.match() calls)
 * measured by the V1MeasureAgent java agent. Retains the input that maximises
 * regex NFA step count, and mutates it with byte-level, chunk-repeat, dictionary
 * and crossover operators.
 *
 * <p>Implements {@link SignalSource} so DoSGuide can read per-execution signals.
 *
 * <p>Input model: raw bytes decoded as ISO-8859-1 by the frozen fuzz harness.
 */
public class V1Guidance implements Guidance, SignalSource {

    // ---- configuration ----
    private final int maxInputSize;
    private final long maxDurationMs;
    private final long startTimeMs;
    private final PrintStream log;
    private final File corpusDir;
    private final Random rng;

    // ---- state ----
    private long totalTrials;
    private byte[] bestInput;
    private long bestRegexSteps;
    private byte[] currentInput;
    private double lastRegexSteps;   // per-execution value for lastSignals()
    private long lastLogTimeMs;
    private long staleSince;         // trial count when bestRegexSteps was last improved

    // ---- dictionary tokens from VFSURIValidator source (lines 235-240) ----
    private static final byte[][] DICTIONARY = {
        bytes("ftp://"),  bytes("sftp://"),  bytes("http://"),  bytes("https://"),
        bytes("webdav://"), bytes("smb://"),
        bytes("FTP://"),  bytes("SFTP://"),  bytes("HTTP://"),  bytes("HTTPS://"),
        bytes("WEBDAV://"), bytes("SMB://"),
        bytes("a:"), bytes("a@"),
        bytes(":"),  bytes("@"),  bytes("/"),  bytes("!"),
        bytes("file://"), bytes("FILE://"),
    };

    /**
     * Seed input: protocol prefix + two (colon, at-sign) pairs + non-slash terminator.
     * This triggers a small amount of backtracking (regex fails because there is no
     * terminal {@code /path}), giving the hill-climb a non-zero starting gradient.
     * 15 bytes — fits within even a 16-byte MAX_INPUT_SIZE test.
     */
    private static final byte[] SEED = bytes("ftp://a:a@a:a@!");

    // ---- constructor ----

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.maxDurationMs = maxDurationMs;
        this.startTimeMs = System.currentTimeMillis();
        this.log = log;
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.rng = new Random();
        this.totalTrials = 0;
        // Respect maxInputSize for the seed
        this.bestInput = SEED.length <= maxInputSize
                ? SEED.clone()
                : Arrays.copyOf(SEED, maxInputSize);
        this.bestRegexSteps = 0;
        this.lastRegexSteps = 0;
        this.lastLogTimeMs = startTimeMs;
        this.staleSince = 0;
    }

    // ---- Guidance interface ----

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset the agent's counter before each execution
        RegexStepCounter.reset();

        if (totalTrials == 0) {
            currentInput = bestInput.clone();
        } else {
            currentInput = mutate(bestInput);
        }
        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
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
        long steps = RegexStepCounter.get();
        lastRegexSteps = (double) steps;

        boolean improved = false;

        if (steps > bestRegexSteps) {
            // Primary: hill-climb — retain input that maximises regexSteps
            bestRegexSteps = steps;
            bestInput = currentInput.clone();
            staleSince = totalTrials;
            improved = true;
            saveCorpusEntry(steps);
        } else if (bestRegexSteps == 0 && currentInput.length > bestInput.length) {
            // [R46] Signal at zero — retain longer inputs to cross the threshold
            bestInput = currentInput.clone();
            staleSince = totalTrials;
        } else if (totalTrials - staleSince > 500) {
            // Plateau escape: accept longer inputs at ≥90% of best signal
            if (steps >= (long) (bestRegexSteps * 0.9)
                    && currentInput.length > bestInput.length) {
                bestInput = currentInput.clone();
                staleSince = totalTrials;
            }
        }

        totalTrials++;

        // Structured log every 1 second
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            long elapsedSec = (now - startTimeMs) / 1000;
            log.printf("[V1] t=%ds trials=%d bestSteps=%d lastSteps=%d bestLen=%d improved=%s%n",
                    elapsedSec, totalTrials, bestRegexSteps, steps,
                    bestInput.length, improved);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: measurement is done by the java agent, not JQF tracing
        return new Consumer<TraceEvent>() {
            @Override
            public void accept(TraceEvent e) {
                // intentionally empty
            }
        };
    }

    // ---- SignalSource interface ----

    @Override
    public Map<String, Double> lastSignals() {
        // Per-execution value from the most recent handleResult, not a running total
        return Collections.singletonMap("regexSteps", lastRegexSteps);
    }

    // ---- mutation operators ----

    private byte[] mutate(byte[] parent) {
        byte[] result;
        double r = rng.nextDouble();

        if (r < 0.10) {
            result = byteFlip(parent);
        } else if (r < 0.20) {
            result = byteInsert(parent);
        } else if (r < 0.25) {
            result = byteDelete(parent);
        } else if (r < 0.55) {
            result = chunkRepeat(parent);
        } else if (r < 0.80) {
            result = dictInsert(parent);
        } else if (r < 0.90) {
            result = dictReplace(parent);
        } else {
            result = crossover(parent, SEED);
        }

        // Enforce max input size
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        // Ensure non-empty
        if (result.length == 0) {
            result = bestInput.clone();
        }
        return result;
    }

    /** Flip one random byte to a random value. */
    private byte[] byteFlip(byte[] parent) {
        if (parent.length == 0) return parent.clone();
        byte[] result = parent.clone();
        int pos = rng.nextInt(result.length);
        result[pos] = (byte) rng.nextInt(256);
        return result;
    }

    /** Insert one random byte at a random position. */
    private byte[] byteInsert(byte[] parent) {
        if (parent.length >= maxInputSize) return parent.clone();
        byte[] result = new byte[parent.length + 1];
        int pos = rng.nextInt(parent.length + 1);
        System.arraycopy(parent, 0, result, 0, pos);
        result[pos] = (byte) rng.nextInt(256);
        if (pos < parent.length) {
            System.arraycopy(parent, pos, result, pos + 1, parent.length - pos);
        }
        return result;
    }

    /** Delete one random byte (only if input is long enough). */
    private byte[] byteDelete(byte[] parent) {
        if (parent.length <= 10) return parent.clone();
        byte[] result = new byte[parent.length - 1];
        int pos = rng.nextInt(parent.length);
        System.arraycopy(parent, 0, result, 0, pos);
        if (pos < parent.length - 1) {
            System.arraycopy(parent, pos + 1, result, pos, parent.length - pos - 1);
        }
        return result;
    }

    /**
     * Repeat a contiguous chunk 2–8 times in place, or double the whole input.
     * This is the dominant operator (30% weight) because the ReDoS cost grows
     * with repeated colon/at-sign sequences.
     */
    private byte[] chunkRepeat(byte[] parent) {
        if (parent.length == 0) return parent.clone();

        // 15% chance of doubling the entire input (rapid growth toward input_bytes)
        if (rng.nextDouble() < 0.15 && parent.length * 2 <= maxInputSize) {
            byte[] doubled = new byte[parent.length * 2];
            System.arraycopy(parent, 0, doubled, 0, parent.length);
            System.arraycopy(parent, 0, doubled, parent.length, parent.length);
            return doubled;
        }

        int chunkSize;
        int repeats;
        if (rng.nextBoolean()) {
            // Small chunk: 1–64 bytes, 2–8 repeats (fine structure)
            chunkSize = 1 + rng.nextInt(Math.min(64, parent.length));
            repeats = 2 + rng.nextInt(7);
        } else {
            // Large chunk: up to half input, 2–4 repeats (rapid growth)
            int maxChunk = Math.max(1, parent.length / 2);
            chunkSize = 1 + rng.nextInt(maxChunk);
            repeats = 2 + rng.nextInt(3);
        }

        int start = rng.nextInt(parent.length - chunkSize + 1);
        int totalChunkBytes = chunkSize * repeats;
        int newLen = parent.length - chunkSize + totalChunkBytes;

        // Cap to maxInputSize
        if (newLen > maxInputSize) {
            repeats = (maxInputSize - parent.length + chunkSize) / chunkSize;
            if (repeats < 2) return parent.clone();
            totalChunkBytes = chunkSize * repeats;
            newLen = parent.length - chunkSize + totalChunkBytes;
        }

        byte[] result = new byte[newLen];
        // Copy before chunk
        System.arraycopy(parent, 0, result, 0, start);
        // Repeat chunk
        for (int i = 0; i < repeats; i++) {
            System.arraycopy(parent, start, result, start + i * chunkSize, chunkSize);
        }
        // Copy after original chunk
        int afterOrig = start + chunkSize;
        int afterNew = start + totalChunkBytes;
        if (afterOrig < parent.length) {
            System.arraycopy(parent, afterOrig, result, afterNew, parent.length - afterOrig);
        }
        return result;
    }

    /** Insert a dictionary token at a random position. */
    private byte[] dictInsert(byte[] parent) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int available = maxInputSize - parent.length;
        if (available <= 0) return parent.clone();
        if (token.length > available) {
            token = Arrays.copyOf(token, available);
        }
        int pos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[parent.length + token.length];
        System.arraycopy(parent, 0, result, 0, pos);
        System.arraycopy(token, 0, result, pos, token.length);
        if (pos < parent.length) {
            System.arraycopy(parent, pos, result, pos + token.length, parent.length - pos);
        }
        return result;
    }

    /** Overwrite bytes at a random position with a dictionary token. */
    private byte[] dictReplace(byte[] parent) {
        if (parent.length == 0) return parent.clone();
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(parent.length);
        byte[] result = parent.clone();
        int copyLen = Math.min(token.length, result.length - pos);
        System.arraycopy(token, 0, result, pos, copyLen);
        return result;
    }

    /** Splice a random segment from the donor (seed) into the parent. */
    private byte[] crossover(byte[] parent, byte[] donor) {
        if (donor.length == 0 || parent.length >= maxInputSize) return parent.clone();
        int srcStart = rng.nextInt(donor.length);
        int srcLen = 1 + rng.nextInt(donor.length - srcStart);
        int available = maxInputSize - parent.length;
        if (srcLen > available) {
            srcLen = available;
        }
        if (srcLen <= 0) return parent.clone();

        int dstPos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[parent.length + srcLen];
        System.arraycopy(parent, 0, result, 0, dstPos);
        System.arraycopy(donor, srcStart, result, dstPos, srcLen);
        if (dstPos < parent.length) {
            System.arraycopy(parent, dstPos, result, dstPos + srcLen, parent.length - dstPos);
        }
        return result;
    }

    // ---- helpers ----

    private void saveCorpusEntry(long steps) {
        try {
            File f = new File(corpusDir,
                    String.format("id_%06d_steps_%d", totalTrials, steps));
            FileOutputStream fos = new FileOutputStream(f);
            try {
                fos.write(currentInput);
            } finally {
                fos.close();
            }
        } catch (IOException e) {
            // best-effort save
        }
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }
}
