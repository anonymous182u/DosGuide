package fuzz.guidance;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import dosguide.validate.SignalSource;
import fuzz.agent.DToACounters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Consumer;

/**
 * Abstract Cost-Gradient Fuzzing (CGF) guidance base class.
 *
 * Provides:
 *   - Corpus management with cost-based selection
 *   - Byte-level + IEEE754-aware mutation operators
 *   - Dictionary of DoS-inducing boundary doubles
 *   - Counter reset/read lifecycle integration with DToACounters
 *   - Duration-based termination (maxDurationMs)
 *
 * Subclasses define:
 *   - Minimum input size
 *   - Which DToACounters signals to read
 *   - How to compute cost from signals
 */
public abstract class AbstractCGFGuidance implements Guidance, SignalSource {

    // --- Configuration ---
    protected final File outputDir;
    protected final long maxDurationMs;
    protected final int maxInputSize;
    protected final Random random;
    protected final PrintStream log;

    // --- Timing ---
    private long startTimeMs = -1;

    // --- State ---
    protected long numTrials;
    protected byte[] currentInput;
    protected final List<byte[]> corpus = new ArrayList<>();
    protected final List<Double> corpusCosts = new ArrayList<>();
    protected double bestCost = 0.0;

    // --- Per-execution signals ---
    private Map<String, Double> lastSignals = Collections.emptyMap();

    // --- Dictionary of interesting doubles for mutation ---
    protected static final double[] DICTIONARY_DOUBLES = {
            Double.MAX_VALUE,                              // 1.7976931348623157E308
            Double.MIN_VALUE,                              // 4.9E-324 (smallest subnormal)
            Double.MIN_NORMAL,                             // 2.2250738585072014E-308
            Double.longBitsToDouble(0x000FFFFFFFFFFFFFL),  // largest subnormal
            1e20, 1e50, 1e100, 1e200, 1e308,
            -1e20, -1e100, -1e200, -1e308,
            0.1, 0.01, 0.001, 1e-10, 1e-100, 1e-300,
            Double.POSITIVE_INFINITY,
            Double.NEGATIVE_INFINITY,
            0.0, -0.0,
            Math.PI, Math.E,
            // Doubles with maximum mantissa at various exponents
            Double.longBitsToDouble(0x7FEFFFFFFFFFFFFFL),  // MAX_VALUE
            Double.longBitsToDouble(0x4340000000000000L),  // 2^53 (exact integer boundary)
            Double.longBitsToDouble(0x4330000000000000L),  // 2^52
            Double.longBitsToDouble(0x3FF0000000000001L),  // 1.0 + ulp
            Double.longBitsToDouble(0xFFEFFFFFFFFFFFFFl),  // -MAX_VALUE
    };

    /**
     * Full constructor used by DoSGuide factory.
     */
    protected AbstractCGFGuidance(File outputDir, long maxDurationMs,
                                  Random random, PrintStream log) {
        this.outputDir = outputDir;
        this.maxDurationMs = maxDurationMs;
        this.random = random;
        this.log = log != null ? log : System.out;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
    }

    /**
     * Backward-compatible constructor used by FuzzRunner (frozen).
     * Uses maxTrials as a duration estimate (ms) and defaults for outputDir/log.
     */
    protected AbstractCGFGuidance(long maxTrials, Random random) {
        this(null, maxTrials, random, System.out);
    }

    // --- Abstract methods for subclasses ---

    /** Minimum input bytes required by the harness method. */
    protected abstract int minInputSize();

    /** Read the relevant DToACounters and return as a signal map. */
    protected abstract Map<String, Double> readSignals();

    /** Compute a scalar cost from the signal map (higher = more expensive). */
    protected abstract double computeCost(Map<String, Double> signals);

    // --- Guidance interface ---

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Initialize start time on first call
        if (startTimeMs < 0) {
            startTimeMs = System.currentTimeMillis();
        }

        // Reset counters before each execution
        DToACounters.reset();

        // Generate or mutate input
        currentInput = generateOrMutate();
        numTrials++;
        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (startTimeMs < 0) {
            return true; // haven't started yet
        }
        return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        // Read signals from the completed execution
        Map<String, Double> signals = readSignals();
        double cost = computeCost(signals);
        signals.put("cost", cost);
        lastSignals = signals;

        // Log progress periodically
        if (numTrials % 1000 == 0 || cost > bestCost) {
            if (cost > bestCost) {
                log.printf("[CGF] Trial %d: NEW BEST cost=%.2f signals=%s%n",
                        numTrials, cost, signals);
            } else if (numTrials % 1000 == 0) {
                log.printf("[CGF] Trial %d: bestCost=%.2f corpusSize=%d%n",
                        numTrials, bestCost, corpus.size());
            }
        }

        // Update corpus: keep inputs that improve cost or show interesting behavior
        if (result == Result.SUCCESS || result == Result.FAILURE) {
            if (cost > 0 && corpus.isEmpty()) {
                // Seed the corpus with the first non-zero-cost input
                addToCorpus(currentInput, cost);
            } else if (cost > bestCost) {
                // New best — always add
                addToCorpus(currentInput, cost);
                bestCost = cost;
            } else if (cost > bestCost * 0.8 && corpus.size() < 200) {
                // Within 80% of best — add for diversity (up to corpus cap)
                addToCorpus(currentInput, cost);
            }
        }

        // Handle timeout as a high-value result (potential DoS!)
        if (result == Result.TIMEOUT) {
            double timeoutCost = 1e9; // very high cost
            signals.put("timeout", 1.0);
            signals.put("cost", timeoutCost);
            lastSignals = signals;
            addToCorpus(currentInput, timeoutCost);
            bestCost = Math.max(bestCost, timeoutCost);
            log.printf("[CGF] Trial %d: TIMEOUT detected! Input saved.%n", numTrials);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No coverage feedback needed — we use agent-instrumented cost as the signal
        return e -> { };
    }

    // --- SignalSource interface ---

    @Override
    public Map<String, Double> lastSignals() {
        return lastSignals != null ? Collections.unmodifiableMap(lastSignals) : Collections.emptyMap();
    }

    // --- Corpus management ---

    private void addToCorpus(byte[] input, double cost) {
        corpus.add(input.clone());
        corpusCosts.add(cost);
        // Prune if too large: remove lowest-cost entries
        while (corpus.size() > 200) {
            int minIdx = 0;
            double minCost = corpusCosts.get(0);
            for (int i = 1; i < corpusCosts.size(); i++) {
                if (corpusCosts.get(i) < minCost) {
                    minCost = corpusCosts.get(i);
                    minIdx = i;
                }
            }
            corpus.remove(minIdx);
            corpusCosts.remove(minIdx);
        }
    }

    // --- Input generation & mutation ---

    private byte[] generateOrMutate() {
        // 10% pure random, 90% mutation from corpus (when corpus is non-empty)
        if (corpus.isEmpty() || random.nextInt(10) == 0) {
            return generateRandom();
        }
        // Weighted selection: prefer higher-cost corpus entries
        byte[] seed = selectFromCorpus();
        return mutate(seed);
    }

    private byte[] selectFromCorpus() {
        // Tournament selection: pick 3 random, return the highest-cost one
        int bestIdx = random.nextInt(corpus.size());
        double best = corpusCosts.get(bestIdx);
        for (int i = 0; i < 2; i++) {
            int idx = random.nextInt(corpus.size());
            if (corpusCosts.get(idx) > best) {
                best = corpusCosts.get(idx);
                bestIdx = idx;
            }
        }
        return corpus.get(bestIdx);
    }

    protected byte[] generateRandom() {
        int size = minInputSize() + random.nextInt(32);
        size = Math.min(size, maxInputSize);
        byte[] data = new byte[size];
        random.nextBytes(data);
        return data;
    }

    protected byte[] mutate(byte[] seed) {
        byte[] m = seed.clone();
        // Ensure minimum size
        if (m.length < minInputSize()) {
            byte[] expanded = new byte[minInputSize()];
            System.arraycopy(m, 0, expanded, 0, Math.min(m.length, expanded.length));
            m = expanded;
        }

        // Apply 1-3 mutations
        int numMutations = 1 + random.nextInt(3);
        for (int n = 0; n < numMutations; n++) {
            int op = random.nextInt(7);
            switch (op) {
                case 0: // Single bit flip
                    m[random.nextInt(m.length)] ^= (byte) (1 << random.nextInt(8));
                    break;

                case 1: // Random byte overwrite (1-4 bytes)
                {
                    int start = random.nextInt(m.length);
                    int len = 1 + random.nextInt(Math.min(4, m.length - start));
                    for (int i = start; i < start + len; i++) {
                        m[i] = (byte) random.nextInt(256);
                    }
                    break;
                }

                case 2: // Dictionary double injection
                {
                    if (m.length >= 8) {
                        double d = DICTIONARY_DOUBLES[random.nextInt(DICTIONARY_DOUBLES.length)];
                        long bits = Double.doubleToRawLongBits(d);
                        ByteBuffer.wrap(m, 0, 8).putLong(bits);
                    }
                    break;
                }

                case 3: // IEEE754 exponent bit flip
                {
                    if (m.length >= 8) {
                        int expBit = 52 + random.nextInt(11); // exponent field: bits 52-62
                        long rawBits = ByteBuffer.wrap(m, 0, 8).getLong();
                        rawBits ^= (1L << expBit);
                        ByteBuffer.wrap(m, 0, 8).putLong(rawBits);
                    }
                    break;
                }

                case 4: // IEEE754 mantissa scramble
                {
                    if (m.length >= 8) {
                        long rawBits = ByteBuffer.wrap(m, 0, 8).getLong();
                        // Preserve sign+exponent (bits 63-52), randomize mantissa (bits 0-51)
                        long mantissaMask = (1L << 52) - 1;
                        rawBits = (rawBits & ~mantissaMask) | (random.nextLong() & mantissaMask);
                        ByteBuffer.wrap(m, 0, 8).putLong(rawBits);
                    }
                    break;
                }

                case 5: // Parameter byte mutation
                {
                    if (m.length > 8) {
                        // Randomize parameter byte(s) — try boundary values
                        int[] boundaries = {0, 1, 99, 100, 127, 128, 254, 255};
                        m[8] = (byte) boundaries[random.nextInt(boundaries.length)];
                    }
                    break;
                }

                case 6: // Targeted exponent maximization
                {
                    if (m.length >= 8) {
                        // Set exponent to near-maximum (0x7FE = 2046, max finite)
                        long rawBits = ByteBuffer.wrap(m, 0, 8).getLong();
                        long signBit = rawBits & (1L << 63);
                        long mantissa = rawBits & ((1L << 52) - 1);
                        // Random high exponent: 1023..2046
                        int exp = 1023 + random.nextInt(1024);
                        rawBits = signBit | ((long) exp << 52) | mantissa;
                        ByteBuffer.wrap(m, 0, 8).putLong(rawBits);
                    }
                    break;
                }
            }
        }
        return m;
    }
}
