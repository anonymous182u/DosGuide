package fuzz.guidance;

import fuzz.agent.DToACounters;

import java.io.File;
import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * Cost-Gradient Fuzzing guidance for V2 target: fuzzNumberToStringRadix.
 *
 * Target: Number.prototype.toString(radix)
 * Input: 9 bytes — bytes[0..7]=double, bytes[8]=radix byte ((b & 0xFF) % 35 + 2)
 * Sink: DToA.JS_dtobasestr (fractional digit loop for non-decimal radix)
 *
 * Signals:
 *   - bigIntOps: count of BigInteger multiply/divideAndRemainder/pow in DToA
 *   - sinkTimeNs: cumulative wall-clock time inside JS_dtobasestr
 *   - pow5multCalls: count of pow5mult invocations
 */
public class V2Guidance extends AbstractCGFGuidance {

    public V2Guidance(File outputDir, long maxDurationMs, Random random, PrintStream log) {
        super(outputDir, maxDurationMs, random, log);
    }

    /** Backward-compatible constructor used by frozen FuzzRunner. */
    public V2Guidance(long maxTrials, Random random) {
        super(maxTrials, random);
    }

    @Override
    protected int minInputSize() {
        return 9;
    }

    @Override
    protected Map<String, Double> readSignals() {
        Map<String, Double> signals = new LinkedHashMap<>();
        signals.put("bigIntOps", (double) DToACounters.getBigIntOps());
        signals.put("sinkTimeNs", (double) DToACounters.getJsDtobasestrTimeNs());
        signals.put("pow5multCalls", (double) DToACounters.getPow5multCalls());
        return signals;
    }

    @Override
    protected double computeCost(Map<String, Double> signals) {
        double bigIntOps = signals.getOrDefault("bigIntOps", 0.0);
        double sinkTimeNs = signals.getOrDefault("sinkTimeNs", 0.0);
        // Primary: BigInteger operations (higher = more expensive)
        // Secondary: wall-clock time in JS_dtobasestr (normalized to ms)
        return bigIntOps * 1000.0 + sinkTimeNs / 1_000_000.0;
    }
}
