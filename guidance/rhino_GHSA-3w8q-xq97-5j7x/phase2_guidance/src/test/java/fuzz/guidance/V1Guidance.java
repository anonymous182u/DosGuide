package fuzz.guidance;

import fuzz.agent.DToACounters;

import java.io.File;
import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * Cost-Gradient Fuzzing guidance for V1 target: fuzzNumberToFixed.
 *
 * Target: Number.prototype.toFixed(digits)
 * Input: 9 bytes — bytes[0..7]=double, bytes[8]=precision (mod 101)
 * Sink: DToA.JS_dtoa (via JS_dtostr → JS_dtoa)
 *
 * Signals:
 *   - bigIntOps: count of BigInteger multiply/divideAndRemainder/pow in DToA
 *   - sinkTimeNs: cumulative wall-clock time inside JS_dtoa
 *   - pow5multCalls: count of pow5mult invocations
 */
public class V1Guidance extends AbstractCGFGuidance {

    public V1Guidance(File outputDir, long maxDurationMs, Random random, PrintStream log) {
        super(outputDir, maxDurationMs, random, log);
    }

    /** Backward-compatible constructor used by frozen FuzzRunner. */
    public V1Guidance(long maxTrials, Random random) {
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
        signals.put("sinkTimeNs", (double) DToACounters.getJsDtoaTimeNs());
        signals.put("pow5multCalls", (double) DToACounters.getPow5multCalls());
        signals.put("dtostrTimeNs", (double) DToACounters.getJsDtostrTimeNs());
        return signals;
    }

    @Override
    protected double computeCost(Map<String, Double> signals) {
        double bigIntOps = signals.getOrDefault("bigIntOps", 0.0);
        double sinkTimeNs = signals.getOrDefault("sinkTimeNs", 0.0);
        double dtostrTimeNs = signals.getOrDefault("dtostrTimeNs", 0.0);
        // Primary: BigInteger operations (higher = more expensive)
        // Secondary: wall-clock time in sink (normalized to ms)
        return bigIntOps * 1000.0 + (sinkTimeNs + dtostrTimeNs) / 1_000_000.0;
    }
}
