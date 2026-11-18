package fuzz.guidance;

import fuzz.agent.DToACounters;

import java.io.File;
import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * Cost-Gradient Fuzzing guidance for V3 target: fuzzNumberFormatMethods.
 *
 * Target: all four Number formatting methods (toFixed/toString/toExponential/toPrecision)
 * Input: 10 bytes — bytes[0..7]=double, bytes[8]=param, bytes[9]=methodSel
 * Sinks: DToA.JS_dtoa, DToA.JS_dtobasestr, DToA.JS_dtostr (whichever applies)
 *
 * Signals:
 *   - bigIntOps: count of BigInteger multiply/divideAndRemainder/pow in DToA
 *   - sinkTimeNs: sum of all sink times (matches plan signal name)
 *   - dtoaTimeNs: cumulative wall-clock time inside JS_dtoa
 *   - dtobasestrTimeNs: cumulative wall-clock time inside JS_dtobasestr
 *   - dtostrTimeNs: cumulative wall-clock time inside JS_dtostr
 *   - pow5multCalls: count of pow5mult invocations
 */
public class V3Guidance extends AbstractCGFGuidance {

    public V3Guidance(File outputDir, long maxDurationMs, Random random, PrintStream log) {
        super(outputDir, maxDurationMs, random, log);
    }

    /** Backward-compatible constructor used by frozen FuzzRunner. */
    public V3Guidance(long maxTrials, Random random) {
        super(maxTrials, random);
    }

    @Override
    protected int minInputSize() {
        return 10;
    }

    @Override
    protected Map<String, Double> readSignals() {
        Map<String, Double> signals = new LinkedHashMap<>();
        long bigIntOps = DToACounters.getBigIntOps();
        long dtoaTimeNs = DToACounters.getJsDtoaTimeNs();
        long dtobasestrTimeNs = DToACounters.getJsDtobasestrTimeNs();
        long dtostrTimeNs = DToACounters.getJsDtostrTimeNs();
        long pow5multCalls = DToACounters.getPow5multCalls();
        long totalSinkTimeNs = dtoaTimeNs + dtobasestrTimeNs + dtostrTimeNs;

        signals.put("bigIntOps", (double) bigIntOps);
        signals.put("sinkTimeNs", (double) totalSinkTimeNs);
        signals.put("dtoaTimeNs", (double) dtoaTimeNs);
        signals.put("dtobasestrTimeNs", (double) dtobasestrTimeNs);
        signals.put("dtostrTimeNs", (double) dtostrTimeNs);
        signals.put("pow5multCalls", (double) pow5multCalls);
        return signals;
    }

    @Override
    protected double computeCost(Map<String, Double> signals) {
        double bigIntOps = signals.getOrDefault("bigIntOps", 0.0);
        double sinkTimeNs = signals.getOrDefault("sinkTimeNs", 0.0);
        // Primary: BigInteger operations (higher = more expensive)
        // Secondary: total wall-clock time across all sinks (normalized to ms)
        return bigIntOps * 1000.0 + sinkTimeNs / 1_000_000.0;
    }
}
