package fuzz.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent that registers a ClassFileTransformer to instrument
 * {@code org.mozilla.javascript.DToA} at class-load time.
 *
 * Instrumentation targets:
 *   1. BigInteger.multiply / divideAndRemainder / pow calls → incrementBigIntOps()
 *   2. JS_dtoa entry/exit → timing via enterJsDtoa/exitJsDtoa
 *   3. JS_dtobasestr entry/exit → timing via enterJsDtobasestr/exitJsDtobasestr
 *   4. JS_dtostr entry/exit → timing via enterJsDtostr/exitJsDtostr
 *   5. pow5mult entry → incrementPow5mult()
 *
 * Agent jar manifest must contain:
 *   Premain-Class: fuzz.agent.DToAMeasureAgent
 */
public class DToAMeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.err.println("[DToAMeasureAgent] Installing DToA class transformer");
        inst.addTransformer(new DToAClassTransformer(), false);
    }
}
