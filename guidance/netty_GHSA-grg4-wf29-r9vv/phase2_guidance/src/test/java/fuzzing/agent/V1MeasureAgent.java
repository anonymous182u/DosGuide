package fuzzing.agent;

import java.lang.instrument.Instrumentation;

/**
 * Measurement-only java agent for target V1. Attach with
 * {@code -javaagent:target/v1-agent.jar}. It registers {@link V1Transformer}, which rewrites
 * {@code io.netty.handler.codec.compression.Bzip2BlockDecompressor} so that its
 * {@code read()}, {@code blockLength()} and {@code checkCRC()} methods report to
 * {@code fuzzing.v1.V1Counters}. It never generates or alters inputs.
 */
public final class V1MeasureAgent {
    private V1MeasureAgent() { }

    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer(new V1Transformer(), false);
        System.err.println("[V1Agent] installed; instrumenting " + V1Transformer.TARGET_CLASS);
    }

    public static void agentmain(String args, Instrumentation inst) {
        premain(args, inst);
    }
}
