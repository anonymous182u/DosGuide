package com.fuzzer.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent that registers the V1Transformer to instrument
 * {@code io.netty.handler.codec.compression.Snappy.decode(ByteBuf, ByteBuf)}.
 *
 * <p>Measurement-only: this agent observes execution and reports signals
 * via {@code V1Signal}. It does not generate inputs or embed payloads.</p>
 *
 * <p>Attach via: {@code -javaagent:target/v1-agent.jar}</p>
 */
public class V1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new V1Transformer(), false);
        System.err.println("[V1Agent] Transformer registered — will instrument Snappy.decode(ByteBuf,ByteBuf)");
    }
}
