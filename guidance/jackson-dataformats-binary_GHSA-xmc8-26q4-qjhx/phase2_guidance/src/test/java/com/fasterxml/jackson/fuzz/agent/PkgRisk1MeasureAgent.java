package com.fasterxml.jackson.fuzz.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent that instruments:
 *   - CBORParser._finishBytes(int) to measure allocation size (V1 signal)
 *   - BaseNodeDeserializer.deserializeArray/deserializeObject to measure nesting depth (PkgRisk1 signal)
 *
 * Usage: -javaagent:target/pkgrisk1-agent.jar
 */
public final class PkgRisk1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.err.println("[MeasureAgent] Loading measurement agent");
        inst.addTransformer(new AllocationSizeTransformer());
        System.err.println("[MeasureAgent] Registered AllocationSizeTransformer for CBORParser._finishBytes");
        inst.addTransformer(new NestingDepthTransformer());
        System.err.println("[MeasureAgent] Registered NestingDepthTransformer for BaseNodeDeserializer");
    }
}
