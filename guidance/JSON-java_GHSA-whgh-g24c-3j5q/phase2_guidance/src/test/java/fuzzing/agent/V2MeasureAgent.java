package fuzzing.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent entry point for V2 (XML recursion depth measurement).
 * Registers V2Transformer to instrument org.json.XML#parse().
 *
 * Usage: -javaagent:target/v2-agent.jar
 */
public class V2MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new V2Transformer());
        System.err.println("[V2MeasureAgent] Registered V2Transformer for XML#parse()");
    }
}
