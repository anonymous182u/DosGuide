package fuzzing.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent entry point for V1 (JSON recursion depth measurement).
 * Registers V1Transformer to instrument org.json.JSONTokener#nextValue().
 *
 * Usage: -javaagent:target/v1-agent.jar
 */
public class V1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new V1Transformer());
        System.err.println("[V1MeasureAgent] Registered V1Transformer for JSONTokener#nextValue()");
    }
}
