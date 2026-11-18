package fuzzing.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent that installs the V1DepthTransformer to measure
 * JSONML.parse() recursion depth.
 *
 * Usage: -javaagent:target/v1-agent.jar
 */
public class V1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new V1DepthTransformer(), false);
        System.err.println("[V1Agent] Installed JSONML.parse() depth transformer");
    }
}
