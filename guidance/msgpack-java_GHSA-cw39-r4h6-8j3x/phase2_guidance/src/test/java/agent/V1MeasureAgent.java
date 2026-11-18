package agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent premain entry point for V1 (recursion depth measurement).
 * Registers V1Transformer to instrument MessageUnpacker.unpackValue().
 * Measurement-only ([R37]): does not generate inputs or embed payloads.
 *
 * Usage: -javaagent:target/v1-agent.jar
 * No --add-opens flags needed (instruments application code, not JDK internals).
 */
public class V1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new V1Transformer(), true);
        // Attempt retransform if the class is already loaded
        for (Class<?> c : inst.getAllLoadedClasses()) {
            if ("org.msgpack.core.MessageUnpacker".equals(c.getName())) {
                try {
                    inst.retransformClasses(c);
                } catch (Exception e) {
                    System.err.println("[V1Agent] Retransform failed: " + e.getMessage());
                }
            }
        }
    }
}
