package fuzzing.agent;

import java.lang.instrument.Instrumentation;

/**
 * Combined Java agent that registers BOTH V1 and V2 transformers.
 * Saves the Instrumentation reference for possible retransformation.
 *
 * Usage: -javaagent:target/dos-measure-agent.jar
 */
public class CombinedMeasureAgent {

    private static volatile Instrumentation savedInst;

    public static void premain(String agentArgs, Instrumentation inst) {
        savedInst = inst;
        inst.addTransformer(new V1Transformer(), true);
        inst.addTransformer(new V2Transformer(), true);
        System.err.println("[CombinedMeasureAgent] Registered V1Transformer (JSONTokener#nextValue) "
                + "and V2Transformer (XML#parse)");
    }

    /**
     * Retransform already-loaded target classes. Called from the guidance
     * to handle the case where classes were loaded before the transformer
     * was registered, or by a classloader that bypasses Instrumentation.
     */
    public static void retransformIfNeeded() {
        Instrumentation inst = savedInst;
        if (inst == null) {
            System.err.println("[CombinedMeasureAgent] No Instrumentation available, skipping retransform");
            return;
        }
        try {
            for (Class<?> c : inst.getAllLoadedClasses()) {
                String name = c.getName();
                if ("org.json.JSONTokener".equals(name) || "org.json.XML".equals(name)) {
                    if (inst.isModifiableClass(c)) {
                        System.err.println("[CombinedMeasureAgent] Retransforming: " + name);
                        inst.retransformClasses(c);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[CombinedMeasureAgent] Retransform error: " + e);
        }
    }

    public static Instrumentation getInstrumentation() {
        return savedInst;
    }
}
