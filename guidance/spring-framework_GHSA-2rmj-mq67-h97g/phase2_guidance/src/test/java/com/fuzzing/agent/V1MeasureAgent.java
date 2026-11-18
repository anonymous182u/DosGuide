package com.fuzzing.agent;

import java.lang.instrument.Instrumentation;
import java.util.Collections;
import java.util.Set;

/**
 * Java agent that instruments java.util.regex.Pattern$Node.match() and all
 * subclass overrides to count regex VM steps via V1Counters.step().
 *
 * Usage: -javaagent:agent/v1-agent.jar
 *
 * The agent:
 * 1. V1Counters is on bootstrap classpath via Boot-Class-Path manifest attribute.
 * 2. Adds a read edge from java.base to the unnamed module (so Pattern code
 *    can call V1Counters.step()).
 * 3. Registers V1NodeTransformer to instrument Pattern inner classes.
 * 4. Retransforms any already-loaded Pattern inner classes.
 *
 * Measurement-only ([R37]).
 */
public final class V1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.err.println("[V1Agent] premain starting");

        // Step 1: V1Counters is already on bootstrap classpath via Boot-Class-Path
        //         manifest attribute (the JVM processes this before premain).
        //         Force-load it now so we can get its Module.
        try {
            Class<?> countersClass = Class.forName(
                    "com.fuzzing.agent.V1Counters", true, null);
            System.err.println("[V1Agent] V1Counters loaded from bootstrap CL: "
                    + countersClass.getClassLoader());

            // Step 2: Add read edge from java.base to V1Counters' module
            //         (unnamed module of bootstrap CL). Without this, java.base
            //         code (Pattern$Node) cannot access V1Counters.step().
            Module countersModule = countersClass.getModule();
            Module javaBase = Object.class.getModule();
            System.err.println("[V1Agent] countersModule=" + countersModule
                    + " javaBase=" + javaBase);

            inst.redefineModule(
                    javaBase,
                    Set.of(countersModule),           // extraReads
                    Collections.emptyMap(),            // extraExports
                    Collections.emptyMap(),            // extraOpens
                    Collections.emptySet(),            // extraUses
                    Collections.emptyMap()             // extraProvides
            );
            System.err.println("[V1Agent] Added read edge: java.base -> "
                    + countersModule);
        } catch (Throwable t) {
            System.err.println("[V1Agent] WARNING: Module setup failed: " + t);
            t.printStackTrace(System.err);
            // Continue anyway — transformer registration might still help
        }

        // Step 3: Register the transformer (with retransform capability)
        try {
            V1NodeTransformer transformer = new V1NodeTransformer();
            inst.addTransformer(transformer, true);
            System.err.println("[V1Agent] Transformer registered (canRetransform=true)");
        } catch (Throwable t) {
            System.err.println("[V1Agent] FATAL: Could not register transformer: " + t);
            t.printStackTrace(System.err);
            return; // Cannot proceed without transformer
        }

        // Step 4: Retransform any already-loaded Pattern inner classes
        try {
            int retransformed = 0;
            for (Class<?> loaded : inst.getAllLoadedClasses()) {
                String name = loaded.getName();
                if (name.startsWith("java.util.regex.Pattern$")) {
                    if (inst.isModifiableClass(loaded)) {
                        try {
                            inst.retransformClasses(loaded);
                            retransformed++;
                            System.err.println("[V1Agent] Retransformed: " + name);
                        } catch (Throwable t) {
                            System.err.println("[V1Agent] Could not retransform "
                                    + name + ": " + t);
                        }
                    }
                }
            }
            System.err.println("[V1Agent] Retransformed " + retransformed
                    + " already-loaded Pattern classes");
        } catch (Throwable t) {
            System.err.println("[V1Agent] WARNING: Retransform scan failed: " + t);
        }

        System.err.println("[V1Agent] premain complete — transformer active");
    }

    private V1MeasureAgent() { }
}
