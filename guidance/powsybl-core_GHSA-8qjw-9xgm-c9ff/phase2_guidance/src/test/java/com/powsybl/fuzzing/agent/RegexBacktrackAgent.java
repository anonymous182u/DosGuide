package com.powsybl.fuzzing.agent;

import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;

/**
 * Java agent that instruments {@code java.util.regex.Pattern$*} inner classes
 * to count NFA backtracking steps via {@code RegexStepCounter.increment()}.
 *
 * <p>Usage: {@code -javaagent:regex-agent.jar}</p>
 *
 * <p>The agent registers a {@link RegexNodeTransformer} and then retransforms
 * any already-loaded {@code Pattern$*} classes so that the instrumentation
 * takes effect even if Pattern was loaded before the agent.</p>
 *
 * <p>MANIFEST.MF requirements:</p>
 * <pre>
 * Premain-Class: com.powsybl.fuzzing.agent.RegexBacktrackAgent
 * Can-Retransform-Classes: true
 * Boot-Class-Path: regex-agent.jar &lt;path-to-asm-9.8.jar&gt;
 * </pre>
 */
public class RegexBacktrackAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[RegexBacktrackAgent] Installing NFA step counter instrumentation");

        RegexNodeTransformer transformer = new RegexNodeTransformer();
        inst.addTransformer(transformer, true);

        // Retransform already-loaded Pattern$* classes
        int retransformed = 0;
        for (Class<?> clazz : inst.getAllLoadedClasses()) {
            String name = clazz.getName();
            if (name.startsWith("java.util.regex.Pattern$")) {
                if (inst.isModifiableClass(clazz)) {
                    try {
                        inst.retransformClasses(clazz);
                        retransformed++;
                    } catch (UnmodifiableClassException e) {
                        System.err.println("[RegexBacktrackAgent] WARN: Cannot retransform "
                                + name + ": " + e.getMessage());
                    }
                }
            }
        }
        System.out.println("[RegexBacktrackAgent] Retransformed " + retransformed
                + " Pattern$* classes; transformer active for future loads");
    }
}
