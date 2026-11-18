package org.keycloak.fuzzing.agent;

import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.util.ArrayList;
import java.util.List;

/**
 * Java agent that measures regex NFA backtracking steps by instrumenting
 * every {@code java.util.regex.Pattern$*} inner class's {@code match()} method.
 * <p>
 * Measurement-only ([R37]): the agent never generates inputs or embeds payloads.
 * <p>
 * Bootstrap-classpath handling: {@code RegexStepCounter} is placed on the
 * bootstrap classpath via the {@code Boot-Class-Path} manifest attribute
 * (pointing to {@code regex-counter-boot.jar} — a tiny jar containing only
 * the counter class, located next to the agent jar).  This ensures that
 * instrumented bootstrap classes ({@code Pattern$Node} and subclasses) can
 * resolve the counter class regardless of how the agent is loaded.
 */
public class V1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.err.println("[V1Agent] premain() starting");

        // Step 1: force-load the transformer (and its ASM dependencies) via
        // the system classloader.  This must happen before we register it.
        PatternNodeTransformer transformer = new PatternNodeTransformer();

        // Step 2: register the transformer (with canRetransform=true so we
        // can retransform already-loaded Pattern$* classes).
        inst.addTransformer(transformer, true);
        System.err.println("[V1Agent] Registered PatternNodeTransformer");

        // Step 3: retransform any Pattern$* classes that are already loaded.
        // In some JVMs, Pattern inner classes may be loaded during init before
        // the agent's premain runs.
        List<Class<?>> toRetransform = new ArrayList<>();
        for (Class<?> c : inst.getAllLoadedClasses()) {
            String name = c.getName();
            if (name.startsWith("java.util.regex.Pattern$")
                    && inst.isModifiableClass(c)) {
                toRetransform.add(c);
            }
        }
        if (!toRetransform.isEmpty()) {
            System.err.println("[V1Agent] Retransforming " + toRetransform.size()
                    + " already-loaded Pattern$* classes");
            for (Class<?> c : toRetransform) {
                try {
                    inst.retransformClasses(c);
                } catch (UnmodifiableClassException e) {
                    System.err.println("[V1Agent] Could not retransform "
                            + c.getName() + ": " + e.getMessage());
                }
            }
        }

        System.err.println("[V1Agent] premain() done — regex step counting active");
    }
}
