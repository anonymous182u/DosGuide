package com.googlecode.vfsjfilechooser2.fuzz.agent;

import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.jar.JarFile;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ClassVisitor;

/**
 * Java agent that instruments {@code java.util.regex.Pattern$Node.match()} and all
 * overrides in Pattern's inner classes to count regex NFA state transitions via
 * {@link regexmeasure.RegexStepCounter}.
 *
 * <p>The agent JAR's {@code Boot-Class-Path} manifest attribute adds
 * {@code v1-counter.jar} (containing only {@code RegexStepCounter}) to the
 * bootstrap classpath, so instrumented {@code java.base} classes can call it.
 * The agent and ASM adapter classes stay on the system classpath so they can
 * find the ASM library in {@code target/dependency/}.
 *
 * <p>Usage: {@code -javaagent:target/v1-agent.jar}
 */
public class V1MeasureAgent implements ClassFileTransformer {

    private static final String TARGET_PREFIX = "java/util/regex/Pattern$";

    // ---- premain entry point ----

    public static void premain(String agentArgs, Instrumentation inst) {
        try {
            // Boot-Class-Path in MANIFEST.MF already adds v1-counter.jar to bootstrap CL.
            // As a fallback, also add it programmatically.
            addCounterToBootstrap(agentArgs, inst);

            // Register this transformer (retransform-capable)
            V1MeasureAgent transformer = new V1MeasureAgent();
            inst.addTransformer(transformer, true);

            // Retransform all already-loaded Pattern$ inner classes
            int count = 0;
            for (Class<?> c : inst.getAllLoadedClasses()) {
                String name = c.getName();
                if (name.startsWith("java.util.regex.Pattern$")
                        && inst.isModifiableClass(c)) {
                    try {
                        inst.retransformClasses(c);
                        count++;
                    } catch (Throwable t) {
                        System.err.println("[V1Agent] Cannot retransform "
                                + name + ": " + t);
                    }
                }
            }
            System.err.println("[V1Agent] Retransformed " + count
                    + " Pattern$ inner classes");

        } catch (Throwable t) {
            System.err.println("[V1Agent] premain failed: " + t);
            t.printStackTrace(System.err);
        }
    }

    /**
     * Adds the counter JAR (not the agent JAR!) to the bootstrap classpath.
     * The counter JAR contains only {@code RegexStepCounter} and has no
     * ASM dependencies, so it loads cleanly on the bootstrap classloader.
     */
    private static void addCounterToBootstrap(String agentArgs,
                                               Instrumentation inst) {
        try {
            // Find the agent JAR location
            File agentJar;
            if (agentArgs != null && !agentArgs.isEmpty()) {
                agentJar = new File(agentArgs);
            } else {
                agentJar = new File(V1MeasureAgent.class.getProtectionDomain()
                        .getCodeSource().getLocation().toURI());
            }

            // Counter JAR is next to the agent JAR
            File counterJar = new File(agentJar.getParentFile(), "v1-counter.jar");
            if (counterJar.isFile()) {
                inst.appendToBootstrapClassLoaderSearch(new JarFile(counterJar));
                System.err.println("[V1Agent] Added counter JAR to bootstrap: "
                        + counterJar.getAbsolutePath());
            } else {
                System.err.println("[V1Agent] Counter JAR not found at: "
                        + counterJar.getAbsolutePath()
                        + " (relying on Boot-Class-Path manifest attribute)");
            }
        } catch (Throwable t) {
            System.err.println("[V1Agent] WARNING: failed to add counter to bootstrap: " + t);
        }
    }

    // ---- ClassFileTransformer ----

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (className == null || !className.startsWith(TARGET_PREFIX)) {
            return null; // not a target — leave unchanged
        }
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            ClassVisitor cv = new NodeMatchAdapter(cw);
            cr.accept(cv, 0);
            byte[] result = cw.toByteArray();
            System.err.println("[V1Agent] Instrumented: " + className);
            return result;
        } catch (Throwable e) {
            System.err.println("[V1Agent] Error transforming " + className
                    + ": " + e);
            e.printStackTrace(System.err);
            return null; // return null = keep original bytecode
        }
    }
}
