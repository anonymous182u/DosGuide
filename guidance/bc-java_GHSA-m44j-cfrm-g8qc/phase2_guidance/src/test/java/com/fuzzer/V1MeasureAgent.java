package com.fuzzer;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.jar.JarFile;

/**
 * Custom Java agent that instruments ScalarUtil.addShifted_NP and
 * ScalarUtil.subShifted_NP to count iterations of the while loop
 * in Scalar25519.reduceBasisVar.
 *
 * Each call to either method == one loop iteration.
 * The count is exported via V1Counters.increment().
 *
 * Measurement-only: does not generate inputs or embed payloads [R37].
 */
public class V1MeasureAgent {

    private static final String TARGET_CLASS =
            "org/bouncycastle/math/ec/rfc8032/ScalarUtil";

    public static void premain(String agentArgs, Instrumentation inst) {
        try {
            // Add agent jar to bootstrap classpath so V1Counters is visible
            // to both the instrumented BC code and the Guidance on the app classpath
            String agentJarPath = V1MeasureAgent.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI()
                    .getPath();
            inst.appendToBootstrapClassLoaderSearch(new JarFile(agentJarPath));
        } catch (Exception e) {
            System.err.println("[V1MeasureAgent] WARNING: could not add to bootstrap: " + e);
            // Fall back: V1Counters may still work if classloaders share the class
        }

        inst.addTransformer(new ScalarUtilTransformer(), false);
    }

    /**
     * Transforms ScalarUtil: inserts a call to V1Counters.increment()
     * at the entry of addShifted_NP and subShifted_NP.
     */
    static class ScalarUtilTransformer implements ClassFileTransformer {

        @Override
        public byte[] transform(ClassLoader loader,
                                String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (!TARGET_CLASS.equals(className)) {
                return null; // don't transform
            }

            try {
                ClassReader cr = new ClassReader(classfileBuffer);
                ClassWriter cw = new ClassWriter(cr, 0);
                ClassVisitor cv = new InstrumentingClassVisitor(cw);
                cr.accept(cv, 0);
                return cw.toByteArray();
            } catch (Exception e) {
                System.err.println("[V1MeasureAgent] ERROR transforming " + className + ": " + e);
                return null;
            }
        }
    }

    /**
     * ClassVisitor that intercepts addShifted_NP and subShifted_NP methods.
     */
    static class InstrumentingClassVisitor extends ClassVisitor {

        InstrumentingClassVisitor(ClassVisitor cv) {
            super(Opcodes.ASM9, cv);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv != null && ("addShifted_NP".equals(name) || "subShifted_NP".equals(name))) {
                return new InstrumentingMethodVisitor(mv);
            }
            return mv;
        }
    }

    /**
     * MethodVisitor that injects V1Counters.increment() at method entry.
     */
    static class InstrumentingMethodVisitor extends MethodVisitor {

        InstrumentingMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // Insert: V1Counters.increment();
            mv.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    "com/fuzzer/V1Counters",
                    "increment",
                    "()V",
                    false
            );
        }
    }
}
