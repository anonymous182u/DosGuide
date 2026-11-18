package com.fuzzer.agent;

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
 * Custom Java agent that instruments QuotedQualityCSV.sort() to count
 * Double.compareTo() invocations — the exact comparison driving the
 * O(n^3) gnome-sort loop (CWE-407).
 *
 * Measurement-only: does not generate inputs or embed payloads ([R37]).
 * Uses ASM core (transitive via jqf-instrument) — NOT JQF's built-in agent ([R43]).
 */
public class V1MeasureAgent {

    private static final String TARGET_CLASS = "org/eclipse/jetty/http/QuotedQualityCSV";
    private static final String TARGET_METHOD = "sort";
    private static final String TARGET_DESC = "()V";

    public static void premain(String agentArgs, Instrumentation inst) {
        // Make V1Counters visible to all classloaders (QuotedQualityCSV may be
        // loaded by a different classloader than the test classes).
        try {
            String agentJarPath = V1MeasureAgent.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI().getPath();
            if (agentJarPath.endsWith(".jar")) {
                inst.appendToBootstrapClassLoaderSearch(new JarFile(agentJarPath));
            }
        } catch (Exception e) {
            // If we cannot add to bootstrap, V1Counters is still on the app classpath
            // which is sufficient when everything shares the same classloader.
        }

        inst.addTransformer(new SortComparisonTransformer(), false);
    }

    /**
     * ClassFileTransformer that intercepts QuotedQualityCSV and rewrites sort()
     * to increment V1Counters before every Double.compareTo call.
     */
    static class SortComparisonTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (!TARGET_CLASS.equals(className)) {
                return null; // no transformation
            }
            try {
                ClassReader cr = new ClassReader(classfileBuffer);
                ClassWriter cw = new ClassWriter(cr, 0);
                ClassVisitor cv = new SortInstrumentingClassVisitor(cw);
                cr.accept(cv, 0);
                return cw.toByteArray();
            } catch (Exception e) {
                System.err.println("[V1MeasureAgent] ERROR transforming " + className + ": " + e);
                return null; // return original on error
            }
        }
    }

    /**
     * ClassVisitor that delegates to a special MethodVisitor for sort()V.
     */
    static class SortInstrumentingClassVisitor extends ClassVisitor {
        SortInstrumentingClassVisitor(ClassVisitor cv) {
            super(Opcodes.ASM9, cv);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                return new SortMethodVisitor(mv);
            }
            return mv;
        }
    }

    /**
     * MethodVisitor for sort()V that inserts V1Counters.incrementComparisons()
     * before every INVOKEVIRTUAL java/lang/Double.compareTo:(Ljava/lang/Double;)I.
     */
    static class SortMethodVisitor extends MethodVisitor {
        SortMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name,
                                    String descriptor, boolean isInterface) {
            if (opcode == Opcodes.INVOKEVIRTUAL
                    && "java/lang/Double".equals(owner)
                    && "compareTo".equals(name)
                    && "(Ljava/lang/Double;)I".equals(descriptor)) {
                // Insert: V1Counters.incrementComparisons() before the compareTo call
                super.visitMethodInsn(
                        Opcodes.INVOKESTATIC,
                        "com/fuzzer/agent/V1Counters",
                        "incrementComparisons",
                        "()V",
                        false
                );
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }
}
