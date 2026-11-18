package com.fuzzing.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.AdviceAdapter;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * Java agent that instruments CachedOutputStream.writeCacheTo(StringBuilder, String)
 * to measure the number of characters appended — the allocation at the vulnerability's sink.
 *
 * Measurement-only ([R37]): does not generate inputs or embed payloads.
 */
public class V1MeasureAgent {

    private static final String TARGET_CLASS = "org/apache/cxf/io/CachedOutputStream";
    private static final String TARGET_METHOD = "writeCacheTo";
    private static final String TARGET_DESC = "(Ljava/lang/StringBuilder;Ljava/lang/String;)V";

    private static final String COUNTERS_CLASS = "com/fuzzing/agent/V1Counters";

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new WriteCacheToTransformer(), false);
    }

    private static class WriteCacheToTransformer implements ClassFileTransformer {
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
                ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                     String signature, String[] exceptions) {
                        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                        if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                            return new WriteCacheToAdvice(Opcodes.ASM9, mv, access, name, descriptor);
                        }
                        return mv;
                    }
                };
                cr.accept(cv, ClassReader.EXPAND_FRAMES);
                return cw.toByteArray();
            } catch (Exception e) {
                System.err.println("[V1MeasureAgent] Failed to transform " + className + ": " + e);
                return null;
            }
        }
    }

    /**
     * AdviceAdapter that injects V1Counters.onEntry(sb) at method entry
     * and V1Counters.onExit(sb) at method exit (both normal and exceptional).
     *
     * The method signature is: void writeCacheTo(StringBuilder out, String charsetName)
     * 'this' is slot 0, 'out' (StringBuilder) is slot 1, 'charsetName' is slot 2.
     */
    private static class WriteCacheToAdvice extends AdviceAdapter {

        WriteCacheToAdvice(int api, MethodVisitor mv, int access, String name, String desc) {
            super(api, mv, access, name, desc);
        }

        @Override
        protected void onMethodEnter() {
            // V1Counters.onEntry(out)  — 'out' is arg index 0 (first non-this param)
            loadArg(0); // push StringBuilder (slot 1 for instance method)
            invokeStatic(
                org.objectweb.asm.Type.getObjectType(COUNTERS_CLASS),
                new org.objectweb.asm.commons.Method("onEntry", "(Ljava/lang/StringBuilder;)V")
            );
        }

        @Override
        protected void onMethodExit(int opcode) {
            // V1Counters.onExit(out) — called on both RETURN and ATHROW
            loadArg(0);
            invokeStatic(
                org.objectweb.asm.Type.getObjectType(COUNTERS_CLASS),
                new org.objectweb.asm.commons.Method("onExit", "(Ljava/lang/StringBuilder;)V")
            );
        }
    }
}
