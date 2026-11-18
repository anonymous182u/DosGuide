package com.fasterxml.jackson.fuzz.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based ClassFileTransformer that instruments CBORParser._finishBytes(int)
 * to record the allocation size parameter via AllocationSizeCounters.record().
 *
 * At the entry of _finishBytes(int len), inserts:
 *   ILOAD 1          // load len parameter
 *   I2L              // convert to long
 *   INVOKESTATIC AllocationSizeCounters.record(J)V
 */
public final class AllocationSizeTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS =
            "com/fasterxml/jackson/dataformat/cbor/CBORParser";

    private static final String COUNTERS_CLASS =
            "com/fasterxml/jackson/fuzz/agent/AllocationSizeCounters";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null;
        }
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    ClassLoader cl = loader != null ? loader : ClassLoader.getSystemClassLoader();
                    try {
                        Class<?> c1 = Class.forName(type1.replace('/', '.'), false, cl);
                        Class<?> c2 = Class.forName(type2.replace('/', '.'), false, cl);
                        if (c1.isAssignableFrom(c2)) return type1;
                        if (c2.isAssignableFrom(c1)) return type2;
                        if (c1.isInterface() || c2.isInterface()) return "java/lang/Object";
                        do { c1 = c1.getSuperclass(); } while (!c1.isAssignableFrom(c2));
                        return c1.getName().replace('.', '/');
                    } catch (ClassNotFoundException e) {
                        return "java/lang/Object";
                    }
                }
            };
            ClassVisitor cv = new AllocClassVisitor(cw);
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            byte[] result = cw.toByteArray();
            System.err.println("[V1Agent] Instrumented " + className
                    + " (" + result.length + " bytes)");
            return result;
        } catch (Throwable t) {
            System.err.println("[V1Agent] FAILED to transform " + className + ": " + t);
            t.printStackTrace(System.err);
            return null;
        }
    }

    private static final class AllocClassVisitor extends ClassVisitor {
        AllocClassVisitor(ClassWriter cw) {
            super(Opcodes.ASM9, cw);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv != null && "_finishBytes".equals(name) && "(I)[B".equals(descriptor)) {
                System.err.println("[V1Agent] Instrumenting method: " + name + descriptor);
                return new AllocMethodVisitor(mv);
            }
            return mv;
        }
    }

    /**
     * At method entry, reads the int len parameter and records it.
     */
    private static final class AllocMethodVisitor extends MethodVisitor {
        AllocMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // Load the 'len' parameter (int at local var index 1)
            mv.visitVarInsn(Opcodes.ILOAD, 1);
            // Convert int → long
            mv.visitInsn(Opcodes.I2L);
            // Call AllocationSizeCounters.record(long)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                    "record", "(J)V", false);
        }
    }
}
