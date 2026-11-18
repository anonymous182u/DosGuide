package com.fasterxml.jackson.fuzz.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based ClassFileTransformer that instruments BaseNodeDeserializer's
 * deserializeArray and deserializeObject methods to track nesting depth
 * via NestingDepthCounters.enter() / exit().
 *
 * Instrumentation wraps each target method in:
 *   NestingDepthCounters.enter();
 *   try { ... original body ... } finally { NestingDepthCounters.exit(); }
 */
public final class NestingDepthTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS =
            "com/fasterxml/jackson/databind/deser/std/BaseNodeDeserializer";

    private static final String COUNTERS_CLASS =
            "com/fasterxml/jackson/fuzz/agent/NestingDepthCounters";

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
            // Classloader-aware ClassWriter for correct frame computation
            ClassWriter cw = new LoaderAwareClassWriter(cr, loader);
            ClassVisitor cv = new DepthClassVisitor(cw);
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            byte[] result = cw.toByteArray();
            System.err.println("[PkgRisk1Agent] Instrumented " + className
                    + " (" + result.length + " bytes)");
            return result;
        } catch (Throwable t) {
            System.err.println("[PkgRisk1Agent] FAILED to transform " + className + ": " + t);
            t.printStackTrace(System.err);
            return null;
        }
    }

    /** ClassWriter that uses the target classloader for frame computation. */
    private static final class LoaderAwareClassWriter extends ClassWriter {
        private final ClassLoader loader;

        LoaderAwareClassWriter(ClassReader cr, ClassLoader loader) {
            super(cr, ClassWriter.COMPUTE_FRAMES);
            this.loader = loader;
        }

        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            ClassLoader cl = loader != null ? loader : ClassLoader.getSystemClassLoader();
            try {
                Class<?> c1 = Class.forName(type1.replace('/', '.'), false, cl);
                Class<?> c2 = Class.forName(type2.replace('/', '.'), false, cl);
                if (c1.isAssignableFrom(c2)) return type1;
                if (c2.isAssignableFrom(c1)) return type2;
                if (c1.isInterface() || c2.isInterface()) return "java/lang/Object";
                do {
                    c1 = c1.getSuperclass();
                } while (!c1.isAssignableFrom(c2));
                return c1.getName().replace('.', '/');
            } catch (ClassNotFoundException e) {
                return "java/lang/Object";
            }
        }
    }

    /** ClassVisitor that intercepts the target methods for instrumentation. */
    private static final class DepthClassVisitor extends ClassVisitor {
        DepthClassVisitor(ClassWriter cw) {
            super(Opcodes.ASM9, cw);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv != null && shouldInstrument(name, descriptor)) {
                System.err.println("[PkgRisk1Agent] Instrumenting method: " + name + descriptor);
                return new DepthMethodVisitor(mv);
            }
            return mv;
        }

        private static boolean shouldInstrument(String name, String descriptor) {
            if ("deserializeArray".equals(name) || "deserializeObject".equals(name)) {
                return descriptor.startsWith("(Lcom/fasterxml/jackson/core/JsonParser;");
            }
            return false;
        }
    }

    /**
     * MethodVisitor that wraps the method in enter()/exit() with try-finally.
     *
     * Pattern emitted:
     *   NestingDepthCounters.enter();
     *   try {
     *       ... original body (each return preceded by exit()) ...
     *   } catch (Throwable t) {
     *       NestingDepthCounters.exit();
     *       throw t;
     *   }
     */
    private static final class DepthMethodVisitor extends MethodVisitor {
        private final Label tryStart = new Label();
        private final Label tryEnd = new Label();
        private final Label catchHandler = new Label();

        DepthMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // NestingDepthCounters.enter();
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                    "enter", "()V", false);
            // Register the try-catch-all BEFORE labels are visited
            mv.visitTryCatchBlock(tryStart, tryEnd, catchHandler, null);
            // Mark start of protected region
            mv.visitLabel(tryStart);
        }

        @Override
        public void visitInsn(int opcode) {
            // Before each return instruction, call exit()
            if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                        "exit", "()V", false);
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitMaxs(int maxStack, int maxLocals) {
            // End of protected region
            mv.visitLabel(tryEnd);
            // Exception handler: exit() then rethrow
            mv.visitLabel(catchHandler);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                    "exit", "()V", false);
            mv.visitInsn(Opcodes.ATHROW);
            // Let ClassWriter compute correct values
            super.visitMaxs(0, 0);
        }
    }
}
