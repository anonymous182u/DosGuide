package com.fuzzer.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * ASM-based ClassFileTransformer that instruments
 * {@code io.netty.handler.codec.compression.Snappy.decode(ByteBuf, ByteBuf)}.
 *
 * <p>At method entry: calls {@code V1Signal.onDecodeEntry(out)} to record
 * the baseline capacity of the {@code out} ByteBuf (local variable slot 2).</p>
 *
 * <p>Before each RETURN: calls {@code V1Signal.onDecodeExit(out)} to compute
 * and accumulate the capacity growth.</p>
 */
public class V1Transformer implements ClassFileTransformer {

    private static final String TARGET_CLASS = "io/netty/handler/codec/compression/Snappy";
    private static final String TARGET_METHOD = "decode";
    private static final String TARGET_DESC =
            "(Lio/netty/buffer/ByteBuf;Lio/netty/buffer/ByteBuf;)V";

    private static final String SIGNAL_CLASS = "com/fuzzer/guidance/V1Signal";
    private static final String SIGNAL_ENTRY = "onDecodeEntry";
    private static final String SIGNAL_EXIT  = "onDecodeExit";
    private static final String SIGNAL_DESC  = "(Ljava/lang/Object;)V";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null; // no transformation
        }

        System.err.println("[V1Agent] Transforming class: " + className);

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            // COMPUTE_MAXS recalculates max stack/locals; frames are passed through
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);

            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor,
                            signature, exceptions);
                    if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                        System.err.println("[V1Agent] Instrumenting method: " + name + descriptor);
                        return new DecodeMethodVisitor(mv);
                    }
                    return mv;
                }
            };

            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            byte[] result = cw.toByteArray();
            System.err.println("[V1Agent] Transformation complete — new size: " + result.length);
            return result;
        } catch (Throwable t) {
            System.err.println("[V1Agent] ERROR transforming " + className + ": " + t);
            t.printStackTrace(System.err);
            return null; // return original bytecode on error
        }
    }

    /**
     * Visits Snappy.decode() and injects V1Signal calls at entry and before
     * each RETURN instruction.
     */
    private static class DecodeMethodVisitor extends MethodVisitor {

        DecodeMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // --- method entry: V1Signal.onDecodeEntry(out) ---
            // out is local variable slot 2 (this=0, in=1, out=2)
            mv.visitVarInsn(Opcodes.ALOAD, 2);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, SIGNAL_CLASS,
                    SIGNAL_ENTRY, SIGNAL_DESC, false);
        }

        @Override
        public void visitInsn(int opcode) {
            if (opcode == Opcodes.RETURN) {
                // --- before RETURN: V1Signal.onDecodeExit(out) ---
                mv.visitVarInsn(Opcodes.ALOAD, 2);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, SIGNAL_CLASS,
                        SIGNAL_EXIT, SIGNAL_DESC, false);
            }
            super.visitInsn(opcode);
        }
    }
}
