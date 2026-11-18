package fuzzing.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * Inserts counter calls before every IRETURN of three methods of
 * {@code io.netty.handler.codec.compression.Bzip2BlockDecompressor}:
 * <ul>
 *   <li>{@code read()I}:        DUP; INVOKESTATIC V1Counters.onRead(I)V</li>
 *   <li>{@code blockLength()I}: DUP; INVOKESTATIC V1Counters.onBlockLength(I)V</li>
 *   <li>{@code checkCRC()I}:    INVOKESTATIC V1Counters.onBlockAccepted()V (only normal returns; a CRC
 *       mismatch throws and is not counted)</li>
 * </ul>
 * The inserted code has no branches, so only max stack needs recomputing (COMPUTE_MAXS).
 */
public final class V1Transformer implements ClassFileTransformer {
    static final String TARGET_CLASS = "io/netty/handler/codec/compression/Bzip2BlockDecompressor";
    private static final String COUNTERS = "fuzzing/v1/V1Counters";

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null;
        }
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            final int[] count = new int[1];
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] ex) {
                    MethodVisitor mv = super.visitMethod(access, name, desc, sig, ex);
                    if ("()I".equals(desc)) {
                        if ("read".equals(name)) {
                            count[0]++;
                            return new ReturnHook(mv, "onRead", true);
                        }
                        if ("blockLength".equals(name)) {
                            count[0]++;
                            return new ReturnHook(mv, "onBlockLength", true);
                        }
                        if ("checkCRC".equals(name)) {
                            count[0]++;
                            return new ReturnHook(mv, "onBlockAccepted", false);
                        }
                    }
                    return mv;
                }
            };
            cr.accept(cv, 0);
            byte[] out = cw.toByteArray();
            setInstrumented(loader, count[0]);
            System.err.println("[V1Agent] instrumented " + count[0] + " methods of " + className);
            return out;
        } catch (Throwable t) {
            System.err.println("[V1Agent] instrumentation failed: " + t);
            return null;
        }
    }

    private static void setInstrumented(ClassLoader loader, int n) {
        try {
            ClassLoader l = loader != null ? loader : ClassLoader.getSystemClassLoader();
            Class<?> c = Class.forName(COUNTERS.replace('/', '.'), true, l);
            c.getField("instrumentedMethods").setInt(null, n);
        } catch (Throwable ignored) {
            // counters class not visible yet; the signal itself still works
        }
    }

    private static final class ReturnHook extends MethodVisitor {
        private final String hook;
        private final boolean passValue;

        ReturnHook(MethodVisitor mv, String hook, boolean passValue) {
            super(Opcodes.ASM9, mv);
            this.hook = hook;
            this.passValue = passValue;
        }

        @Override
        public void visitInsn(int opcode) {
            if (opcode == Opcodes.IRETURN) {
                if (passValue) {
                    super.visitInsn(Opcodes.DUP);
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS, hook, "(I)V", false);
                } else {
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS, hook, "()V", false);
                }
            }
            super.visitInsn(opcode);
        }
    }
}
