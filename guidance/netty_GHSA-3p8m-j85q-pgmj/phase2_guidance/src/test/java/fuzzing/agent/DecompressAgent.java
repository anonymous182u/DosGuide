package fuzzing.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * Java agent that instruments BrotliDecoder#pull and ZstdDecoder#decode
 * to measure total decompressed bytes emitted per execution.
 *
 * <p>BrotliDecoder#pull: before each ARETURN, duplicates the returned
 * ByteBuf, calls readableBytes(), and adds the value to
 * {@link DecompressCounters#addBrotliBytes(long)}.</p>
 *
 * <p>ZstdDecoder#decode: before each List.add(Object) call inside the
 * decode method, duplicates the added ByteBuf, calls readableBytes(),
 * and adds the value to {@link DecompressCounters#addZstdBytes(long)}.</p>
 */
public class DecompressAgent {

    private static final String BROTLI_CLASS = "io/netty/handler/codec/compression/BrotliDecoder";
    private static final String ZSTD_CLASS   = "io/netty/handler/codec/compression/ZstdDecoder";

    public static void premain(String agentArgs, Instrumentation inst) {
        System.err.println("[DecompressAgent] Agent loaded, registering transformer");
        inst.addTransformer(new DecompressTransformer(), false);
    }

    private static final class DecompressTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (BROTLI_CLASS.equals(className)) {
                System.err.println("[DecompressAgent] Transforming BrotliDecoder");
                return transformBrotliDecoder(classfileBuffer);
            }
            if (ZSTD_CLASS.equals(className)) {
                System.err.println("[DecompressAgent] Transforming ZstdDecoder");
                return transformZstdDecoder(classfileBuffer);
            }
            return null;
        }
    }

    // ---- BrotliDecoder instrumentation ----

    private static byte[] transformBrotliDecoder(byte[] classfileBuffer) {
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                    if ("pull".equals(name)
                            && "(Lio/netty/buffer/ByteBufAllocator;)Lio/netty/buffer/ByteBuf;".equals(descriptor)) {
                        return new PullMethodVisitor(mv);
                    }
                    return mv;
                }
            };
            cr.accept(cv, 0);
            System.err.println("[DecompressAgent] BrotliDecoder#pull instrumented successfully");
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[DecompressAgent] Failed to transform BrotliDecoder: " + e);
            e.printStackTrace(System.err);
            return null;
        }
    }

    /**
     * Instruments BrotliDecoder#pull: before each ARETURN, measures the
     * returned ByteBuf's readableBytes and adds to the counter.
     */
    private static final class PullMethodVisitor extends MethodVisitor {
        PullMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitInsn(int opcode) {
            if (opcode == Opcodes.ARETURN) {
                // Stack before: [ByteBuf]
                mv.visitInsn(Opcodes.DUP);
                // Stack: [ByteBuf, ByteBuf]
                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                        "io/netty/buffer/ByteBuf", "readableBytes", "()I", false);
                // Stack: [ByteBuf, int]
                mv.visitInsn(Opcodes.I2L);
                // Stack: [ByteBuf, long]
                mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                        "fuzzing/agent/DecompressCounters", "addBrotliBytes", "(J)V", false);
                // Stack: [ByteBuf]
            }
            super.visitInsn(opcode);
        }
    }

    // ---- ZstdDecoder instrumentation ----

    private static byte[] transformZstdDecoder(byte[] classfileBuffer) {
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                    if ("decode".equals(name)
                            && "(Lio/netty/channel/ChannelHandlerContext;Lio/netty/buffer/ByteBuf;Ljava/util/List;)V"
                            .equals(descriptor)) {
                        return new DecodeMethodVisitor(mv);
                    }
                    return mv;
                }
            };
            cr.accept(cv, 0);
            System.err.println("[DecompressAgent] ZstdDecoder#decode instrumented successfully");
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[DecompressAgent] Failed to transform ZstdDecoder: " + e);
            e.printStackTrace(System.err);
            return null;
        }
    }

    /**
     * Instruments ZstdDecoder#decode: before each List.add(Object) call,
     * duplicates the added ByteBuf and measures its readableBytes.
     */
    private static final class DecodeMethodVisitor extends MethodVisitor {
        DecodeMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name,
                                    String descriptor, boolean isInterface) {
            if (opcode == Opcodes.INVOKEINTERFACE
                    && "java/util/List".equals(owner)
                    && "add".equals(name)
                    && "(Ljava/lang/Object;)Z".equals(descriptor)) {
                // Stack before: [list, object]
                mv.visitInsn(Opcodes.DUP);
                // Stack: [list, object, object]
                mv.visitTypeInsn(Opcodes.CHECKCAST, "io/netty/buffer/ByteBuf");
                // Stack: [list, object, ByteBuf]
                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                        "io/netty/buffer/ByteBuf", "readableBytes", "()I", false);
                // Stack: [list, object, int]
                mv.visitInsn(Opcodes.I2L);
                // Stack: [list, object, long]
                mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                        "fuzzing/agent/DecompressCounters", "addZstdBytes", "(J)V", false);
                // Stack: [list, object]
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }
}
