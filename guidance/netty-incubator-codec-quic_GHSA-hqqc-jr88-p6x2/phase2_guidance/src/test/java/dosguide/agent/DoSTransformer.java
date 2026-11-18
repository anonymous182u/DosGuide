package dosguide.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * ASM transformer injecting calls to {@code dosguide/agent/DoSCounters} static hooks (all {@code ()V},
 * so the operand stack and stack-map frames are unaffected).
 */
final class DoSTransformer implements ClassFileTransformer {

    static final String COUNTERS = "dosguide/agent/DoSCounters";

    static final String TREE_NODE = "java/util/HashMap$TreeNode";
    static final String BYTE_BUFFER = "java/nio/ByteBuffer";
    static final String CODEC = "io/netty/incubator/codec/quic/QuicheQuicCodec";

    private final AtomicInteger transformed = new AtomicInteger();

    int transformedCount() {
        return transformed.get();
    }

    private final StringBuffer names = new StringBuffer();

    String transformedNames() {
        return names.toString();
    }

    /** Records the name and publishes it in the (bootstrap) DoSCounters.transformedNames field. */
    private void record(String name) {
        if (names.length() > 0) {
            names.append(',');
        }
        names.append(name);
        try {
            Class<?> c = Class.forName("dosguide.agent.DoSCounters", false, null);
            c.getField("transformedNames").set(null, names.toString());
        } catch (Throwable ignored) {
            // DoSCounters not yet on the bootstrap path: published by DoSMeasureAgent.install
        }
    }

    @Override
    public byte[] transform(Module module, ClassLoader loader, String className, Class<?> redefined,
                            ProtectionDomain pd, byte[] buf) {
        return transform(loader, className, redefined, pd, buf);
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> redefined,
                            ProtectionDomain pd, byte[] buf) {
        if (className == null) {
            return null;
        }
        if (!TREE_NODE.equals(className) && !BYTE_BUFFER.equals(className) && !CODEC.equals(className)) {
            return null;
        }
        try {
            ClassReader cr = new ClassReader(buf);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            cr.accept(new HookClassVisitor(cw, className), 0);
            byte[] out = cw.toByteArray();
            transformed.incrementAndGet();
            record(className.replace('/', '.'));
            System.err.println("[DoSMeasureAgent] transformed " + className
                    + (redefined != null ? " (retransformed)" : ""));
            return out;
        } catch (Throwable t) {
            System.err.println("[DoSMeasureAgent] failed to transform " + className + ": " + t);
            return null;
        }
    }

    private static final class HookClassVisitor extends ClassVisitor {
        private final String owner;

        HookClassVisitor(ClassVisitor cv, String owner) {
            super(Opcodes.ASM9, cv);
            this.owner = owner;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
            MethodVisitor mv = super.visitMethod(access, name, desc, sig, exc);
            if (mv == null) {
                return null;
            }
            switch (owner) {
                case TREE_NODE:
                    if ("find".equals(name)
                            && "(ILjava/lang/Object;Ljava/lang/Class;)Ljava/util/HashMap$TreeNode;".equals(desc)) {
                        return new NodeVisitHook(mv);
                    }
                    if ("putTreeVal".equals(name)) {
                        return new ScopeHook(mv, "putEnter", "putExit");
                    }
                    if ("treeify".equals(name)) {
                        return new ScopeHook(mv, "onTreeify", null);
                    }
                    return mv;
                case BYTE_BUFFER:
                    if ("equals".equals(name) && "(Ljava/lang/Object;)Z".equals(desc)) {
                        return new ScopeHook(mv, "onKeyEquals", null);
                    }
                    return mv;
                case CODEC:
                    if ("getChannel".equals(name) && desc.startsWith("(Ljava/nio/ByteBuffer;)")) {
                        return new ScopeHook(mv, "v1Enter", "v1Exit");
                    }
                    if ("channelRead".equals(name)
                            && "(Lio/netty/channel/ChannelHandlerContext;Ljava/lang/Object;)V".equals(desc)) {
                        return new DatagramBytesHook(mv);
                    }
                    if ("addChannel".equals(name)
                            && "(Lio/netty/incubator/codec/quic/QuicheQuicChannel;)V".equals(desc)) {
                        return new ScopeHook(mv, "addEnter", "addExit");
                    }
                    return mv;
                default:
                    return mv;
            }
        }
    }

    private static void callHook(MethodVisitor mv, String hook) {
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS, hook, "()V", false);
    }

    /** Calls an enter hook at method entry and an exit hook before every return / athrow. */
    private static final class ScopeHook extends MethodVisitor {
        private final String enter;
        private final String exit;

        ScopeHook(MethodVisitor mv, String enter, String exit) {
            super(Opcodes.ASM9, mv);
            this.enter = enter;
            this.exit = exit;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            if (enter != null) {
                callHook(mv, enter);
            }
        }

        @Override
        public void visitInsn(int opcode) {
            if (exit != null && ((opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN)
                    || opcode == Opcodes.ATHROW)) {
                callHook(mv, exit);
            }
            super.visitInsn(opcode);
        }
    }

    /**
     * In QuicheQuicCodec#channelRead(ctx, msg): reports {@code ((ByteBufHolder) msg).content().readableBytes()}
     * at entry. The method itself casts msg to DatagramPacket (a ByteBufHolder) first, so the inserted cast
     * does not change behaviour; no branch is inserted, so no stack-map frame is needed.
     */
    private static final class DatagramBytesHook extends MethodVisitor {
        DatagramBytesHook(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            mv.visitVarInsn(Opcodes.ALOAD, 2);
            mv.visitTypeInsn(Opcodes.CHECKCAST, "io/netty/buffer/ByteBufHolder");
            mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, "io/netty/buffer/ByteBufHolder", "content",
                    "()Lio/netty/buffer/ByteBuf;", true);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "io/netty/buffer/ByteBuf", "readableBytes", "()I", false);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS, "onDatagramBytes", "(I)V", false);
        }
    }

    /** In TreeNode#find: one onTreeVisit() call before each read of the node's {@code hash} field. */
    private static final class NodeVisitHook extends MethodVisitor {
        NodeVisitHook(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitFieldInsn(int opcode, String fowner, String name, String desc) {
            if (opcode == Opcodes.GETFIELD && "hash".equals(name) && "I".equals(desc)) {
                callHook(mv, "onTreeVisit");
            }
            super.visitFieldInsn(opcode, fowner, name, desc);
        }
    }
}
