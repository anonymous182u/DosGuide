package org.xnio.fuzz.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based ClassFileTransformer that injects recursion-depth counting into:
 *
 *   AbstractIoFuture$NotifierState.notifyDone(AbstractIoFuture, Object)
 *     → calls RecursionCounters.enterNotify() at entry,
 *       RecursionCounters.exitNotify() before each RETURN.
 *
 *   AbstractIoFuture$CancellableState.cancel()
 *     → calls RecursionCounters.enterCancel() at entry,
 *       RecursionCounters.exitCancel() before each RETURN.
 *
 * Measurement-only — never generates inputs or embeds payloads [R37].
 */
public final class RecursionTransformer implements ClassFileTransformer {

    private static final String NOTIFIER_STATE =
            "org/xnio/AbstractIoFuture$NotifierState";
    private static final String CANCELLABLE_STATE =
            "org/xnio/AbstractIoFuture$CancellableState";
    private static final String COUNTERS =
            "org/xnio/fuzz/agent/RecursionCounters";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (className == null) return null;

        if (className.equals(NOTIFIER_STATE)) {
            return instrumentClass(classfileBuffer,
                    "notifyDone",
                    "(Lorg/xnio/AbstractIoFuture;Ljava/lang/Object;)V",
                    "enterNotify", "exitNotify");
        }
        if (className.equals(CANCELLABLE_STATE)) {
            return instrumentClass(classfileBuffer,
                    "cancel", "()V",
                    "enterCancel", "exitCancel");
        }
        return null;
    }

    private byte[] instrumentClass(byte[] classfileBuffer,
                                   String methodName, String methodDesc,
                                   String enterMethod, String exitMethod) {
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                                                 String descriptor,
                                                 String signature,
                                                 String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name,
                            descriptor, signature, exceptions);
                    if (name.equals(methodName) && descriptor.equals(methodDesc)) {
                        return new DepthMethodVisitor(mv, enterMethod, exitMethod);
                    }
                    return mv;
                }
            }, 0);
            return cw.toByteArray();
        } catch (Throwable t) {
            System.err.println("[RecursionTransformer] WARN: failed to instrument "
                    + methodName + ": " + t);
            return null; // leave class unchanged on error
        }
    }

    /**
     * MethodVisitor that injects recursion-depth enter/exit calls.
     * At method entry: INVOKESTATIC RecursionCounters.enterXxx()V
     * Before each RETURN: INVOKESTATIC RecursionCounters.exitXxx()V
     */
    private static final class DepthMethodVisitor extends MethodVisitor {
        private final String enterMethod;
        private final String exitMethod;

        DepthMethodVisitor(MethodVisitor mv, String enterMethod, String exitMethod) {
            super(Opcodes.ASM9, mv);
            this.enterMethod = enterMethod;
            this.exitMethod = exitMethod;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // Inject depth-enter call at method entry
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS,
                    enterMethod, "()V", false);
        }

        @Override
        public void visitInsn(int opcode) {
            if (opcode == Opcodes.RETURN) {
                // Inject depth-exit call before RETURN
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS,
                        exitMethod, "()V", false);
            }
            super.visitInsn(opcode);
        }
    }
}
