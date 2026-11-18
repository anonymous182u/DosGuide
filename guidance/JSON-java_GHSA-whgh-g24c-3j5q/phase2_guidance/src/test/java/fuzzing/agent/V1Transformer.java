package fuzzing.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based ClassFileTransformer that instruments org.json.JSONTokener#nextValue()
 * to call DepthCounters.enter() at method entry and DepthCounters.exit() before
 * each normal return instruction.
 *
 * Uses COMPUTE_FRAMES with a safe getCommonSuperClass override to avoid
 * ClassNotFoundException during frame computation.
 */
public class V1Transformer implements ClassFileTransformer {

    private static final String TARGET_CLASS = "org/json/JSONTokener";
    private static final String TARGET_METHOD = "nextValue";
    private static final String TARGET_DESC = "()Ljava/lang/Object;";

    private static final String COUNTERS_CLASS = "fuzzing/agent/DepthCounters";

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
            // Override getCommonSuperClass to avoid Class.forName failures
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    // Safe fallback: Object is always a valid common supertype
                    // for reference types. This avoids ClassNotFoundException
                    // when ASM tries to resolve org.json types.
                    return "java/lang/Object";
                }
            };
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                    if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                        return new NextValueAdapter(mv);
                    }
                    return mv;
                }
            };
            // SKIP_FRAMES: let COMPUTE_FRAMES recompute all frames from scratch
            cr.accept(cv, ClassReader.SKIP_FRAMES);
            byte[] result = cw.toByteArray();
            System.err.println("[V1Transformer] Successfully instrumented " + className + "#" + TARGET_METHOD);
            return result;
        } catch (Throwable t) {
            System.err.println("[V1Transformer] ERROR transforming " + className + ": " + t);
            t.printStackTrace(System.err);
            return null;
        }
    }

    /**
     * Simple enter/exit instrumentation without try-finally.
     * Injects DepthCounters.enter() at method entry and
     * DepthCounters.exit() before each return instruction.
     */
    private static class NextValueAdapter extends MethodVisitor {

        NextValueAdapter(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // DepthCounters.enter();
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS, "enter", "()V", false);
        }

        @Override
        public void visitInsn(int opcode) {
            // Intercept every RETURN instruction: call exit() before returning
            if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS, "exit", "()V", false);
            }
            super.visitInsn(opcode);
        }
    }
}
