package fuzz.agent;

import org.objectweb.asm.*;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.Set;

/**
 * ASM-based ClassFileTransformer that instruments {@code org.mozilla.javascript.DToA}.
 *
 * Injected instrumentation:
 *   - Before every INVOKEVIRTUAL on java.math.BigInteger for multiply/divideAndRemainder/pow:
 *     call DToACounters.incrementBigIntOps()
 *   - At entry/exit of JS_dtoa: call DToACounters.enterJsDtoa()/exitJsDtoa()
 *   - At entry/exit of JS_dtobasestr: call DToACounters.enterJsDtobasestr()/exitJsDtobasestr()
 *   - At entry/exit of JS_dtostr: call DToACounters.enterJsDtostr()/exitJsDtostr()
 *   - At entry of pow5mult: call DToACounters.incrementPow5mult()
 *
 * Uses only asm-core (no asm-commons dependency) for version compatibility.
 */
public class DToAClassTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS = "org/mozilla/javascript/DToA";
    private static final String COUNTERS_CLASS = "fuzz/agent/DToACounters";
    private static final String BIG_INTEGER_CLASS = "java/math/BigInteger";

    private static final Set<String> BIGINT_METHODS = Set.of(
            "multiply", "divideAndRemainder", "pow"
    );

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null; // pass through unmodified
        }
        try {
            System.err.println("[DToAClassTransformer] Transforming " + className);
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    // Safe fallback to avoid class-loading issues during transformation
                    try {
                        return super.getCommonSuperClass(type1, type2);
                    } catch (Exception e) {
                        return "java/lang/Object";
                    }
                }
            };
            ClassVisitor cv = new DToAClassVisitor(Opcodes.ASM9, cw);
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            byte[] result = cw.toByteArray();
            System.err.println("[DToAClassTransformer] Transformation complete, "
                    + classfileBuffer.length + " -> " + result.length + " bytes");
            return result;
        } catch (Throwable t) {
            System.err.println("[DToAClassTransformer] ERROR transforming " + className);
            t.printStackTrace(System.err);
            return null; // return unmodified class on error
        }
    }

    /**
     * ClassVisitor that dispatches to method-specific MethodVisitors.
     */
    private static class DToAClassVisitor extends ClassVisitor {

        DToAClassVisitor(int api, ClassVisitor cv) {
            super(api, cv);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv == null) return null;

            // Determine which timing instrumentation applies to this method
            String enterMethod = null;
            String exitMethod = null;

            switch (name) {
                case "JS_dtoa":
                    enterMethod = "enterJsDtoa";
                    exitMethod = "exitJsDtoa";
                    break;
                case "JS_dtobasestr":
                    enterMethod = "enterJsDtobasestr";
                    exitMethod = "exitJsDtobasestr";
                    break;
                case "JS_dtostr":
                    enterMethod = "enterJsDtostr";
                    exitMethod = "exitJsDtostr";
                    break;
                case "pow5mult":
                    enterMethod = "incrementPow5mult";
                    exitMethod = null; // only entry counting
                    break;
                default:
                    break;
            }

            // Wrap all DToA methods for BigInteger call instrumentation,
            // plus specific methods for timing
            return new DToAMethodVisitor(Opcodes.ASM9, mv, enterMethod, exitMethod);
        }
    }

    /**
     * MethodVisitor that injects:
     *   1. Entry call (if enterMethod != null) at method start
     *   2. Exit call (if exitMethod != null) before each return instruction
     *   3. BigInteger operation counting before multiply/divideAndRemainder/pow calls
     */
    private static class DToAMethodVisitor extends MethodVisitor {

        private final String enterMethod;
        private final String exitMethod;

        DToAMethodVisitor(int api, MethodVisitor mv,
                          String enterMethod, String exitMethod) {
            super(api, mv);
            this.enterMethod = enterMethod;
            this.exitMethod = exitMethod;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // Inject entry call at method start
            if (enterMethod != null) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                        enterMethod, "()V", false);
            }
        }

        @Override
        public void visitInsn(int opcode) {
            // Inject exit call before every return instruction
            if (exitMethod != null
                    && opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                        exitMethod, "()V", false);
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name,
                                    String descriptor, boolean isInterface) {
            // Inject BigInteger operation counter before each BigInteger method call
            if (opcode == Opcodes.INVOKEVIRTUAL
                    && BIG_INTEGER_CLASS.equals(owner)
                    && BIGINT_METHODS.contains(name)) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                        "incrementBigIntOps", "()V", false);
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }
}
