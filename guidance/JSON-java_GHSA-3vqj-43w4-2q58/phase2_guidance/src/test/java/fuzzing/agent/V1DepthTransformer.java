package fuzzing.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based ClassFileTransformer that instruments {@code org.json.JSONML#parse}
 * to count recursion depth via {@link V1DepthCounters}.
 *
 * At method entry: calls {@code V1DepthCounters.onEnter()} (increments depth, updates max).
 * Before each ARETURN: calls {@code V1DepthCounters.onExit()} (decrements depth).
 *
 * Exceptional exits are NOT instrumented because:
 *   (a) the max depth is already recorded on entry, and
 *   (b) V1DepthCounters.reset() is called before each new execution.
 */
public class V1DepthTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS = "org/json/JSONML";
    private static final String TARGET_METHOD = "parse";
    private static final String TARGET_DESC =
            "(Lorg/json/XMLTokener;ZLorg/json/JSONArray;Z)Ljava/lang/Object;";

    private static final String COUNTERS_CLASS = "fuzzing/agent/V1DepthCounters";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null;            // leave all other classes untouched
        }
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    // Defensive: avoid ClassNotFoundException during frame computation
                    try {
                        return super.getCommonSuperClass(type1, type2);
                    } catch (Exception e) {
                        return "java/lang/Object";
                    }
                }
            };

            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                                                  String descriptor, String signature,
                                                  String[] exceptions) {
                    MethodVisitor writer = super.visitMethod(access, name, descriptor,
                            signature, exceptions);
                    if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                        return new MethodVisitor(Opcodes.ASM9, writer) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                // Inject onEnter at the very start of the method
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                        COUNTERS_CLASS, "onEnter", "()V", false);
                            }

                            @Override
                            public void visitInsn(int opcode) {
                                if (opcode == Opcodes.ARETURN) {
                                    // Before every normal return, inject onExit
                                    super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                            COUNTERS_CLASS, "onExit", "()V", false);
                                }
                                super.visitInsn(opcode);
                            }
                        };
                    }
                    return writer;
                }
            };

            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            System.err.println("[V1Agent] Instrumented " + TARGET_CLASS + "#" + TARGET_METHOD);
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[V1Agent] Transform failed for " + className + ": " + e);
            e.printStackTrace(System.err);
            return null;            // return original bytecode on failure
        }
    }
}
