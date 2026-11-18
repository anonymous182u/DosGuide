package fuzzing.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.AdviceAdapter;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based ClassFileTransformer that instruments
 * com.ctc.wstx.dtd.FullDTDReader#readContentSpec to track recursion depth.
 *
 * On method entry: calls V1Counters.enter()
 * On method exit (normal + exceptional): calls V1Counters.exit()
 */
public class V1ClassTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS = "com/ctc/wstx/dtd/FullDTDReader";
    private static final String TARGET_METHOD = "readContentSpec";
    private static final String TARGET_DESC =
            "(Lcom/ctc/wstx/util/PrefixedName;ZZ)Lcom/ctc/wstx/dtd/ContentSpec;";

    private static final String COUNTERS_CLASS = "fuzzing/agent/V1Counters";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null; // no transformation
        }
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                  String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                    if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                        return new AdviceAdapter(Opcodes.ASM9, mv, access, name, descriptor) {
                            @Override
                            protected void onMethodEnter() {
                                // Call V1Counters.enter()
                                mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                        COUNTERS_CLASS, "enter", "()V", false);
                            }

                            @Override
                            protected void onMethodExit(int opcode) {
                                // Call V1Counters.exit() on both normal return and exception
                                mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                        COUNTERS_CLASS, "exit", "()V", false);
                            }
                        };
                    }
                    return mv;
                }
            };
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[V1Agent] ERROR transforming " + className + ": " + e.getMessage());
            e.printStackTrace(System.err);
            return null; // return untransformed
        }
    }
}
