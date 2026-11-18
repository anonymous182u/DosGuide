package agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.AdviceAdapter;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based ClassFileTransformer that instruments MessageUnpacker.unpackValue()
 * to call V1Counters.enter()/exit() for recursion depth measurement.
 * Measurement-only ([R37]).
 */
public class V1Transformer implements ClassFileTransformer {

    private static final String TARGET_CLASS = "org/msgpack/core/MessageUnpacker";
    private static final String TARGET_METHOD = "unpackValue";
    private static final String TARGET_DESC = "()Lorg/msgpack/value/ImmutableValue;";

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
                                invokeStatic(
                                    org.objectweb.asm.Type.getType("Lagent/V1Counters;"),
                                    new org.objectweb.asm.commons.Method("enter", "()V")
                                );
                            }

                            @Override
                            protected void onMethodExit(int opcode) {
                                invokeStatic(
                                    org.objectweb.asm.Type.getType("Lagent/V1Counters;"),
                                    new org.objectweb.asm.commons.Method("exit", "()V")
                                );
                            }
                        };
                    }
                    return mv;
                }
            };
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[V1Agent] Failed to transform " + className + ": " + e.getMessage());
            return null;
        }
    }
}
