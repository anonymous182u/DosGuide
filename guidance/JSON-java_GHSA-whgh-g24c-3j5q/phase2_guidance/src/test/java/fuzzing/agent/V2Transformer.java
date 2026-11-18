package fuzzing.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based ClassFileTransformer that instruments org.json.XML#parse()
 * to call XmlDepthCounters.enter() at method entry and XmlDepthCounters.exit()
 * before each normal return instruction.
 *
 * Target method: parse(Lorg/json/XMLTokener;Lorg/json/JSONObject;Ljava/lang/String;Lorg/json/XMLParserConfiguration;)Z
 */
public class V2Transformer implements ClassFileTransformer {

    private static final String TARGET_CLASS = "org/json/XML";
    private static final String TARGET_METHOD = "parse";
    private static final String TARGET_DESC =
            "(Lorg/json/XMLTokener;Lorg/json/JSONObject;Ljava/lang/String;Lorg/json/XMLParserConfiguration;)Z";

    private static final String COUNTERS_CLASS = "fuzzing/agent/XmlDepthCounters";

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
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    return "java/lang/Object";
                }
            };
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                    if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                        return new ParseAdapter(mv);
                    }
                    return mv;
                }
            };
            cr.accept(cv, ClassReader.SKIP_FRAMES);
            byte[] result = cw.toByteArray();
            System.err.println("[V2Transformer] Successfully instrumented " + className + "#" + TARGET_METHOD);
            return result;
        } catch (Throwable t) {
            System.err.println("[V2Transformer] ERROR transforming " + className + ": " + t);
            t.printStackTrace(System.err);
            return null;
        }
    }

    /**
     * Simple enter/exit instrumentation without try-finally.
     */
    private static class ParseAdapter extends MethodVisitor {

        ParseAdapter(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS, "enter", "()V", false);
        }

        @Override
        public void visitInsn(int opcode) {
            if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS, "exit", "()V", false);
            }
            super.visitInsn(opcode);
        }
    }
}
