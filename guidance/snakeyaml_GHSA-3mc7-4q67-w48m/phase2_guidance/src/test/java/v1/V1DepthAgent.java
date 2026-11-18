package v1;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.jar.JarFile;

/**
 * Java agent that instruments Composer.composeNode() to measure recursion depth.
 * Measurement-only — does not generate inputs or embed exploit payloads.
 *
 * Uses raw MethodVisitor (no AdviceAdapter) for maximum compatibility.
 * Only depends on core ASM (no asm-commons or asm-tree).
 *
 * Instruments: org.yaml.snakeyaml.composer.Composer#composeNode(Node)
 * Signal: recursion depth (enter/exit) and node count (enter)
 * Storage: ThreadLocal in v1.DepthCounters
 */
public class V1DepthAgent {

    private static final String TARGET_CLASS = "org/yaml/snakeyaml/composer/Composer";
    private static final String TARGET_METHOD = "composeNode";
    private static final String TARGET_DESC = "(Lorg/yaml/snakeyaml/nodes/Node;)Lorg/yaml/snakeyaml/nodes/Node;";

    public static void premain(String agentArgs, Instrumentation inst) {
        System.err.println("[V1DepthAgent] premain: registering transformer");

        // Try to add this jar to the bootstrap classpath so that DepthCounters
        // is visible regardless of which classloader loads Composer.
        try {
            String loc = V1DepthAgent.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI().getPath();
            System.err.println("[V1DepthAgent] agent location: " + loc);
            if (loc.endsWith(".jar")) {
                inst.appendToBootstrapClassLoaderSearch(new JarFile(loc));
                System.err.println("[V1DepthAgent] added to bootstrap classpath");
            }
        } catch (Throwable t) {
            System.err.println("[V1DepthAgent] bootstrap append skipped: " + t);
        }

        inst.addTransformer(new DepthTransformer());
        System.err.println("[V1DepthAgent] transformer registered");
    }

    /**
     * Named (non-anonymous) ClassFileTransformer for clarity and reliable class loading.
     */
    static final class DepthTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (className == null || !TARGET_CLASS.equals(className)) {
                return null;
            }
            System.err.println("[V1DepthAgent] transforming " + className);
            try {
                return doTransform(classfileBuffer);
            } catch (Throwable t) {
                System.err.println("[V1DepthAgent] FAILED: " + t);
                t.printStackTrace(System.err);
                return null;
            }
        }

        private byte[] doTransform(byte[] original) {
            ClassReader cr = new ClassReader(original);
            // ClassWriter(cr, 0): copies constant pool from reader, no stack/frame recomputation.
            // Safe because our added INVOKESTATIC void()V doesn't change stack depth or frames.
            ClassWriter cw = new ClassWriter(cr, 0);
            cr.accept(new DepthClassVisitor(cw), 0);
            byte[] result = cw.toByteArray();
            System.err.println("[V1DepthAgent] transformed " + original.length + " -> " + result.length + " bytes");
            return result;
        }
    }

    /**
     * Named ClassVisitor that wraps the target method's visitor.
     */
    static final class DepthClassVisitor extends ClassVisitor {
        DepthClassVisitor(ClassVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                System.err.println("[V1DepthAgent] instrumenting " + name + descriptor);
                return new DepthMethodVisitor(mv);
            }
            return mv;
        }
    }

    /**
     * Named MethodVisitor that injects DepthCounters.enter() at method entry
     * and DepthCounters.exit() before each return instruction.
     *
     * No AdviceAdapter needed — just intercept visitCode() and visitInsn().
     */
    static final class DepthMethodVisitor extends MethodVisitor {
        DepthMethodVisitor(MethodVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // Insert DepthCounters.enter() right after method entry
            super.visitMethodInsn(Opcodes.INVOKESTATIC,
                    "v1/DepthCounters", "enter", "()V", false);
        }

        @Override
        public void visitInsn(int opcode) {
            // Insert DepthCounters.exit() before any return instruction
            if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                        "v1/DepthCounters", "exit", "()V", false);
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitMaxs(int maxStack, int maxLocals) {
            // Add 1 to maxStack to account for potential INVOKESTATIC overhead.
            // INVOKESTATIC void()V doesn't actually add to the stack,
            // but being conservative avoids VerifyError in edge cases.
            super.visitMaxs(maxStack + 1, maxLocals);
        }
    }
}
