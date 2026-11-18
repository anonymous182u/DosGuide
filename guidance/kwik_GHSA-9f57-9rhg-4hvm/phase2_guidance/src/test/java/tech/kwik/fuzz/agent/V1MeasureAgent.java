package tech.kwik.fuzz.agent;

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
 * Java agent that instruments {@code ConnectionSource.equals(Object)} to count
 * invocations via {@link V1Counters#incrementEquals()}.
 * <p>
 * The agent adds itself to the bootstrap class loader so that {@code V1Counters}
 * is reachable from the application class loader where {@code ConnectionSource}
 * lives.
 */
public final class V1MeasureAgent {

    private static final String TARGET_CLASS = "tech/kwik/core/server/impl/ConnectionSource";
    private static final String COUNTER_CLASS = "tech/kwik/fuzz/agent/V1Counters";

    public static void premain(String args, Instrumentation inst) {
        // Add this jar to the bootstrap class loader so V1Counters is visible everywhere
        try {
            String jarPath = V1MeasureAgent.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI().getPath();
            inst.appendToBootstrapClassLoaderSearch(new JarFile(jarPath));
            System.err.println("[V1Agent] Added agent jar to bootstrap classpath: " + jarPath);
        } catch (Exception e) {
            System.err.println("[V1Agent] WARNING: could not add to bootstrap classpath: " + e);
        }

        inst.addTransformer(new EqualsTransformer());
        System.err.println("[V1Agent] Registered transformer for " + TARGET_CLASS.replace('/', '.'));
    }

    /** Transformer that injects a counter increment at the top of equals(). */
    private static final class EqualsTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (!TARGET_CLASS.equals(className)) {
                return null; // pass through unmodified
            }
            try {
                return instrumentEquals(classfileBuffer);
            } catch (Exception e) {
                System.err.println("[V1Agent] Instrumentation FAILED: " + e);
                e.printStackTrace(System.err);
                return null;
            }
        }
    }

    private static byte[] instrumentEquals(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);

        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("equals".equals(name) && "(Ljava/lang/Object;)Z".equals(descriptor)) {
                    System.err.println("[V1Agent] Instrumenting ConnectionSource.equals");
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            // Insert: V1Counters.incrementEquals();
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                    COUNTER_CLASS, "incrementEquals", "()V", false);
                        }
                    };
                }
                return mv;
            }
        };

        cr.accept(cv, 0);
        System.err.println("[V1Agent] Successfully instrumented ConnectionSource.equals");
        return cw.toByteArray();
    }
}
