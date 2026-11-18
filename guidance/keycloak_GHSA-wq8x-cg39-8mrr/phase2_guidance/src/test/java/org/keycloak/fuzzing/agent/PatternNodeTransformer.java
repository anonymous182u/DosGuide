package org.keycloak.fuzzing.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * ASM-based {@link ClassFileTransformer} that instruments every
 * {@code java.util.regex.Pattern$*} inner class's
 * {@code boolean match(Matcher, int, CharSequence)} method to call
 * {@link RegexStepCounter#increment()} at entry.
 * <p>
 * Each call to {@code match()} is one NFA step in Java's regex engine.
 * Counting these calls measures the exact backtracking work.
 */
public class PatternNodeTransformer implements ClassFileTransformer {

    /** Descriptor of Pattern$Node.match(Matcher, int, CharSequence) → boolean. */
    private static final String MATCH_DESC =
            "(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z";

    /** Internal name of the counter class (on the bootstrap classpath). */
    private static final String COUNTER_OWNER =
            "org/keycloak/fuzzing/agent/RegexStepCounter";

    @Override
    public byte[] transform(ClassLoader loader,
                            String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {

        // Only instrument Pattern inner classes (Pattern$Node and subclasses).
        if (className == null ||
                !className.startsWith("java/util/regex/Pattern$")) {
            return null; // no transformation
        }

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            // COMPUTE_MAXS recalculates maxStack/maxLocals to account for the
            // injected INVOKESTATIC.  We pass 'cr' so that the constant pool
            // and frame data are copied efficiently.
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            boolean[] modified = {false};

            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                                                 String descriptor,
                                                 String signature,
                                                 String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name,
                            descriptor, signature, exceptions);
                    if ("match".equals(name) && MATCH_DESC.equals(descriptor)) {
                        modified[0] = true;
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                // Inject: RegexStepCounter.increment();
                                super.visitMethodInsn(
                                        Opcodes.INVOKESTATIC,
                                        COUNTER_OWNER,
                                        "increment",
                                        "()V",
                                        false);
                            }
                        };
                    }
                    return mv;
                }
            };

            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            if (modified[0]) {
                System.err.println("[V1Agent] Instrumented match() in " + className);
                return cw.toByteArray();
            }
            return null; // class has no match() method — leave unchanged
        } catch (Exception e) {
            System.err.println("[V1Agent] Failed to transform " + className
                    + ": " + e.getMessage());
            return null; // leave class unchanged on error
        }
    }
}
