package com.fuzzing.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * ASM-based ClassFileTransformer that instruments every Pattern$Node subclass's
 * match(Matcher, int, CharSequence) method to call V1Counters.step().
 *
 * This counts the total regex VM state transitions / backtracking steps,
 * which is the mechanism-aligned signal for CWE-1333 quadratic regex DoS.
 *
 * Measurement-only ([R37]).
 */
public final class V1NodeTransformer implements ClassFileTransformer {

    private static final String MATCH_NAME = "match";
    // boolean match(Matcher, int, CharSequence)
    private static final String MATCH_DESC =
            "(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z";
    private static final String COUNTERS_OWNER = "com/fuzzing/agent/V1Counters";

    @Override
    public byte[] transform(ClassLoader loader,
                            String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {

        // Only instrument Pattern inner classes (Pattern$Node and all subclasses)
        if (className == null || !className.startsWith("java/util/regex/Pattern$")) {
            return null; // no transformation
        }

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, 0);
            final boolean[] instrumented = {false};

            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access,
                                                 String name,
                                                 String descriptor,
                                                 String signature,
                                                 String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor,
                            signature, exceptions);
                    if (MATCH_NAME.equals(name) && MATCH_DESC.equals(descriptor)) {
                        instrumented[0] = true;
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                // Insert: V1Counters.step() at method entry
                                super.visitMethodInsn(
                                        Opcodes.INVOKESTATIC,
                                        COUNTERS_OWNER,
                                        "step",
                                        "()V",
                                        false);
                            }
                        };
                    }
                    return mv;
                }
            };
            cr.accept(cv, 0);

            if (instrumented[0]) {
                System.err.println("[V1Agent] Instrumented match() in " + className);
            }

            // Always return the (potentially instrumented) bytecode for Pattern classes
            return cw.toByteArray();
        } catch (Throwable t) {
            System.err.println("[V1Agent] WARNING: failed to transform " + className
                    + ": " + t.getMessage());
            t.printStackTrace(System.err);
            return null;
        }
    }
}
