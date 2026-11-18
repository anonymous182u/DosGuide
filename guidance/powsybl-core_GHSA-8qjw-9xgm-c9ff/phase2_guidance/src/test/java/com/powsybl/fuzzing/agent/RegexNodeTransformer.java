package com.powsybl.fuzzing.agent;

import org.objectweb.asm.*;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based {@link ClassFileTransformer} that injects a call to
 * {@code RegexStepCounter.increment()} at the entry of every
 * {@code match*} method in {@code java.util.regex.Pattern$*} inner classes.
 *
 * <p>Targeted methods:</p>
 * <ul>
 *   <li>{@code match(Matcher, int, CharSequence)} — the base dispatch in every Node subclass</li>
 *   <li>{@code match0/match1/match2(Matcher, int, int, CharSequence)} — Curly's greedy/lazy/possessive variants</li>
 * </ul>
 *
 * <p>The injected bytecode is a single {@code INVOKESTATIC} to
 * {@code com/powsybl/fuzzing/counter/RegexStepCounter.increment()V},
 * which is on the bootstrap classpath alongside the instrumented classes.</p>
 */
public class RegexNodeTransformer implements ClassFileTransformer {

    private static final String COUNTER_INTERNAL =
            "com/powsybl/fuzzing/counter/RegexStepCounter";

    /**
     * Only transform classes whose internal name starts with
     * {@code java/util/regex/Pattern$}.
     */
    @Override
    public byte[] transform(ClassLoader loader,
                            String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {

        if (className == null) return null;
        if (!className.startsWith("java/util/regex/Pattern$")) return null;

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                                                 String descriptor, String signature,
                                                 String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor,
                            signature, exceptions);
                    if (isMatchMethod(name, descriptor)) {
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                // Inject: RegexStepCounter.increment();
                                mv.visitMethodInsn(
                                        Opcodes.INVOKESTATIC,
                                        COUNTER_INTERNAL,
                                        "increment",
                                        "()V",
                                        false);
                            }
                        };
                    }
                    return mv;
                }
            };
            cr.accept(cv, 0);
            return cw.toByteArray();
        } catch (Exception e) {
            // If transformation fails, return null to keep original bytecode
            System.err.println("[RegexNodeTransformer] WARN: failed to transform "
                    + className + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Returns true for methods that are NFA backtracking entry points:
     * <ul>
     *   <li>{@code match(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z}</li>
     *   <li>{@code match0|match1|match2(Ljava/util/regex/Matcher;IILjava/lang/CharSequence;)Z}</li>
     * </ul>
     */
    private static boolean isMatchMethod(String name, String descriptor) {
        if (name.equals("match")) {
            return descriptor.equals(
                    "(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z");
        }
        if (name.equals("match0") || name.equals("match1") || name.equals("match2")) {
            return descriptor.equals(
                    "(Ljava/util/regex/Matcher;IILjava/lang/CharSequence;)Z");
        }
        return false;
    }
}
