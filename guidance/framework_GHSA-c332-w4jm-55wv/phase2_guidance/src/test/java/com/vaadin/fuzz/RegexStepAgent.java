package com.vaadin.fuzz;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Java agent that instruments all java.util.regex.Pattern$* inner classes
 * to count invocations of the {@code match(Matcher, int, CharSequence)} method.
 *
 * Each match() entry point gets an INVOKESTATIC to
 * {@link RegexStepCounter#increment()}, which counts NFA state transitions
 * (the actual backtracking work of the regex engine).
 *
 * Usage: -javaagent:target/regex-step-agent.jar
 *
 * The agent jar's manifest declares Boot-Class-Path so that
 * {@link RegexStepCounter} is visible to the bootstrap classloader.
 */
public final class RegexStepAgent implements ClassFileTransformer {

    /** Descriptor of Pattern$Node.match(Matcher, int, CharSequence) -> boolean */
    private static final String MATCH_DESC =
            "(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z";

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new RegexStepAgent());
        System.err.println("[RegexStepAgent] installed; instrumenting java.util.regex.Pattern$* match()");
    }

    @Override
    public byte[] transform(ClassLoader loader,
                            String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {

        if (className == null) return null;

        // Only instrument Pattern inner classes (Pattern$Node, Pattern$Curly, etc.)
        if (!className.startsWith("java/util/regex/Pattern$")) {
            return null;
        }

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, 0);
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                                                  String descriptor,
                                                  String signature,
                                                  String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor,
                                                          signature, exceptions);
                    if ("match".equals(name) && MATCH_DESC.equals(descriptor)) {
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                // Insert: RegexStepCounter.increment();
                                mv.visitMethodInsn(
                                        Opcodes.INVOKESTATIC,
                                        "com/vaadin/fuzz/RegexStepCounter",
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
        } catch (Throwable t) {
            System.err.println("[RegexStepAgent] WARNING: failed to instrument " + className
                    + ": " + t.getMessage());
            return null; // Return null to leave the class unchanged
        }
    }
}
