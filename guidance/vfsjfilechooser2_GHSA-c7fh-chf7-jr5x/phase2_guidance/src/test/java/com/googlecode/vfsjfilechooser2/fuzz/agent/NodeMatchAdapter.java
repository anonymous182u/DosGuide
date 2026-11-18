package com.googlecode.vfsjfilechooser2.fuzz.agent;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * ASM ClassVisitor that instruments the {@code match(Matcher, int, CharSequence)} method
 * in every Pattern$Node subclass. Each method entry gets a call to
 * {@code regexmeasure.RegexStepCounter.increment()}.
 */
public class NodeMatchAdapter extends ClassVisitor {

    /** Descriptor of Pattern$Node.match(Matcher, int, CharSequence) → boolean. */
    private static final String MATCH_DESC =
            "(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z";

    /** Internal name of the counter class (on the bootstrap classpath). */
    private static final String COUNTER_CLASS = "regexmeasure/RegexStepCounter";

    public NodeMatchAdapter(ClassVisitor cv) {
        super(Opcodes.ASM9, cv);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        if ("match".equals(name) && MATCH_DESC.equals(descriptor)) {
            return new IncrementingMethodVisitor(mv);
        }
        return mv;
    }

    /**
     * Wraps a MethodVisitor to inject {@code RegexStepCounter.increment()} at method entry.
     */
    private static class IncrementingMethodVisitor extends MethodVisitor {

        IncrementingMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // Insert: INVOKESTATIC regexmeasure/RegexStepCounter.increment()V
            super.visitMethodInsn(
                    Opcodes.INVOKESTATIC,
                    COUNTER_CLASS,
                    "increment",
                    "()V",
                    false);
        }
    }
}
