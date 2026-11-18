package com.fuzzing.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.function.Consumer;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Java agent that instruments DefaultHtmlErrorResponseBodyProvider#html(HtmlErrorPage)
 * to count invocations (cache misses) and sum the length of each returned HTML string.
 *
 * Cross-classloader communication uses System.getProperties() to store:
 *   "V1_COUNTERS"        → long[2]: [0]=htmlCallCount, [1]=totalAllocatedChars
 *   "V1_ON_HTML_ENTRY"   → Runnable that increments counters[0]
 *   "V1_ON_HTML_RETURN"  → Consumer&lt;String&gt; that adds the String's length to counters[1]
 *
 * The instrumented code only calls JDK interfaces (Runnable, Consumer) retrieved from
 * System.getProperties(), so it works from any classloader.
 */
public final class V1MeasureAgent {

    private static final String TARGET_CLASS =
            "io/micronaut/http/server/exceptions/response/DefaultHtmlErrorResponseBodyProvider";
    private static final String TARGET_METHOD = "html";

    /** Shared counter array: [0]=htmlCallCount, [1]=totalAllocatedChars */
    public static long[] counters;

    public static void premain(String args, Instrumentation inst) {
        counters = new long[2];
        System.getProperties().put("V1_COUNTERS", counters);

        // Callbacks that the instrumented code invokes via System.getProperties()
        Runnable onEntry = () -> counters[0]++;
        Consumer<String> onReturn = (s) -> { if (s != null) counters[1] += s.length(); };

        System.getProperties().put("V1_ON_HTML_ENTRY", onEntry);
        System.getProperties().put("V1_ON_HTML_RETURN", onReturn);

        inst.addTransformer(new V1Transformer());
    }

    /**
     * ClassFileTransformer that rewrites the html() method of
     * DefaultHtmlErrorResponseBodyProvider.
     */
    static final class V1Transformer implements ClassFileTransformer, Opcodes {

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
                ClassVisitor cv = new ClassVisitor(ASM9, cw) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                     String signature, String[] exceptions) {
                        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                        if (TARGET_METHOD.equals(name) && descriptor.endsWith(")Ljava/lang/String;")) {
                            return new HtmlMethodVisitor(mv);
                        }
                        return mv;
                    }
                };
                cr.accept(cv, ClassReader.EXPAND_FRAMES);
                return cw.toByteArray();
            } catch (Exception e) {
                System.err.println("[V1MeasureAgent] Transformation error: " + e);
                return null;
            }
        }
    }

    /**
     * Injects at method entry:  ((Runnable) System.getProperties().get("V1_ON_HTML_ENTRY")).run()
     * Injects before ARETURN:   ((Consumer) System.getProperties().get("V1_ON_HTML_RETURN")).accept(retVal)
     */
    private static final class HtmlMethodVisitor extends MethodVisitor implements Opcodes {

        HtmlMethodVisitor(MethodVisitor mv) {
            super(ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // ((Runnable) System.getProperties().get("V1_ON_HTML_ENTRY")).run();
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "getProperties",
                    "()Ljava/util/Properties;", false);
            mv.visitLdcInsn("V1_ON_HTML_ENTRY");
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/util/Properties", "get",
                    "(Ljava/lang/Object;)Ljava/lang/Object;", false);
            mv.visitTypeInsn(CHECKCAST, "java/lang/Runnable");
            mv.visitMethodInsn(INVOKEINTERFACE, "java/lang/Runnable", "run", "()V", true);
        }

        @Override
        public void visitInsn(int opcode) {
            if (opcode == ARETURN) {
                // Stack: ..., returnString
                mv.visitInsn(DUP);
                // Stack: ..., returnString, returnString

                // Get the consumer callback
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "getProperties",
                        "()Ljava/util/Properties;", false);
                mv.visitLdcInsn("V1_ON_HTML_RETURN");
                mv.visitMethodInsn(INVOKEVIRTUAL, "java/util/Properties", "get",
                        "(Ljava/lang/Object;)Ljava/lang/Object;", false);
                mv.visitTypeInsn(CHECKCAST, "java/util/function/Consumer");
                // Stack: ..., returnString, returnString, consumer

                mv.visitInsn(SWAP);
                // Stack: ..., returnString, consumer, returnString

                mv.visitMethodInsn(INVOKEINTERFACE, "java/util/function/Consumer", "accept",
                        "(Ljava/lang/Object;)V", true);
                // Stack: ..., returnString
            }
            super.visitInsn(opcode);
        }
    }
}
