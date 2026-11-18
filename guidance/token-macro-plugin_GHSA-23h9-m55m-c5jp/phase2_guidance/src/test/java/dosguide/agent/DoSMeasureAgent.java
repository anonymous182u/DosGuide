package dosguide.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Measurement-only Java agent (R37, R43) for both V1 and V2 targets.
 *
 * <ul>
 *   <li><b>V1</b> — instruments {@code Parser#processToken()Z} to call
 *       {@link V1Counter#increment()} on entry (R36 §2: recursion depth /
 *       total nodes visited).</li>
 *   <li><b>V2</b> — instruments
 *       {@code BeginningOrEndMatchTransorm#transform(String)} to wrap the
 *       {@code CharSequence} passed to {@code Pattern.matcher()} with
 *       {@link CharSequenceProxy}, which counts {@code charAt()} calls
 *       as regex-VM steps (R36 §1: backtracking step count).</li>
 * </ul>
 *
 * Both target classes are Java-8 bytecode (major 52); ASM 5.0.3 is
 * sufficient.
 */
public class DoSMeasureAgent implements Opcodes {

    private static final String PARSER_INTERNAL =
            "org/jenkinsci/plugins/tokenmacro/Parser";
    private static final String TRANSFORM_INTERNAL =
            "org/jenkinsci/plugins/tokenmacro/transform/BeginningOrEndMatchTransorm";

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new DoSTransformer(), false);
        System.err.println("[DoSMeasureAgent] registered (V1=Parser#processToken, "
                + "V2=BeginningOrEndMatchTransorm#transform)");
    }

    // ---------------------------------------------------------------
    //  ClassFileTransformer
    // ---------------------------------------------------------------

    static class DoSTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader,
                                String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (PARSER_INTERNAL.equals(className)) {
                return instrumentV1(classfileBuffer);
            }
            if (TRANSFORM_INTERNAL.equals(className)) {
                return instrumentV2(classfileBuffer);
            }
            return null;                       // no change
        }
    }

    // ---------------------------------------------------------------
    //  V1: Parser#processToken() — count invocations
    // ---------------------------------------------------------------

    private static byte[] instrumentV1(byte[] bytes) {
        try {
            ClassReader cr = new ClassReader(bytes);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String a, String b) {
                    return "java/lang/Object";     // safe fallback in agent
                }
            };
            cr.accept(new ClassVisitor(ASM5, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                        String desc, String sig, String[] exc) {
                    MethodVisitor mv = super.visitMethod(access, name, desc, sig, exc);
                    if ("processToken".equals(name) && "()Z".equals(desc)) {
                        return new MethodVisitor(ASM5, mv) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                // V1Counter.increment();
                                mv.visitMethodInsn(INVOKESTATIC,
                                        "dosguide/agent/V1Counter",
                                        "increment", "()V", false);
                            }
                        };
                    }
                    return mv;
                }
            }, ClassReader.EXPAND_FRAMES);
            System.err.println("[DoSMeasureAgent] instrumented Parser#processToken");
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[DoSMeasureAgent] V1 instrumentation failed: " + e);
            return null;
        }
    }

    // ---------------------------------------------------------------
    //  V2: BeginningOrEndMatchTransorm#transform(String) — count
    //      charAt() via CharSequenceProxy wrapped before matcher()
    // ---------------------------------------------------------------

    private static byte[] instrumentV2(byte[] bytes) {
        try {
            ClassReader cr = new ClassReader(bytes);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String a, String b) {
                    return "java/lang/Object";
                }
            };
            cr.accept(new ClassVisitor(ASM5, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                        String desc, String sig, String[] exc) {
                    MethodVisitor mv = super.visitMethod(access, name, desc, sig, exc);
                    if ("transform".equals(name)
                            && "(Ljava/lang/String;)Ljava/lang/String;".equals(desc)) {
                        return new TransformMethodVisitor(mv);
                    }
                    return mv;
                }
            }, ClassReader.EXPAND_FRAMES);
            System.err.println("[DoSMeasureAgent] instrumented "
                    + "BeginningOrEndMatchTransorm#transform");
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[DoSMeasureAgent] V2 instrumentation failed: " + e);
            return null;
        }
    }

    /**
     * Rewrites {@code transform(String)}:
     * <ol>
     *   <li>Inserts {@code V2Counter.reset()} at method entry.</li>
     *   <li>Before {@code Pattern.matcher(CharSequence)}, wraps the
     *       CharSequence with {@code CharSequenceProxy.wrap()}.</li>
     * </ol>
     */
    private static class TransformMethodVisitor extends MethodVisitor implements Opcodes {

        TransformMethodVisitor(MethodVisitor mv) {
            super(ASM5, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // V2Counter.reset();
            mv.visitMethodInsn(INVOKESTATIC,
                    "dosguide/agent/V2Counter", "reset", "()V", false);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name,
                                    String desc, boolean itf) {
            if (opcode == INVOKEVIRTUAL
                    && "java/util/regex/Pattern".equals(owner)
                    && "matcher".equals(name)
                    && "(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;".equals(desc)) {
                // Stack: [..., Pattern, CharSequence]
                // Wrap the CharSequence on top of stack:
                mv.visitMethodInsn(INVOKESTATIC,
                        "dosguide/agent/CharSequenceProxy", "wrap",
                        "(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;",
                        false);
                // Stack: [..., Pattern, CharSequenceProxy-as-CharSequence]
            }
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }
}
