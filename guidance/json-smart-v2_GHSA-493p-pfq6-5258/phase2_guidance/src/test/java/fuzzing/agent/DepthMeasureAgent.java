package fuzzing.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * Custom Java agent that instruments JSONParserBase to measure recursion depth
 * and node count for the parser DoS vulnerability (CWE-674).
 *
 * Instrumented methods:
 *   - readArray(JsonReaderI)  : enterDepth() on entry, exitDepth() in finally
 *   - readObject(JsonReaderI) : enterDepth() on entry, exitDepth() in finally
 *   - readMain(JsonReaderI, boolean[]) : enterNode() on entry only
 *
 * Measurement only — does not generate inputs or embed payloads ([R37]).
 */
public class DepthMeasureAgent {

    private static final String TARGET_CLASS = "net/minidev/json/parser/JSONParserBase";
    private static final String COUNTERS_CLASS = "fuzzing/agent/DepthCounters";

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new Transformer(), false);
    }

    static class Transformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (!TARGET_CLASS.equals(className)) {
                return null; // don't transform other classes
            }
            System.out.println("[DepthMeasureAgent] Transforming " + className
                    + " (loader=" + loader + ")");
            try {
                ClassReader cr = new ClassReader(classfileBuffer);
                // Use a ClassWriter that resolves classes via the target's own
                // classloader.  This is critical when JQF's InstrumentingClassLoader
                // triggers the transform – the default ClassWriter.getCommonSuperClass
                // would fail because it uses Class.forName with the system classloader.
                final ClassLoader resolveLoader = loader != null ? loader
                        : ClassLoader.getSystemClassLoader();
                ClassWriter cw = new ClassWriter(cr,
                        ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS) {
                    @Override
                    protected String getCommonSuperClass(String type1, String type2) {
                        try {
                            Class<?> c1 = Class.forName(type1.replace('/', '.'),
                                    false, resolveLoader);
                            Class<?> c2 = Class.forName(type2.replace('/', '.'),
                                    false, resolveLoader);
                            if (c1.isAssignableFrom(c2)) return type1;
                            if (c2.isAssignableFrom(c1)) return type2;
                            if (c1.isInterface() || c2.isInterface())
                                return "java/lang/Object";
                            do { c1 = c1.getSuperclass(); }
                            while (!c1.isAssignableFrom(c2));
                            return c1.getName().replace('.', '/');
                        } catch (Exception e) {
                            return "java/lang/Object";
                        }
                    }
                };
                ClassVisitor cv = new ParserClassVisitor(cw);
                cr.accept(cv, ClassReader.EXPAND_FRAMES);
                byte[] result = cw.toByteArray();
                System.out.println("[DepthMeasureAgent] Successfully transformed "
                        + className + " (" + result.length + " bytes)");
                return result;
            } catch (Throwable t) {
                System.err.println("[DepthMeasureAgent] ERROR transforming "
                        + className + ": " + t);
                t.printStackTrace(System.err);
                return null; // fall back to uninstrumented class
            }
        }
    }

    static class ParserClassVisitor extends ClassVisitor {
        ParserClassVisitor(ClassVisitor cv) {
            super(Opcodes.ASM9, cv);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv == null) return null;

            // readArray(Lnet/minidev/json/writer/JsonReaderI;)Ljava/lang/Object;
            // readObject(Lnet/minidev/json/writer/JsonReaderI;)Ljava/lang/Object;
            if (("readArray".equals(name) || "readObject".equals(name))
                    && descriptor.startsWith("(Lnet/minidev/json/writer/JsonReaderI;)")) {
                return new DepthTrackingMethodVisitor(mv, access, name, descriptor);
            }

            // readMain(Lnet/minidev/json/writer/JsonReaderI;[Z)Ljava/lang/Object;
            if ("readMain".equals(name)
                    && descriptor.startsWith("(Lnet/minidev/json/writer/JsonReaderI;[Z)")) {
                return new NodeCountMethodVisitor(mv);
            }

            return mv;
        }
    }

    /**
     * Wraps readArray/readObject with enterDepth() on entry and exitDepth() in
     * a try-finally block so that depth is decremented even on exceptions.
     */
    static class DepthTrackingMethodVisitor extends MethodVisitor {
        private final Label tryStart = new Label();
        private final Label tryEnd = new Label();
        private final Label catchHandler = new Label();

        DepthTrackingMethodVisitor(MethodVisitor mv, int access, String name, String desc) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // Register the try-catch-all block (must come before labels are visited)
            super.visitTryCatchBlock(tryStart, tryEnd, catchHandler, null);
            // Call DepthCounters.enterDepth()
            super.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                    "enterDepth", "()V", false);
            // Mark start of the try block
            super.visitLabel(tryStart);
        }

        @Override
        public void visitInsn(int opcode) {
            // Before any return instruction, call exitDepth()
            if (opcode == Opcodes.ARETURN || opcode == Opcodes.RETURN) {
                super.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                        "exitDepth", "()V", false);
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitMaxs(int maxStack, int maxLocals) {
            // Mark end of the try block
            super.visitLabel(tryEnd);
            // Catch handler: exception is on the stack
            super.visitLabel(catchHandler);
            // Store the exception temporarily
            super.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                    "exitDepth", "()V", false);
            // Rethrow the exception (still on the stack)
            super.visitInsn(Opcodes.ATHROW);
            // Let ASM compute the correct maxStack/maxLocals
            super.visitMaxs(maxStack, maxLocals);
        }
    }

    /**
     * Inserts enterNode() at the start of readMain to count total node visits.
     */
    static class NodeCountMethodVisitor extends MethodVisitor {
        NodeCountMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            super.visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS_CLASS,
                    "enterNode", "()V", false);
        }
    }
}
