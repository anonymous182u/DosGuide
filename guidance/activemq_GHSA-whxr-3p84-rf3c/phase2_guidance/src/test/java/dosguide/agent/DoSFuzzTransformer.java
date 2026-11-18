package dosguide.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * Custom ClassFileTransformer that instruments three methods in
 * BaseDataStreamMarshaller for ANY openwire version (v1 through v12).
 * Each version has its own independent BaseDataStreamMarshaller class
 * that contains the same sink methods.
 *
 * V1: looseUnmarshalByteArray — captures the int size before new byte[size]
 * V2: looseUnmarsalThrowable — counts recursion depth via entry/exit hooks
 * V3: looseUnmarsalNestedObject — counts nesting depth via entry/exit hooks
 *
 * Measurement-only: no input generation or exploit payloads.
 */
public class DoSFuzzTransformer implements ClassFileTransformer {

    private static final String COLLECTOR =
        "dosguide/agent/SignalCollector";

    /**
     * Check if this class is any version's BaseDataStreamMarshaller.
     * Matches: org/apache/activemq/openwire/v{N}/BaseDataStreamMarshaller
     */
    private static boolean isTargetClass(String className) {
        if (className == null) return false;
        return className.startsWith("org/apache/activemq/openwire/v")
            && className.endsWith("/BaseDataStreamMarshaller");
    }

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!isTargetClass(className)) {
            return null; // no transformation
        }
        try {
            System.err.println("[DoSFuzzAgent] Transforming " + className);
            ClassReader cr = new ClassReader(classfileBuffer);
            // Use a ClassWriter that delegates class resolution to the target classloader
            // to avoid TypeNotPresentException during COMPUTE_FRAMES.
            final ClassLoader resolveLoader = loader != null ? loader
                    : Thread.currentThread().getContextClassLoader();
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected ClassLoader getClassLoader() {
                    return resolveLoader;
                }
            };
            ClassVisitor cv = new InstrumentingClassVisitor(cw);
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            System.err.println("[DoSFuzzAgent] Successfully transformed " + className);
            return cw.toByteArray();
        } catch (Throwable t) {
            System.err.println("[DoSFuzzAgent] ERROR transforming " + className + ": " + t);
            t.printStackTrace(System.err);
            return null; // return original on error
        }
    }

    /**
     * ClassVisitor that delegates to method-specific MethodVisitors.
     */
    private static class InstrumentingClassVisitor extends ClassVisitor {
        InstrumentingClassVisitor(ClassWriter cw) {
            super(Opcodes.ASM9, cw);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                          String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv == null) return null;

            if ("looseUnmarshalByteArray".equals(name)
                    && "(Ljava/io/DataInput;)[B".equals(descriptor)) {
                return new AllocSizeMethodVisitor(mv);
            }
            if ("looseUnmarsalThrowable".equals(name)
                    && "(Lorg/apache/activemq/openwire/OpenWireFormat;Ljava/io/DataInput;)Ljava/lang/Throwable;".equals(descriptor)) {
                return new RecursionDepthMethodVisitor(mv, "enterThrowable", "exitThrowable");
            }
            if ("looseUnmarsalNestedObject".equals(name)
                    && "(Lorg/apache/activemq/openwire/OpenWireFormat;Ljava/io/DataInput;)Lorg/apache/activemq/command/DataStructure;".equals(descriptor)) {
                return new RecursionDepthMethodVisitor(mv, "enterNesting", "exitNesting");
            }
            return mv;
        }
    }

    /**
     * V1: Instruments looseUnmarshalByteArray to capture the int size
     * passed to new byte[size]. We look for the NEWARRAY T_BYTE instruction
     * and insert a DUP + call to SignalCollector.recordAlloc(int) before it.
     */
    private static class AllocSizeMethodVisitor extends MethodVisitor {
        AllocSizeMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (opcode == Opcodes.NEWARRAY && operand == Opcodes.T_BYTE) {
                // Stack has: ..., size(int)
                // DUP the size, call recordAlloc, then do NEWARRAY
                mv.visitInsn(Opcodes.DUP);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, COLLECTOR,
                    "recordAlloc", "(I)V", false);
            }
            super.visitIntInsn(opcode, operand);
        }
    }

    /**
     * V2/V3: Instruments entry and exit of a recursive method.
     * On entry: call the enterXxx method on SignalCollector.
     * On every return/athrow: call the exitXxx method.
     * Wraps the entire method body in try-finally to ensure exit on exceptions.
     */
    private static class RecursionDepthMethodVisitor extends MethodVisitor {
        private final String enterMethod;
        private final String exitMethod;

        RecursionDepthMethodVisitor(MethodVisitor mv, String enterMethod, String exitMethod) {
            super(Opcodes.ASM9, mv);
            this.enterMethod = enterMethod;
            this.exitMethod = exitMethod;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // Insert enter call at method entry
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, COLLECTOR,
                enterMethod, "()V", false);
        }

        @Override
        public void visitInsn(int opcode) {
            // Before every RETURN or ATHROW, insert exit call
            if (opcode == Opcodes.ARETURN || opcode == Opcodes.RETURN
                    || opcode == Opcodes.IRETURN || opcode == Opcodes.LRETURN
                    || opcode == Opcodes.FRETURN || opcode == Opcodes.DRETURN
                    || opcode == Opcodes.ATHROW) {
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, COLLECTOR,
                    exitMethod, "()V", false);
            }
            super.visitInsn(opcode);
        }
    }
}
