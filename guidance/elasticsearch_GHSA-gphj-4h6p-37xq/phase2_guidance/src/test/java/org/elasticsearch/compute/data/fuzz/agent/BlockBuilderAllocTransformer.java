package org.elasticsearch.compute.data.fuzz.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * ASM-based class-file transformer that instruments the constructors of
 * {@code IntBlockBuilder} and {@code LongBlockBuilder}.
 *
 * <p>For each constructor, immediately before the {@code NEWARRAY} bytecode instruction
 * (offset 28 — where the values array is allocated), this transformer injects:
 * <pre>
 *   DUP                            // duplicate initialSize (already on the stack)
 *   ICONST_4 / BIPUSH 8            // push element size (4 for int, 8 for long)
 *   INVOKESTATIC AllocCounter.recordAlloc(II)V
 * </pre>
 * This records the true allocation size (using long arithmetic) at the exact
 * consumption hotspot, before the NEWARRAY that may OOM.
 */
public class BlockBuilderAllocTransformer implements ClassFileTransformer {

    private static final String INT_BUILDER  = "org/elasticsearch/compute/data/IntBlockBuilder";
    private static final String LONG_BUILDER = "org/elasticsearch/compute/data/LongBlockBuilder";
    private static final String CONSTRUCTOR_DESC = "(ILorg/elasticsearch/compute/data/BlockFactory;)V";

    private static final String COUNTER_CLASS  = "org/elasticsearch/compute/data/fuzz/agent/AllocCounter";
    private static final String COUNTER_METHOD = "recordAlloc";
    private static final String COUNTER_DESC   = "(II)V";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (className == null) return null;
        if (!INT_BUILDER.equals(className) && !LONG_BUILDER.equals(className)) {
            return null; // no transformation for other classes
        }

        boolean isInt = INT_BUILDER.equals(className);
        int elemSize  = isInt ? 4 : 8;
        int arrayType = isInt ? Opcodes.T_INT : Opcodes.T_LONG;

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, 0); // no COMPUTE_FRAMES needed
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                  String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                    if ("<init>".equals(name) && CONSTRUCTOR_DESC.equals(descriptor)) {
                        return new NewArrayInstrumentor(mv, elemSize, arrayType);
                    }
                    return mv;
                }
            };
            cr.accept(cv, 0);
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[BlockBuilderAllocTransformer] Failed to transform "
                    + className + ": " + e);
            return null; // return original bytecode on failure
        }
    }

    /**
     * MethodVisitor that intercepts {@code NEWARRAY} instructions in the constructor
     * and inserts a call to {@link AllocCounter#recordAlloc(int, int)} before them.
     */
    private static final class NewArrayInstrumentor extends MethodVisitor {
        private final int elemSize;
        private final int expectedArrayType;

        NewArrayInstrumentor(MethodVisitor mv, int elemSize, int expectedArrayType) {
            super(Opcodes.ASM9, mv);
            this.elemSize = elemSize;
            this.expectedArrayType = expectedArrayType;
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (opcode == Opcodes.NEWARRAY && operand == expectedArrayType) {
                // Stack before: ..., initialSize
                // We insert instrumentation BEFORE the NEWARRAY executes.
                mv.visitInsn(Opcodes.DUP);                       // ..., initialSize, initialSize
                if (elemSize <= 5) {
                    mv.visitInsn(Opcodes.ICONST_0 + elemSize);   // ICONST_4
                } else {
                    mv.visitIntInsn(Opcodes.BIPUSH, elemSize);   // BIPUSH 8
                }
                mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                        COUNTER_CLASS, COUNTER_METHOD, COUNTER_DESC, false);
                // Stack after instrumentation: ..., initialSize  (ready for NEWARRAY)
            }
            super.visitIntInsn(opcode, operand);
        }
    }
}
