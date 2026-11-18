package org.xerial.snappy.fuzz;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Custom Java agent that instruments allocation sites in snappy-java
 * to measure bytes requested by NEWARRAY T_BYTE instructions.
 * <p>
 * Instrumented sites:
 * <ul>
 *   <li>SnappyInputStream.hasNextChunk(): 1st NEWARRAY T_BYTE → AllocCounters.record0 (V1 signal)</li>
 *   <li>SnappyInputStream.hasNextChunk(): 2nd NEWARRAY T_BYTE → AllocCounters.record1 (V2 signal)</li>
 *   <li>Snappy.uncompress(byte[]): 1st NEWARRAY T_BYTE → AllocCounters.record2 (V3 signal)</li>
 * </ul>
 * <p>
 * The agent is measurement-only: it does not generate inputs or embed exploit payloads.
 */
public class AllocationMeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new AllocTransformer(), false);
        System.err.println("[AllocationMeasureAgent] Registered class transformer");
    }

    static class AllocTransformer implements ClassFileTransformer {

        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if ("org/xerial/snappy/SnappyInputStream".equals(className)) {
                System.err.println("[AllocationMeasureAgent] Instrumenting SnappyInputStream.hasNextChunk");
                return instrumentClass(classfileBuffer, "hasNextChunk", "()Z",
                        new int[]{0, 1});
            }
            if ("org/xerial/snappy/Snappy".equals(className)) {
                System.err.println("[AllocationMeasureAgent] Instrumenting Snappy.uncompress([B)[B");
                return instrumentClass(classfileBuffer, "uncompress", "([B)[B",
                        new int[]{2});
            }
            return null; // no transformation for other classes
        }

        /**
         * Instrument a class by injecting AllocCounters.recordN(int) calls
         * before each NEWARRAY T_BYTE instruction in the specified method.
         *
         * @param classBytes  original bytecode
         * @param methodName  method to instrument
         * @param methodDesc  method descriptor
         * @param slotMapping slot index for each NEWARRAY T_BYTE occurrence (in order)
         * @return modified bytecode, or null on failure
         */
        private byte[] instrumentClass(byte[] classBytes, String methodName,
                                       String methodDesc, int[] slotMapping) {
            try {
                ClassReader cr = new ClassReader(classBytes);
                ClassWriter cw = new ClassWriter(cr,
                        ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
                cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name,
                                                     String descriptor, String signature,
                                                     String[] exceptions) {
                        MethodVisitor mv = super.visitMethod(access, name, descriptor,
                                signature, exceptions);
                        if (name.equals(methodName) && descriptor.equals(methodDesc)) {
                            return new AllocMethodVisitor(mv, slotMapping);
                        }
                        return mv;
                    }
                }, 0);
                byte[] result = cw.toByteArray();
                System.err.println("[AllocationMeasureAgent] Successfully instrumented "
                        + methodName + methodDesc);
                return result;
            } catch (Exception e) {
                System.err.println("[AllocationMeasureAgent] Failed to instrument "
                        + methodName + ": " + e.getMessage());
                e.printStackTrace(System.err);
                return null;
            }
        }
    }

    /**
     * MethodVisitor that injects DUP + INVOKESTATIC AllocCounters.recordN(I)V
     * before each NEWARRAY T_BYTE instruction.
     */
    static class AllocMethodVisitor extends MethodVisitor {
        private final int[] slotMapping;
        private int newArrayByteCount = 0;

        AllocMethodVisitor(MethodVisitor mv, int[] slotMapping) {
            super(Opcodes.ASM9, mv);
            this.slotMapping = slotMapping;
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (opcode == Opcodes.NEWARRAY && operand == Opcodes.T_BYTE) {
                if (newArrayByteCount < slotMapping.length) {
                    int slot = slotMapping[newArrayByteCount];
                    // Stack: [..., count]
                    mv.visitInsn(Opcodes.DUP);
                    // Stack: [..., count, count]
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                            "org/xerial/snappy/fuzz/AllocCounters",
                            "record" + slot, "(I)V", false);
                    // Stack: [..., count]
                    System.err.println("[AllocationMeasureAgent] Injected record"
                            + slot + " before NEWARRAY T_BYTE #" + newArrayByteCount);
                }
                newArrayByteCount++;
            }
            super.visitIntInsn(opcode, operand);
        }
    }
}
