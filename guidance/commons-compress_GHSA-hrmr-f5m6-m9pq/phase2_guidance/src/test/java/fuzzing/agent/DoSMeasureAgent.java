package fuzzing.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * Custom Java agent that instruments both V1 and PkgRisk1 target methods.
 * Measurement-only: does not generate inputs or embed payloads [R37].
 *
 * V1: instruments ZipArchiveInputStream#readStored([BII)I
 *     — sums positive return values into V1Counters.
 * PkgRisk1: instruments BZip2CompressorInputStream#read([BII)I
 *     — sums positive return values into PkgRisk1Counters.
 */
public final class DoSMeasureAgent {

    private static final String ZIP_CLASS = "org/apache/commons/compress/archivers/zip/ZipArchiveInputStream";
    private static final String BZ2_CLASS = "org/apache/commons/compress/compressors/bzip2/BZip2CompressorInputStream";

    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer(new Transformer(), false);
    }

    private static final class Transformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String className,
                                Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (ZIP_CLASS.equals(className)) {
                return instrumentClass(classfileBuffer, "readStored", "([BII)I",
                        "fuzzing/agent/V1Counters", "addBytes");
            }
            if (BZ2_CLASS.equals(className)) {
                return instrumentClass(classfileBuffer, "read", "([BII)I",
                        "fuzzing/agent/PkgRisk1Counters", "addBytes");
            }
            return null; // no transformation
        }
    }

    /**
     * Instruments a single method: before every IRETURN, duplicate the return value
     * and call CounterClass.addBytes(int).
     */
    private static byte[] instrumentClass(byte[] classBytes, String methodName,
                                          String methodDesc, String counterClass,
                                          String counterMethod) {
        ClassReader cr = new ClassReader(classBytes);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
        cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (name.equals(methodName) && descriptor.equals(methodDesc)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitInsn(int opcode) {
                            if (opcode == Opcodes.IRETURN) {
                                // Stack: ..., int_return_value
                                mv.visitInsn(Opcodes.DUP);
                                // Stack: ..., int_return_value, int_return_value
                                mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                        counterClass, counterMethod, "(I)V", false);
                                // Stack: ..., int_return_value
                            }
                            super.visitInsn(opcode);
                        }
                    };
                }
                return mv;
            }
        }, 0);
        return cw.toByteArray();
    }
}
