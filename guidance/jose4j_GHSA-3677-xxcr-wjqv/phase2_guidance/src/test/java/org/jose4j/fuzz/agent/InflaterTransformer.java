package org.jose4j.fuzz.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.AdviceAdapter;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * ASM-based ClassFileTransformer that instruments
 * org.jose4j.zip.DeflateRFC1951CompressionAlgorithm.decompress(byte[]) → byte[]
 * to call InflateCounters.addBytes(returnValue.length) on every normal return.
 *
 * This measures total decompressed bytes at the exact site where the amplification
 * cost is incurred (CWE-409 decompression bomb) — the jose4j decompress() method
 * that wraps java.util.zip.Inflater.
 *
 * Unlike instrumenting the JDK Inflater class directly, this approach:
 * - Transforms a class that loads DURING the test (not at JVM bootstrap),
 *   so the validation framework sees the rewrite happen
 * - Only captures jose4j decompression (not JVM-internal inflate calls
 *   for jar reading, class loading, etc.), giving deterministic signals
 * - Avoids COMPUTE_FRAMES issues with JDK internal classes
 * - Both instrumented code and Guidance share the same classloader,
 *   so InflateCounters reset/get work correctly (no dual-class problem)
 */
public final class InflaterTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS = "org/jose4j/zip/DeflateRFC1951CompressionAlgorithm";
    private static final String TARGET_METHOD = "decompress";
    private static final String TARGET_DESC = "([B)[B";
    private static final String COUNTERS_CLASS = "org/jose4j/fuzz/agent/InflateCounters";

    /** Track whether we actually transformed a class (for diagnostics). */
    private volatile boolean transformed = false;

    public boolean wasTransformed() {
        return transformed;
    }

    @Override
    public byte[] transform(ClassLoader loader,
                            String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null; // don't touch other classes
        }
        try {
            System.err.println("[V1MeasureAgent] Transforming " + className);
            ClassReader cr = new ClassReader(classfileBuffer);
            // Use COMPUTE_MAXS only — safer than COMPUTE_FRAMES for cross-classloader scenarios
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                    if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                        System.err.println("[V1MeasureAgent] Instrumenting " + name + descriptor);
                        return new DecompressAdvice(Opcodes.ASM9, mv, access, name, descriptor);
                    }
                    return mv;
                }
            };
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            transformed = true;
            System.err.println("[V1MeasureAgent] Successfully transformed DeflateRFC1951CompressionAlgorithm");
            return cw.toByteArray();
        } catch (Throwable t) {
            System.err.println("[V1MeasureAgent] Failed to transform DeflateRFC1951CompressionAlgorithm: " + t);
            t.printStackTrace(System.err);
            return null; // return untouched class
        }
    }

    /**
     * AdviceAdapter that injects InflateCounters.addBytes(returnValue.length) on method exit.
     *
     * The decompress method returns byte[] (the decompressed data).
     * On ARETURN we: DUP the byte[] ref, ARRAYLENGTH to get its length (int),
     * then INVOKESTATIC InflateCounters.addBytes(int).
     */
    private static final class DecompressAdvice extends AdviceAdapter {

        protected DecompressAdvice(int api, MethodVisitor mv, int access, String name, String desc) {
            super(api, mv, access, name, desc);
        }

        @Override
        protected void onMethodExit(int opcode) {
            if (opcode == ARETURN) {
                // Stack: ..., byte[] (return value = decompressed data)
                dup();                  // ..., byte[], byte[]
                arrayLength();          // ..., byte[], int (length = decompressed bytes)
                visitMethodInsn(INVOKESTATIC, COUNTERS_CLASS, "addBytes", "(I)V", false);
                // Stack: ..., byte[] (original return value unchanged)
            }
        }
    }
}
