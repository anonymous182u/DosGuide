package com.fuzzer.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * ASM ClassFileTransformer that instruments DeflateUtil.decode(byte[]).
 *
 * Transformation: before every ARETURN in decode([B)Ljava/io/InputStream;,
 * inserts INVOKESTATIC V1CountingStream.wrap(InputStream)InputStream.
 * This wraps the InflaterInputStream in a byte-counting FilterInputStream
 * so that every byte read by DocumentBuilder.parse() is counted in V1Counters.
 *
 * Instrumented class: org.keycloak.saml.processing.api.util.DeflateUtil
 * — an application-level Keycloak class (not a JDK class), so no
 * --add-reads or --add-opens JVM flags are required.
 */
public final class V1DeflateUtilTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS =
            "org/keycloak/saml/processing/api/util/DeflateUtil";
    private static final String TARGET_METHOD = "decode";
    private static final String TARGET_DESC = "([B)Ljava/io/InputStream;";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null; // no transformation for other classes
        }
        try {
            System.err.println("[V1Agent] Transforming " + className);
            ClassReader cr = new ClassReader(classfileBuffer);
            // COMPUTE_FRAMES with safe getCommonSuperClass fallback
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    // Safe fallback: avoids ClassNotFoundException during transformation
                    return "java/lang/Object";
                }
            };
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                                                  String descriptor, String signature,
                                                  String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor,
                                                         signature, exceptions);
                    if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                        System.err.println("[V1Agent] Instrumenting method: " + name + descriptor);
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitInsn(int opcode) {
                                if (opcode == Opcodes.ARETURN) {
                                    // Before ARETURN: stack has InputStream (InflaterInputStream)
                                    // Insert: INVOKESTATIC V1CountingStream.wrap(InputStream)InputStream
                                    super.visitMethodInsn(
                                            Opcodes.INVOKESTATIC,
                                            "com/fuzzer/agent/V1CountingStream",
                                            "wrap",
                                            "(Ljava/io/InputStream;)Ljava/io/InputStream;",
                                            false);
                                    // Stack now has V1CountingStream (which IS-A InputStream)
                                }
                                super.visitInsn(opcode);
                            }
                        };
                    }
                    return mv;
                }
            };
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            byte[] result = cw.toByteArray();
            System.err.println("[V1Agent] DeflateUtil transformed successfully ("
                    + classfileBuffer.length + " -> " + result.length + " bytes)");
            return result;
        } catch (Throwable t) {
            System.err.println("[V1Agent] ERROR transforming DeflateUtil: " + t);
            t.printStackTrace(System.err);
            return null; // return null = keep original bytecode
        }
    }
}
