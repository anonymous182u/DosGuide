package com.fuzzing.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.AdviceAdapter;

/**
 * Java agent that instruments MultipartStream to count:
 * - readBoundary() calls  → V1Counters.incrementBoundary()
 * - readByte() calls while inside readHeaders() → V1Counters.onReadByte()
 * - readHeaders() entry/exit → V1Counters.enterHeaders() / exitHeaders()
 *
 * Uses ASM AdviceAdapter for safe method-enter / method-exit injection.
 */
public class V1MeasureAgent implements ClassFileTransformer {

    private static final String TARGET_CLASS = "org/apache/commons/fileupload/MultipartStream";
    private static final String COUNTERS      = "com/fuzzing/agent/V1Counters";

    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer(new V1MeasureAgent());
    }

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain pd, byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) {
            return null; // unchanged
        }
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
                @Override
                protected String getCommonSuperClass(String type1, String type2) {
                    // Safe fallback for agent transformations where referenced
                    // classes may not yet be loadable by the bootstrap loader.
                    try {
                        return super.getCommonSuperClass(type1, type2);
                    } catch (Exception e) {
                        return "java/lang/Object";
                    }
                }
            };

            cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name,
                                                  String descriptor, String signature,
                                                  String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor,
                            signature, exceptions);

                    // readBoundary()Z — count boundary iterations
                    if ("readBoundary".equals(name) && "()Z".equals(descriptor)) {
                        return new AdviceAdapter(Opcodes.ASM9, mv, access, name, descriptor) {
                            @Override
                            protected void onMethodEnter() {
                                visitMethodInsn(INVOKESTATIC, COUNTERS,
                                        "incrementBoundary", "()V", false);
                            }
                        };
                    }

                    // readByte()B — count byte reads while inside readHeaders
                    if ("readByte".equals(name) && "()B".equals(descriptor)) {
                        return new AdviceAdapter(Opcodes.ASM9, mv, access, name, descriptor) {
                            @Override
                            protected void onMethodEnter() {
                                visitMethodInsn(INVOKESTATIC, COUNTERS,
                                        "onReadByte", "()V", false);
                            }
                        };
                    }

                    // readHeaders()Ljava/lang/String; — flag in-headers + count exit
                    if ("readHeaders".equals(name)
                            && "()Ljava/lang/String;".equals(descriptor)) {
                        return new AdviceAdapter(Opcodes.ASM9, mv, access, name, descriptor) {
                            @Override
                            protected void onMethodEnter() {
                                visitMethodInsn(INVOKESTATIC, COUNTERS,
                                        "enterHeaders", "()V", false);
                            }
                            @Override
                            protected void onMethodExit(int opcode) {
                                // Called before every RETURN and ATHROW instruction.
                                visitMethodInsn(INVOKESTATIC, COUNTERS,
                                        "exitHeaders", "()V", false);
                            }
                        };
                    }

                    return mv;
                }
            }, ClassReader.EXPAND_FRAMES);

            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[V1MeasureAgent] transformation failed: " + e);
            e.printStackTrace(System.err);
            return null; // return untransformed class
        }
    }
}
