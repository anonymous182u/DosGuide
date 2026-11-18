package org.opensearch.fuzz.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.AdviceAdapter;

/**
 * Rewrites the recursive productions of Lucene's classic QueryParser and the OpenSearch sink
 * QueryStringQueryParser#parse so that they call into {@link V1Counters}. Measurement only:
 * the transformer adds static calls with no arguments and changes no other behaviour.
 */
public final class V1ParserTransformer implements ClassFileTransformer {

    static final String QUERY_PARSER = "org/apache/lucene/queryparser/classic/QueryParser";
    static final String QS_PARSER = "org/opensearch/index/search/QueryStringQueryParser";
    private static final String COUNTERS = "org/opensearch/fuzz/agent/V1Counters";
    private static final String PROD_DESC = "(Ljava/lang/String;)Lorg/apache/lucene/search/Query;";

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className == null) {
            return null;
        }
        final boolean isQp = QUERY_PARSER.equals(className);
        final boolean isQs = QS_PARSER.equals(className);
        if (!isQp && !isQs) {
            return null;
        }
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            final int[] count = {0};
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] ex) {
                    MethodVisitor mv = super.visitMethod(access, name, desc, sig, ex);
                    if (!PROD_DESC.equals(desc)) {
                        return mv;
                    }
                    final String enter;
                    final String exit;
                    if (isQp && "Clause".equals(name)) {
                        enter = "enterClause";
                        exit = "exitClause";
                    } else if (isQp && "Query".equals(name)) {
                        enter = "enterQuery";
                        exit = null;
                    } else if (isQs && "parse".equals(name)) {
                        enter = "enterParse";
                        exit = "exitParse";
                    } else {
                        return mv;
                    }
                    count[0]++;
                    return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
                        @Override
                        protected void onMethodEnter() {
                            visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS, enter, "()V", false);
                        }

                        @Override
                        protected void onMethodExit(int opcode) {
                            if (exit != null && opcode != Opcodes.ATHROW) {
                                visitMethodInsn(Opcodes.INVOKESTATIC, COUNTERS, exit, "()V", false);
                            }
                        }
                    };
                }
            };
            // AdviceAdapter (via LocalVariablesSorter) only accepts expanded stack map frames.
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            V1Counters.instrumentedMethods += count[0];
            System.err.println("[V1MeasureAgent] instrumented " + count[0] + " method(s) in " + className.replace('/', '.'));
            return cw.toByteArray();
        } catch (Throwable t) {
            System.err.println("[V1MeasureAgent] failed to instrument " + className + ": " + t);
            t.printStackTrace();
            return null;
        }
    }
}
