package dosguide.agent;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Measurement-only java agent for the netty QUIC connection-id HashDoS targets (V1, PkgRisk1).
 *
 * <p>Instruments (see {@link DoSTransformer}):</p>
 * <ul>
 *   <li>{@code java.util.HashMap$TreeNode#find}: one counter call per tree-bin node visited</li>
 *   <li>{@code java.util.HashMap$TreeNode#putTreeVal}: scope enter/exit</li>
 *   <li>{@code java.util.HashMap$TreeNode#treeify}: treeification events</li>
 *   <li>{@code java.nio.ByteBuffer#equals}: key comparisons</li>
 *   <li>{@code io.netty.incubator.codec.quic.QuicheQuicCodec#getChannel} / {@code #addChannel}: scopes</li>
 * </ul>
 *
 * <p>This class must not reference {@link DoSCounters} directly (that would load it through the
 * application class loader before it is put on the bootstrap path).</p>
 */
public final class DoSMeasureAgent {

    private DoSMeasureAgent() {
    }

    public static void premain(String args, Instrumentation inst) throws Exception {
        install(inst);
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        install(inst);
    }

    private static void install(Instrumentation inst) throws Exception {
        File countersJar = writeCountersJar();
        inst.appendToBootstrapClassLoaderSearch(new JarFile(countersJar));

        DoSTransformer transformer = new DoSTransformer();
        inst.addTransformer(transformer, true);

        Class<?> treeNode = Class.forName("java.util.HashMap$TreeNode");
        Class<?> byteBuffer = java.nio.ByteBuffer.class;
        for (Class<?> c : new Class<?>[] {treeNode, byteBuffer}) {
            if (inst.isModifiableClass(c)) {
                inst.retransformClasses(c);
            } else {
                System.err.println("[DoSMeasureAgent] not modifiable: " + c.getName());
            }
        }
        Class<?> counters = Class.forName("dosguide.agent.DoSCounters", true, null);
        counters.getField("agentActive").setBoolean(null, true);
        counters.getField("transformedClasses").setInt(null, transformer.transformedCount());
        counters.getField("transformedNames").set(null, transformer.transformedNames());
        System.err.println("[DoSMeasureAgent] installed; counters loader="
                + counters.getClassLoader() + " retransformed=" + transformer.transformedCount());
    }

    /** Copies the DoSCounters class file (a resource of the agent jar) into a temp jar. */
    private static File writeCountersJar() throws IOException {
        String res = "dosguide/agent/DoSCounters.class";
        byte[] bytes;
        try (InputStream in = DoSMeasureAgent.class.getClassLoader().getResourceAsStream(res)) {
            if (in == null) {
                throw new IOException("resource not found: " + res);
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            in.transferTo(bos);
            bytes = bos.toByteArray();
        }
        File jar = File.createTempFile("dosguide-counters", ".jar");
        jar.deleteOnExit();
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jar))) {
            jos.putNextEntry(new JarEntry(res));
            jos.write(bytes);
            jos.closeEntry();
        }
        return jar;
    }
}
