package org.elasticsearch.compute.data.fuzz.agent;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.util.jar.JarFile;

/**
 * Java agent entry point. Registers the {@link BlockBuilderAllocTransformer} that
 * instruments IntBlockBuilder and LongBlockBuilder constructors to measure allocation
 * bytes at the NEWARRAY hotspot.
 *
 * Measurement only — this agent never generates inputs or embeds payloads ([R37]).
 *
 * Usage: -javaagent:target/blockbuilder-alloc-agent.jar
 */
public class BlockBuilderAllocAgent {

    public static void premain(String args, Instrumentation inst) {
        // Add the agent JAR to the bootstrap classpath so that AllocCounter is
        // visible to every classloader (including JQF's InstrumentingClassLoader).
        try {
            URL agentUrl = BlockBuilderAllocAgent.class
                    .getProtectionDomain().getCodeSource().getLocation();
            File agentFile = new File(agentUrl.toURI());
            if (agentFile.isFile()) {
                inst.appendToBootstrapClassLoaderSearch(new JarFile(agentFile));
            }
        } catch (Exception e) {
            System.err.println("[BlockBuilderAllocAgent] WARN: could not add to bootstrap classpath: " + e);
        }

        // Register the class-file transformer (measurement only).
        inst.addTransformer(new BlockBuilderAllocTransformer(), false);
    }
}
