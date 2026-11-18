package fuzzing.agent;

import java.lang.instrument.Instrumentation;
import java.util.jar.JarFile;

/**
 * Java agent (measurement-only) that instruments FullDTDReader#readContentSpec
 * to track recursion depth via V1Counters.
 *
 * Usage: -javaagent:target/v1-agent.jar
 *
 * The agent appends V1Counters to the bootstrap classloader so it is
 * accessible from both the instrumented Woodstox code (loaded by the app
 * classloader) and the Guidance (loaded by the test classloader).
 */
public class V1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[V1Agent] Registering V1ClassTransformer for FullDTDReader#readContentSpec");

        // Append the agent jar itself to the bootstrap classloader search
        // so that V1Counters is visible to instrumented code in any classloader.
        String agentJarPath = findAgentJarPath();
        if (agentJarPath != null) {
            try {
                inst.appendToBootstrapClassLoaderSearch(new JarFile(agentJarPath));
                System.out.println("[V1Agent] Appended agent jar to bootstrap classloader: " + agentJarPath);
            } catch (Exception e) {
                System.err.println("[V1Agent] WARNING: Could not append to bootstrap classloader: " + e.getMessage());
                // Continue anyway — the counters may still work if classloaders align
            }
        }

        inst.addTransformer(new V1ClassTransformer());
        System.out.println("[V1Agent] Transformer registered successfully");
    }

    /**
     * Finds the path of the agent jar from the java.class.path or sun.java.command.
     * Falls back to searching for 'v1-agent.jar' in common locations.
     */
    private static String findAgentJarPath() {
        // Try to find from the protection domain of this class
        try {
            java.security.CodeSource cs =
                    V1MeasureAgent.class.getProtectionDomain().getCodeSource();
            if (cs != null && cs.getLocation() != null) {
                String path = cs.getLocation().getPath();
                if (path.endsWith(".jar")) {
                    return path;
                }
            }
        } catch (Exception e) {
            // ignore
        }

        // Try to find from the classpath
        String cp = System.getProperty("java.class.path", "");
        for (String entry : cp.split(System.getProperty("path.separator", ":"))) {
            if (entry.contains("v1-agent")) {
                return entry;
            }
        }

        return null;
    }
}
