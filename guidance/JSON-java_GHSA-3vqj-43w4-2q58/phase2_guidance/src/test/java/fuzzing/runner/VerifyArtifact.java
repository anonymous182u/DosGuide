package fuzzing.runner;

/**
 * Prints the CodeSource of org.json.JSONML to verify
 * the vulnerable jar is on the classpath.
 */
public class VerifyArtifact {
    public static void main(String[] args) throws Exception {
        Class<?> clazz = Class.forName("org.json.JSONML");
        System.out.println("Class: " + clazz.getName());
        System.out.println("CodeSource: " + clazz.getProtectionDomain().getCodeSource().getLocation());
    }
}
