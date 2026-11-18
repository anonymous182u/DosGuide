package verify;

/**
 * Utility to verify the vulnerable artifact is on the classpath.
 * Prints the code source of MessageUnpacker and MessagePack classes.
 */
public class ArtifactCheck {
    public static void main(String[] args) throws Exception {
        Class<?> clz = Class.forName("org.msgpack.core.MessageUnpacker");
        System.out.println("MessageUnpacker loaded from: " +
                clz.getProtectionDomain().getCodeSource().getLocation());

        Class<?> clz2 = Class.forName("org.msgpack.core.MessagePack");
        System.out.println("MessagePack loaded from: " +
                clz2.getProtectionDomain().getCodeSource().getLocation());
    }
}
