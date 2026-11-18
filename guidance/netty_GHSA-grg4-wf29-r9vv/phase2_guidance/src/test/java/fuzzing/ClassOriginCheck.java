package fuzzing;

/** Prints where the vulnerable Netty classes are loaded from (must be lib/ or target/dependency jars). */
public final class ClassOriginCheck {
    private ClassOriginCheck() { }

    public static void main(String[] args) throws Exception {
        String[] names = {
            "io.netty.handler.codec.compression.Bzip2Decoder",
            "io.netty.handler.codec.compression.Bzip2Encoder",
            "io.netty.channel.embedded.EmbeddedChannel",
            "io.netty.buffer.Unpooled",
        };
        for (String n : names) {
            Class<?> c = Class.forName(n);
            System.out.println(n + " -> " + c.getProtectionDomain().getCodeSource().getLocation());
        }
    }
}
