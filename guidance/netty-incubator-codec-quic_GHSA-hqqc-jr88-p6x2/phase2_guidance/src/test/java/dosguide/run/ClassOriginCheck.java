package dosguide.run;

import java.security.CodeSource;

/** Prints where the vulnerable classes are loaded from (must be lib/*.jar, not target/classes). */
public final class ClassOriginCheck {

    private ClassOriginCheck() {
    }

    public static void main(String[] args) throws Exception {
        String[] names = {
            "io.netty.incubator.codec.quic.QuicheQuicCodec",
            "io.netty.incubator.codec.quic.QuicheQuicServerCodec",
            "io.netty.incubator.codec.quic.QuicServerCodecBuilder",
            "io.netty.incubator.codec.quic.Quic",
        };
        for (String n : names) {
            Class<?> c = Class.forName(n, false, ClassOriginCheck.class.getClassLoader());
            CodeSource cs = c.getProtectionDomain().getCodeSource();
            System.out.println(n + " -> " + (cs == null ? "null" : cs.getLocation()));
        }
        Class<?> counters = Class.forName("dosguide.agent.DoSCounters");
        System.out.println("dosguide.agent.DoSCounters loader -> " + counters.getClassLoader()
                + " (null = bootstrap, i.e. agent attached)");
    }
}
