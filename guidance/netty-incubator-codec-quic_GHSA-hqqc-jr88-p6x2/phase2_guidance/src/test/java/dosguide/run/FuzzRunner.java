package dosguide.run;

import dosguide.guidance.PkgRisk1Guidance;
import dosguide.guidance.V1Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner: {@code FuzzRunner <V1|PkgRisk1> [seconds] [outDir]}.
 * seconds <= 0 or absent means infinite (unless -Ddosguide.durationSec is set).
 *
 * <pre>
 *   V1       -> QuicCodecFuzzTest#fuzzQuicServerCodecChannelRead   (corpus out/V1/corpus)
 *   PkgRisk1 -> QuicCodecFuzzTest#fuzzQuicServerCodecChannelRead2  (corpus out/PkgRisk1/corpus)
 * </pre>
 */
public final class FuzzRunner {

    public static final String TEST_CLASS = "io.netty.incubator.codec.quic.fuzz.QuicCodecFuzzTest";

    private FuzzRunner() {
    }

    public static String testMethod(String targetId) {
        switch (normalize(targetId)) {
            case "V1":
                return "fuzzQuicServerCodecChannelRead";
            case "PkgRisk1":
                return "fuzzQuicServerCodecChannelRead2";
            default:
                throw new IllegalArgumentException("unknown target " + targetId + " (expected V1 or PkgRisk1)");
        }
    }

    static String normalize(String id) {
        if (id == null) {
            return "";
        }
        String s = id.trim();
        if (s.equalsIgnoreCase("V1")) {
            return "V1";
        }
        if (s.equalsIgnoreCase("PkgRisk1") || s.equalsIgnoreCase("PkgRisk-1")) {
            return "PkgRisk1";
        }
        return s;
    }

    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        switch (normalize(targetId)) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            case "PkgRisk1":
                return new PkgRisk1Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("unknown target " + targetId + " (expected V1 or PkgRisk1)");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: FuzzRunner <V1|PkgRisk1> [seconds (<=0: infinite)] [outDir]");
            System.exit(2);
        }
        String target = normalize(args[0]);
        long seconds = args.length > 1 ? Long.parseLong(args[1]) : 0L;
        File out = new File(args.length > 2 ? args[2] : System.getProperty("dosguide.out", "out"));
        out.mkdirs();
        String method = testMethod(target);
        Guidance guidance = createGuidance(target, out, seconds > 0 ? seconds * 1000L : 0L, System.out);
        System.out.println("{\"event\":\"run\",\"target\":\"" + target + "\",\"testClass\":\"" + TEST_CLASS
                + "\",\"method\":\"" + method + "\",\"seconds\":" + seconds + "}");
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, method, cl, guidance, System.out);
        System.out.println("{\"event\":\"done\",\"target\":\"" + target + "\"}");
        System.exit(0);
    }
}
