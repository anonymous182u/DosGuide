package fuzzing;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import fuzzing.v1.V1Guidance;

import java.io.File;
import java.io.PrintStream;

/**
 * CLI runner.
 *
 * <pre>
 *   FuzzRunner V1 [seconds]                         # V1 via fuzzBzip2DecoderDecode, corpus out/V1/corpus
 *   FuzzRunner fuzzBzip2DecoderDecode2 [seconds]    # same guidance, separate corpus out/V1-decode2/corpus
 *   FuzzRunner V1:&lt;method&gt; [seconds]
 * </pre>
 * Infinite by default; time-bounded via the seconds argument or -Dfuzz.duration=SECONDS.
 * Output root: -Dfuzz.out (default "out").
 */
public final class FuzzRunner {
    public static final String TEST_CLASS = "fuzzing.Bzip2DecoderFuzzTest";

    private FuzzRunner() { }

    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        String id = targetId.contains(":") ? targetId.substring(0, targetId.indexOf(':')) : targetId;
        if (!"V1".equals(id)) {
            throw new IllegalArgumentException("Unknown target: " + targetId + " (available: V1)");
        }
        return new V1Guidance(targetId, outputDir, maxDurationMs, log);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: FuzzRunner <V1|V1:method|fuzzBzip2DecoderDecode|fuzzBzip2DecoderDecode2> [seconds]");
            System.exit(2);
        }
        String sel = args[0];
        String target = "V1";
        String method;
        String dirName;
        if (sel.startsWith("V1:")) {
            method = sel.substring(3);
            dirName = method.equals("fuzzBzip2DecoderDecode") ? "V1" : "V1-" + method;
        } else if (sel.equals("V1") || sel.equals("fuzzBzip2DecoderDecode")) {
            method = "fuzzBzip2DecoderDecode";
            dirName = "V1";
        } else if (sel.equals("fuzzBzip2DecoderDecode2")) {
            method = "fuzzBzip2DecoderDecode2";
            dirName = "V1-decode2";
        } else {
            System.err.println("Unknown target/method: " + sel);
            System.exit(2);
            return;
        }
        long seconds = Long.getLong("fuzz.duration", 0L);
        if (args.length > 1) {
            seconds = Long.parseLong(args[1]);
        }
        File outDir = new File(System.getProperty("fuzz.out", "out"), dirName);
        outDir.mkdirs();
        Guidance guidance = createGuidance(target, outDir, seconds * 1000L, System.out);
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(TEST_CLASS, method, cl, guidance, System.out);
        System.exit(0);
    }
}
