package fuzzing;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Metadata replay feeder: reads a corpus metadata JSON (out/V1/corpus/id_NNNNNN.json, written by V1Guidance),
 * prints its metadata, loads the referenced input and replays it deterministically through the harness.
 * Usage: ReplayV1 &lt;meta.json | corpus-dir&gt; [method]
 */
public final class ReplayV1 {
    private ReplayV1() { }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ReplayV1 <meta.json|corpus-dir> [method]");
            System.exit(2);
        }
        File f = new File(args[0]);
        File[] metas = f.isDirectory() ? f.listFiles((d, n) -> n.endsWith(".json")) : new File[] {f};
        if (metas == null) {
            metas = new File[0];
        }
        java.util.Arrays.sort(metas);
        int rc = 0;
        for (File meta : metas) {
            String json = new String(Files.readAllBytes(meta.toPath()), StandardCharsets.UTF_8);
            String file = field(json, "file");
            String method = args.length > 1 ? args[1] : methodFor(field(json, "label"));
            System.out.println("[Replay] meta=" + meta.getPath());
            System.out.println("[Replay] " + json.trim());
            File input = new File(meta.getParentFile(), file);
            byte[] data = Files.readAllBytes(input.toPath());
            rc |= ReproV1.run(data, method);
        }
        System.exit(rc);
    }

    private static String methodFor(String label) {
        if (label != null && label.contains("fuzzBzip2DecoderDecode2")) {
            return "fuzzBzip2DecoderDecode2";
        }
        return "fuzzBzip2DecoderDecode";
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }
}
