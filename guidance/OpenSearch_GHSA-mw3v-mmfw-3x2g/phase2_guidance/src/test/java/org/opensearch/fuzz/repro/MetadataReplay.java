package org.opensearch.fuzz.repro;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Metadata replay feeder: reads the JSON metadata that V1Guidance writes next to each corpus entry
 * (out/V1/corpus/id_NNNNNN.json), loads the referenced input, prints the metadata and replays the
 * input deterministically into the frozen harness through {@link V1Repro}.
 *
 * Usage: MetadataReplay &lt;metadata.json | corpus dir&gt; [--only-throwable] [--top N]
 *   --only-throwable  replay only entries whose recorded JQF result was FAILURE or TIMEOUT
 *   --top N           replay the N entries with the highest recorded maxClauseDepth
 */
public final class MetadataReplay {

    private static final Pattern FIELD = Pattern.compile("\"([A-Za-z_]+)\":(\"((?:[^\"\\\\]|\\\\.)*)\"|[-0-9.]+|null)");

    private MetadataReplay() {
    }

    static String field(String json, String name) {
        Matcher m = FIELD.matcher(json);
        while (m.find()) {
            if (m.group(1).equals(name)) {
                return m.group(3) != null ? m.group(3) : m.group(2);
            }
        }
        return null;
    }

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.err.println("Usage: MetadataReplay <metadata.json|corpusDir> [--only-throwable] [--top N]");
            System.exit(2);
        }
        boolean onlyThrowable = Arrays.asList(args).contains("--only-throwable");
        int top = Integer.MAX_VALUE;
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals("--top")) {
                top = Integer.parseInt(args[i + 1]);
            }
        }
        File src = new File(args[0]);
        List<File> metas = new ArrayList<>();
        if (src.isDirectory()) {
            File[] fs = src.listFiles((d, n) -> n.endsWith(".json"));
            if (fs != null) {
                metas.addAll(Arrays.asList(fs));
            }
        } else {
            metas.add(src);
        }
        List<String[]> entries = new ArrayList<>();
        for (File mf : metas) {
            String json = new String(Files.readAllBytes(mf.toPath()), StandardCharsets.UTF_8);
            String res = String.valueOf(field(json, "jqfResult"));
            if (onlyThrowable && !(res.equals("FAILURE") || res.equals("TIMEOUT"))) {
                continue;
            }
            entries.add(new String[] {mf.getPath(), json});
        }
        entries.sort((a, b) -> Long.compare(num(field(b[1], "maxClauseDepth")), num(field(a[1], "maxClauseDepth"))));
        boolean any = false;
        int n = 0;
        for (String[] e : entries) {
            if (n++ >= top) {
                break;
            }
            File mf = new File(e[0]);
            String json = e[1];
            String file = field(json, "file");
            File input = new File(mf.getParentFile(), file == null ? "" : file);
            System.out.println("== metadata " + mf.getPath());
            for (String k : new String[] {"target", "test_class", "method", "id", "length", "maxClauseDepth",
                "parserVisits", "reason", "jqfResult", "throwable", "parent", "ops", "elapsedMs"}) {
                System.out.println("   " + k + " = " + field(json, k));
            }
            if (!input.isFile()) {
                System.out.println("   input file missing: " + input);
                continue;
            }
            any |= V1Repro.replay(Files.readAllBytes(input.toPath()), input.getPath());
        }
        System.exit(any ? 1 : 0);
    }

    private static long num(String s) {
        try {
            return s == null ? 0L : (long) Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }
}
