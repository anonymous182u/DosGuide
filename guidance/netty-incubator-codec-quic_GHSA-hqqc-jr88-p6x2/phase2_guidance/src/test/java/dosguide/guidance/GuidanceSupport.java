package dosguide.guidance;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Map;

/** File and JSON helpers for the per-target guidances (not a Guidance). */
final class GuidanceSupport {

    private GuidanceSupport() {
    }

    static int maxInputSize() {
        return Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 1048576);
    }

    static long resolveDuration(long maxDurationMs) {
        if (maxDurationMs > 0) {
            return maxDurationMs;
        }
        String d = System.getProperty("dosguide.durationSec");
        if (d != null) {
            try {
                return Long.parseLong(d.trim()) * 1000L;
            } catch (NumberFormatException ignored) {
                // fall through: infinite
            }
        }
        return 0L;
    }

    static void writeAtomic(File f, byte[] data) {
        try {
            File tmp = new File(f.getParentFile(), f.getName() + ".tmp");
            Files.write(tmp.toPath(), data);
            Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            System.err.println("[guidance] write failed " + f + ": " + e);
        }
    }

    static void writeText(File f, String s) {
        writeAtomic(f, s.getBytes(StandardCharsets.UTF_8));
    }

    static String esc(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c < 0x20) {
                b.append(' ');
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    static String json(Map<String, Double> m) {
        StringBuilder b = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Double> e : m.entrySet()) {
            if (!first) {
                b.append(',');
            }
            first = false;
            double v = e.getValue();
            b.append('"').append(e.getKey()).append("\":");
            if (v == Math.rint(v) && Math.abs(v) < 1e15) {
                b.append((long) v);
            } else {
                b.append(String.format(java.util.Locale.ROOT, "%.3f", v));
            }
        }
        return b.append('}').toString();
    }
}
