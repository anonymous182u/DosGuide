package org.opensearch.fuzz.repro;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.opensearch.fuzz.tests.QueryParserFuzzTest;
import org.opensearch.index.query.QueryShardException;

/**
 * Deterministic reproduction for V1: feeds the saved bytes once into the frozen harness method
 * QueryParserFuzzTest#fuzzQueryStringQueryBuilderToQuery(InputStream), the same call JQF makes,
 * and reports whether the harness threw an undeclared throwable (for example StackOverflowError).
 *
 * Usage: V1Repro &lt;input.bin&gt; [more.bin ...]   (JVM: -Xmx1g -Xss1m)
 * Exit code 1 if any input reproduces an undeclared throwable.
 */
public final class V1Repro {

    private V1Repro() {
    }

    /** @return true if the harness threw a throwable it does not declare. */
    public static boolean replay(byte[] data, String label) {
        String text = new String(data, StandardCharsets.UTF_8);
        System.out.println("== V1 replay: " + label);
        System.out.println("   length(bytes)=" + data.length + " length(chars)=" + text.length());
        System.out.println("   input preview: " + preview(text));
        QueryParserFuzzTest test = new QueryParserFuzzTest();
        long t0 = System.nanoTime();
        try {
            test.fuzzQueryStringQueryBuilderToQuery(new ByteArrayInputStream(data));
            System.out.println("   outcome: completed normally in " + ms(t0) + " ms");
            return false;
        } catch (IOException | QueryShardException | IllegalArgumentException declared) {
            System.out.println("   outcome: declared rejection " + declared.getClass().getName() + " in " + ms(t0) + " ms");
            return false;
        } catch (Throwable undeclared) {
            StackTraceElement[] st = undeclared.getStackTrace();
            System.out.println("   outcome: UNDECLARED " + undeclared.getClass().getName() + " after " + ms(t0)
                + " ms (stack frames=" + st.length + ")");
            for (int i = 0; i < Math.min(8, st.length); i++) {
                System.out.println("      at " + st[i]);
            }
            return true;
        }
    }

    static String preview(String s) {
        StringBuilder b = new StringBuilder();
        int lim = Math.min(s.length(), 160);
        for (int i = 0; i < lim; i++) {
            char c = s.charAt(i);
            b.append(c < 0x20 ? String.format("\\u%04x", (int) c) : String.valueOf(c));
        }
        if (s.length() > lim) {
            b.append("... (+").append(s.length() - lim).append(" chars)");
        }
        return b.toString();
    }

    private static long ms(long t0) {
        return (System.nanoTime() - t0) / 1_000_000L;
    }

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.err.println("Usage: V1Repro <input.bin> [more.bin ...]");
            System.exit(2);
        }
        boolean any = false;
        for (String a : args) {
            File f = new File(a);
            any |= replay(Files.readAllBytes(f.toPath()), f.getPath());
        }
        System.exit(any ? 1 : 0);
    }
}
