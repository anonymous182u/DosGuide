package dosguide.run;

import io.netty.incubator.codec.quic.fuzz.QuicCodecFuzzTest;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic replay: {@code ReplayFeeder <meta.json | input.bin> [V1|PkgRisk1]}.
 *
 * <p>Reads a guidance metadata file (out/&lt;Target&gt;/meta/id_*.json or out/&lt;Target&gt;/current.json),
 * loads the referenced input, prints the metadata and a summary of the decoded records (DCID count, lengths,
 * number of distinct ByteBuffer.hashCode values, largest hash class, first DCIDs in hex), then invokes the
 * frozen harness method directly with the bytes and reports wall time and any throwable (rethrown).</p>
 */
public final class ReplayFeeder {

    private ReplayFeeder() {
    }

    public static void main(String[] args) throws Throwable {
        if (args.length < 1) {
            System.err.println("usage: ReplayFeeder <meta.json|input.bin> [V1|PkgRisk1]");
            System.exit(2);
        }
        File f = new File(args[0]);
        String method;
        File input;
        if (f.getName().endsWith(".json")) {
            String meta = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            System.out.println("metadata: " + meta);
            String file = field(meta, "file");
            String test = field(meta, "test");
            input = new File(f.getParentFile(), file);
            method = test != null ? test : FuzzRunner.testMethod(args.length > 1 ? args[1] : "V1");
        } else {
            input = f;
            method = FuzzRunner.testMethod(args.length > 1 ? args[1] : "V1");
        }
        byte[] data = Files.readAllBytes(input.toPath());
        System.out.println("input: " + input.getPath() + " (" + data.length + " bytes)");
        describe(data);

        Method m = QuicCodecFuzzTest.class.getMethod(method, java.io.InputStream.class);
        QuicCodecFuzzTest test = new QuicCodecFuzzTest();
        System.out.println("replaying " + QuicCodecFuzzTest.class.getName() + "#" + method);
        long t0 = System.nanoTime();
        try {
            m.invoke(test, new ByteArrayInputStream(data));
            System.out.printf("completed in %.1f ms%n", (System.nanoTime() - t0) / 1e6);
        } catch (InvocationTargetException e) {
            System.out.printf("threw after %.1f ms: %s%n", (System.nanoTime() - t0) / 1e6, e.getCause());
            throw e.getCause();
        }
    }

    private static String field(String json, String name) {
        Matcher mt = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return mt.find() ? mt.group(1) : null;
    }

    private static void describe(byte[] data) {
        List<byte[]> recs = new ArrayList<>();
        int off = 0;
        while (off < data.length) {
            int len = Math.min(data[off] & 0xff, data.length - off - 1);
            byte[] r = new byte[len];
            System.arraycopy(data, off + 1, r, 0, len);
            recs.add(r);
            off += 1 + len;
        }
        Map<Integer, Integer> lenHist = new HashMap<>();
        Map<Integer, Integer> hashClasses = new HashMap<>();
        for (byte[] r : recs) {
            lenHist.merge(r.length, 1, Integer::sum);
            hashClasses.merge(java.nio.ByteBuffer.wrap(r).hashCode(), 1, Integer::sum);
        }
        int largest = 0;
        for (int v : hashClasses.values()) {
            largest = Math.max(largest, v);
        }
        System.out.println("records (Initial packets): " + recs.size() + ", DCID length histogram: " + lenHist);
        System.out.println("distinct ByteBuffer.hashCode values: " + hashClasses.size()
                + ", largest hash class: " + largest);
        for (int i = 0; i < Math.min(5, recs.size()); i++) {
            StringBuilder hex = new StringBuilder();
            for (byte b : recs.get(i)) {
                hex.append(String.format("%02x", b & 0xff));
            }
            System.out.println("  dcid[" + i + "] = " + hex);
        }
    }
}
