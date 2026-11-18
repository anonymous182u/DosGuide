package fuzzing;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Reproduction: runs one input file through the frozen harness method (default fuzzBzip2DecoderDecode)
 * and reports the throwable it raised, if any. Usage: ReproV1 &lt;input.bin&gt; [method]
 */
public final class ReproV1 {
    private ReproV1() { }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ReproV1 <input.bin> [method]");
            System.exit(2);
        }
        String method = args.length > 1 ? args[1] : "fuzzBzip2DecoderDecode";
        byte[] data = Files.readAllBytes(Paths.get(args[0]));
        System.exit(run(data, method));
    }

    /** Returns 0 if the harness completed or threw a declared exception, 1 for an undeclared throwable. */
    static int run(byte[] data, String method) throws Exception {
        Method m = Bzip2DecoderFuzzTest.class.getMethod(method, InputStream.class);
        Object test = new Bzip2DecoderFuzzTest();
        System.out.println("[Repro] method=" + method + " length=" + data.length + " head=" + hex(data, 32));
        long t0 = System.currentTimeMillis();
        try {
            m.invoke(test, new ByteArrayInputStream(data));
            System.out.println("[Repro] completed normally in " + (System.currentTimeMillis() - t0) + " ms");
            return 0;
        } catch (InvocationTargetException ite) {
            Throwable t = ite.getCause();
            boolean declared = false;
            for (Class<?> ex : m.getExceptionTypes()) {
                declared |= ex.isInstance(t);
            }
            System.out.println("[Repro] threw " + t + " after " + (System.currentTimeMillis() - t0)
                    + " ms (declared=" + declared + ")");
            return declared ? 0 : 1;
        }
    }

    static String hex(byte[] d, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(max, d.length); i++) {
            sb.append(String.format("%02x", d[i] & 0xff));
        }
        return d.length > max ? sb + "..." : sb.toString();
    }
}
