package dosguide.validate;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Scale probe: measures how much of each resource one execution of the frozen fuzz test uses on one
 * input, so that the Block 1 agent can check its `scale` estimate against measurements on small inputs.
 *
 * <p>The input runs once through the fuzz test, in a fresh JVM, without any javaagent or guidance, in a thread whose
 * stack is the probe's stack cap. The probe records, from the moment the fuzz test receives the input until it
 * returns, the thread's CPU time, the wall time, the bytes the thread allocated and the peak heap in use above the
 * level at the start. The stack is reported only as fitting the cap or not: a thread's requested stack size is
 * rounded up to a platform minimum (about 136 KB on Linux) and the bytes a frame takes change once the JIT compiles
 * a method, so a search for the smallest stack that fits is not reliable. A size series that
 * doubles its parameter shows where the cap is crossed.
 *
 * <p>Every measurement stays below the evaluation's limits, so the probe never shows whether an input would fail
 * under them: the caller gives a time cap of a tenth of the per-execution time limit, a stack cap of a quarter of the
 * thread stack size, runs this JVM with a quarter of the heap, and refuses inputs longer than a quarter of the input
 * size limit. An execution that reaches a cap is reported as exceeding it ("time_cap", "stack_cap", "heap_cap").
 * Any other throwable is reported as "completed": it is the fuzz test's oracle firing, which the probe must not show.
 * The time cap applies to the whole fuzz-test run, including JQF's start-up.
 *
 * <pre>
 * java -Xmx256m [other fixed JVM options] -cp validate-artifact.jar:&lt;fuzz test class path&gt; dosguide.validate.ScaleProbe
 *     --test-class C --method m --input FILE --out OUT.json --time-cap-ms 2000 --stack-cap-bytes 262144
 * </pre>
 */
public final class ScaleProbe {

    private ScaleProbe() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> o = new LinkedHashMap<>();
        for (int i = 0; i + 1 < args.length; i += 2) {
            o.put(args[i], args[i + 1]);
        }
        Class<?> testClass = Class.forName(o.get("--test-class"), true, ScaleProbe.class.getClassLoader());
        String method = o.get("--method");
        byte[] input = Files.readAllBytes(Path.of(o.get("--input")));
        Path out = Path.of(o.get("--out"));
        long timeCapMs = Long.parseLong(o.getOrDefault("--time-cap-ms", "2000"));
        long stackCap = Long.parseLong(o.getOrDefault("--stack-cap-bytes", String.valueOf(256 * 1024)));

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("input_bytes", input.length);
        report.put("time_cap_ms", timeCapMs);
        report.put("stack_cap_bytes", stackCap);
        report.put("heap_cap_bytes", Runtime.getRuntime().maxMemory());

        Run first = run(testClass, method, input, stackCap, timeCapMs, true);
        report.put("outcome", first.outcome);
        if (first.detail != null) {
            report.put("detail", first.detail);
        }
        if (first.finished) {
            report.put("cpu_ms", first.cpuNs / 1e6);
            report.put("wall_ms", first.execNs / 1e6);
            report.put("allocated_bytes", first.allocated);
            report.put("peak_heap_bytes", first.peakHeap);
        }
        if (first.outcome.equals("time_cap")) {
            write(out, report);
            Runtime.getRuntime().halt(0); // the stuck execution cannot be stopped
        }
        write(out, report);
        Runtime.getRuntime().halt(0);
    }

    private static void write(Path out, Map<String, Object> report) throws Exception {
        Files.writeString(out, Json.write(report) + "\n", StandardCharsets.UTF_8);
    }

    private static final class Run {
        String outcome = "time_cap";
        String detail;
        boolean finished;
        long cpuNs;
        long execNs;
        long allocated;
        long peakHeap;
    }

    /** One execution of the fuzz test on the input in a thread with the given stack size. */
    private static Run run(Class<?> testClass, String method, byte[] input, long stack, long timeCapMs,
                           boolean measureHeap) throws InterruptedException {
        Run r = new Run();
        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        if (measureHeap) {
            System.gc();
        }
        long[] peak = {0};
        OneInput g = new OneInput(input, mem);
        Thread t = new Thread(null, () -> {
            try {
                GuidedFuzzing.run(testClass, method, g, new PrintStream(OutputStream.nullOutputStream()));
            } catch (Throwable e) {
                g.error = g.error == null ? e : g.error;
            }
        }, "scale-probe", stack);
        t.setDaemon(true);
        long start = System.nanoTime();
        t.start();
        long deadline = start + timeCapMs * 1_000_000L;
        while (t.isAlive() && System.nanoTime() < deadline) {
            if (measureHeap && g.heapAtStart >= 0) {
                peak[0] = Math.max(peak[0], mem.getHeapMemoryUsage().getUsed() - g.heapAtStart);
            }
            t.join(2);
        }
        if (t.isAlive()) {
            return r; // time_cap
        }
        r.execNs = g.execNs;
        r.peakHeap = Math.max(0, peak[0]);
        r.cpuNs = g.cpuNs;
        r.allocated = g.allocated;
        Throwable e = root(g.error);
        if (e instanceof StackOverflowError) {
            r.outcome = "stack_cap";
        } else if (e instanceof OutOfMemoryError) {
            r.outcome = "heap_cap";
        } else if (e != null) {
            // Any other throwable is the fuzz test's oracle firing (an AssertionError of a bound check, or any
            // undeclared exception), i.e. whether the input fails: it is reported like a completed execution and
            // its class is not recorded anywhere the agent can read (reporting "threw java.lang.AssertionError"
            // would tell the agent that the input fails).
            r.outcome = "completed";
            r.finished = true;
        } else {
            r.outcome = "completed";
            r.finished = true;
            if (g.invalid) {
                r.detail = "the fuzz test rejected the input (assumption violated)";
            }
        }
        return r;
    }

    private static Throwable root(Throwable t) {
        while (t != null && t.getCause() != null && t.getCause() != t
                && !(t instanceof StackOverflowError) && !(t instanceof OutOfMemoryError)) {
            t = t.getCause();
        }
        return t;
    }

    /** Supplies the input once and measures the fuzz test's thread around the execution. */
    private static final class OneInput implements Guidance {
        private final byte[] input;
        private boolean given;
        private final MemoryMXBean mem;
        private long cpu0;
        private long alloc0;
        private long t0;
        volatile long heapAtStart = -1;
        volatile long cpuNs;
        volatile long execNs;
        volatile long allocated;
        volatile Throwable error;
        volatile boolean invalid;

        OneInput(byte[] input, MemoryMXBean mem) {
            this.input = input;
            this.mem = mem;
        }

        @Override
        public boolean hasInput() {
            return !given;
        }

        @Override
        public InputStream getInput() {
            given = true;
            com.sun.management.ThreadMXBean tm = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
            heapAtStart = mem.getHeapMemoryUsage().getUsed();
            alloc0 = tm.getCurrentThreadAllocatedBytes();
            cpu0 = tm.getCurrentThreadCpuTime();
            t0 = System.nanoTime();
            return new ByteArrayInputStream(input);
        }

        @Override
        public void handleResult(Result result, Throwable e) {
            com.sun.management.ThreadMXBean tm = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
            execNs = System.nanoTime() - t0;
            cpuNs = tm.getCurrentThreadCpuTime() - cpu0;
            allocated = tm.getCurrentThreadAllocatedBytes() - alloc0;
            if (result == Result.FAILURE && e != null) {
                error = e;
            } else if (result == Result.INVALID) {
                invalid = true;
            }
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return ev -> {
            };
        }
    }
}
