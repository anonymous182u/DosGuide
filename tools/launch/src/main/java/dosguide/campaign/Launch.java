package dosguide.campaign;

import edu.berkeley.cs.jqf.fuzz.ei.ZestGuidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.InstrumentingClassLoader;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.lang.management.ManagementFactory;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Runs one fuzzing campaign, or a replay, on a JQF fuzz test and decides its failures the same way for every
 * engine (the campaign launcher of the DoSGuide evaluation).
 *
 * <p>Engines: {@code guidance} (a synthesized guidance from its {@code FuzzRunner#createGuidance} factory),
 * {@code zest} (JQF's unmodified ZestGuidance, with coverage from JQF's InstrumentingClassLoader, as in the JQF
 * Maven plugin) and {@code replay} (given input files, in order). The fuzz test's class path is loaded by a child
 * class loader; JQF itself comes from this launcher, as the plugin provides it.
 *
 * <p>Failures follow JQF's semantics and the harness alone decides them:
 * <ul>
 *   <li>FAILURE: JQF classified the execution as FAILURE, i.e. the fuzz test threw a throwable not declared in
 *       its {@code throws} clause;</li>
 *   <li>TIMEOUT: one execution ran longer than {@code --timeout-ms} by the wall clock, measured by a watchdog of
 *       this launcher.</li>
 * </ul>
 * A TIMEOUT that a guidance reports itself, exceptions thrown by a guidance's trace callbacks, and files a
 * guidance writes are not failures. Such a failure is only a candidate: it counts once replaying its input in a
 * fresh JVM, with the same JVM options but no javaagent and no guidance, fails too. The first confirmed failure
 * ends the campaign; {@code result.json} in the output directory records it.
 *
 * <p>With the fixed version of the library ({@code --fixed-lib}, replacing the {@code --cp} entries that
 * {@code --fixed-drop} matches), a confirmed failure is replayed once more on the fixed version and counts only if
 * it does not fail there. A failure that the fixed version shows too is not the vulnerability: it is recorded,
 * and fuzzing goes on (after a timeout the stuck execution still ends the run). Repeats of such a failure (same
 * kind, root cause, top frames and input length within a factor of two) are counted without replaying them again.
 * The time spent in replays is left out of the budget and of the times reported.
 */
public final class Launch {

    private static final Pattern OUTCOME = Pattern.compile("\"outcome\"\\s*:\\s*\"(\\w+)\"");
    private static final Pattern KIND = Pattern.compile("\"kind\"\\s*:\\s*\"(\\w+)\"");
    private static final int RESERVE_BYTES = 16 << 20;

    /**
     * Memory set aside so that a failure can still be recorded when the library keeps the heap full after an
     * OutOfMemoryError (e.g. a half-built document held by a ThreadLocal). Released before recording.
     */
    private static volatile byte[] reserve = new byte[RESERVE_BYTES];

    private final Options o;
    private final long t0 = System.nanoTime();
    private final Map<String, Object> report = new LinkedHashMap<>();
    private final List<Map<String, Object>> candidates = new ArrayList<>();
    /** The fuzz test's class path with the fixed library, or null without --fixed-lib. */
    private String fixedCp;
    /** Failures that the fixed version shows too, by signature, with how often each occurred. */
    private final Map<String, Integer> fixedAlsoFails = new LinkedHashMap<>();
    private int fixedReplayErrors;
    /** Time spent recording and replaying candidates, left out of the fuzzing clock. */
    private volatile long pausedNanos;
    private final java.util.concurrent.atomic.AtomicInteger candidateCount = new java.util.concurrent.atomic.AtomicInteger();
    private Map<String, Object> firstFailure;
    private Oracle oracle;
    private PrintStream log = System.err;
    private boolean finished;
    /** Set when the watchdog takes an execution as a timeout; from then on the watchdog ends the run. */
    private volatile boolean timeoutTaken;

    private Launch(Options o) {
        this.o = o;
    }

    public static void main(String[] args) {
        Options o;
        try {
            o = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("Launch: " + e.getMessage());
            System.err.println("usage: Launch --engine guidance|zest|replay --cp <class path> --test-class <class> "
                    + "--method <name> --out <dir> [--timeout-ms 20000] [--max-input-bytes 10240] [--budget-sec 0] "
                    + "[--factory <Class#method> --target <id>] [--seeds <dir>] [--inputs <file|dir>] [--no-confirm] "
                    + "[--fixed-lib <class path> --fixed-drop <regex>]");
            System.exit(2);
            return;
        }
        Launch l = new Launch(o);
        try {
            l.run();
        } catch (Throwable t) {
            l.report.put("error", describe(t));
        }
        l.finish();
        System.exit(0); // guidance or JQF threads may linger
    }

    private void run() throws Exception {
        Files.createDirectories(o.out.resolve("candidates"));
        log = new PrintStream(new FileOutputStream(o.out.resolve("launcher.log").toFile()), true, StandardCharsets.UTF_8);
        report.put("engine", o.engine);
        report.put("test_class", o.testClass);
        report.put("method", o.method);
        report.put("target", o.target);
        report.put("timeout_ms", o.timeoutMs);
        report.put("max_input_bytes", o.maxInputBytes);
        report.put("budget_sec", o.budgetSec);
        report.put("jvm_args", ManagementFactory.getRuntimeMXBean().getInputArguments());

        // Timeouts are the watchdog's, for every engine; Zest reads these when it is constructed.
        System.clearProperty("jqf.ei.TIMEOUT");
        System.setProperty("jqf.ei.MAX_INPUT_SIZE", String.valueOf(o.maxInputBytes));
        System.setProperty("jqf.ei.QUIET_MODE", "true");

        String[] cp = classPath(o.cp);
        if (o.fixedLib != null) {
            fixedCp = fixedClassPath(cp);
            report.put("fixed_cp", fixedCp);
        }
        ClassLoader parent = Launch.class.getClassLoader();
        ClassLoader loader = o.engine.equals("zest") ? new InstrumentingClassLoader(cp, parent)
                : new URLClassLoader(InstrumentingClassLoader.stringsToUrls(cp), parent);
        Thread.currentThread().setContextClassLoader(loader);

        oracle = new Oracle(createGuidance(loader), Thread.currentThread());
        Thread watchdog = new Thread(this::watch, "launch-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        org.junit.runner.Result junit = null;
        try {
            junit = GuidedFuzzing.run(o.testClass, o.method, loader, oracle, log);
        } catch (Throwable t) {
            report.put("run_error", describe(t));
        }
        // No input executed (e.g. no such @Fuzz method, or the test class does not initialize): the run tested
        // nothing, so it is an error, not a run without failure.
        synchronized (oracle) {
            if (oracle.trials == 0 && firstFailure == null && !timeoutTaken) {
                String why = junit != null && !junit.getFailures().isEmpty() ? junit.getFailures().get(0).getMessage()
                        : String.valueOf(report.getOrDefault("run_error", "the test ran no input"));
                report.put("error", "no input was executed: " + why);
            } else if (firstFailure == null && !timeoutTaken && !oracle.stop && o.budgetSec > 0
                    && elapsedMs() < o.budgetSec * 1000 - 5_000) {
                // The fuzzing loop ended before the budget without a failure: the guidance threw (JQF ends the run on a
                // GuidanceException) or its hasInput() returned false. That is not a run without failure.
                String why = junit != null && !junit.getFailures().isEmpty() ? junit.getFailures().get(0).getMessage()
                        : String.valueOf(report.getOrDefault("run_error", "the guidance's hasInput() returned false"));
                report.put("error", "the fuzzing loop ended after " + elapsedMs() + " ms of the " + o.budgetSec
                        + " s budget: " + why);
            }
        }
        // A timed-out execution can finish while the watchdog is still confirming it; the watchdog then writes
        // the result and ends the run.
        while (timeoutTaken) {
            Thread.sleep(200);
        }
    }

    private Guidance createGuidance(ClassLoader loader) throws Exception {
        switch (o.engine) {
            case "guidance": {
                int hash = o.factory.indexOf('#');
                Class<?> owner = Class.forName(o.factory.substring(0, hash), true, loader);
                Method factory = owner.getMethod(o.factory.substring(hash + 1), String.class, File.class, long.class,
                        PrintStream.class);
                // The budget is the launcher's (Oracle.hasInput, on the fuzzing clock, without the replays); the
                // guidance gets no deadline of its own, as in the validation.
                long maxDurationMs = TimeUnit.DAYS.toMillis(365);
                Object g;
                try {
                    g = factory.invoke(null, o.target, o.out.resolve("guidance-out").toFile(), maxDurationMs, log);
                } catch (InvocationTargetException e) {
                    throw new IllegalStateException(o.factory + " threw " + describe(e.getCause()), e.getCause());
                }
                if (!(g instanceof Guidance)) {
                    throw new IllegalStateException(o.factory + " returned " + (g == null ? "null" : g.getClass().getName())
                            + ", not a JQF Guidance");
                }
                return (Guidance) g;
            }
            case "zest": {
                Duration duration = null; // the launcher's budget stops Zest (Oracle.hasInput)
                File out = o.out.resolve("zest").toFile();
                String title = o.testClass + "#" + o.method;
                return o.seeds == null ? new ZestGuidance(title, duration, out)
                        : new ZestGuidance(title, duration, out, o.seeds.toFile());
            }
            case "replay": {
                List<Path> inputs;
                if (Files.isDirectory(o.inputs)) {
                    try (Stream<Path> s = Files.list(o.inputs)) {
                        inputs = s.filter(Files::isRegularFile).sorted().toList();
                    }
                } else {
                    inputs = List.of(o.inputs);
                }
                return new Replay(inputs);
            }
            default:
                throw new IllegalArgumentException("unknown engine " + o.engine);
        }
    }

    // ------------------------------------------------------------------
    // Failures
    // ------------------------------------------------------------------

    /** Ends the run when one execution takes longer than the timeout. The stuck execution cannot be resumed. */
    private void watch() {
        while (true) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                return;
            }
            byte[] input;
            synchronized (oracle) {
                if (!oracle.inFlight || System.nanoTime() - oracle.started <= o.timeoutMs * 1_000_000L) {
                    continue;
                }
                oracle.inFlight = false;
                timeoutTaken = true;
                input = oracle.recorded.toByteArray();
            }
            StackTraceElement[] stack = oracle.fuzzThread.getStackTrace();
            boolean counts = candidate("TIMEOUT", null, stack, input);
            if (!counts) {
                report.put("stopped", fixedCp == null
                        ? "an execution exceeded the timeout, but its replay did not; the stuck execution ended the run"
                        : "an execution exceeded the timeout, but its replay did not, or the fixed version times out "
                        + "too; the stuck execution ended the run");
            }
            finish();
            Runtime.getRuntime().halt(0);
        }
    }

    /**
     * Records a candidate failure, confirms it by replay (unless --no-confirm), with the fixed library checks that
     * the fixed version does not fail on it, and returns whether it counts. The first failure that counts stops
     * the campaign.
     */
    private boolean candidate(String kind, Throwable error, StackTraceElement[] stuck, byte[] input) {
        long begin = System.nanoTime();
        boolean counts;
        try {
            // A repeat of a failure the fixed version shows too is only counted: no replay, no collection.
            boolean repeat;
            try {
                repeat = knownOnFixed(kind, error, stuck, input);
            } catch (OutOfMemoryError e) {
                reserve = null;
                System.gc();
                repeat = knownOnFixed(kind, error, stuck, input);
            }
            if (repeat) {
                counts = false;
            } else {
                reserve = null;
                System.gc();
                counts = recordOnce(kind, error, stuck, input);
            }
        } finally {
            pausedNanos += System.nanoTime() - begin;
        }
        if (!counts && reserve == null) {
            try {
                reserve = new byte[RESERVE_BYTES]; // fuzzing goes on: set memory aside again for the next one
            } catch (OutOfMemoryError e) {
                log.println("[Launch] could not set memory aside again");
            }
        }
        return counts;
    }

    private boolean recordOnce(String kind, Throwable error, StackTraceElement[] stuck, byte[] input) {
        int n = candidateCount.getAndIncrement();
        try {
            return record(n, kind, error, stuck, input);
        } catch (OutOfMemoryError e) {
            System.gc(); // what the failed attempt allocated is garbage now
            return record(n, kind, error, stuck, input);
        }
    }

    /** Counts a repeat of a failure the fixed version showed too; true if this candidate is one. */
    private boolean knownOnFixed(String kind, Throwable error, StackTraceElement[] stuck, byte[] input) {
        if (fixedCp == null) {
            return false;
        }
        String sig = signature(kind, error, stuck, input.length);
        synchronized (fixedAlsoFails) {
            Integer seen = fixedAlsoFails.get(sig);
            if (seen == null) {
                return false;
            }
            fixedAlsoFails.put(sig, seen + 1);
            // A failure without stack frames (HotSpot preallocates only four OutOfMemoryErrors with a backtrace; later
            // ones have none) has a signature of kind, cause and input length only, which every such failure of that
            // length shares, whatever allocation failed. Thousands of OOMs can fall into a few such signatures, so an
            // OOM of the CVE's allocation of the same length would never be replayed.
            // These are replayed for the first 20 repeats and then at every power of two.
            if (stackless(error, stuck)) {
                int n = seen + 1;
                return n >= 20 && Integer.bitCount(n) != 1;
            }
            return true;
        }
    }

    private static boolean stackless(Throwable error, StackTraceElement[] stuck) {
        Throwable root = error;
        while (root != null && root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        StackTraceElement[] st = root != null ? root.getStackTrace() : stuck;
        return st == null || st.length == 0;
    }

    /** Kind, root cause, the top five frames and the input length's power of two: what repeats of one bug share. */
    private static String signature(String kind, Throwable error, StackTraceElement[] stuck, int inputBytes) {
        Throwable root = error;
        while (root != null && root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        StackTraceElement[] st = root != null ? root.getStackTrace() : stuck;
        StringBuilder b = new StringBuilder(kind).append(' ').append(root == null ? "-" : root.getClass().getName());
        for (int i = 0; st != null && i < st.length && i < 5; i++) {
            b.append(" | ").append(st[i]);
        }
        return b.append(" | len 2^").append(32 - Integer.numberOfLeadingZeros(Math.max(inputBytes, 1))).toString();
    }

    private boolean record(int n, String kind, Throwable error, StackTraceElement[] stuck, byte[] input) {
        Map<String, Object> c = new LinkedHashMap<>();
        Path file = o.out.resolve("candidates").resolve(String.format("c%03d.input", n));
        try {
            Files.write(file, input);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        c.put("index", n);
        c.put("kind", kind);
        c.put("trial", oracle.trials);
        c.put("found_at_ms", elapsedMs());
        c.put("input", o.out.relativize(file).toString());
        c.put("input_bytes", input.length);
        if (oracle.currentLabel != null) {
            c.put("replayed_file", oracle.currentLabel);
        }
        if (error != null) {
            Throwable root = error;
            while (root.getCause() != null && root.getCause() != root) {
                root = root.getCause();
            }
            c.put("error", describe(error));
            c.put("root_cause", describe(root));
            c.put("stack_depth", root.getStackTrace().length);
            c.put("stack", frames(root.getStackTrace()));
        } else {
            c.put("stack", frames(stuck));
        }
        Map<String, Object> confirmation = o.confirm ? replay(file, n, o.cp, "replay")
                : Map.of("outcome", "failure", "kind", kind, "note", "this run is itself a confirmation replay");
        boolean confirmed = "failure".equals(confirmation.get("outcome"));
        c.put("confirmation", confirmation);
        c.put("confirmed", confirmed);
        boolean counts = confirmed;
        if (confirmed && fixedCp != null) {
            // The vulnerability is what the fix removes: a failure that the fixed version shows too is another one.
            Map<String, Object> fixed = replay(file, n, fixedCp, "fixed");
            c.put("fixed_replay", fixed);
            if ("failure".equals(fixed.get("outcome"))) {
                c.put("fails_on_fixed", true);
                synchronized (fixedAlsoFails) {
                    fixedAlsoFails.merge(signature(kind, error, stuck, input.length), 1, Integer::sum);
                }
                counts = false;
            } else if (!"no_failure".equals(fixed.get("outcome"))) {
                fixedReplayErrors++; // undecided; it does not count
                counts = false;
            }
            c.put("counts", counts);
        }
        synchronized (candidates) {
            candidates.add(c);
            candidates.sort((a, b) -> Integer.compare((Integer) a.get("index"), (Integer) b.get("index")));
        }
        log.println("[Launch] candidate " + n + " " + kind + " confirmed=" + confirmed
                + (fixedCp != null ? " counts=" + counts : ""));
        if (counts) {
            synchronized (this) {
                if (firstFailure == null) {
                    firstFailure = c;
                }
            }
            synchronized (oracle) {
                oracle.stop = true;
            }
        }
        return counts;
    }

    /**
     * Replays the input in a fresh JVM with the same JVM options, without javaagents and without guidance, on the
     * class path {@code cp} (the fuzz test's, or the one with the fixed library), into candidates/cNNN-{suffix}.
     */
    private Map<String, Object> replay(Path input, int n, String cp, String suffix) {
        Map<String, Object> out = new LinkedHashMap<>();
        Path dir = o.out.resolve("candidates").resolve(String.format("c%03d-%s", n, suffix));
        List<String> cmd = new ArrayList<>();
        cmd.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        for (String a : ManagementFactory.getRuntimeMXBean().getInputArguments()) {
            if (!a.startsWith("-javaagent") && !a.startsWith("-agentlib") && !a.startsWith("-agentpath")) {
                cmd.add(a);
            }
        }
        cmd.addAll(List.of("-cp", launcherJar(), Launch.class.getName(), "--engine", "replay", "--cp", cp,
                "--test-class", o.testClass, "--method", o.method, "--inputs", input.toString(),
                "--timeout-ms", String.valueOf(o.timeoutMs), "--max-input-bytes", String.valueOf(o.maxInputBytes),
                "--out", dir.toString(), "--no-confirm"));
        try {
            Files.createDirectories(dir);
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true)
                    .redirectOutput(dir.resolve("stdout.txt").toFile()).start();
            if (!p.waitFor(o.timeoutMs + 300_000L, TimeUnit.MILLISECONDS)) {
                p.destroyForcibly();
                out.put("outcome", "error");
                out.put("error", "the confirmation replay did not finish");
                return out;
            }
            String result = Files.readString(dir.resolve("result.json"), StandardCharsets.UTF_8);
            Matcher m = OUTCOME.matcher(result);
            out.put("outcome", m.find() ? m.group(1) : "error");
            Matcher k = KIND.matcher(result);
            if (k.find()) {
                out.put("kind", k.group(1));
            }
        } catch (IOException | InterruptedException e) {
            out.put("outcome", "error");
            out.put("error", describe(e));
        }
        out.put("dir", o.out.relativize(dir).toString());
        return out;
    }

    private synchronized void finish() {
        if (finished) {
            return;
        }
        finished = true;
        reserve = null;
        try {
            writeResult();
        } catch (OutOfMemoryError e) {
            System.gc();
            writeResult();
        }
    }

    private void writeResult() {
        report.put("outcome", firstFailure != null ? "failure" : report.containsKey("error") ? "error" : "no_failure");
        report.put("time_to_first_failure_ms", firstFailure == null ? null : firstFailure.get("found_at_ms"));
        report.put("first_failure", firstFailure);
        report.put("elapsed_ms", elapsedMs());
        report.put("replay_ms", pausedNanos / 1_000_000L);
        if (fixedCp != null) {
            synchronized (fixedAlsoFails) {
                report.put("failures_also_on_fixed", fixedAlsoFails.values().stream().mapToInt(Integer::intValue).sum());
                report.put("failures_also_on_fixed_by_signature", new LinkedHashMap<>(fixedAlsoFails));
            }
            report.put("fixed_replay_errors", fixedReplayErrors);
        }
        if (oracle != null) {
            report.put("trials", oracle.trials);
            report.put("invalid", oracle.invalid);
            report.put("guidance_reported_timeouts_ignored", oracle.guidanceTimeouts);
            report.put("guidance_errors", oracle.guidanceErrors);
            report.put("callback_errors", oracle.callbackErrors);
            if (oracle.firstGuidanceProblem != null) {
                report.put("first_guidance_problem", oracle.firstGuidanceProblem);
            }
        }
        synchronized (candidates) {
            report.put("candidates", new ArrayList<>(candidates));
        }
        try {
            Files.createDirectories(o.out);
            Files.writeString(o.out.resolve("result.json"), Json.write(report) + "\n", StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("Launch: cannot write result.json: " + e.getMessage());
        }
        System.out.println("RESULT outcome=" + report.get("outcome")
                + (firstFailure == null ? "" : " kind=" + firstFailure.get("kind") + " ttf_ms=" + firstFailure.get("found_at_ms")
                + " input=" + o.out.resolve(String.valueOf(firstFailure.get("input")))));
        System.out.flush();
    }

    /** Class path entries, with `dir/*` expanded to the jars in dir as the java launcher does. */
    private static String[] classPath(String cp) throws IOException {
        List<String> out = new ArrayList<>();
        for (String e : cp.split(File.pathSeparator)) {
            if (e.isBlank()) {
                continue;
            }
            if (e.endsWith("*")) {
                Path dir = Path.of(e.substring(0, e.length() - 1));
                if (Files.isDirectory(dir)) {
                    try (Stream<Path> s = Files.list(dir)) {
                        s.filter(p -> p.toString().endsWith(".jar")).sorted().forEach(p -> out.add(p.toString()));
                    }
                }
            } else {
                out.add(e);
            }
        }
        return out.toArray(String[]::new);
    }

    /** The fuzzing clock: time since the start, without the time spent recording and replaying candidates. */
    private long elapsedMs() {
        return (System.nanoTime() - t0 - pausedNanos) / 1_000_000L;
    }

    /** The fuzz test's class path with the fixed library: --fixed-lib, then the entries --fixed-drop does not match. */
    private String fixedClassPath(String[] cp) throws IOException {
        Pattern drop = Pattern.compile(o.fixedDrop);
        List<String> out = new ArrayList<>(Arrays.asList(classPath(o.fixedLib)));
        List<String> dropped = new ArrayList<>();
        for (String e : cp) {
            if (drop.matcher(Path.of(e).getFileName().toString()).find()) {
                dropped.add(e);
            } else {
                out.add(e);
            }
        }
        if (dropped.isEmpty()) {
            throw new IllegalArgumentException("--fixed-drop " + o.fixedDrop + " matches no --cp entry");
        }
        report.put("fixed_dropped", dropped);
        return String.join(File.pathSeparator, out);
    }

    private static String launcherJar() {
        try {
            return Path.of(Launch.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        } catch (Exception e) {
            return System.getProperty("java.class.path");
        }
    }

    private static List<String> frames(StackTraceElement[] st) {
        List<String> out = new ArrayList<>();
        for (int i = 0; st != null && i < st.length && i < 40; i++) {
            out.add(st[i].toString());
        }
        return out;
    }

    static String describe(Throwable t) {
        String m = t.getMessage();
        return t.getClass().getName() + (m == null ? "" : ": " + (m.length() > 300 ? m.substring(0, 300) + "..." : m));
    }

    // ------------------------------------------------------------------
    // Guidance wrapper
    // ------------------------------------------------------------------

    /**
     * Delegates to the engine's guidance and takes failures only from JQF's classification. It records the bytes
     * the test reads, caps them at --max-input-bytes, and keeps exceptions of the guidance's trace callbacks from
     * reaching the test (except JVM errors such as StackOverflowError).
     */
    private final class Oracle implements Guidance {
        final Guidance real;
        final Thread fuzzThread;
        boolean stop;
        boolean inFlight;
        long started;
        ByteArrayOutputStream recorded = new ByteArrayOutputStream();
        String currentLabel;
        int trials;
        int invalid;
        int guidanceTimeouts;
        int guidanceErrors;
        int callbackErrors;
        String firstGuidanceProblem;

        Oracle(Guidance real, Thread fuzzThread) {
            this.real = real;
            this.fuzzThread = fuzzThread;
        }

        @Override
        public boolean hasInput() {
            synchronized (this) {
                if (stop) {
                    return false;
                }
            }
            if (o.budgetSec > 0 && elapsedMs() >= o.budgetSec * 1000) {
                return false;
            }
            return real.hasInput();
        }

        @Override
        public InputStream getInput() {
            InputStream in = real.getInput();
            synchronized (this) {
                trials++;
                recorded = new ByteArrayOutputStream();
                currentLabel = real instanceof Replay r ? r.current : null;
                started = System.nanoTime();
                inFlight = true;
                return new Capped(new Tee(in, recorded), o.maxInputBytes);
            }
        }

        @Override
        public void handleResult(Result result, Throwable error) {
            if (result == Result.FAILURE) {
                reserve = null; // before allocating anything: the heap may still be full
            }
            byte[] input;
            synchronized (this) {
                if (!inFlight) {
                    return; // the watchdog has taken this execution as a timeout
                }
                inFlight = false;
                input = recorded.toByteArray();
            }
            if (result == Result.INVALID) {
                invalid++;
            } else if (result == Result.TIMEOUT) {
                guidanceTimeouts++; // a guidance's own timeout is not a failure
            } else if (result == Result.FAILURE) {
                candidate("FAILURE", error, null, input);
            }
            try {
                real.handleResult(result, error);
            } catch (Throwable t) {
                guidanceErrors++;
                problem("handleResult threw " + describe(t));
            }
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            Consumer<TraceEvent> c = real.generateCallBack(thread);
            if (c == null) {
                return e -> { };
            }
            return e -> {
                try {
                    c.accept(e);
                } catch (VirtualMachineError vme) {
                    throw vme; // e.g. a StackOverflowError that happens to occur inside the callback
                } catch (Throwable t) {
                    callbackErrors++;
                    problem("a trace callback threw " + describe(t));
                }
            };
        }

        @Override
        public void observeGeneratedArgs(Object[] args) {
            real.observeGeneratedArgs(args);
        }

        private synchronized void problem(String what) {
            if (firstGuidanceProblem == null) {
                firstGuidanceProblem = what;
                log.println("[Launch] " + what);
            }
        }
    }

    /** The replay engine: each given input once, in order. */
    private static final class Replay implements Guidance {
        final Deque<Path> inputs;
        String current;

        Replay(List<Path> inputs) {
            this.inputs = new ArrayDeque<>(inputs);
        }

        @Override
        public boolean hasInput() {
            return !inputs.isEmpty();
        }

        @Override
        public InputStream getInput() {
            Path p = inputs.poll();
            current = p.getFileName().toString();
            try {
                return new ByteArrayInputStream(Files.readAllBytes(p));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        @Override
        public void handleResult(Result result, Throwable error) {
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return e -> { };
        }
    }

    /** Records the bytes the test actually reads. */
    private static final class Tee extends FilterInputStream {
        private final ByteArrayOutputStream copy;

        Tee(InputStream in, ByteArrayOutputStream copy) {
            super(in);
            this.copy = copy;
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b >= 0) {
                synchronized (copy) {
                    copy.write(b);
                }
            }
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            int n = super.read(buf, off, len);
            if (n > 0) {
                synchronized (copy) {
                    copy.write(buf, off, n);
                }
            }
            return n;
        }
    }

    /** Ends the stream after a fixed number of bytes, the same input size limit for every engine. */
    private static final class Capped extends FilterInputStream {
        private long left;

        Capped(InputStream in, long limit) {
            super(in);
            this.left = limit;
        }

        @Override
        public int read() throws IOException {
            if (left <= 0) {
                return -1;
            }
            int b = super.read();
            if (b >= 0) {
                left--;
            }
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            if (left <= 0) {
                return -1;
            }
            int n = super.read(buf, off, (int) Math.min(len, left));
            if (n > 0) {
                left -= n;
            }
            return n;
        }

        @Override
        public int available() throws IOException {
            return (int) Math.min(super.available(), left);
        }
    }

    // ------------------------------------------------------------------
    // Options
    // ------------------------------------------------------------------

    private static final class Options {
        String engine;
        String cp;
        String testClass;
        String method;
        Path out;
        long timeoutMs = 20_000;
        long maxInputBytes = 10_240; // JQF's default for Zest; a subject's oracle.json may raise it for every engine
        long budgetSec;
        String factory;
        String target;
        Path seeds;
        Path inputs;
        boolean confirm = true;
        String fixedLib;
        String fixedDrop;

        static Options parse(String[] args) {
            Options o = new Options();
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                if (a.equals("--no-confirm")) {
                    o.confirm = false;
                    continue;
                }
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("missing value for " + a);
                }
                String v = args[++i];
                switch (a) {
                    case "--engine" -> o.engine = v;
                    case "--cp" -> o.cp = v;
                    case "--test-class" -> o.testClass = v;
                    case "--method" -> o.method = v;
                    case "--out" -> o.out = Path.of(v).toAbsolutePath();
                    case "--timeout-ms" -> o.timeoutMs = Long.parseLong(v);
                    case "--max-input-bytes" -> o.maxInputBytes = Long.parseLong(v);
                    case "--budget-sec" -> o.budgetSec = Long.parseLong(v);
                    case "--factory" -> o.factory = v;
                    case "--target" -> o.target = v;
                    case "--seeds" -> o.seeds = Path.of(v);
                    case "--inputs" -> o.inputs = Path.of(v);
                    case "--fixed-lib" -> o.fixedLib = v;
                    case "--fixed-drop" -> o.fixedDrop = v;
                    default -> throw new IllegalArgumentException("unknown option " + a);
                }
            }
            if (o.engine == null || o.cp == null || o.testClass == null || o.method == null || o.out == null) {
                throw new IllegalArgumentException("--engine, --cp, --test-class, --method and --out are required");
            }
            if (o.engine.equals("guidance") && (o.factory == null || !o.factory.contains("#") || o.target == null)) {
                throw new IllegalArgumentException("--engine guidance needs --factory Class#method and --target");
            }
            if (o.engine.equals("replay") && o.inputs == null) {
                throw new IllegalArgumentException("--engine replay needs --inputs");
            }
            if ((o.fixedLib == null) != (o.fixedDrop == null)) {
                throw new IllegalArgumentException("--fixed-lib and --fixed-drop go together");
            }
            return o;
        }
    }
}
