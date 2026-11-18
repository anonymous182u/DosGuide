package dosguide.validate;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Consumer;

/**
 * Validates synthesized guidance by execution (ValidateArtifact in the DoSGuide pipeline).
 *
 * <p>The target's fuzz test runs under JQF through a wrapper around the synthesized guidance: first
 * on inputs the guidance generates itself, then on inputs the validator substitutes (repeats of
 * earlier inputs, random bytes and simple variants of earlier inputs). After each execution the
 * wrapper reads the guidance's per-execution signal values ({@code lastSignals()}). Afterwards it
 * lets the guidance complete a few cycles without running the target. The checks:
 * <ul>
 *   <li>runs: the executions complete without the guidance throwing;</li>
 *   <li>signal_varies: some signal takes at least two values;</li>
 *   <li>reset: re-running an input gives the same value, and no signal only ever grows;</li>
 *   <li>depends_on_execution: a signal stays near zero when the target does not run;</li>
 *   <li>instrumentation: an attached agent rewrote classes (ideally the sink's class); with a guidance
 *       plan, it rewrote the classes the plan instruments with bytecode;</li>
 *   <li>plan_signals: with a guidance plan, lastSignals() returns every planned signal.</li>
 * </ul>
 * With {@code --max-input-bytes} the run has the campaign's input size limit: the System property
 * {@code jqf.ei.MAX_INPUT_SIZE} is set to it and longer inputs are cut, as the campaign launcher does.
 *
 * <p>With {@code --probe-input-limit P} the run is the input-limit probe instead: the property is set to the
 * small value P, the test runs only on inputs the guidance generates, and the single check is
 * <ul>
 *   <li>input_limit: no generated input is longer than P, i.e. the guidance takes its maximum input length
 *       from the property rather than from a limit of its own.</li>
 * </ul>
 * With {@code --probe-growth N} the run is the growth probe: the test runs only on inputs the guidance generates,
 * for at most {@code --budget-ms}, and the single check is
 * <ul>
 *   <li>input_growth: some generated input is at least N bytes long (N is the target's input_bytes, at most the
 *       input size limit), i.e. the guidance can grow its inputs to the length the vulnerability needs.</li>
 * </ul>
 * With {@code --probe-progress LIST} the run is the progress probe: the test runs on inputs the guidance generates for
 * {@code --budget-ms}, then on the inputs of the agent's own size series (Block 1's scale measurement; LIST names one
 * file per line). The report records, per signal, the largest value the guidance's own inputs reached in each eighth of
 * an octave of input length, and the signal values of each series input; the Python front end compares the two at the
 * same input length and decides the check `progress`.
 * With {@code --examples DIR} the substituted inputs also include the files in DIR (ordinary well-formed examples the
 * agent provides) and each of them repeated twice.
 * Whether an input makes the test fail plays no part in the verdict.
 */
public final class ValidateArtifact {

    private static final int MAX_EXAMPLES = 10;

    private final Options o;
    private final Map<String, Object> report;
    private final Reporter reporter;
    private final List<byte[]> examples = new ArrayList<>();

    private ValidateArtifact(Options o, Map<String, Object> report, Reporter reporter) {
        this.o = o;
        this.report = report;
        this.reporter = reporter;
    }

    public static void main(String[] args) {
        Options o;
        try {
            o = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("ValidateArtifact: " + e.getMessage());
            System.err.println("usage: ValidateArtifact --factory <Class#method> --target <id> --test-class <class> "
                    + "--method <name> --out <report.json> [--work <dir>] [--intended A,B] [--planned-signals a,b] "
                    + "[--planned-classes A,B] [--agent] [--own 40] "
                    + "[--random 40] [--repeats 5] [--probes 3] [--seed 1] [--exec-timeout-ms 20000] "
                    + "[--max-input-bytes N] [--probe-input-limit P] [--probe-growth N [--budget-ms 60000]] "
                    + "[--probe-progress LIST [--budget-ms 60000]] [--examples DIR]");
            System.exit(2);
            return;
        }
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("tool", "ValidateArtifact");
        report.put("target", o.target);
        Reporter reporter = new Reporter(o.out, report);
        try {
            new ValidateArtifact(o, report, reporter).run();
        } catch (Throwable t) {
            report.put("error", describe(t));
        }
        reporter.finish();
        System.exit(0); // guidance or JQF threads may linger
    }

    private void run() throws Exception {
        List<Map<String, Object>> checks = new ArrayList<>();
        report.put("checks", checks);
        Files.createDirectories(o.work);
        PrintStream log = new PrintStream(new FileOutputStream(o.work.resolve("guidance.log").toFile()), true,
                StandardCharsets.UTF_8);

        // The input size limit the guidance sees when it is created, as in the campaign launcher.
        long limit = o.probeInputLimit > 0 ? o.probeInputLimit : o.maxInputBytes;
        if (limit > 0) {
            System.setProperty("jqf.ei.MAX_INPUT_SIZE", String.valueOf(limit));
            report.put("max_input_bytes", limit);
        }

        // Contract: guidance factory, lastSignals(), fuzz test method.
        List<String> contract = new ArrayList<>();
        Guidance real = null;
        Method lastSignals = null;
        Class<?> testClass = null;
        ClassLoader cl = ValidateArtifact.class.getClassLoader();
        try {
            int hash = o.factory.indexOf('#');
            Class<?> owner = Class.forName(o.factory.substring(0, hash), true, cl);
            Method factory = owner.getMethod(o.factory.substring(hash + 1), String.class, File.class, long.class,
                    PrintStream.class);
            if (!Modifier.isStatic(factory.getModifiers())) {
                contract.add(o.factory + " must be static");
            } else {
                Object g = factory.invoke(null, o.target, o.work.resolve("guidance-out").toFile(),
                        24L * 3600 * 1000, log);
                if (g instanceof Guidance gg) {
                    real = gg;
                } else {
                    contract.add(o.factory + "(\"" + o.target + "\", ...) returned "
                            + (g == null ? "null" : g.getClass().getName()) + ", not a JQF Guidance");
                }
            }
        } catch (NoSuchMethodException e) {
            contract.add("no method `public static Guidance " + o.factory.replace('#', '.')
                    + "(String targetId, File outputDir, long maxDurationMs, PrintStream log)`");
        } catch (InvocationTargetException e) {
            contract.add(o.factory + " threw " + describe(e.getCause()));
        } catch (ClassNotFoundException e) {
            contract.add("class " + e.getMessage() + " is not on the class path (was the project built?)");
        }
        if (real != null) {
            try {
                lastSignals = real.getClass().getMethod("lastSignals");
                if (!Map.class.isAssignableFrom(lastSignals.getReturnType())) {
                    contract.add(real.getClass().getName() + ".lastSignals() must return a Map<String, ? extends Number>");
                    lastSignals = null;
                }
            } catch (NoSuchMethodException e) {
                contract.add(real.getClass().getName() + " does not implement dosguide.validate.SignalSource "
                        + "(public Map<String, Double> lastSignals())");
            }
        }
        try {
            testClass = Class.forName(o.testClass, true, cl);
            String name = o.method;
            if (Arrays.stream(testClass.getMethods()).noneMatch(m -> m.getName().equals(name))) {
                contract.add("fuzz test " + o.testClass + "." + o.method + " does not exist");
                testClass = null;
            }
        } catch (ClassNotFoundException | LinkageError e) {
            contract.add("fuzz test class " + o.testClass + " cannot be loaded: " + describe(e));
        }
        checks.add(check("contract", contract.isEmpty() ? "pass" : "fail",
                contract.isEmpty() ? "factory, lastSignals() and fuzz test found" : String.join("; ", contract)));
        if (!contract.isEmpty()) {
            return;
        }

        loadExamples();
        Wrapper w = new Wrapper(real, lastSignals);
        loadSeries(w);
        Thread watchdog = new Thread(() -> watch(w, checks), "validate-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        try {
            GuidedFuzzing.run(testClass, o.method, w, log);
        } catch (Throwable t) {
            synchronized (w) {
                w.runError = describe(t);
            }
        }
        if (o.probeInputLimit == 0 && o.probeGrowth == 0 && o.probeProgress == null) {
            w.probe(o.probes);
        }
        synchronized (w) {
            evaluate(w, checks);
        }
    }

    /** The agent's example inputs (--examples): at most MAX_EXAMPLES regular files, each cut to the input size limit. */
    private void loadExamples() throws IOException {
        if (o.examples == null || !Files.isDirectory(o.examples)) {
            return;
        }
        List<Path> files;
        try (var s = Files.list(o.examples)) {
            files = s.filter(Files::isRegularFile).sorted().limit(MAX_EXAMPLES).toList();
        }
        for (Path f : files) {
            byte[] b = Files.readAllBytes(f);
            examples.add(o.maxInputBytes > 0 && b.length > o.maxInputBytes ? Arrays.copyOf(b, (int) o.maxInputBytes) : b);
        }
        report.put("example_inputs", files.size());
    }

    /** The progress probe's series inputs (--probe-progress): one file per line, in order, each cut to the limit. */
    private void loadSeries(Wrapper w) throws IOException {
        if (o.probeProgress == null) {
            return;
        }
        for (String line : Files.readAllLines(o.probeProgress, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            byte[] b = Files.readAllBytes(Path.of(line.trim()));
            w.seriesQueue.add(o.maxInputBytes > 0 && b.length > o.maxInputBytes ? Arrays.copyOf(b, (int) o.maxInputBytes) : b);
        }
    }

    /** Stops the run if a single execution takes too long, keeping the executions recorded so far. */
    private void watch(Wrapper w, List<Map<String, Object>> checks) {
        while (true) {
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                return;
            }
            synchronized (w) {
                if (w.inFlight && System.nanoTime() - w.started > o.execTimeoutMs * 1_000_000L) {
                    report.put("stopped_early", "an execution took longer than " + o.execTimeoutMs
                            + " ms; the checks use the executions recorded before it");
                    evaluate(w, checks);
                    reporter.finish();
                    Runtime.getRuntime().halt(0);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Checks
    // ------------------------------------------------------------------

    private void evaluate(Wrapper w, List<Map<String, Object>> checks) {
        checks.removeIf(c -> !"contract".equals(c.get("name")));
        if (o.probeInputLimit > 0) {
            evaluateInputLimit(w, checks);
            return;
        }
        if (o.probeGrowth > 0) {
            evaluateGrowth(w, checks);
            return;
        }
        if (o.probeProgress != null) {
            evaluateProgress(w, checks);
            return;
        }
        List<Exec> execs = new ArrayList<>(w.execs);
        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("own", execs.stream().filter(e -> e.kind.equals("own")).count());
        counts.put("repeat", execs.stream().filter(e -> e.kind.equals("repeat")).count());
        counts.put("random", execs.stream().filter(e -> e.kind.equals("random")).count());
        counts.put("example", execs.stream().filter(e -> e.kind.equals("example")).count());
        counts.put("probe", w.probes.size());
        report.put("executions", counts);
        // Recorded for the record only; never used for the verdict and never sent to the agent.
        report.put("test_failures_not_used", execs.stream().filter(e -> "FAILURE".equals(e.result)).count());

        // runs
        long guidanceErrors = execs.stream().filter(e -> e.guidanceError != null).count();
        List<String> runProblems = new ArrayList<>();
        if (w.runError != null) {
            runProblems.add("the JQF run stopped with " + w.runError);
        }
        if (execs.size() < Math.min(10, o.own)) {
            runProblems.add("only " + execs.size() + " execution(s) completed");
        }
        if (guidanceErrors > 0) {
            Exec first = execs.stream().filter(e -> e.guidanceError != null).findFirst().orElseThrow();
            runProblems.add("the guidance threw in " + guidanceErrors + " execution(s), first: " + first.guidanceError);
        }
        if (w.signalError != null) {
            runProblems.add("lastSignals() threw " + w.signalError);
        }
        checks.add(check("runs", runProblems.isEmpty() ? "pass" : "fail",
                runProblems.isEmpty() ? execs.size() + " executions completed" : String.join("; ", runProblems)));

        // signal_varies
        // The agent's example inputs are run but do not count: a signal can vary only on them while every input the
        // guidance generates gives 0, and such a guidance never reaches its sink.
        Map<String, List<Double>> series = new TreeMap<>();
        Set<String> varyOnExamples = new LinkedHashSet<>();
        Map<String, Set<Double>> exampleValues = new TreeMap<>();
        for (Exec e : execs) {
            if (e.kind.equals("example")) {
                e.signals.forEach((k, v) -> exampleValues.computeIfAbsent(k, x -> new LinkedHashSet<>()).add(v));
                continue;
            }
            e.signals.forEach((k, v) -> series.computeIfAbsent(k, x -> new ArrayList<>()).add(v));
        }
        exampleValues.forEach((k, v) -> {
            if (v.size() >= 2 || (series.containsKey(k) && v.stream().anyMatch(x -> !close(x, series.get(k).get(0))))) {
                varyOnExamples.add(k);
            }
        });
        Map<String, Object> summary = new LinkedHashMap<>();
        Set<String> varying = new LinkedHashSet<>();
        for (Map.Entry<String, List<Double>> s : series.entrySet()) {
            List<Double> v = s.getValue();
            long distinct = v.stream().distinct().count();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("min", v.stream().mapToDouble(Double::doubleValue).min().orElse(0));
            m.put("max", v.stream().mapToDouble(Double::doubleValue).max().orElse(0));
            m.put("distinct", distinct);
            summary.put(s.getKey(), m);
            if (distinct >= 2) {
                varying.add(s.getKey());
            }
        }
        report.put("signals", summary);
        // Per kind of input (own, repeat, random, example): which inputs made a signal vary.
        Map<String, Map<String, Object>> byKind = new TreeMap<>();
        Map<String, Set<String>> varyingByKind = new TreeMap<>();
        for (String kind : List.of("own", "repeat", "random", "example")) {
            Map<String, List<Double>> ks = new TreeMap<>();
            for (Exec e : execs) {
                if (e.kind.equals(kind)) {
                    e.signals.forEach((k, v) -> ks.computeIfAbsent(k, x -> new ArrayList<>()).add(v));
                }
            }
            Map<String, Object> km = new TreeMap<>();
            ks.forEach((k, v) -> {
                long d = v.stream().distinct().count();
                km.put(k, Map.of("min", v.stream().mapToDouble(Double::doubleValue).min().orElse(0),
                        "max", v.stream().mapToDouble(Double::doubleValue).max().orElse(0), "distinct", d));
                if (d >= 2) {
                    varyingByKind.computeIfAbsent(kind, x -> new LinkedHashSet<>()).add(k);
                }
            });
            if (!km.isEmpty()) {
                byKind.put(kind, km);
            }
        }
        report.put("signals_by_kind", byKind);
        if (!o.plannedSignals.isEmpty()) {
            List<String> missing = o.plannedSignals.stream().filter(s -> !series.containsKey(s)).toList();
            checks.add(check("plan_signals", missing.isEmpty() ? "pass" : "fail", missing.isEmpty()
                    ? "lastSignals() returns every planned signal " + o.plannedSignals
                    : "the plan declares " + missing + " but lastSignals() returns " + series.keySet()
                            + "; return the planned signals under their planned names"));
        }
        if (series.isEmpty()) {
            checks.add(check("signal_varies", "fail", "lastSignals() returned no numeric values in any execution"));
        } else if (varying.isEmpty()) {
            List<String> consts = new ArrayList<>();
            series.forEach((k, v) -> consts.add("`" + k + "` = " + fmt(v.get(0))));
            // Measuring something else (e.g. the input length at the decoder's entry instead of the decompressed
            // bytes) would pass this check and make the guidance useless. A signal that stays at zero because no
            // input reaches the resource-consuming code is fixed by generating inputs that reach it, so the message
            // says so.
            long counted = execs.stream().filter(e -> !e.kind.equals("example")).count();
            checks.add(check("signal_varies", "fail", "every signal had the same value on all " + counted
                    + " inputs the guidance generated and the validator's variants of them (" + String.join(", ", consts)
                    + "): the measurement does not respond to the input"
                    + (varyOnExamples.isEmpty() ? "" : "; it varied only on your example inputs ("
                            + String.join(", ", varyOnExamples) + "), so the guidance's own inputs never reach the code "
                            + "the signal measures and the fuzzing would make no progress")
                    + ". If it stays constant because no generated input reaches the code that consumes the resource "
                    + "(for example, every input is rejected before that code runs), make the guidance generate inputs "
                    + "that reach it, and keep measuring the resource where it is consumed: a quantity measured before "
                    + "that code, such as the input length, does not fix the guidance."));
        } else if (!varyingByKind.containsKey("own")) {
            // The signal can vary only because the validator's variants of the guidance's inputs (e.g. an input
            // repeated twice) reach the sink while every input the guidance generates gives 0; such a guidance
            // never reaches the sink while fuzzing.
            List<String> ownConst = new ArrayList<>();
            Map<String, Object> own = byKind.getOrDefault("own", Map.of());
            own.forEach((k, v) -> ownConst.add("`" + k + "` = " + fmt((Double) ((Map<?, ?>) v).get("min"))));
            checks.add(check("signal_varies", "fail", "the signal varied (" + varying + ") only on inputs the validator "
                    + "substituted, not on the " + execs.stream().filter(e -> e.kind.equals("own")).count()
                    + " inputs the guidance generated (" + String.join(", ", ownConst) + "): the guidance's own inputs "
                    + "never reach the code the signal measures, so the fuzzing would make no progress. Make the "
                    + "guidance's seeds and mutations produce inputs that reach that code (check that a mutation such as "
                    + "a length or checksum repair does not make every input invalid), and keep measuring the resource "
                    + "where it is consumed."));
        } else {
            checks.add(check("signal_varies", "pass", "varying: " + varying + " (on the guidance's own inputs: "
                    + varyingByKind.get("own") + ")"));
        }

        // reset
        List<String> resetFail = new ArrayList<>();
        List<String> resetWarn = new ArrayList<>();
        for (String k : varying) {
            int higher = 0;
            int lower = 0;
            int match = 0;
            List<String> pairs = new ArrayList<>();
            for (Exec e : execs) {
                if (!e.kind.equals("repeat") || e.ref < 0 || e.ref >= execs.size()) {
                    continue;
                }
                Double a = execs.get(e.ref).signals.get(k);
                Double b = e.signals.get(k);
                if (a == null || b == null) {
                    continue;
                }
                if (close(a, b)) {
                    match++;
                } else if (b > a) {
                    higher++;
                } else {
                    lower++;
                }
                if (pairs.size() < 3) {
                    pairs.add(fmt(a) + " then " + fmt(b));
                }
            }
            List<Double> v = series.get(k);
            int inc = 0;
            int dec = 0;
            for (int i = 1; i < v.size(); i++) {
                if (v.get(i) > v.get(i - 1) && !close(v.get(i), v.get(i - 1))) {
                    inc++;
                } else if (v.get(i) < v.get(i - 1) && !close(v.get(i), v.get(i - 1))) {
                    dec++;
                }
            }
            if (higher > 0 && match == 0 && lower == 0) {
                resetFail.add("`" + k + "`: re-running the same input gave a larger value (" + String.join(", ", pairs)
                        + "), so state from earlier executions is carried over");
            } else if (dec == 0 && inc >= 3) {
                resetFail.add("`" + k + "` never decreased over " + v.size() + " executions (from " + fmt(v.get(0))
                        + " to " + fmt(v.get(v.size() - 1)) + "): it accumulates across executions or reports a "
                        + "best-so-far value instead of the value of the last execution");
            } else if (higher + lower > 0) {
                resetWarn.add("`" + k + "`: re-running the same input gave different values (" + String.join(", ", pairs)
                        + "), so the value is not determined by the executed input (timing, or computed from "
                        + "something other than the execution)");
            }
        }
        if (varying.isEmpty()) {
            checks.add(check("reset", "skipped", "no varying signal"));
        } else if (!resetFail.isEmpty()) {
            checks.add(check("reset", "fail", String.join("; ", resetFail)));
        } else {
            checks.add(check("reset", resetWarn.isEmpty() ? "pass" : "warn",
                    resetWarn.isEmpty() ? "re-running inputs reproduced their values" : String.join("; ", resetWarn)));
        }

        // depends_on_execution
        if (w.probes.isEmpty()) {
            checks.add(check("depends_on_execution", "skipped",
                    "the guidance could not complete a cycle without the target" + (w.probeError == null ? ""
                            : " (" + w.probeError + ")")));
        } else if (!varying.isEmpty()) {
            List<String> problems = new ArrayList<>();
            for (String k : varying) {
                double median = median(series.get(k).stream().filter(x -> x != 0).toList());
                double probeMax = w.probes.stream().mapToDouble(p -> Math.abs(p.getOrDefault(k, 0.0))).max().orElse(0);
                if (median != 0 && probeMax >= 0.5 * Math.abs(median)) {
                    problems.add("`" + k + "` was " + fmt(probeMax) + " in a cycle where the target did not run "
                            + "(median when it ran: " + fmt(median) + "): it is computed from the input or from "
                            + "stale state, not measured during the execution");
                }
            }
            checks.add(check("depends_on_execution", problems.isEmpty() ? "pass" : "fail",
                    problems.isEmpty() ? "signals stay near zero when the target does not run" : String.join("; ", problems)));
        } else {
            checks.add(check("depends_on_execution", "skipped", "no varying signal"));
        }

        // instrumentation
        if (!o.agent && !o.plannedClasses.isEmpty()) {
            checks.add(check("instrumentation", "fail", "the plan instruments " + o.plannedClasses
                    + " with bytecode, but analysis/launch.json declares no javaagent"));
        } else if (!o.agent) {
            checks.add(check("instrumentation", "skipped", "no javaagent declared"));
        } else if (!TransformObserver.attached()) {
            checks.add(check("instrumentation", "fail", "the observer agent is not attached (validator setup error)"));
        } else {
            Set<String> transformed = TransformObserver.transformed();
            transformed.removeIf(n -> n.startsWith("edu.berkeley.cs.jqf.") || n.startsWith("org.junit.")
                    || n.startsWith("dosguide.validate."));
            report.put("transformed_classes", new ArrayList<>(transformed).subList(0, Math.min(50, transformed.size())));
            List<String> plannedMissing = o.plannedClasses.stream()
                    .filter(p -> transformed.stream().noneMatch(t -> matches(t, p))).toList();
            if (transformed.isEmpty()) {
                checks.add(check("instrumentation", "fail", "the javaagent rewrote no class while the test ran, so its "
                        + "counters can only stay at their initial values"));
            } else if (!o.plannedClasses.isEmpty() && plannedMissing.size() == o.plannedClasses.size()) {
                checks.add(check("instrumentation", "fail", "the plan instruments " + o.plannedClasses
                        + ", but the javaagent rewrote " + abbreviate(transformed) + " and none of them"));
            } else if (!plannedMissing.isEmpty()) {
                checks.add(check("instrumentation", "warn", "the javaagent rewrote " + abbreviate(transformed)
                        + " but not the planned " + plannedMissing));
            } else if (!o.intended.isEmpty() && transformed.stream().noneMatch(this::isIntended)) {
                checks.add(check("instrumentation", "warn", "the javaagent rewrote " + abbreviate(transformed)
                        + " but none of the sink classes " + o.intended));
            } else {
                checks.add(check("instrumentation", "pass", "rewrote " + abbreviate(transformed)));
            }
        }
        report.put("ok", checks.stream().noneMatch(c -> "fail".equals(c.get("status"))));
    }

    /** The input-limit probe: with jqf.ei.MAX_INPUT_SIZE set to P, no generated input may be longer than P. */
    private void evaluateInputLimit(Wrapper w, List<Map<String, Object>> checks) {
        List<Exec> execs = new ArrayList<>(w.execs);
        long p = o.probeInputLimit;
        long over = execs.stream().filter(e -> e.input.length > p).count();
        int longest = execs.stream().mapToInt(e -> e.input.length).max().orElse(0);
        report.put("executions", Map.of("own", execs.size()));
        report.put("longest_input", longest);
        if (execs.isEmpty()) {
            checks.add(check("input_limit", "fail", "with jqf.ei.MAX_INPUT_SIZE=" + p + " no execution completed"
                    + (w.runError != null ? " (" + w.runError + ")" : "")
                    + "; the guidance must also run when the input size limit is small"));
        } else if (over > 0) {
            checks.add(check("input_limit", "fail", "with jqf.ei.MAX_INPUT_SIZE=" + p + " the guidance generated "
                    + over + " of " + execs.size() + " inputs longer than " + p + " bytes; take the maximum input "
                    + "length from the System property jqf.ei.MAX_INPUT_SIZE (the evaluation sets it to the input "
                    + "size limit), never generate a longer input, and impose no smaller maximum of your own"));
        } else {
            checks.add(check("input_limit", "pass", "with jqf.ei.MAX_INPUT_SIZE=" + p + " the " + execs.size()
                    + " generated inputs were at most " + longest + " bytes"));
        }
        report.put("ok", checks.stream().noneMatch(c -> "fail".equals(c.get("status"))));
    }

    /**
     * The growth probe: within the time budget, the guidance must generate an input at least as long as the target
     * needs (the register's input_bytes, at most the input size limit). A guidance that keeps only inputs with a
     * non-zero signal, while its signal is zero below the length the target needs, never grows its inputs that far.
     */
    private void evaluateGrowth(Wrapper w, List<Map<String, Object>> checks) {
        long need = o.probeGrowth;
        report.put("executions", Map.of("own", w.growthExecs));
        report.put("longest_input", w.growthLongest);
        report.put("needed_input_bytes", need);
        report.put("growth", w.growthCurve);
        long seconds = Math.round(o.budgetMs / 1000.0);
        if (w.growthExecs == 0) {
            checks.add(check("input_growth", "fail", "the growth probe completed no execution"
                    + (w.runError != null ? " (" + w.runError + ")" : "")));
        } else if (w.growthLongest >= need) {
            checks.add(check("input_growth", "pass", "the guidance generated a " + w.growthLongest + "-byte input after "
                    + w.growthReachedMs + " ms (" + w.growthReachedExec + " executions); the target needs " + need));
        } else {
            checks.add(check("input_growth", "fail", "in " + seconds + " s (" + w.growthExecs + " executions) the longest "
                    + "input the guidance generated was " + w.growthLongest + " bytes, but the target register says the "
                    + "vulnerability needs inputs of " + need + " bytes (`input_bytes`, at most the input size limit). "
                    + "The guidance must be able to grow its inputs to that length within the first minute of fuzzing: "
                    + "keep inputs that grow even while the signal is flat (for example below a threshold where it is "
                    + "zero), and use operators that grow inputs quickly (appending or repeating blocks, doubling)"));
        }
        report.put("ok", checks.stream().noneMatch(c -> "fail".equals(c.get("status"))));
    }

    /**
     * The progress probe's measurements; the verdict is the Python front end's (validate.py progress_check), which
     * compares the guidance's own inputs with the agent's size series at the same input length. The check is "measured"
     * unless the run stopped with an error while it ran the guidance's own inputs.
     */
    private void evaluateProgress(Wrapper w, List<Map<String, Object>> checks) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("budget_ms", o.budgetMs);
        p.put("own_ms", w.progressSeries ? w.progressOwnMs : w.growthElapsedMs());
        p.put("executions", w.progressExecs);
        p.put("longest_input", w.progressLongest);
        p.put("phase", w.progressSeries ? "series" : "own");
        Map<String, Object> best = new TreeMap<>();
        w.progressBest.forEach((k, buckets) -> {
            List<Object> pts = new ArrayList<>();
            buckets.values().forEach(a -> pts.add(List.of((long) a[0], a[1], (long) a[2])));
            best.put(k, pts);
        });
        p.put("own_best", best);
        p.put("series", w.seriesResults);
        if (w.progressSeries && w.inFlight && !w.seriesQueue.isEmpty()) {
            p.put("series_unfinished_bytes", w.seriesQueue.peek().length); // still running when the probe stopped
        }
        report.put("progress", p);
        if (w.runError != null && !w.progressSeries) {
            checks.add(check("progress", "fail", "the run stopped with " + w.runError));
        } else {
            checks.add(check("progress", "measured", w.progressExecs + " executions of the guidance's own inputs, "
                    + w.seriesResults.size() + " series inputs"));
        }
        report.put("ok", checks.stream().noneMatch(c -> "fail".equals(c.get("status"))));
    }

    private boolean isIntended(String fqn) {
        return o.intended.stream().anyMatch(want -> matches(fqn, want));
    }

    /** True if a loaded class name matches a class as written in a plan or sink (simple or qualified name). */
    private static boolean matches(String fqn, String want) {
        if (fqn.equals(want)) {
            return true;
        }
        String simple = fqn.substring(fqn.lastIndexOf('.') + 1);
        String outer = simple.contains("$") ? simple.substring(0, simple.indexOf('$')) : simple;
        String w = want.contains(".") ? want.substring(want.lastIndexOf('.') + 1) : want;
        if (w.contains("$") && simple.equals(w)) {
            return true;
        }
        w = w.contains("$") ? w.substring(0, w.indexOf('$')) : w;
        return outer.equals(w) && (!want.contains(".") || fqn.startsWith(want.substring(0, want.lastIndexOf('.'))));
    }

    private static String abbreviate(Set<String> names) {
        List<String> l = new ArrayList<>(names);
        return l.size() <= 5 ? l.toString() : l.subList(0, 5) + " and " + (l.size() - 5) + " more";
    }

    private static boolean close(double a, double b) {
        return Math.abs(a - b) <= 1e-9 + 0.01 * Math.max(Math.abs(a), Math.abs(b));
    }

    private static double median(List<Double> v) {
        if (v.isEmpty()) {
            return 0;
        }
        double[] s = v.stream().mapToDouble(Double::doubleValue).sorted().toArray();
        return s[s.length / 2];
    }

    private static String fmt(double d) {
        return d == Math.rint(d) && Math.abs(d) < 1e15 ? String.valueOf((long) d) : String.format("%.4g", d);
    }

    private static Map<String, Object> check(String name, String status, String detail) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        m.put("status", status);
        m.put("detail", detail);
        return m;
    }

    static String describe(Throwable t) {
        if (t == null) {
            return "null";
        }
        while ((t instanceof InvocationTargetException || t.getClass().getSimpleName().equals("GuidanceException"))
                && t.getCause() != null && t.getCause() != t) {
            t = t.getCause();
        }
        String m = t.getMessage();
        return t.getClass().getName() + (m == null ? "" : ": " + (m.length() > 200 ? m.substring(0, 200) + "..." : m));
    }

    // ------------------------------------------------------------------
    // Wrapper guidance
    // ------------------------------------------------------------------

    private record Planned(String kind, byte[] bytes, int ref) {
    }

    private static final class Exec {
        final String kind;
        final int ref;
        final byte[] input;
        final String result;
        String guidanceError;
        Map<String, Double> signals = Map.of();

        Exec(String kind, int ref, byte[] input, String result) {
            this.kind = kind;
            this.ref = ref;
            this.input = input;
            this.result = result;
        }
    }

    /** Delegates to the synthesized guidance, choosing the inputs and recording the signal per execution. */
    private final class Wrapper implements Guidance {
        final Guidance real;
        final Method lastSignals;
        final Deque<Planned> plan = new ArrayDeque<>();
        final List<Exec> execs = new ArrayList<>();
        final List<Map<String, Double>> probes = new ArrayList<>();
        boolean substitutionsPlanned;
        boolean inFlight;
        long started;
        ByteArrayOutputStream recorded;
        String runError;
        String signalError;
        String probeError;

        // The growth probe keeps only the lengths: its inputs may be up to the input size limit, over many executions.
        long growthExecs;
        int growthLongest;
        long growthReachedMs = -1;
        long growthReachedExec = -1;
        final List<Map<String, Object>> growthCurve = new ArrayList<>();
        final long growthStart = System.nanoTime();

        // The progress probe: the guidance's own inputs until the budget ends, then the series inputs. Of the own
        // inputs it keeps, per signal and eighth of an octave of input length, the largest value {bytes, value, ms}.
        boolean progressSeries;
        long progressOwnMs;
        long progressExecs;
        int progressLongest;
        final Deque<byte[]> seriesQueue = new ArrayDeque<>();
        final List<Map<String, Object>> seriesResults = new ArrayList<>();
        final Map<String, TreeMap<Integer, double[]>> progressBest = new TreeMap<>();

        Wrapper(Guidance real, Method lastSignals) {
            this.real = real;
            this.lastSignals = lastSignals;
            if (o.probeGrowth == 0 && o.probeProgress == null) {
                for (int i = 0; i < o.own; i++) {
                    plan.add(new Planned("own", null, -1));
                }
            }
            // The input-limit, growth and progress probes plan no substitutions.
            substitutionsPlanned = o.probeInputLimit > 0 || o.probeGrowth > 0 || o.probeProgress != null;
        }

        private long growthElapsedMs() {
            return (System.nanoTime() - growthStart) / 1_000_000L;
        }

        @Override
        public synchronized boolean hasInput() {
            if (o.probeGrowth > 0) {
                return growthLongest < o.probeGrowth && growthElapsedMs() < o.budgetMs && realHasInput();
            }
            if (o.probeProgress != null) {
                if (!progressSeries) {
                    if (growthElapsedMs() < o.budgetMs && realHasInput()) {
                        return true;
                    }
                    progressSeries = true;
                    progressOwnMs = growthElapsedMs();
                }
                return !seriesQueue.isEmpty();
            }
            while (true) {
                if (plan.isEmpty()) {
                    if (substitutionsPlanned) {
                        return false;
                    }
                    planSubstitutions();
                    substitutionsPlanned = true;
                    continue;
                }
                if (plan.peek().kind().equals("own") && !realHasInput()) {
                    plan.removeIf(p -> p.kind().equals("own"));
                    continue;
                }
                return true;
            }
        }

        private boolean realHasInput() {
            try {
                return real.hasInput();
            } catch (Throwable t) {
                runError = "hasInput() threw " + describe(t);
                return false;
            }
        }

        @Override
        public synchronized InputStream getInput() {
            Planned p = plan.peek();
            recorded = new ByteArrayOutputStream();
            started = System.nanoTime();
            inFlight = true;
            if (o.probeProgress != null && progressSeries) {
                try {
                    real.getInput(); // for its side effects, e.g. resetting counters
                } catch (Throwable t) {
                    runError = "getInput() threw " + describe(t);
                }
                return new ByteArrayInputStream(seriesQueue.peek());
            }
            if (o.probeGrowth > 0 || o.probeProgress != null || p.kind().equals("own")) {
                // Cut as the campaign does; the probe reads one byte past its limit to see a longer input.
                long cap = o.probeInputLimit > 0 ? o.probeInputLimit + 1 : o.maxInputBytes;
                InputStream in = real.getInput();
                return new Tee(cap > 0 ? new Capped(in, cap) : in, recorded);
            }
            try {
                real.getInput(); // for its side effects, e.g. resetting counters
            } catch (Throwable t) {
                runError = "getInput() threw " + describe(t);
            }
            return new ByteArrayInputStream(p.bytes());
        }

        @Override
        public synchronized void handleResult(Result result, Throwable error) {
            if (o.probeGrowth > 0) {
                inFlight = false;
                growthExecs++;
                int len = recorded.size();
                if (len > growthLongest) {
                    growthLongest = len;
                    Map<String, Object> point = new LinkedHashMap<>();
                    point.put("ms", growthElapsedMs());
                    point.put("execution", growthExecs);
                    point.put("bytes", len);
                    if (growthCurve.size() < 200) {
                        growthCurve.add(point);
                    }
                    if (len >= o.probeGrowth && growthReachedMs < 0) {
                        growthReachedMs = growthElapsedMs();
                        growthReachedExec = growthExecs;
                    }
                }
                recorded = null;
                try {
                    real.handleResult(result, error);
                } catch (Throwable t) {
                    runError = "handleResult() threw " + describe(t);
                }
                return;
            }
            if (o.probeProgress != null) {
                inFlight = false;
                try {
                    real.handleResult(result, error);
                } catch (Throwable t) {
                    runError = "handleResult() threw " + describe(t);
                }
                Map<String, Double> signals = readSignals();
                if (progressSeries) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("bytes", seriesQueue.poll().length);
                    m.put("signals", signals);
                    seriesResults.add(m);
                } else {
                    progressExecs++;
                    int len = recorded.size();
                    progressLongest = Math.max(progressLongest, len);
                    int bucket = len == 0 ? -1 : (int) Math.floor(8 * Math.log(len) / Math.log(2));
                    signals.forEach((k, v) -> {
                        double[] b = progressBest.computeIfAbsent(k, x -> new TreeMap<>()).get(bucket);
                        if (b == null || v > b[1]) {
                            progressBest.get(k).put(bucket, new double[]{len, v, growthElapsedMs()});
                        }
                    });
                }
                recorded = null;
                return;
            }
            Planned p = plan.poll();
            inFlight = false;
            if (p == null) {
                return;
            }
            Exec e = new Exec(p.kind(), p.ref(), p.kind().equals("own") ? recorded.toByteArray() : p.bytes(),
                    result.name());
            try {
                real.handleResult(result, error);
            } catch (Throwable t) {
                e.guidanceError = describe(t);
            }
            e.signals = readSignals();
            execs.add(e);
        }

        @Override
        public Consumer<TraceEvent> generateCallBack(Thread thread) {
            return real.generateCallBack(thread);
        }

        @Override
        public void observeGeneratedArgs(Object[] args) {
            real.observeGeneratedArgs(args);
        }

        Map<String, Double> readSignals() {
            try {
                Object v = lastSignals.invoke(real);
                Map<String, Double> out = new TreeMap<>();
                if (v instanceof Map<?, ?> m) {
                    m.forEach((k, x) -> {
                        if (x instanceof Number n && Double.isFinite(n.doubleValue())) {
                            out.put(String.valueOf(k), n.doubleValue());
                        }
                    });
                }
                return out;
            } catch (Throwable t) {
                signalError = describe(t);
                return Map.of();
            }
        }

        /** Repeats of earlier inputs, random bytes, and prefixes, mutations and doublings of earlier inputs. */
        private void planSubstitutions() {
            List<Integer> own = new ArrayList<>();
            for (int i = 0; i < execs.size(); i++) {
                if (execs.get(i).kind.equals("own") && execs.get(i).input.length > 0) {
                    own.add(i);
                }
            }
            List<Integer> bySignal = new ArrayList<>(own);
            bySignal.sort((a, b) -> Double.compare(total(execs.get(b)), total(execs.get(a))));
            Set<String> seen = new LinkedHashSet<>();
            for (int i : bySignal) {
                if (seen.size() >= o.repeats) {
                    break;
                }
                if (seen.add(execs.get(i).signals.toString())) {
                    plan.add(new Planned("repeat", execs.get(i).input, i));
                }
            }
            // The agent's well-formed example inputs, and each repeated twice: a signal that only responds to inputs
            // the format accepts can show that it varies (see the signal_varies message).
            for (byte[] ex : examples) {
                plan.add(new Planned("example", ex, -1));
                long cap = o.maxInputBytes > 0 ? o.maxInputBytes : 2L * ex.length;
                byte[] twice = new byte[(int) Math.min(cap, 2L * ex.length)];
                for (int j = 0; j < twice.length; j++) {
                    twice[j] = ex[j % ex.length];
                }
                if (ex.length > 0) {
                    plan.add(new Planned("example", twice, -1));
                }
            }
            Random rnd = new Random(o.seed);
            for (int i = 0; i < o.random; i++) {
                int kind = own.isEmpty() ? 0 : i % 4;
                byte[] src = own.isEmpty() ? null : execs.get(own.get(rnd.nextInt(own.size()))).input;
                byte[] b;
                switch (kind) {
                    case 1 -> b = Arrays.copyOf(src, 1 + rnd.nextInt(src.length));
                    case 2 -> {
                        b = src.clone();
                        for (int f = 1 + rnd.nextInt(8); f > 0; f--) {
                            b[rnd.nextInt(b.length)] = (byte) rnd.nextInt(256);
                        }
                    }
                    case 3 -> {
                        int n = (int) Math.min(o.maxInputBytes > 0 ? Math.min(65536, o.maxInputBytes) : 65536,
                                src.length * 2L);
                        b = new byte[n];
                        for (int j = 0; j < n; j++) {
                            b[j] = src[j % src.length];
                        }
                    }
                    default -> {
                        b = new byte[1 + rnd.nextInt(2048)];
                        rnd.nextBytes(b);
                    }
                }
                plan.add(new Planned("random", b, -1));
            }
        }

        private double total(Exec e) {
            return e.signals.values().stream().mapToDouble(Math::abs).sum();
        }

        /** Lets the guidance complete cycles without running the target. */
        void probe(int n) {
            for (int i = 0; i < n; i++) {
                try {
                    synchronized (this) {
                        real.getInput();
                        real.handleResult(Result.SUCCESS, null);
                        probes.add(readSignals());
                    }
                } catch (Throwable t) {
                    probeError = describe(t);
                    return;
                }
            }
        }
    }

    /** Ends the stream after a fixed number of bytes, as the campaign launcher cuts inputs. */
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
                copy.write(b);
            }
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            int n = super.read(buf, off, len);
            if (n > 0) {
                copy.write(buf, off, n);
            }
            return n;
        }
    }

    // ------------------------------------------------------------------
    // Options and report
    // ------------------------------------------------------------------

    private static final class Options {
        String factory;
        String target;
        String testClass;
        String method;
        Path out;
        Path work;
        List<String> intended = List.of();
        List<String> plannedSignals = List.of();
        List<String> plannedClasses = List.of();
        boolean agent;
        int own = 40;
        int random = 40;
        int repeats = 5;
        int probes = 3;
        long seed = 1;
        long execTimeoutMs = 20_000;
        long maxInputBytes = 0;
        long probeInputLimit = 0;
        long probeGrowth = 0;
        long budgetMs = 60_000;
        Path probeProgress;
        Path examples;

        static Options parse(String[] args) {
            Options o = new Options();
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                if (a.equals("--agent")) {
                    o.agent = true;
                    continue;
                }
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("missing value for " + a);
                }
                String v = args[++i];
                switch (a) {
                    case "--factory" -> o.factory = v;
                    case "--target" -> o.target = v;
                    case "--test-class" -> o.testClass = v;
                    case "--method" -> o.method = v;
                    case "--out" -> o.out = Path.of(v);
                    case "--work" -> o.work = Path.of(v);
                    case "--intended" -> o.intended = csv(v);
                    case "--planned-signals" -> o.plannedSignals = csv(v);
                    case "--planned-classes" -> o.plannedClasses = csv(v);
                    case "--own" -> o.own = Integer.parseInt(v);
                    case "--random" -> o.random = Integer.parseInt(v);
                    case "--repeats" -> o.repeats = Integer.parseInt(v);
                    case "--probes" -> o.probes = Integer.parseInt(v);
                    case "--seed" -> o.seed = Long.parseLong(v);
                    case "--exec-timeout-ms" -> o.execTimeoutMs = Long.parseLong(v);
                    case "--max-input-bytes" -> o.maxInputBytes = Long.parseLong(v);
                    case "--probe-input-limit" -> o.probeInputLimit = Long.parseLong(v);
                    case "--probe-growth" -> o.probeGrowth = Long.parseLong(v);
                    case "--budget-ms" -> o.budgetMs = Long.parseLong(v);
                    case "--probe-progress" -> o.probeProgress = Path.of(v);
                    case "--examples" -> o.examples = Path.of(v);
                    default -> throw new IllegalArgumentException("unknown option " + a);
                }
            }
            if (o.factory == null || !o.factory.contains("#") || o.target == null || o.testClass == null
                    || o.method == null || o.out == null) {
                throw new IllegalArgumentException("--factory Class#method, --target, --test-class, --method and --out "
                        + "are required");
            }
            if (o.work == null) {
                o.work = o.out.toAbsolutePath().getParent().resolve("validate-work-" + o.target);
            }
            return o;
        }

        private static List<String> csv(String v) {
            return v.isBlank() ? List.of()
                    : Arrays.stream(v.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
        }
    }

    /** Writes the report once, from whichever thread finishes first. */
    private static final class Reporter {
        private final Path out;
        private final Map<String, Object> report;
        private boolean written;

        Reporter(Path out, Map<String, Object> report) {
            this.out = out;
            this.report = report;
        }

        synchronized void finish() {
            if (written) {
                return;
            }
            written = true;
            report.putIfAbsent("ok", false);
            try {
                Files.writeString(out, Json.write(report) + "\n", StandardCharsets.UTF_8);
            } catch (IOException e) {
                System.err.println("ValidateArtifact: cannot write " + out + ": " + e.getMessage());
            }
        }
    }
}
