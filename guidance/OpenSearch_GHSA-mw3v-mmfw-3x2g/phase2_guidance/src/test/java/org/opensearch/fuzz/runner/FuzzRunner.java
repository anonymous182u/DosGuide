package org.opensearch.fuzz.runner;

import java.io.File;
import java.io.PrintStream;
import java.security.CodeSource;
import java.util.LinkedHashMap;
import java.util.Map;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import org.opensearch.fuzz.agent.V1Counters;
import org.opensearch.fuzz.guidance.V1Guidance;

/**
 * CLI runner.
 *
 * Usage: FuzzRunner &lt;targetId | fuzzMethodName&gt; [durationSeconds] [outputDir]
 *   targetId        V1 (or the @Fuzz method name fuzzQueryStringQueryBuilderToQuery)
 *   durationSeconds 0 or absent means run indefinitely (also -Dfuzz.durationSec=N)
 *   outputDir       default out/&lt;targetId&gt; (corpus in &lt;outputDir&gt;/corpus, logs in &lt;outputDir&gt;/logs)
 *
 * JVM: -Xmx1g -Xss1m -javaagent:target/v1-agent.jar
 */
public final class FuzzRunner {

    public static final String TEST_CLASS = "org.opensearch.fuzz.tests.QueryParserFuzzTest";

    /** target id to @Fuzz method of the frozen harness. */
    public static final Map<String, String> TARGETS = new LinkedHashMap<>();
    static {
        TARGETS.put("V1", "fuzzQueryStringQueryBuilderToQuery");
    }

    private FuzzRunner() {
    }

    public static Guidance createGuidance(String targetId, File outputDir, long maxDurationMs, PrintStream log) {
        switch (targetId) {
            case "V1":
                return new V1Guidance(outputDir, maxDurationMs, log);
            default:
                throw new IllegalArgumentException("unknown target id: " + targetId + " (known: " + TARGETS.keySet() + ")");
        }
    }

    static String resolveTargetId(String sel) {
        if (TARGETS.containsKey(sel)) {
            return sel;
        }
        for (Map.Entry<String, String> e : TARGETS.entrySet()) {
            if (e.getValue().equals(sel)) {
                return e.getKey();
            }
        }
        throw new IllegalArgumentException("unknown target or method: " + sel + " (targets: " + TARGETS + ")");
    }

    /** Class Origin Check: prints where the vulnerable classes are loaded from. */
    public static void printClassOrigin(ClassLoader cl, PrintStream out) {
        String[] names = {
            "org.opensearch.index.search.QueryStringQueryParser",
            "org.opensearch.index.query.QueryStringQueryBuilder",
            "org.apache.lucene.queryparser.classic.QueryParser"
        };
        for (String n : names) {
            try {
                Class<?> c = Class.forName(n, false, cl);
                CodeSource cs = c.getProtectionDomain().getCodeSource();
                out.println("{\"event\":\"class-origin\",\"class\":\"" + n + "\",\"location\":\""
                    + (cs == null ? "null" : cs.getLocation()) + "\"}");
            } catch (ClassNotFoundException e) {
                out.println("{\"event\":\"class-origin\",\"class\":\"" + n + "\",\"location\":\"NOT FOUND\"}");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: FuzzRunner <targetId|fuzzMethod> [durationSeconds] [outputDir]");
            System.err.println("Targets: " + TARGETS);
            System.exit(2);
        }
        String targetId = resolveTargetId(args[0]);
        long seconds = args.length > 1 ? Long.parseLong(args[1]) : Long.getLong("fuzz.durationSec", 0L);
        File outDir = new File(args.length > 2 ? args[2] : "out/" + targetId);
        String method = TARGETS.get(targetId);

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        printClassOrigin(cl, System.out);
        System.out.println("{\"event\":\"agent-check\",\"instrumentedMethods\":" + V1Counters.instrumentedMethods
            + ",\"note\":\"counts grow when the parser classes are loaded during the first execution\"}");

        Guidance guidance = createGuidance(targetId, outDir, seconds * 1000L, System.out);
        org.junit.runner.Result res = GuidedFuzzing.run(TEST_CLASS, method, cl, guidance, System.out);
        System.out.println("{\"event\":\"done\",\"target\":\"" + targetId + "\",\"method\":\"" + method
            + "\",\"instrumentedMethods\":" + V1Counters.instrumentedMethods
            + ",\"junitFailures\":" + (res == null ? -1 : res.getFailureCount()) + "}");
        System.exit(0);
    }
}
