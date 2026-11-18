package org.opensearch.fuzz.agent;

/**
 * Measurement-only counters for target V1 (CWE-674, classic QueryParser recursion under
 * QueryStringQueryParser#parse). The hooks are injected by {@link V1ParserTransformer}:
 * <ul>
 *   <li>org.opensearch.index.search.QueryStringQueryParser#parse(String): enterParse / exitParse (gate)</li>
 *   <li>org.apache.lucene.queryparser.classic.QueryParser#Clause(String): enterClause / exitClause</li>
 *   <li>org.apache.lucene.queryparser.classic.QueryParser#Query(String): enterQuery</li>
 * </ul>
 * Counting happens only while QueryStringQueryParser#parse is active, so the
 * parser recursion is measured only inside the target's sink.
 *
 * The fields are plain statics because JQF runs the fuzz method, getInput() and handleResult()
 * on one thread. Exits are hooked only on normal returns. An exception thrown inside the
 * recursion (ParseException, StackOverflowError) ends the whole parse, and the peak depth has
 * already been recorded at that point. The Guidance calls {@link #reset()} before every execution.
 */
public final class V1Counters {

    private V1Counters() {
    }

    /** Number of active QueryStringQueryParser#parse frames (gate). */
    private static int parseDepth;
    /** Number of currently active QueryParser#Clause frames inside the gate. */
    private static int curClause;
    /** Peak of curClause during the current execution. */
    private static int maxClause;
    /** Invocations of Clause and Query inside the gate during the current execution. */
    private static long visits;

    /** Number of methods the agent rewrote (diagnostics for the class origin and agent check). */
    public static volatile int instrumentedMethods;

    public static void reset() {
        parseDepth = 0;
        curClause = 0;
        maxClause = 0;
        visits = 0L;
    }

    public static void enterParse() {
        parseDepth++;
    }

    public static void exitParse() {
        if (parseDepth > 0) {
            parseDepth--;
        }
    }

    public static void enterClause() {
        if (parseDepth > 0) {
            visits++;
            int c = ++curClause;
            if (c > maxClause) {
                maxClause = c;
            }
        }
    }

    public static void exitClause() {
        if (parseDepth > 0 && curClause > 0) {
            curClause--;
        }
    }

    public static void enterQuery() {
        if (parseDepth > 0) {
            visits++;
        }
    }

    public static int maxClauseDepth() {
        return maxClause;
    }

    public static long parserVisits() {
        return visits;
    }
}
