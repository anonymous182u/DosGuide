package org.opensearch.fuzz.agent;

import java.lang.instrument.Instrumentation;

/**
 * Custom measurement-only javaagent for V1 (not JQF's instrumentation agent).
 * Attach with: -javaagent:target/v1-agent.jar
 * The manifest (src/test/resources/v1-agent.mf) declares Premain-Class and Can-Retransform-Classes.
 */
public final class V1MeasureAgent {

    private V1MeasureAgent() {
    }

    public static void premain(String args, Instrumentation inst) {
        install(inst);
    }

    public static void agentmain(String args, Instrumentation inst) {
        install(inst);
    }

    private static void install(Instrumentation inst) {
        V1ParserTransformer transformer = new V1ParserTransformer();
        // Plain load-time transformer: the parser classes are loaded lazily during the first
        // fuzz execution, after premain, so they pass through transform() when they are defined.
        inst.addTransformer(transformer);
        String qp = V1ParserTransformer.QUERY_PARSER.replace('/', '.');
        String qs = V1ParserTransformer.QS_PARSER.replace('/', '.');
        for (Class<?> c : inst.getAllLoadedClasses()) {
            String n = c.getName();
            if (n.equals(qp) || n.equals(qs)) {
                System.err.println("[V1MeasureAgent] WARNING: " + n + " was loaded before premain and stays uninstrumented");
            }
        }
        System.err.println("[V1MeasureAgent] installed (targets: " + qp + "#Clause/#Query, " + qs + "#parse)");
    }
}
