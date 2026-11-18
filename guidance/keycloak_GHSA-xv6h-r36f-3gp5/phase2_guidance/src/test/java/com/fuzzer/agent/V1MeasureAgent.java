package com.fuzzer.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent premain entry point for V1 (CWE-409 deflate decompression bomb).
 * Registers V1DeflateUtilTransformer to instrument
 * org.keycloak.saml.processing.api.util.DeflateUtil.decode(byte[]).
 *
 * Measurement only — does not generate inputs or embed payloads [R37].
 */
public final class V1MeasureAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new V1DeflateUtilTransformer(), false);
        System.err.println("[V1Agent] Registered DeflateUtil.decode transformer");
    }
}
