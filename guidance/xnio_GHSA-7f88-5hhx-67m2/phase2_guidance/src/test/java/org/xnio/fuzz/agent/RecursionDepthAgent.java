package org.xnio.fuzz.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent that measures recursion depth in AbstractIoFuture's state-chain
 * traversal methods.  Measurement-only — does not generate inputs or embed
 * exploit payloads [R37].
 *
 * Instruments:
 *   AbstractIoFuture$NotifierState.notifyDone   → RecursionCounters.NOTIFY_DEPTH
 *   AbstractIoFuture$CancellableState.cancel     → RecursionCounters.CANCEL_DEPTH
 */
public final class RecursionDepthAgent {

    private RecursionDepthAgent() {}

    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer(new RecursionTransformer(), false);
    }
}
