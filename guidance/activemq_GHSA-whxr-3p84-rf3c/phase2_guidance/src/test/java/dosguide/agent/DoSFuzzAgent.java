package dosguide.agent;

import java.lang.instrument.Instrumentation;

/**
 * Java agent premain class for DoS fuzzing instrumentation.
 *
 * Registers the {@link DoSFuzzTransformer} which instruments:
 * - BaseDataStreamMarshaller.looseUnmarshalByteArray (V1: allocation size)
 * - BaseDataStreamMarshaller.looseUnmarsalThrowable  (V2: recursion depth)
 * - BaseDataStreamMarshaller.looseUnmarsalNestedObject (V3: nesting depth)
 *
 * Measurement-only: does not generate inputs or embed payloads.
 */
public class DoSFuzzAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.err.println("[DoSFuzzAgent] Installing DoS measurement transformer");
        inst.addTransformer(new DoSFuzzTransformer());
    }
}
