package com.fuzzing.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.*;
import java.nio.file.*;
import java.util.function.Consumer;

/**
 * Replays a single saved input file through the fuzz harness and prints
 * the agent-measured signal values.
 *
 * Usage:  java ... ReplayRunner &lt;input_file&gt;
 */
public class ReplayRunner {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ReplayRunner <input_file>");
            System.exit(1);
        }

        final byte[] input = Files.readAllBytes(Path.of(args[0]));
        System.out.printf("[ReplayRunner] Replaying %s (%d bytes)%n", args[0], input.length);

        // Retrieve the agent counters
        Object obj = System.getProperties().get("V1_COUNTERS");
        final long[] counters;
        if (obj instanceof long[]) {
            counters = (long[]) obj;
        } else {
            counters = new long[2];
            System.err.println("[ReplayRunner] WARNING: V1_COUNTERS not found — agent may not be loaded");
        }

        Guidance replay = new Guidance() {
            private boolean done = false;

            @Override
            public InputStream getInput() throws IllegalStateException, GuidanceException {
                counters[0] = 0;
                counters[1] = 0;
                return new ByteArrayInputStream(input);
            }

            @Override
            public boolean hasInput() {
                return !done;
            }

            @Override
            public void handleResult(Result result, Throwable error) throws GuidanceException {
                done = true;
                System.out.printf("[ReplayRunner] Result:              %s%n", result);
                System.out.printf("[ReplayRunner] htmlCallCount:       %d%n", counters[0]);
                System.out.printf("[ReplayRunner] totalAllocatedChars: %d%n", counters[1]);
                if (error != null) {
                    System.out.println("[ReplayRunner] Error:");
                    error.printStackTrace(System.out);
                }
            }

            @Override
            public Consumer<TraceEvent> generateCallBack(Thread thread) {
                return e -> {};
            }
        };

        GuidedFuzzing.run(
                "com.fuzzing.harness.SanitizerFuzzTest",
                "fuzzHtmlErrorResponseBodyProviderBody",
                Thread.currentThread().getContextClassLoader(),
                replay, System.out);

        System.out.println("[ReplayRunner] Done.");
    }
}
