package org.xnio.fuzz;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import org.xnio.fuzz.agent.RecursionCounters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.function.Consumer;

/**
 * Replays a single saved input against a chosen fuzz target, printing the
 * result and measured recursion depth.
 *
 * Usage:  java ... ReplayRunner <targetId> <inputFile>
 */
public final class ReplayRunner {

    private ReplayRunner() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <targetId> <inputFile>");
            System.exit(1);
        }

        String targetId = args[0];
        File inputFile = new File(args[1]);

        if (!inputFile.exists()) {
            System.err.println("Input file not found: " + inputFile);
            System.exit(1);
        }

        byte[] inputData = Files.readAllBytes(inputFile.toPath());
        System.out.printf("[ReplayRunner] target=%s input=%s size=%d bytes%n",
                targetId, inputFile.getName(), inputData.length);

        // Print class origin check
        try {
            Class<?> aif = Class.forName("org.xnio.AbstractIoFuture");
            System.out.println("[ReplayRunner] AbstractIoFuture loaded from: "
                    + aif.getProtectionDomain().getCodeSource().getLocation());
        } catch (Exception e) {
            System.err.println("[ReplayRunner] WARNING: Could not determine origin: " + e);
        }

        String testMethod;
        switch (targetId) {
            case "V1":
                testMethod = "fuzzIoFutureAddNotifier";
                break;
            case "V2":
                testMethod = "fuzzFutureResultAddCancelHandler";
                break;
            default:
                System.err.println("Unknown target: " + targetId);
                System.exit(1);
                return;
        }

        // Single-shot guidance that replays the input exactly once
        Guidance replay = new Guidance() {
            private boolean done = false;

            @Override
            public boolean hasInput() {
                return !done;
            }

            @Override
            public InputStream getInput() {
                RecursionCounters.resetNotify();
                RecursionCounters.resetCancel();
                return new ByteArrayInputStream(inputData);
            }

            @Override
            public void handleResult(Result result, Throwable error) {
                done = true;
                long notifyDepth = RecursionCounters.getNotifyMaxDepth();
                long cancelDepth = RecursionCounters.getCancelMaxDepth();

                System.out.printf("[ReplayRunner] result=%s notifyDepth=%d cancelDepth=%d%n",
                        result, notifyDepth, cancelDepth);
                if (error != null) {
                    System.out.printf("[ReplayRunner] error=%s: %s%n",
                            error.getClass().getName(), error.getMessage());
                }
            }

            @Override
            public Consumer<TraceEvent> generateCallBack(Thread thread) {
                return (event) -> {};
            }
        };

        GuidedFuzzing.run("org.xnio.fuzz.XnioFuzzTest", testMethod, replay, System.out);
        System.out.println("[ReplayRunner] Done.");
    }
}
