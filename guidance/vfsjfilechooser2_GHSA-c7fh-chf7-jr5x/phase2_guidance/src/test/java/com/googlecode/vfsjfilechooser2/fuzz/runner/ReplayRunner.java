package com.googlecode.vfsjfilechooser2.fuzz.runner;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import regexmeasure.RegexStepCounter;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.function.Consumer;

/**
 * Deterministic replay of a saved fuzz input.
 *
 * <p>Usage: {@code java -javaagent:target/v1-agent.jar --add-opens java.base/java.util.regex=ALL-UNNAMED
 *   -cp <classpath> com.googlecode.vfsjfilechooser2.fuzz.runner.ReplayRunner <inputFile> [testClass] [testMethod]}
 *
 * <p>Prints input metadata, regex step count and wall-clock time.
 */
public class ReplayRunner {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ReplayRunner <inputFile> [testClass] [testMethod]");
            System.exit(1);
        }

        File inputFile = new File(args[0]);
        String testClass = args.length > 1 ? args[1]
                : "com.googlecode.vfsjfilechooser2.fuzz.harness.VFSURIValidatorFuzzTest";
        String testMethod = args.length > 2 ? args[2]
                : "fuzzVFSURIValidatorIsValid";

        final byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

        System.out.println("=== Replay ===");
        System.out.println("Input file:   " + inputFile.getAbsolutePath());
        System.out.println("Input size:   " + inputBytes.length + " bytes");
        System.out.println("Test class:   " + testClass);
        System.out.println("Test method:  " + testMethod);

        // Show preview as ISO-8859-1 (first 200 chars)
        String preview = new String(inputBytes, StandardCharsets.ISO_8859_1);
        if (preview.length() > 200) {
            preview = preview.substring(0, 200) + "...";
        }
        System.out.println("Input preview: " + preview);

        // One-shot replay guidance
        Guidance replayGuidance = new Guidance() {
            private boolean used = false;

            @Override
            public InputStream getInput() throws IllegalStateException, GuidanceException {
                RegexStepCounter.reset();
                return new ByteArrayInputStream(inputBytes);
            }

            @Override
            public boolean hasInput() {
                return !used;
            }

            @Override
            public void handleResult(Result result, Throwable error)
                    throws GuidanceException {
                used = true;
                long steps = RegexStepCounter.get();
                System.out.println("=== Result ===");
                System.out.println("Outcome:      " + result);
                System.out.println("Regex steps:  " + steps);
                if (error != null) {
                    System.out.println("Error:        " + error.getClass().getName()
                            + ": " + error.getMessage());
                }
            }

            @Override
            public Consumer<TraceEvent> generateCallBack(Thread thread) {
                return new Consumer<TraceEvent>() {
                    @Override
                    public void accept(TraceEvent e) {
                        // intentionally empty
                    }
                };
            }
        };

        long startNs = System.nanoTime();
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        GuidedFuzzing.run(testClass, testMethod, cl, replayGuidance, System.err);
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

        System.out.println("Wall time:    " + elapsedMs + " ms");
    }
}
