package com.fuzzing.replay;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.fuzzing.httpheaders.HttpHeadersFuzzTest;

/**
 * Replay runner: loads a saved corpus input file and replays it through the
 * fuzz test, printing diagnostics (input bytes, ISO-8859-1 string, timing,
 * regex steps, exceptions).
 *
 * Usage: java ... ReplayRunner <inputFile> [targetId]
 *   targetId defaults to V1.
 */
public final class ReplayRunner {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ReplayRunner <inputFile> [targetId]");
            System.exit(1);
        }

        Path inputPath = Paths.get(args[0]);
        String targetId = args.length >= 2 ? args[1] : "V1";

        byte[] inputBytes = Files.readAllBytes(inputPath);
        String inputStr = new String(inputBytes, StandardCharsets.ISO_8859_1);

        System.out.println("=== Replay: " + inputPath.getFileName() + " ===");
        System.out.println("Target:       " + targetId);
        System.out.println("Input length: " + inputBytes.length + " bytes");
        System.out.println("Input (first 200 chars): "
                + inputStr.substring(0, Math.min(200, inputStr.length()))
                        .replace("\n", "\\n").replace("\r", "\\r")
                        .replace("\t", "\\t"));

        // Print hex dump (first 100 bytes)
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < Math.min(100, inputBytes.length); i++) {
            hex.append(String.format("%02x ", inputBytes[i] & 0xFF));
        }
        System.out.println("Hex (first 100): " + hex.toString().trim());

        // Reset agent counter if available
        try {
            Class<?> counters = Class.forName(
                    "com.fuzzing.agent.V1Counters", true, null);
            counters.getMethod("reset").invoke(null);
        } catch (ClassNotFoundException e) {
            System.out.println("(Agent not loaded — step count unavailable)");
        }

        // Execute
        long startNs = System.nanoTime();
        Throwable caught = null;
        try {
            HttpHeadersFuzzTest test = new HttpHeadersFuzzTest();
            InputStream is = new ByteArrayInputStream(inputBytes);
            switch (targetId) {
                case "V1" -> test.fuzzHttpHeadersGetIfNoneMatch(is);
                default -> throw new IllegalArgumentException(
                        "Unknown target: " + targetId);
            }
        } catch (Throwable t) {
            caught = t;
        }
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

        // Read step count
        long steps = 0;
        try {
            Class<?> counters = Class.forName(
                    "com.fuzzing.agent.V1Counters", true, null);
            steps = (long) counters.getMethod("getStepCount").invoke(null);
        } catch (ClassNotFoundException e) {
            // ignore
        }

        System.out.println("Wall time:    " + elapsedMs + " ms");
        System.out.println("Regex steps:  " + steps);
        if (caught != null) {
            System.out.println("Exception:    " + caught.getClass().getName()
                    + ": " + caught.getMessage());
        } else {
            System.out.println("Result:       OK (no exception)");
        }
        System.out.println("=== End Replay ===");
    }

    private ReplayRunner() { }
}
