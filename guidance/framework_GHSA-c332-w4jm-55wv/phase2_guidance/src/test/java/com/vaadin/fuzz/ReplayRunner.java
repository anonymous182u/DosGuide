package com.vaadin.fuzz;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.vaadin.data.ValueContext;

/**
 * Replay runner for deterministic reproduction of saved corpus inputs.
 *
 * Usage:
 *   java ... com.vaadin.fuzz.ReplayRunner V1 path/to/input.bin
 *   java ... com.vaadin.fuzz.ReplayRunner V2 path/to/input.bin
 *
 * Reads the binary input file, decodes it as UTF-8, runs the appropriate
 * validator, and prints the result with timing information.
 *
 * Also loads any .meta file alongside the input for step-count context.
 */
public final class ReplayRunner {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayRunner <V1|V2> <input-file>");
            System.exit(1);
        }

        String targetId = args[0];
        String inputPath = args[1];

        byte[] inputBytes = Files.readAllBytes(Paths.get(inputPath));
        String value = new String(inputBytes, StandardCharsets.UTF_8);

        System.out.printf("=== Replay ===%n");
        System.out.printf("Target:       %s%n", targetId);
        System.out.printf("Input file:   %s%n", inputPath);
        System.out.printf("Input length: %d bytes%n", inputBytes.length);
        System.out.printf("Input string: %.200s%s%n", value,
                value.length() > 200 ? "... [truncated]" : "");

        // Print metadata if available
        String metaPath = inputPath.replaceAll("\\.bin$", ".meta");
        File metaFile = new File(metaPath);
        if (metaFile.exists()) {
            System.out.printf("Metadata:%n%s", Files.readString(metaFile.toPath()));
        }

        long startNs = System.nanoTime();

        switch (targetId) {
            case "V1": {
                com.vaadin.v7.data.validator.EmailValidator validator =
                        new com.vaadin.v7.data.validator.EmailValidator("invalid email");
                boolean valid = validator.isValid(value);
                long elapsedNs = System.nanoTime() - startNs;
                System.out.printf("Valid:   %s%n", valid);
                System.out.printf("Elapsed: %.3f ms%n", elapsedNs / 1_000_000.0);
                break;
            }
            case "V2": {
                com.vaadin.data.validator.EmailValidator validator =
                        new com.vaadin.data.validator.EmailValidator("invalid email");
                com.vaadin.data.ValidationResult result = validator.apply(value, new ValueContext());
                long elapsedNs = System.nanoTime() - startNs;
                System.out.printf("Error:   %s%n", result.isError());
                System.out.printf("Elapsed: %.3f ms%n", elapsedNs / 1_000_000.0);
                break;
            }
            default:
                System.err.println("Unknown target: " + targetId);
                System.exit(1);
        }
    }
}
