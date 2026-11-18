package com.fuzzer.replay;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.QuotedQualityCSV;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Replay runner for reproducing findings from corpus.
 * Reads a saved input file and its metadata, then replays it
 * deterministically through the original program under test ([R7]).
 *
 * Usage: java ... com.fuzzer.replay.ReplayRunner <inputFile> [metaFile]
 */
public class ReplayRunner {

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: ReplayRunner <inputFile> [metaFile]");
            System.exit(1);
        }

        Path inputPath = Paths.get(args[0]);
        byte[] inputBytes = Files.readAllBytes(inputPath);

        System.out.println("=== Replay Runner ===");
        System.out.println("Input file: " + inputPath);
        System.out.println("Input size: " + inputBytes.length + " bytes");

        // Read metadata if available
        if (args.length >= 2) {
            Path metaPath = Paths.get(args[1]);
            if (Files.exists(metaPath)) {
                String meta = Files.readString(metaPath);
                System.out.println("Metadata: " + meta);
            }
        } else {
            // Try to find .meta file alongside the input
            String metaName = inputPath.getFileName().toString().replace(".bin", ".meta");
            Path metaPath = inputPath.resolveSibling(metaName);
            if (Files.exists(metaPath)) {
                String meta = Files.readString(metaPath);
                System.out.println("Metadata: " + meta);
            }
        }

        // Decode as ISO-8859-1 (same as fuzz harness)
        String accept = new String(inputBytes, StandardCharsets.ISO_8859_1);
        System.out.println("Accept header value (first 200 chars): " +
                (accept.length() > 200 ? accept.substring(0, 200) + "..." : accept));

        // Count comma-separated values
        int valueCount = 1;
        for (int i = 0; i < accept.length(); i++) {
            if (accept.charAt(i) == ',') valueCount++;
        }
        System.out.println("Approximate CSV value count: " + valueCount);

        // Replay the exact execution path
        System.out.println("\n--- Replaying execution ---");
        long startNs = System.nanoTime();

        try {
            HttpFields fields = new HttpFields();
            fields.add(HttpHeader.ACCEPT, accept);
            List<String> result = fields.getQualityCSV(HttpHeader.ACCEPT,
                    QuotedQualityCSV.MOST_SPECIFIC_MIME_ORDERING);

            long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
            System.out.println("Execution completed in " + elapsedMs + " ms");
            System.out.println("Sorted values count: " + result.size());
            if (!result.isEmpty()) {
                System.out.println("First value: " + result.get(0));
                System.out.println("Last value: " + result.get(result.size() - 1));
            }
        } catch (Throwable t) {
            long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
            System.out.println("Execution threw " + t.getClass().getName() +
                    " after " + elapsedMs + " ms");
            System.out.println("Message: " + t.getMessage());
            t.printStackTrace();
        }
    }
}
