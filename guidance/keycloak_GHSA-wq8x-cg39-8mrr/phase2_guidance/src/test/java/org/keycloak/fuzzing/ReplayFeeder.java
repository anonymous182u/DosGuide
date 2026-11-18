package org.keycloak.fuzzing;

import org.keycloak.fuzzing.agent.RegexStepCounter;
import org.keycloak.utils.SearchQueryUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;

/**
 * Replays a saved corpus input through
 * {@link SearchQueryUtils#getFields(String)} and prints the measured
 * regex step count plus result metadata.
 * <p>
 * Requires the {@code -javaagent:target/v1-measure-agent.jar} flag so that
 * {@link RegexStepCounter} is active.
 * <p>
 * Usage: {@code java -javaagent:... ReplayFeeder <inputFile>}
 */
public class ReplayFeeder {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ReplayFeeder <inputFile>");
            System.exit(1);
        }

        File inputFile = new File(args[0]);
        byte[] raw = Files.readAllBytes(inputFile.toPath());
        String query = new String(raw, StandardCharsets.UTF_8);

        System.out.printf("Input file : %s%n", inputFile.getName());
        System.out.printf("Input bytes: %d%n", raw.length);
        System.out.printf("Input (hex): ");
        for (int i = 0; i < Math.min(raw.length, 64); i++) {
            System.out.printf("%02x ", raw[i]);
        }
        if (raw.length > 64) System.out.print("...");
        System.out.println();

        // Reset counter before execution.
        RegexStepCounter.getAndReset();

        long startNs = System.nanoTime();
        Map<String, String> result = SearchQueryUtils.getFields(query);
        long elapsedNs = System.nanoTime() - startNs;

        long steps = RegexStepCounter.get();

        System.out.printf("Elapsed    : %.3f ms%n", elapsedNs / 1_000_000.0);
        System.out.printf("Regex steps: %d%n", steps);
        System.out.printf("Fields     : %d%n", result.size());
        for (Map.Entry<String, String> e : result.entrySet()) {
            String key = e.getKey().length() > 40
                    ? e.getKey().substring(0, 40) + "..." : e.getKey();
            String val = e.getValue().length() > 40
                    ? e.getValue().substring(0, 40) + "..." : e.getValue();
            System.out.printf("  %s = %s%n", key, val);
        }
    }
}
