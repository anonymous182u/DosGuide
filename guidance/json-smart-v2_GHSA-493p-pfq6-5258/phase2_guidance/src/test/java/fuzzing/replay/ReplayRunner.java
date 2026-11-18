package fuzzing.replay;

import fuzzing.agent.DepthCounters;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Replays a saved corpus input through the json-smart parser, printing
 * measured signals and any exception. Supports metadata replay ([R7]).
 *
 * Usage: ReplayRunner <input.bin> [permissive|rfc4627]
 */
public class ReplayRunner {

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: ReplayRunner <input.bin> [permissive|rfc4627]");
            System.exit(1);
        }

        Path inputPath = Path.of(args[0]);
        String mode = (args.length >= 2) ? args[1] : "permissive";

        byte[] rawBytes = Files.readAllBytes(inputPath);
        String inputStr = new String(rawBytes, StandardCharsets.UTF_8);

        // Print metadata if available
        Path metaPath = Path.of(args[0].replaceAll("\\.bin$", ".meta"));
        if (Files.exists(metaPath)) {
            System.out.println("[Replay] Metadata: " + Files.readString(metaPath));
        }

        System.out.printf("[Replay] Input file: %s (%d bytes)%n", inputPath, rawBytes.length);
        System.out.printf("[Replay] Input (truncated): %.200s%n", inputStr);
        System.out.printf("[Replay] Parser mode: %s%n", mode);

        int parserMode = "rfc4627".equalsIgnoreCase(mode)
                ? JSONParser.MODE_RFC4627
                : JSONParser.MODE_PERMISSIVE;

        // Reset and parse
        DepthCounters.reset();
        JSONParser parser = new JSONParser(parserMode);

        try {
            Object result = parser.parse(inputStr);
            System.out.println("[Replay] Parse result type: " + (result == null ? "null" : result.getClass().getSimpleName()));
        } catch (ParseException e) {
            System.out.println("[Replay] ParseException: " + e.getMessage());
        } catch (StackOverflowError e) {
            System.out.println("[Replay] StackOverflowError!");
        } catch (Throwable t) {
            System.out.println("[Replay] Exception: " + t.getClass().getName() + ": " + t.getMessage());
        }

        System.out.printf("[Replay] Signals: maxDepth=%d, nodeCount=%d%n",
                DepthCounters.getMaxDepth(), DepthCounters.getNodeCount());
    }
}
