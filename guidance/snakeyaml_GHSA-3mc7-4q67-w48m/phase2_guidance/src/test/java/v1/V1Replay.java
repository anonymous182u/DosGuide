package v1;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Replay utility for reproducing fuzz findings [R7].
 * Reads a saved corpus input file and replays it through Yaml.load().
 *
 * Usage: java v1.V1Replay <input-file> [input-file2 ...]
 */
public class V1Replay {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java v1.V1Replay <input-file> [input-file2 ...]");
            System.exit(1);
        }

        for (String filePath : args) {
            File f = new File(filePath);
            if (!f.exists()) {
                System.err.println("File not found: " + filePath);
                continue;
            }

            byte[] raw = Files.readAllBytes(f.toPath());
            String yamlStr = new String(raw, StandardCharsets.UTF_8);

            System.out.println("=== Replaying: " + filePath + " ===");
            System.out.println("  Size: " + raw.length + " bytes");
            System.out.println("  Input (first 200 chars): " +
                    yamlStr.substring(0, Math.min(200, yamlStr.length()))
                           .replace("\n", "\\n").replace("\r", "\\r"));

            // Hex dump (first 100 bytes)
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < Math.min(100, raw.length); i++) {
                hex.append(String.format("%02x ", raw[i] & 0xFF));
            }
            System.out.println("  Hex (first 100): " + hex);

            // Replay
            DepthCounters.reset();
            long startNs = System.nanoTime();
            try {
                Object result = new Yaml().load(yamlStr);
                long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
                System.out.println("  Result: SUCCESS (" + elapsedMs + " ms)");
                System.out.println("  Parsed type: " + (result == null ? "null" : result.getClass().getName()));
            } catch (YAMLException e) {
                long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
                System.out.println("  Result: YAMLException (" + elapsedMs + " ms)");
                System.out.println("  Message: " + e.getMessage());
            } catch (StackOverflowError e) {
                long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
                System.out.println("  Result: STACK_OVERFLOW (" + elapsedMs + " ms)");
                System.out.println("  *** V1 vulnerability triggered! ***");
            } catch (OutOfMemoryError e) {
                long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
                System.out.println("  Result: OUT_OF_MEMORY (" + elapsedMs + " ms)");
            } catch (Throwable t) {
                long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
                System.out.println("  Result: " + t.getClass().getName() + " (" + elapsedMs + " ms)");
                System.out.println("  Message: " + t.getMessage());
            }

            long maxDepth = DepthCounters.getMaxDepth();
            long nodeCount = DepthCounters.getNodeCount();
            System.out.println("  maxDepth: " + maxDepth);
            System.out.println("  nodeCount: " + nodeCount);
            System.out.println();
        }
    }
}
