package fuzzing.replay;

import fuzzing.agent.V1Counters;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Replays saved corpus entries against the Woodstox parser and reports
 * the measured recursion depth and any exceptions.
 *
 * Usage: java fuzzing.replay.V1Replay <corpus-file-or-directory>
 *
 * If a directory is given, all .bin files in it are replayed.
 * If a file is given, just that one file is replayed.
 *
 * For each input, prints:
 *   - Input file path
 *   - Input size (bytes)
 *   - Measured maxDepth (recursion depth of readContentSpec)
 *   - Result (SUCCESS / EXCEPTION with message)
 *   - First 200 chars of input as string (for inspection)
 */
public class V1Replay {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: V1Replay <corpus-file-or-directory>");
            System.exit(1);
        }

        File target = new File(args[0]);
        if (target.isDirectory()) {
            File[] files = target.listFiles((dir, name) -> name.endsWith(".bin"));
            if (files == null || files.length == 0) {
                System.err.println("No .bin files found in " + target);
                System.exit(1);
            }
            java.util.Arrays.sort(files);
            for (File f : files) {
                replayFile(f);
            }
        } else {
            replayFile(target);
        }
    }

    private static void replayFile(File file) {
        try {
            byte[] input = Files.readAllBytes(file.toPath());

            // Print metadata sidecar if it exists
            Path metaPath = file.toPath().resolveSibling(
                    file.getName().replace(".bin", ".meta.json"));
            if (Files.exists(metaPath)) {
                System.out.println("Metadata: " + Files.readString(metaPath));
            }

            // Reset counters and replay
            V1Counters.reset();

            String resultStr;
            Throwable caught = null;
            try {
                XMLInputFactory factory = new com.ctc.wstx.stax.WstxInputFactory();
                factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.TRUE);
                factory.setProperty(XMLInputFactory.IS_VALIDATING, Boolean.FALSE);

                InputStream is = new ByteArrayInputStream(input);
                XMLStreamReader reader = factory.createXMLStreamReader(is);
                while (reader.hasNext()) {
                    reader.next();
                }
                reader.close();
                resultStr = "SUCCESS";
            } catch (XMLStreamException e) {
                resultStr = "XMLStreamException: " + e.getMessage();
                caught = e;
            } catch (StackOverflowError e) {
                resultStr = "StackOverflowError";
                caught = e;
            } catch (Throwable t) {
                resultStr = t.getClass().getSimpleName() + ": " + t.getMessage();
                caught = t;
            }

            long maxDepth = V1Counters.getMaxDepth();

            // Show first 200 chars of input as string
            String preview = new String(input, 0, Math.min(input.length, 200));
            preview = preview.replace("\n", "\\n").replace("\r", "\\r");

            System.out.printf("File: %s | Size: %d bytes | maxDepth: %d | Result: %s%n",
                    file.getName(), input.length, maxDepth, resultStr);
            System.out.printf("  Preview: %s%n", preview);
            System.out.println();

        } catch (Exception e) {
            System.err.println("Error reading " + file + ": " + e.getMessage());
        }
    }
}
