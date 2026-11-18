package replay;

import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Replay harness: load saved inputs and replay them through MessageUnpacker.
 * Usage: java replay.MetadataReplay <inputDir|inputFile> [maxInputs]
 *
 * Prints per-input results: file name, input size, outcome (success/exception type).
 */
public class MetadataReplay {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: MetadataReplay <inputDir|inputFile> [maxInputs]");
            System.exit(1);
        }

        Path inputPath = Paths.get(args[0]);
        int maxInputs = args.length >= 2 ? Integer.parseInt(args[1]) : Integer.MAX_VALUE;

        if (Files.isDirectory(inputPath)) {
            File[] files = inputPath.toFile().listFiles((dir, name) -> name.endsWith(".bin"));
            if (files == null || files.length == 0) {
                System.err.println("No .bin files found in: " + inputPath);
                return;
            }
            Arrays.sort(files);
            int count = 0;
            for (File f : files) {
                if (count >= maxInputs) break;
                replayFile(f.toPath());
                count++;
            }
            System.out.printf("Replayed %d inputs.%n", count);
        } else {
            replayFile(inputPath);
        }
    }

    private static void replayFile(Path file) {
        try {
            byte[] data = Files.readAllBytes(file);
            System.out.printf("File: %s, size=%d bytes -> ", file.getFileName(), data.length);

            try (MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(data)) {
                while (unpacker.hasNext()) {
                    unpacker.unpackValue();
                }
                System.out.println("OK (parsed successfully)");
            } catch (Exception e) {
                System.out.printf("EXCEPTION: %s: %s%n", e.getClass().getSimpleName(), e.getMessage());
            }
        } catch (IOException e) {
            System.out.printf("File: %s -> IO_ERROR: %s%n", file.getFileName(), e.getMessage());
        }
    }
}
