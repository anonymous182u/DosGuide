package org.elasticsearch.compute.data.fuzz.replay;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Replays a saved binary input file from the fuzzer and reports metadata
 * about the input and the execution result.
 *
 * <p>Usage: {@code java ... ReplayRunner <inputFile>}
 *
 * <p>Reads the 8-byte input format (4 bytes numAppends + 4 bytes estimatedSize),
 * computes the true allocation size using long arithmetic, shows the overflowed
 * int product, and optionally executes the test method to demonstrate the crash.
 */
public class ReplayRunner {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ReplayRunner <inputFile> [V1|V2]");
            System.err.println("  inputFile: path to an 8-byte binary input file");
            System.err.println("  V1|V2:     target (default: V1). V1=IntBlockBuilder(elem=4), V2=LongBlockBuilder(elem=8)");
            System.exit(1);
        }

        File inputFile = new File(args[0]);
        String targetId = (args.length >= 2) ? args[1] : "V1";
        int elemSize = targetId.equals("V2") ? 8 : 4;

        byte[] rawBytes = readFile(inputFile);
        if (rawBytes.length < 8) {
            System.err.println("ERROR: Input file must be at least 8 bytes, got " + rawBytes.length);
            System.exit(1);
        }

        ByteBuffer buf = ByteBuffer.wrap(rawBytes);
        int numAppendsRaw = buf.getInt();
        int numAppends = numAppendsRaw & Integer.MAX_VALUE;
        int estimatedSize = buf.getInt();

        // True allocation: long arithmetic (what the application SHOULD compute)
        long trueAllocBytes = (long) estimatedSize * elemSize;
        // Overflowed product: int arithmetic (what the vulnerable code computes)
        int overflowedProduct = estimatedSize * elemSize;

        System.out.println("=== Replay Metadata ===");
        System.out.printf("Input file:         %s (%d bytes)%n", inputFile.getName(), rawBytes.length);
        System.out.printf("Target:             %s (elemSize=%d)%n", targetId, elemSize);
        System.out.printf("numAppends (raw):   0x%08X (%d)%n", numAppendsRaw, numAppendsRaw);
        System.out.printf("numAppends (masked): %d%n", numAppends);
        System.out.printf("estimatedSize:      0x%08X (%d)%n", estimatedSize, estimatedSize);
        System.out.println();
        System.out.printf("True allocation:    %d bytes (long: %d * %d)%n",
                trueAllocBytes, (long) estimatedSize, elemSize);
        System.out.printf("Overflowed product: %d (int: %d * %d)%n",
                overflowedProduct, estimatedSize, elemSize);
        System.out.println();

        // Analyze the vulnerability condition
        boolean overflows = (trueAllocBytes != overflowedProduct);
        boolean circuitBreakerRegion;
        if (elemSize == 4) {
            // V1: breaker trips for estimatedSize roughly 153M-536M (REQUEST breaker = 60% of 1GB ≈ 614MB)
            circuitBreakerRegion = estimatedSize > 0 && (long) estimatedSize * elemSize > 600_000_000L
                    && (long) estimatedSize * elemSize < (long) Integer.MAX_VALUE * elemSize;
        } else {
            // V2: breaker trips for smaller estimatedSize due to larger elemSize
            circuitBreakerRegion = estimatedSize > 0 && (long) estimatedSize * elemSize > 600_000_000L
                    && (long) estimatedSize * elemSize < (long) Integer.MAX_VALUE * elemSize;
        }

        System.out.printf("Integer overflow:   %s%n", overflows ? "YES — bypass!" : "no");
        if (overflows) {
            System.out.printf("  The int product %d is %s, so the circuit breaker %s it.%n",
                    overflowedProduct,
                    overflowedProduct <= 0 ? "non-positive" : "small",
                    overflowedProduct <= 0 ? "cannot track" : "underestimates");
            System.out.printf("  But the JVM tries to allocate %d bytes → OOM if heap < %d bytes.%n",
                    trueAllocBytes, trueAllocBytes);
        }

        System.out.println();
        System.out.println("=== Hex Dump ===");
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < Math.min(rawBytes.length, 64); i++) {
            hex.append(String.format("%02X ", rawBytes[i]));
            if ((i + 1) % 16 == 0) hex.append("\n");
        }
        System.out.println(hex.toString().trim());
    }

    private static byte[] readFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.readAllBytes();
        }
    }
}
