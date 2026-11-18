package com.fuzzer.replay;

import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.compression.DecompressionException;
import io.netty.handler.codec.compression.SnappyFrameDecoder;
import io.netty.util.ReferenceCountUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HexFormat;
import java.util.stream.Stream;

/**
 * Replay harness for saved corpus/failure inputs.
 *
 * <p>Usage: {@code java ... com.fuzzer.replay.ReplayRunner <inputFile|corpusDir>}</p>
 *
 * <p>Reads each input file and replays it through a fresh
 * {@link SnappyFrameDecoder} pipeline, printing hex dump, size,
 * outcome, and any exceptions.</p>
 */
public class ReplayRunner {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ReplayRunner <inputFile|corpusDir>");
            System.exit(1);
        }

        Path path = Paths.get(args[0]);
        if (Files.isDirectory(path)) {
            try (Stream<Path> files = Files.list(path)) {
                files.filter(Files::isRegularFile).sorted().forEach(f -> {
                    try {
                        replay(f);
                    } catch (Exception e) {
                        System.err.println("Error replaying " + f + ": " + e);
                    }
                });
            }
        } else {
            replay(path);
        }
    }

    private static void replay(Path file) throws IOException {
        byte[] data = Files.readAllBytes(file);
        System.out.printf("=== Replaying: %s (%d bytes) ===%n", file.getFileName(), data.length);

        // Print hex dump (first 128 bytes)
        int hexLen = Math.min(data.length, 128);
        System.out.printf("Hex: %s%s%n",
                HexFormat.of().formatHex(data, 0, hexLen),
                hexLen < data.length ? "..." : "");

        // Replay through SnappyFrameDecoder
        EmbeddedChannel channel = new EmbeddedChannel(new SnappyFrameDecoder());
        try {
            channel.writeInbound(Unpooled.wrappedBuffer(data));
            Object msg;
            int msgCount = 0;
            while ((msg = channel.readInbound()) != null) {
                msgCount++;
                ReferenceCountUtil.release(msg);
            }
            channel.finish();
            System.out.printf("Result: SUCCESS (%d messages decoded)%n", msgCount);
        } catch (DecompressionException e) {
            System.out.printf("Result: DecompressionException: %s%n", e.getMessage());
        } catch (OutOfMemoryError e) {
            System.out.printf("Result: OutOfMemoryError: %s%n", e.getMessage());
        } catch (Throwable t) {
            System.out.printf("Result: %s: %s%n", t.getClass().getSimpleName(), t.getMessage());
        } finally {
            try {
                channel.releaseInbound();
                channel.releaseOutbound();
            } catch (Throwable ignored) { }
        }
        System.out.println();
    }
}
