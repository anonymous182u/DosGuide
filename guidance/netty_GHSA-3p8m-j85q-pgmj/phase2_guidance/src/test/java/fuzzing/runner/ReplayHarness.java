package fuzzing.runner;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.compression.Brotli;
import io.netty.handler.codec.compression.BrotliDecoder;
import io.netty.handler.codec.compression.Zstd;
import io.netty.handler.codec.compression.ZstdDecoder;
import io.netty.util.ReferenceCountUtil;
import fuzzing.agent.DecompressCounters;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * Replay harness that loads a saved fuzz input and replays it through the decoder,
 * printing metadata about the execution (input size, decompressed bytes, outcome).
 *
 * <p>Usage: {@code java fuzzing.runner.ReplayHarness <V1|V2> <input-file>}</p>
 */
public class ReplayHarness {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ReplayHarness <V1|V2> <input-file>");
            System.exit(1);
        }

        String targetId = args[0].toUpperCase();
        File inputFile = new File(args[1]);
        byte[] input = Files.readAllBytes(inputFile.toPath());

        System.out.printf("=== Replay: %s ===%n", targetId);
        System.out.printf("Input file : %s%n", inputFile.getAbsolutePath());
        System.out.printf("Input bytes: %d%n", input.length);

        DecompressCounters.reset();
        long startNs = System.nanoTime();
        String outcome;

        try {
            switch (targetId) {
                case "V1":
                    if (!Brotli.isAvailable()) {
                        System.out.println("Brotli native library not available.");
                        return;
                    }
                    replayBrotli(input);
                    break;
                case "V2":
                    if (!Zstd.isAvailable()) {
                        System.out.println("Zstd native library not available.");
                        return;
                    }
                    replayZstd(input);
                    break;
                default:
                    System.err.println("Unknown target: " + targetId);
                    System.exit(1);
                    return;
            }
            outcome = "completed";
        } catch (Throwable t) {
            outcome = t.getClass().getSimpleName() + ": " + t.getMessage();
        }

        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
        long brotliBytes = DecompressCounters.getBrotliBytes();
        long zstdBytes = DecompressCounters.getZstdBytes();

        System.out.printf("Outcome    : %s%n", outcome);
        System.out.printf("Elapsed    : %d ms%n", elapsedMs);
        System.out.printf("Brotli decompressed bytes: %d%n", brotliBytes);
        System.out.printf("Zstd decompressed bytes  : %d%n", zstdBytes);
        double expansionRatio = input.length > 0
                ? (double) Math.max(brotliBytes, zstdBytes) / input.length
                : 0;
        System.out.printf("Expansion ratio: %.2f%n", expansionRatio);
    }

    private static void replayBrotli(byte[] input) {
        EmbeddedChannel channel = new EmbeddedChannel(new BrotliDecoder(), new ConsumingHandler());
        channel.writeInbound(Unpooled.wrappedBuffer(input));
        channel.finishAndReleaseAll();
    }

    private static void replayZstd(byte[] input) {
        EmbeddedChannel channel = new EmbeddedChannel(new ZstdDecoder(), new ConsumingHandler());
        channel.writeInbound(Unpooled.wrappedBuffer(input));
        channel.finishAndReleaseAll();
    }

    private static final class ConsumingHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ReferenceCountUtil.release(msg);
        }
    }
}
