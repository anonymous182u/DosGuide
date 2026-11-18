package fuzzing.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.compression.Brotli;
import io.netty.handler.codec.compression.BrotliDecoder;
import io.netty.handler.codec.compression.DecompressionException;
import io.netty.handler.codec.compression.Zstd;
import io.netty.handler.codec.compression.ZstdDecoder;
import io.netty.util.ReferenceCountUtil;
import org.junit.Assume;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;

/**
 * JQF fuzz test for Netty's decompressing decoders in netty-codec-compression.
 *
 * <p>Each execution reads the raw input bytes, builds a channel pipeline with a decoder in its
 * default configuration followed by an application handler that consumes and releases every
 * decompressed buffer it receives, writes the bytes inbound and then closes the channel.</p>
 *
 * <p>{@link DecompressionException} is how the decoders reject malformed input, so it is a normal
 * result. Anything else the library throws is a failure. An execution is skipped (not run) if the
 * decoder's native library cannot be loaded on this platform.</p>
 */
@RunWith(JQF.class)
public class DecompressionFuzzTest {

    /**
     * BrotliDecoder.decode on the inbound path of a channel pipeline.
     */
    @Fuzz
    public void fuzzBrotliDecoderDecode(InputStream data) throws IOException, DecompressionException {
        Assume.assumeTrue(Brotli.isAvailable());
        decodeAll(new BrotliDecoder(), data.readAllBytes());
    }

    /**
     * ZstdDecoder.decode on the inbound path of a channel pipeline.
     */
    @Fuzz
    public void fuzzZstdDecoderDecode(InputStream data) throws IOException, DecompressionException {
        Assume.assumeTrue(Zstd.isAvailable());
        decodeAll(new ZstdDecoder(), data.readAllBytes());
    }

    /**
     * BrotliDecoder.decode on the inbound path of a channel pipeline (the same calls as
     * {@link #fuzzBrotliDecoderDecode}).
     */
    @Fuzz
    public void fuzzBrotliDecoderDecode2(InputStream data) throws IOException, DecompressionException {
        Assume.assumeTrue(Brotli.isAvailable());
        decodeAll(new BrotliDecoder(), data.readAllBytes());
    }

    private static void decodeAll(ChannelHandler decoder, byte[] input) {
        EmbeddedChannel channel = new EmbeddedChannel(decoder, new ConsumingHandler());
        channel.writeInbound(Unpooled.wrappedBuffer(input));
        channel.finishAndReleaseAll();
    }

    /**
     * Application handler behind the decoder: consumes each decompressed message and releases it,
     * as a server that processes the data would.
     */
    private static final class ConsumingHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ReferenceCountUtil.release(msg);
        }
    }
}
