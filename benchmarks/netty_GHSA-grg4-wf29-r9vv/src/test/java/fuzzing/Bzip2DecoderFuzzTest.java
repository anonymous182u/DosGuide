package fuzzing;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.compression.Bzip2Decoder;
import io.netty.handler.codec.compression.DecompressionException;
import io.netty.util.ReferenceCountUtil;

import java.io.IOException;
import java.io.InputStream;

/**
 * JQF fuzz test for Netty's {@link Bzip2Decoder}.
 *
 * <p>Each execution reads the raw input bytes, builds a channel pipeline with a default
 * {@code Bzip2Decoder} followed by an application handler that consumes and releases every
 * decompressed buffer it receives, writes the bytes inbound and then closes the channel.</p>
 *
 * <p>{@link DecompressionException} is how the decoder rejects malformed input, so it is a
 * normal result. Anything else the library throws is a failure.</p>
 */
@RunWith(JQF.class)
public class Bzip2DecoderFuzzTest {

    /**
     * Bzip2Decoder.decode on the inbound path of a channel pipeline.
     */
    @Fuzz
    public void fuzzBzip2DecoderDecode(InputStream data) throws IOException, DecompressionException {
        decodeAll(data.readAllBytes());
    }

    /**
     * Bzip2Decoder.decode on the inbound path of a channel pipeline (the same calls as
     * {@link #fuzzBzip2DecoderDecode}).
     */
    @Fuzz
    public void fuzzBzip2DecoderDecode2(InputStream data) throws IOException, DecompressionException {
        decodeAll(data.readAllBytes());
    }

    private static void decodeAll(byte[] input) {
        EmbeddedChannel channel = new EmbeddedChannel(new Bzip2Decoder(), new ConsumingHandler());
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
