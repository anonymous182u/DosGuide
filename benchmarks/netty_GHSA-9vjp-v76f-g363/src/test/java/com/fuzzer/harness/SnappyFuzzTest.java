package com.fuzzer.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.compression.DecompressionException;
import io.netty.handler.codec.compression.Snappy;
import io.netty.handler.codec.compression.SnappyFrameDecoder;
import io.netty.util.ReferenceCountUtil;

import java.io.IOException;
import java.io.InputStream;

/**
 * JQF fuzz test for Netty's Snappy decompression.
 *
 * <p>{@link DecompressionException} is how the Snappy code rejects malformed input, so it is a
 * normal result. Anything else the library throws is a failure.</p>
 */
@RunWith(JQF.class)
public class SnappyFuzzTest {

    /**
     * Snappy decompression on the inbound path of a channel pipeline. The input bytes
     * are written to an {@link EmbeddedChannel} holding a default {@link SnappyFrameDecoder}
     * (which calls {@code Snappy.decode} for each compressed chunk); the decoded messages are then
     * read from the channel and released, and the channel is closed.
     */
    @Fuzz
    public void fuzzSnappyFrameDecoderDecode(InputStream input) throws IOException, DecompressionException {
        byte[] data = input.readAllBytes();

        EmbeddedChannel channel = new EmbeddedChannel(new SnappyFrameDecoder());
        try {
            channel.writeInbound(Unpooled.wrappedBuffer(data));
            Object msg;
            while ((msg = channel.readInbound()) != null) {
                ReferenceCountUtil.release(msg);
            }
            channel.finish();
        } finally {
            channel.releaseInbound();
            channel.releaseOutbound();
        }
    }

    /**
     * {@code Snappy.decode(ByteBuf, ByteBuf)} called directly on the input bytes, with an
     * output buffer of default capacity limits.
     */
    @Fuzz
    public void fuzzSnappyDecode(InputStream input) throws IOException, DecompressionException {
        byte[] data = input.readAllBytes();

        Snappy snappy = new Snappy();
        ByteBuf in = Unpooled.wrappedBuffer(data);
        ByteBuf out = Unpooled.buffer();
        try {
            snappy.decode(in, out);
        } finally {
            in.release();
            out.release();
        }
    }
}
