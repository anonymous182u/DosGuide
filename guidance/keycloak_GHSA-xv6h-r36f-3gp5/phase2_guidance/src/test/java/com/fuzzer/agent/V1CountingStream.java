package com.fuzzer.agent;

import java.io.FilterInputStream;
import java.io.InputStream;
import java.io.IOException;

/**
 * FilterInputStream wrapper that counts every byte read and reports to V1Counters.
 * Injected by the agent: DeflateUtil.decode() returns V1CountingStream.wrap(inflaterInputStream)
 * instead of the raw InflaterInputStream.
 *
 * No ASM dependency — compiled by Maven as a regular test class.
 */
public final class V1CountingStream extends FilterInputStream {

    private V1CountingStream(InputStream in) {
        super(in);
    }

    /**
     * Wraps an InputStream in a counting stream.
     * Called from the instrumented DeflateUtil.decode() bytecode.
     */
    public static InputStream wrap(InputStream in) {
        return new V1CountingStream(in);
    }

    @Override
    public int read() throws IOException {
        int b = super.read();
        if (b >= 0) {
            V1Counters.addDecompressedBytes(1);
        }
        return b;
    }

    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
        int n = super.read(buf, off, len);
        if (n > 0) {
            V1Counters.addDecompressedBytes(n);
        }
        return n;
    }
}
