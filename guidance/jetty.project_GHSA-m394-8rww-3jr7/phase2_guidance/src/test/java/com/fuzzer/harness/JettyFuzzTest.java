package com.fuzzer.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.function.UnaryOperator;

import org.eclipse.jetty.http2.parser.Parser;
import org.eclipse.jetty.http2.frames.DataFrame;
import org.eclipse.jetty.http2.frames.HeadersFrame;
import org.eclipse.jetty.http2.frames.PingFrame;
import org.eclipse.jetty.http2.frames.PriorityFrame;
import org.eclipse.jetty.http2.frames.ResetFrame;
import org.eclipse.jetty.http2.frames.SettingsFrame;
import org.eclipse.jetty.http2.frames.GoAwayFrame;
import org.eclipse.jetty.http2.frames.WindowUpdateFrame;
import org.eclipse.jetty.io.MappedByteBufferPool;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.QuotedQualityCSV;

/**
 * JQF fuzz harness for Jetty HTTP/2 Parser and quality-sorted header values.
 *
 * fuzzHttp2ParserParseFullListener — HTTP/2 frame parsing (Parser.parse), listener with nine empty callback
 *     overrides
 * fuzzHttp2ParserParseHeadersListener — HTTP/2 frame parsing (Parser.parse), listener overriding only onHeaders and
 *     onConnectionFailure
 * fuzzHttpFieldsGetQualityCSV — quality-ordered Accept header values (HttpFields.getQualityCSV)
 *
 * Each method reads the whole InputStream and hands the bytes to the library.
 */
@RunWith(JQF.class)
public class JettyFuzzTest {

    /**
     * HTTP/2 frame parsing.
     *
     * Feeds the input bytes as HTTP/2 frames to Parser.parse(), with the parser built the way
     * HTTP2ClientConnectionFactory builds it (dynamic table 4096, max header size 8192). The listener
     * has empty overrides of onData, onHeaders, onPriority, onReset, onSettings, onPing, onGoAway,
     * onWindowUpdate and onConnectionFailure.
     */
    @Fuzz
    public void fuzzHttp2ParserParseFullListener(InputStream input) throws IOException {
        byte[] data = input.readAllBytes();
        if (data.length < 9) return; // shorter than one frame header

        MappedByteBufferPool bufferPool = new MappedByteBufferPool();
        Parser parser = new Parser(bufferPool, new Parser.Listener.Adapter() {
            @Override
            public void onData(DataFrame frame) { }
            @Override
            public void onHeaders(HeadersFrame frame) { }
            @Override
            public void onPriority(PriorityFrame frame) { }
            @Override
            public void onReset(ResetFrame frame) { }
            @Override
            public void onSettings(SettingsFrame frame) { }
            @Override
            public void onPing(PingFrame frame) { }
            @Override
            public void onGoAway(GoAwayFrame frame) { }
            @Override
            public void onWindowUpdate(WindowUpdateFrame frame) { }
            @Override
            public void onConnectionFailure(int error, String reason) { }
        }, 4096, 8192);

        parser.init(UnaryOperator.identity());

        ByteBuffer buffer = ByteBuffer.wrap(data);
        parser.parse(buffer);
    }

    /**
     * HTTP/2 frame parsing.
     *
     * Same parser setup as fuzzHttp2ParserParseFullListener; the listener overrides only
     * onHeaders and onConnectionFailure.
     */
    @Fuzz
    public void fuzzHttp2ParserParseHeadersListener(InputStream input) throws IOException {
        byte[] data = input.readAllBytes();
        if (data.length < 9) return;

        MappedByteBufferPool bufferPool = new MappedByteBufferPool();
        Parser parser = new Parser(bufferPool, new Parser.Listener.Adapter() {
            @Override
            public void onHeaders(HeadersFrame frame) { }
            @Override
            public void onConnectionFailure(int error, String reason) { }
        }, 4096, 8192);

        parser.init(UnaryOperator.identity());

        ByteBuffer buffer = ByteBuffer.wrap(data);
        parser.parse(buffer);
    }

    /**
     * Quality-ordered Accept header values.
     *
     * The input is the value of a request's Accept header (bytes taken as ISO-8859-1 characters).
     * It is looked up exactly as Jetty's default ErrorHandler does when it picks the error page format:
     * HttpFields.getQualityCSV(HttpHeader.ACCEPT, QuotedQualityCSV.MOST_SPECIFIC_MIME_ORDERING),
     * which parses the values with QuotedQualityCSV and orders them by quality.
     */
    @Fuzz
    public void fuzzHttpFieldsGetQualityCSV(InputStream input) throws IOException {
        String accept = new String(input.readAllBytes(), StandardCharsets.ISO_8859_1);

        HttpFields fields = new HttpFields();
        fields.add(HttpHeader.ACCEPT, accept);
        fields.getQualityCSV(HttpHeader.ACCEPT, QuotedQualityCSV.MOST_SPECIFIC_MIME_ORDERING);
    }
}
