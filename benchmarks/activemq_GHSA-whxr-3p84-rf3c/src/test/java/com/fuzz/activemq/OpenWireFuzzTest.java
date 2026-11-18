package com.fuzz.activemq;

import java.io.IOException;
import java.io.InputStream;

import org.junit.runner.RunWith;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;

import org.apache.activemq.openwire.OpenWireFormat;
import org.apache.activemq.openwire.OpenWireFormatFactory;
import org.apache.activemq.util.ByteSequence;

/**
 * JQF fuzz tests for ActiveMQ's OpenWire unmarshalling (OpenWireFormat.unmarshal).
 *
 * Each method treats the raw fuzz input as one OpenWire frame (size prefix
 * included) and unmarshals it with an OpenWireFormat created the way the
 * broker's OpenWire transport connector creates it: OpenWireFormatFactory with
 * the maxFrameSize of the broker's shipped configuration (conf/activemq.xml,
 * wireFormat.maxFrameSize=104857600), in its state before wire-format
 * negotiation.
 *
 * Declared exceptions are the ones the OpenWire unmarshallers raise for
 * malformed frames (IOException, and the unchecked ClassCastException,
 * IllegalArgumentException, NullPointerException and
 * NegativeArraySizeException thrown by marshallers and command setters for
 * mistyped or invalid fields); the transport treats all of them as a broken
 * frame and closes the connection, so they count as normal results.
 */
@RunWith(JQF.class)
public class OpenWireFuzzTest {

    /** wireFormat.maxFrameSize of the OpenWire transport connector in the broker's shipped conf/activemq.xml. */
    private static final long BROKER_MAX_FRAME_SIZE = 104857600L;

    private static OpenWireFormat brokerWireFormat() {
        OpenWireFormatFactory factory = new OpenWireFormatFactory();
        factory.setMaxFrameSize(BROKER_MAX_FRAME_SIZE);
        return (OpenWireFormat) factory.createWireFormat();
    }

    /**
     * OpenWireFormat.unmarshal(ByteSequence) with the broker transport's wire
     * format and stack traces enabled (setStackTraceEnabled(true), the value
     * OpenWireFormatFactory negotiates by default).
     */
    @Fuzz
    public void fuzzOpenWireFormatUnmarshalStackTraceEnabled(InputStream input) throws IOException, ClassCastException,
            IllegalArgumentException, NullPointerException, NegativeArraySizeException {
        byte[] data = input.readAllBytes();
        OpenWireFormat owf = brokerWireFormat();
        owf.setStackTraceEnabled(true);
        owf.unmarshal(new ByteSequence(data));
    }

    /**
     * OpenWireFormat.unmarshal(ByteSequence) with the broker transport's
     * wire format.
     */
    @Fuzz
    public void fuzzOpenWireFormatUnmarshal(InputStream input) throws IOException, ClassCastException,
            IllegalArgumentException, NullPointerException, NegativeArraySizeException {
        byte[] data = input.readAllBytes();
        brokerWireFormat().unmarshal(new ByteSequence(data));
    }

    /**
     * OpenWireFormat.unmarshal(ByteSequence) with the broker transport's
     * wire format (the same calls as {@link #fuzzOpenWireFormatUnmarshal}).
     */
    @Fuzz
    public void fuzzOpenWireFormatUnmarshal2(InputStream input) throws IOException, ClassCastException,
            IllegalArgumentException, NullPointerException, NegativeArraySizeException {
        byte[] data = input.readAllBytes();
        brokerWireFormat().unmarshal(new ByteSequence(data));
    }
}
