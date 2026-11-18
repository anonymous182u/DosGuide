package com.fasterxml.jackson.fuzz.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import java.io.IOException;
import java.io.InputStream;

/**
 * Fuzz tests for the jackson-dataformat-cbor parser.
 *
 * Every method reads the raw fuzz input as a CBOR document and hands it to the
 * library's public API with its default configuration. Malformed input is
 * rejected by the library with an IOException (JsonParseException and its
 * subclasses), which is declared and therefore counts as a normal result.
 */
@RunWith(JQF.class)
public class CBORFuzzTest {

    /** Default-configured factory, shared as an application would share it. */
    private static final CBORFactory CBOR_FACTORY = new CBORFactory();

    /** Default-configured data-binding mapper backed by a CBOR factory. */
    private static final ObjectMapper CBOR_MAPPER = new ObjectMapper(new CBORFactory());

    /**
     * Streams the document with CBORParser and, for every floating-point
     * (decimal) value, reads it through the parser's public number accessors
     * (getNumberValue, getText).
     */
    @Fuzz
    public void fuzzCBORParserNextTokenFloatValues(InputStream input) throws IOException {
        byte[] data = input.readAllBytes();
        try (JsonParser parser = CBOR_FACTORY.createParser(data)) {
            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                if (token == JsonToken.VALUE_NUMBER_FLOAT) {
                    parser.getNumberValue();
                    parser.getText();
                }
            }
        }
    }

    /**
     * Streams the document with CBORParser (CBORFactory.createParser(byte[])
     * then nextToken) and reads the content of every scalar through the
     * parser's public accessors: getBinaryValue for byte strings, getText for
     * text strings, getNumberValue for numbers.
     */
    @Fuzz
    public void fuzzCBORParserNextTokenScalarValues(InputStream input) throws IOException {
        byte[] data = input.readAllBytes();
        try (JsonParser parser = CBOR_FACTORY.createParser(data)) {
            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                switch (token) {
                case VALUE_EMBEDDED_OBJECT:
                    parser.getBinaryValue();
                    break;
                case VALUE_STRING:
                    parser.getText();
                    break;
                case VALUE_NUMBER_INT:
                case VALUE_NUMBER_FLOAT:
                    parser.getNumberValue();
                    break;
                default:
                    break;
                }
            }
        }
    }

    /**
     * Deserializes the whole document into a JsonNode tree with
     * ObjectMapper.readTree (jackson-databind on top of the CBOR parser).
     */
    @Fuzz
    public void fuzzObjectMapperReadTree(InputStream input) throws IOException {
        byte[] data = input.readAllBytes();
        CBOR_MAPPER.readTree(data);
    }
}
