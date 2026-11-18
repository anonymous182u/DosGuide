package edu.berkeley.cs.jqf.examples.json;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;

import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Fuzz tests for the json-smart parser.
 *
 * Each method decodes the raw fuzz input as UTF-8 text and parses it with
 * JSONParser.parse(String). The library rejects malformed text with its
 * checked ParseException, which is declared and therefore counts as a normal
 * result.
 */
@RunWith(JQF.class)
public class JsonSmartFuzzTest {

    /**
     * JSONParser.parse(String) in MODE_PERMISSIVE, json-smart's default
     * parser mode (the one JSONValue.parse uses).
     */
    @Fuzz
    public void fuzzJSONParserParsePermissive(InputStream data) throws IOException, ParseException {
        String input = new String(data.readAllBytes(), StandardCharsets.UTF_8);
        JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);
        parser.parse(input);
    }

    /**
     * JSONParser.parse(String) in MODE_RFC4627, a library-provided
     * mode that keeps numbers in BigDecimal / BigInteger form.
     */
    @Fuzz
    public void fuzzJSONParserParseRFC4627(InputStream data) throws IOException, ParseException {
        String input = new String(data.readAllBytes(), StandardCharsets.UTF_8);
        JSONParser parser = new JSONParser(JSONParser.MODE_RFC4627);
        parser.parse(input);
    }
}
