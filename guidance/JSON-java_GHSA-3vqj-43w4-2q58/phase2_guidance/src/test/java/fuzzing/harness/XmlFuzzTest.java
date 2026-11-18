package fuzzing.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.json.JSONException;
import org.json.JSONML;
import org.json.XML;
import org.json.XMLParserConfiguration;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Fuzz tests for JSON-java's XML conversion APIs, one @Fuzz method per entry point.
 *
 * Each method reads the whole input stream, decodes it as UTF-8 and passes the
 * resulting String to a public org.json entry point with its default
 * configuration. JSONException is the library's rejection of malformed input and
 * is declared, so it counts as a normal result.
 */
@RunWith(JQF.class)
public class XmlFuzzTest {

    private static String readUtf8(InputStream input) throws IOException {
        return new String(input.readAllBytes(), StandardCharsets.UTF_8);
    }

    /**
     * XML to JSONML conversion.
     * Entry point: org.json.JSONML.toJSONArray(String).
     */
    @Fuzz
    public void fuzzJSONMLToJSONArray(InputStream input) throws IOException, JSONException {
        String xml = readUtf8(input);
        JSONML.toJSONArray(xml);
    }

    /**
     * XML to JSONObject conversion with an explicit parser configuration.
     * Entry point: org.json.XML.toJSONObject(String, XMLParserConfiguration),
     * called with the library's default configuration (XMLParserConfiguration.ORIGINAL).
     */
    @Fuzz
    public void fuzzXMLToJSONObjectWithConfiguration(InputStream input) throws IOException, JSONException {
        String xml = readUtf8(input);
        XML.toJSONObject(xml, XMLParserConfiguration.ORIGINAL);
    }

    /**
     * XML to JSONObject conversion with the default overload, which
     * converts text content and attribute values to numbers/booleans where possible.
     * Entry point: org.json.XML.toJSONObject(String).
     */
    @Fuzz
    public void fuzzXMLToJSONObject(InputStream input) throws IOException, JSONException {
        String xml = readUtf8(input);
        XML.toJSONObject(xml);
    }
}
