package fuzzing.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.XML;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * JQF fuzz tests for JSON-java's public parsers:
 *   - fuzzJSONObjectAndJSONArrayConstructors: new JSONObject(String) and new JSONArray(String)
 *   - fuzzXMLToJSONObject:                    XML.toJSONObject(String)
 *   - fuzzJSONObjectConstructor:              new JSONObject(String)
 *
 * Each method reads the whole input stream and decodes it as UTF-8. JSONException is
 * the library's rejection of malformed input and counts as a normal result.
 */
@RunWith(JQF.class)
public class JsonFuzzTest {

    private static String readUtf8(InputStream input) throws IOException {
        return new String(input.readAllBytes(), StandardCharsets.UTF_8);
    }

    /**
     * JSON text parsing through both public constructors that take a String.
     * Entry points: new JSONObject(String), new JSONArray(String).
     */
    @Fuzz
    public void fuzzJSONObjectAndJSONArrayConstructors(InputStream input) throws IOException {
        String jsonStr = readUtf8(input);

        try {
            new JSONObject(jsonStr);
        } catch (JSONException e) {
            // input rejected by the library
        }

        try {
            new JSONArray(jsonStr);
        } catch (JSONException e) {
            // input rejected by the library
        }
    }

    /**
     * XML to JSONObject conversion.
     * Entry point: XML.toJSONObject(String).
     */
    @Fuzz
    public void fuzzXMLToJSONObject(InputStream input) throws IOException, JSONException {
        String xmlStr = readUtf8(input);
        XML.toJSONObject(xmlStr);
    }

    /**
     * JSON object parsing, including conversion of unquoted values to numbers.
     * Entry point: new JSONObject(String).
     */
    @Fuzz
    public void fuzzJSONObjectConstructor(InputStream input) throws IOException, JSONException {
        String jsonStr = readUtf8(input);
        new JSONObject(jsonStr);
    }
}
