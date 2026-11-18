package com.fuzzer.saml;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import org.keycloak.saml.SAMLRequestParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;

/**
 * JQF fuzz test for Keycloak's SAML HTTP-Redirect binding (keycloak-saml-core).
 *
 * fuzzSAMLRequestParserParseRequestRedirectBinding: the input is treated as the
 *     DEFLATE-compressed SAML message of a Redirect-binding request. The harness
 *     applies the binding's base64 transport encoding and passes the resulting
 *     SAMLRequest value to SAMLRequestParser.parseRequestRedirectBinding(String).
 *
 * The library is used with its default configuration; anything it throws
 * propagates to JQF.
 */
@RunWith(JQF.class)
public class SAMLRequestParserFuzzTest {

    /**
     * @param dataStream raw bytes from the fuzzing engine: the compressed SAML message
     */
    @Fuzz
    public void fuzzSAMLRequestParserParseRequestRedirectBinding(InputStream dataStream) throws IOException {
        byte[] deflated = dataStream.readAllBytes();
        String samlRequest = Base64.getEncoder().encodeToString(deflated);
        SAMLRequestParser.parseRequestRedirectBinding(samlRequest);
    }
}
