package com.fuzzing.httpheaders;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import org.springframework.http.HttpHeaders;

/**
 * JQF fuzz tests for request-header parsing in Spring's HttpHeaders (spring-web).
 *
 * The input is decoded as ISO-8859-1 (one byte per char, as HTTP header bytes are)
 * and used as the value of a single request header. HttpHeaders rejects values
 * it cannot parse with IllegalArgumentException, which is declared and therefore
 * a normal result.
 */
@RunWith(JQF.class)
public class HttpHeadersFuzzTest {

    /**
     * If-None-Match parsing. The input is the If-None-Match header value;
     * HttpHeaders.getIfNoneMatch() parses it into the list of entity tags, as
     * Spring does when it evaluates a conditional request.
     */
    @Fuzz
    public void fuzzHttpHeadersGetIfNoneMatch(InputStream input) throws IOException, IllegalArgumentException {
        String headerValue = new String(input.readAllBytes(), StandardCharsets.ISO_8859_1);

        HttpHeaders headers = new HttpHeaders();
        headers.put(HttpHeaders.IF_NONE_MATCH, Collections.singletonList(headerValue));
        headers.getIfNoneMatch();
    }

    /**
     * Accept-Language parsing. The input is the Accept-Language header
     * value; HttpHeaders.getAcceptLanguage() parses it with
     * Locale.LanguageRange.parse.
     */
    @Fuzz
    public void fuzzHttpHeadersGetAcceptLanguage(InputStream input) throws IOException, IllegalArgumentException {
        String headerValue = new String(input.readAllBytes(), StandardCharsets.ISO_8859_1);

        HttpHeaders headers = new HttpHeaders();
        headers.put(HttpHeaders.ACCEPT_LANGUAGE, Collections.singletonList(headerValue));
        headers.getAcceptLanguage();
    }
}
