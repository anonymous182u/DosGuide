package com.fuzzing.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.server.exceptions.response.ErrorContext;
import io.micronaut.http.server.exceptions.response.HtmlErrorResponseBodyProvider;
import io.micronaut.http.util.HtmlEntityEncodingHtmlSanitizer;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * JQF fuzz tests for Micronaut's HTML error responses (micronaut-http, micronaut-http-server).
 *
 * Input: raw bytes decoded as UTF-8.
 */
@RunWith(JQF.class)
public class SanitizerFuzzTest {

    /** A default Micronaut application context, started once and shared by all executions. */
    private static final ApplicationContext CONTEXT = ApplicationContext.run();

    /** The HtmlErrorResponseBodyProvider implementation the default context provides. */
    private static final Class<? extends HtmlErrorResponseBodyProvider> HTML_PROVIDER_TYPE =
            CONTEXT.getBeanDefinition(HtmlErrorResponseBodyProvider.class).getBeanType();

    /**
     * HtmlEntityEncodingHtmlSanitizer.sanitize(String) on the whole input.
     */
    @Fuzz
    public void fuzzHtmlEntityEncodingHtmlSanitizerSanitize(InputStream inputStream) throws IOException {
        String input = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        new HtmlEntityEncodingHtmlSanitizer().sanitize(input);
    }

    /**
     * HTML error pages rendered by the server's HtmlErrorResponseBodyProvider.
     *
     * Each execution models one freshly started server: it obtains a new instance
     * of the provider from the application context (with its injected
     * dependencies) and then renders one error response per input line, as the
     * server does for successive requests that end in a 400 error whose message
     * is that line and whose client accepts text/html (the HTML branch of
     * DefaultErrorResponseProcessor).
     */
    @Fuzz
    public void fuzzHtmlErrorResponseBodyProviderBody(InputStream inputStream) throws IOException {
        String input = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        HtmlErrorResponseBodyProvider provider = CONTEXT.createBean(HTML_PROVIDER_TYPE);
        HttpRequest<?> request = HttpRequest.GET("/").accept(MediaType.TEXT_HTML_TYPE);

        int start = 0;
        while (start <= input.length()) {
            int end = input.indexOf('\n', start);
            if (end < 0) {
                end = input.length();
            }
            ErrorContext errorContext = ErrorContext.builder(request)
                    .errorMessage(input.substring(start, end))
                    .build();
            provider.body(errorContext, HttpResponse.badRequest());
            start = end + 1;
        }
    }
}
