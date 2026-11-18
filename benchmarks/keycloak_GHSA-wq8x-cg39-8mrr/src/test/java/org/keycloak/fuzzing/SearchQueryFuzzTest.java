package org.keycloak.fuzzing;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import org.keycloak.utils.SearchQueryUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * JQF fuzz test for Keycloak's search-query parser
 * (org.keycloak.utils.SearchQueryUtils, keycloak-services).
 *
 * fuzzSearchQueryUtilsGetFields: the whole input, decoded as UTF-8, is passed
 *     to SearchQueryUtils.getFields(String).
 *
 * The library is called as an application would call it; any exception or
 * error it raises propagates to JQF.
 */
@RunWith(JQF.class)
public class SearchQueryFuzzTest {

    /**
     * Parses the input as a search query of "key:value" pairs.
     *
     * @param input raw bytes from the fuzzing engine
     */
    @Fuzz
    public void fuzzSearchQueryUtilsGetFields(InputStream input) throws IOException {
        String query = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        SearchQueryUtils.getFields(query);
    }
}
