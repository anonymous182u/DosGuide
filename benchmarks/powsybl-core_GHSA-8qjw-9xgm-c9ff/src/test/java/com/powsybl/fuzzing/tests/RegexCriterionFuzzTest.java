package com.powsybl.fuzzing.tests;

import com.powsybl.iidm.criteria.RegexCriterion;
import com.powsybl.iidm.network.Identifiable;
import com.powsybl.iidm.network.IdentifiableType;
import com.powsybl.iidm.network.Network;
import com.powsybl.commons.extensions.Extension;
import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * JQF fuzz test class for RegexCriterion.
 *
 * <p>Input model: the raw input bytes are split at data.length / 2. The first
 * half, decoded as UTF-8, is the regular expression given to the criterion;
 * the second half, decoded as UTF-8, is the identifier of the network element
 * the criterion is applied to.</p>
 *
 * <p>A malformed regular expression is rejected by the library with
 * {@link PatternSyntaxException}; that is a normal result and is declared.</p>
 */
@RunWith(JQF.class)
public class RegexCriterionFuzzTest {

    /**
     * RegexCriterion(String) followed by
     * filter(Identifiable, IdentifiableType), the library's public API.
     */
    @Fuzz
    public void fuzzRegexCriterionFilter(InputStream input) throws IOException, PatternSyntaxException {
        byte[] data = input.readAllBytes();
        int half = data.length / 2;
        String regex = new String(data, 0, half, StandardCharsets.UTF_8);
        String id = new String(data, half, data.length - half, StandardCharsets.UTF_8);

        RegexCriterion criterion = new RegexCriterion(regex);
        criterion.filter(new InputIdentifiable(id), IdentifiableType.LINE);
    }

    /**
     * The JDK regex API on its own,
     * Pattern.compile(regex).matcher(text).find(), without the RegexCriterion
     * wrapper. Same input model as fuzzRegexCriterionFilter.
     */
    @Fuzz
    public void fuzzPatternMatcherFind(InputStream input) throws IOException, PatternSyntaxException {
        byte[] data = input.readAllBytes();
        int half = data.length / 2;
        String regex = new String(data, 0, half, StandardCharsets.UTF_8);
        String text = new String(data, half, data.length - half, StandardCharsets.UTF_8);

        Pattern.compile(regex).matcher(text).find();
    }

    /**
     * Identifiable whose identifier is the fuzzed value. RegexCriterion.filter
     * only calls getId(); getType() returns LINE. The other abstract methods of
     * Identifiable and Extendable throw UnsupportedOperationException.
     */
    private static class InputIdentifiable implements Identifiable<InputIdentifiable> {
        private final String id;

        InputIdentifiable(String id) {
            this.id = id;
        }

        @Override
        public String getId() {
            return id;
        }

        @Override
        public IdentifiableType getType() {
            return IdentifiableType.LINE;
        }

        @Override
        public Network getNetwork() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean hasProperty() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean hasProperty(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getProperty(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getProperty(String key, String defaultValue) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String setProperty(String key, String value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean removeProperty(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<String> getPropertyNames() {
            throw new UnsupportedOperationException();
        }

        @Override
        public <E extends Extension<InputIdentifiable>> void addExtension(Class<? super E> type, E extension) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <E extends Extension<InputIdentifiable>> E getExtension(Class<? super E> type) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <E extends Extension<InputIdentifiable>> E getExtensionByName(String name) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <E extends Extension<InputIdentifiable>> boolean removeExtension(Class<E> type) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <E extends Extension<InputIdentifiable>> Collection<E> getExtensions() {
            throw new UnsupportedOperationException();
        }
    }
}
