/*
 * EmailValidatorFuzzTest — JQF fuzz test class for the Vaadin e-mail validators.
 *
 * Methods:
 *   fuzzEmailValidatorIsValid → Vaadin 7 compatibility EmailValidator
 *                (com.vaadin.v7.data.validator.EmailValidator.isValid(Object))
 *   fuzzEmailValidatorApply   → Vaadin 8 EmailValidator
 *                (com.vaadin.data.validator.EmailValidator.apply(String, ValueContext))
 *
 * Each method decodes the whole input as UTF-8 and passes the resulting string
 * to the validator's public API with its default configuration, as an
 * application validating a submitted form field would.
 */
package com.vaadin.fuzz;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.runner.RunWith;

import com.vaadin.data.ValueContext;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;

@RunWith(JQF.class)
public class EmailValidatorFuzzTest {

    /**
     * Vaadin 7 compatibility-module EmailValidator, through isValid(Object).
     */
    @Fuzz
    public void fuzzEmailValidatorIsValid(InputStream input) throws IOException {
        String value = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        com.vaadin.v7.data.validator.EmailValidator validator =
                new com.vaadin.v7.data.validator.EmailValidator("invalid email");
        validator.isValid(value);
    }

    /**
     * Vaadin 8 EmailValidator, through its public Validator API
     * apply(String, ValueContext).
     */
    @Fuzz
    public void fuzzEmailValidatorApply(InputStream input) throws IOException {
        String value = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        com.vaadin.data.validator.EmailValidator validator =
                new com.vaadin.data.validator.EmailValidator("invalid email");
        validator.apply(value, new ValueContext());
    }
}
