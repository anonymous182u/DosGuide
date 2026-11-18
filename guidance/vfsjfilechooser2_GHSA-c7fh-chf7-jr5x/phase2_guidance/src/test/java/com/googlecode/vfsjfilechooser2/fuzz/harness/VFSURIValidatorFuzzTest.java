package com.googlecode.vfsjfilechooser2.fuzz.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import com.googlecode.vfsjfilechooser2.utils.VFSURIValidator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * JQF fuzz test harness for VFSURIValidator.isValid(String).
 *
 * Input model: the whole input, decoded as ISO-8859-1 (one char per byte),
 * is the URI string handed to a fresh VFSURIValidator.
 *
 * The three @Fuzz methods are identical: each makes the same call,
 * VFSURIValidator.isValid(String), on the decoded input.
 */
@RunWith(JQF.class)
public class VFSURIValidatorFuzzTest {

    /** VFSURIValidator.isValid(String). */
    @Fuzz
    public void fuzzVFSURIValidatorIsValid(InputStream data) throws IOException {
        validate(data);
    }

    /** VFSURIValidator.isValid(String), same call as fuzzVFSURIValidatorIsValid. */
    @Fuzz
    public void fuzzVFSURIValidatorIsValid2(InputStream data) throws IOException {
        validate(data);
    }

    /** VFSURIValidator.isValid(String), same call as fuzzVFSURIValidatorIsValid. */
    @Fuzz
    public void fuzzVFSURIValidatorIsValid3(InputStream data) throws IOException {
        validate(data);
    }

    private static void validate(InputStream data) throws IOException {
        String uri = new String(readAll(data), StandardCharsets.ISO_8859_1);
        VFSURIValidator validator = new VFSURIValidator();
        validator.isValid(uri);
    }

    /** Reads the whole stream (the fixture is compiled for Java 8, which lacks readAllBytes()). */
    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
}
