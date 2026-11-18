package org.jose4j.fuzz;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.lang.JoseException;
import org.junit.runner.RunWith;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * JQF fuzz test for compressed JWE payloads in jose4j.
 *
 * fuzzJsonWebEncryptionGetPlaintextBytes: the input is the payload of a JWE
 *     whose protected header declares "zip":"DEF" (i.e. the payload is a raw
 *     DEFLATE stream). The harness encrypts the input with a constant A128GCM
 *     content key ("alg":"dir") and serializes the token. The token is then
 *     passed to jose4j's public API with its default settings:
 *     JsonWebEncryption.setKey, setCompactSerialization, getPlaintextBytes.
 *
 * JoseException is jose4j's rejection of a malformed token or payload.
 *
 * Check: besides any error the library raises itself, the test fails when
 * getPlaintextBytes() returns more than MAX_PLAINTEXT_BYTES (204,800) bytes.
 */
@RunWith(JQF.class)
public class JsonWebEncryptionFuzzTest {

    /** Upper bound on the length of the payload returned by getPlaintextBytes(). */
    private static final int MAX_PLAINTEXT_BYTES = 204800;

    private static final byte[] CEK = {
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, (byte) 0x87,
            (byte) 0x98, (byte) 0xa9, (byte) 0xba, (byte) 0xcb, (byte) 0xdc, (byte) 0xed, (byte) 0xfe, 0x0f
    };
    private static final String ENCODED_HEADER = Base64Url.encode(
            "{\"alg\":\"dir\",\"enc\":\"A128GCM\",\"zip\":\"DEF\"}", "UTF-8");
    private static final byte[] IV = new byte[12];

    @Fuzz
    public void fuzzJsonWebEncryptionGetPlaintextBytes(InputStream data) throws IOException, JoseException {
        byte[] compressedPayload = data.readAllBytes();
        String token = produceToken(compressedPayload);

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setKey(new SecretKeySpec(CEK, "AES"));
        jwe.setCompactSerialization(token);
        byte[] plaintext = jwe.getPlaintextBytes();

        if (plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new AssertionError("decompressed JWE payload of " + plaintext.length
                    + " bytes exceeds the limit of " + MAX_PLAINTEXT_BYTES + " bytes");
        }
    }

    /** Compact serialization of a "dir"/A128GCM JWE (RFC 7516 / RFC 7518 §5.3) carrying {@code payload}. */
    private static String produceToken(byte[] payload) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(CEK, "AES"), new GCMParameterSpec(128, IV));
            cipher.updateAAD(ENCODED_HEADER.getBytes(StandardCharsets.US_ASCII));
            byte[] out = cipher.doFinal(payload);
            byte[] ciphertext = Arrays.copyOfRange(out, 0, out.length - 16);
            byte[] tag = Arrays.copyOfRange(out, out.length - 16, out.length);
            return ENCODED_HEADER + ".." + Base64Url.encode(IV) + "." + Base64Url.encode(ciphertext)
                    + "." + Base64Url.encode(tag);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("harness could not produce the JWE", e);
        }
    }
}
