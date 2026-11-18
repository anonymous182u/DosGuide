package com.fuzzer;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * JQF fuzz test for Bouncy Castle Ed25519 signature verification.
 * <p>
 * The whole input is read and split into the arguments of
 * {@link Ed25519#verify(byte[], int, byte[], int, byte[], int, int)}:
 *   bytes[0..63]  = Ed25519 signature (encoded point R followed by scalar S)
 *   bytes[64..95] = Ed25519 public key
 *   bytes[96..]   = message
 */
@RunWith(JQF.class)
public class Ed25519FuzzTest {

    private static final int SIG_SIZE = Ed25519.SIGNATURE_SIZE;   // 64
    private static final int PK_SIZE = Ed25519.PUBLIC_KEY_SIZE;   // 32
    private static final int MIN_INPUT = SIG_SIZE + PK_SIZE + 1;

    /**
     * Ed25519.verify(sig, 0, pk, 0, msg, 0, msg.length) with the library's defaults.
     */
    @Fuzz
    public void fuzzEd25519Verify(InputStream input) throws IOException {
        byte[] data = input.readAllBytes();
        if (data.length < MIN_INPUT) {
            return; // not enough bytes for signature, public key and a message
        }

        byte[] sig = Arrays.copyOfRange(data, 0, SIG_SIZE);
        byte[] pk = Arrays.copyOfRange(data, SIG_SIZE, SIG_SIZE + PK_SIZE);
        byte[] msg = Arrays.copyOfRange(data, SIG_SIZE + PK_SIZE, data.length);

        Ed25519.verify(sig, 0, pk, 0, msg, 0, msg.length);
    }
}
