package org.xerial.snappy.fuzz;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;
import org.xerial.snappy.Snappy;
import org.xerial.snappy.SnappyError;
import org.xerial.snappy.SnappyErrorCode;
import org.xerial.snappy.SnappyInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

/**
 * JQF fuzz tests for snappy-java decompression.
 *
 * Each method reads the whole input stream and passes it to a public snappy-java
 * decompression API with its default configuration. snappy-java rejects corrupt or
 * unsupported compressed data with IOException (SnappyIOException) or SnappyError;
 * both are declared, so a rejected input counts as a normal result. The stream
 * methods (fuzzSnappyInputStreamRead, fuzzSnappyInputStreamReadByteArray) make one
 * exception, see readStream.
 */
@RunWith(JQF.class)
public class SnappyFuzzTest {

    /** Two detail messages of the JVM's OutOfMemoryError. */
    private static final Set<String> JVM_OUT_OF_MEMORY_MESSAGES =
            Set.of("Java heap space", "Requested array size exceeds VM limit");

    /**
     * Stream decompression: new SnappyInputStream(InputStream), then read(byte[]) until end of stream.
     * Check: a SnappyError with error code INVALID_CHUNK_SIZE whose detail message is one of
     * JVM_OUT_OF_MEMORY_MESSAGES is turned into a failure (AssertionError, with the SnappyError as the
     * cause); every other SnappyError stays a rejection.
     */
    private static void readStream(byte[] data) throws IOException, SnappyError {
        byte[] buf = new byte[4096];
        try (SnappyInputStream sis = new SnappyInputStream(new ByteArrayInputStream(data))) {
            while (sis.read(buf) != -1) {
                // consume the decompressed output
            }
        } catch (SnappyError e) {
            String prefix = "[" + e.errorCode.name() + "] ";
            String message = String.valueOf(e.getMessage());
            String detail = message.startsWith(prefix) ? message.substring(prefix.length()) : message;
            if (e.errorCode == SnappyErrorCode.INVALID_CHUNK_SIZE && JVM_OUT_OF_MEMORY_MESSAGES.contains(detail)) {
                throw new AssertionError("SnappyInputStream reported INVALID_CHUNK_SIZE with an OutOfMemoryError message: "
                        + detail, e);
            }
            throw e;
        }
    }

    /**
     * Stream decompression.
     * Entry point: new SnappyInputStream(InputStream), then read(byte[]) until end of stream.
     */
    @Fuzz
    public void fuzzSnappyInputStreamRead(InputStream input) throws IOException, SnappyError {
        readStream(input.readAllBytes());
    }

    /**
     * Stream decompression, same entry point as fuzzSnappyInputStreamRead.
     * Entry point: new SnappyInputStream(InputStream), then read(byte[]) until end of stream.
     */
    @Fuzz
    public void fuzzSnappyInputStreamReadByteArray(InputStream input) throws IOException, SnappyError {
        readStream(input.readAllBytes());
    }

    /**
     * Whole-buffer decompression.
     * Entry point: Snappy.uncompress(byte[]).
     */
    @Fuzz
    public void fuzzSnappyUncompress(InputStream input) throws IOException, SnappyError {
        Snappy.uncompress(input.readAllBytes());
    }
}
