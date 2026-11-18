package com.fuzzing.harness;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import org.apache.commons.fileupload.MultipartStream;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

/**
 * Fuzz test harness for org.apache.commons.fileupload.MultipartStream, the
 * library's multipart parser (public low-level API, also used by
 * FileUploadBase for every upload).
 *
 * Each @Fuzz method reads the whole input stream and derives the boundary and
 * the multipart body from it, then drives MultipartStream the way the class's
 * own usage example does: skipPreamble(), then for every part readHeaders(),
 * body data, readBoundary().
 *
 * MultipartStream rejects malformed or over-limit input with IOException
 * subclasses (MalformedStreamException, FileUploadIOException,
 * IllegalBoundaryException); those are declared and count as normal results.
 */
@RunWith(JQF.class)
public class MultipartFuzzTest {

    /** Default buffer size of MultipartStream (MultipartStream.DEFAULT_BUFSIZE). */
    private static final int DEFAULT_BUFFER_SIZE = 4096;

    /** Longest boundary parameter RFC 2046 allows. */
    private static final int MAX_BOUNDARY_LENGTH = 70;

    /**
     * Upper bound on the length of a part's header section as returned by
     * readHeaders(). Used only in fuzzMultipartStreamReadHeaders, see below.
     */
    private static final int PART_HEADER_SIZE_MAX = 512;

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    /**
     * Part iteration over a whole multipart body; the body data of every part
     * is skipped with discardBodyData().
     *
     * Input model: byte 0 selects the boundary length (4..20), the next bytes
     * are the boundary, the rest is the multipart body. Buffer size is
     * max(boundary length + 6, 256).
     */
    @Fuzz
    public void fuzzMultipartStreamDiscardBodyData(InputStream input) throws IOException {
        byte[] data = readAll(input);
        if (data.length < 2) {
            return;
        }
        int boundaryLen = 4 + (data[0] & 0xFF) % 17;
        if (data.length <= 1 + boundaryLen) {
            return;
        }
        byte[] boundary = Arrays.copyOfRange(data, 1, 1 + boundaryLen);
        byte[] body = Arrays.copyOfRange(data, 1 + boundaryLen, data.length);

        MultipartStream ms = new MultipartStream(new ByteArrayInputStream(body), boundary,
                Math.max(boundaryLen + 6, 256), null);
        boolean hasNext = ms.skipPreamble();
        while (hasNext) {
            ms.readHeaders();
            ms.discardBodyData();
            hasNext = ms.readBoundary();
        }
    }

    /**
     * Header parsing of every part (MultipartStream.readHeaders()).
     *
     * Input model: the first line of the input (up to LF, without a trailing
     * CR) is the boundary parameter of the request's Content-Type; the rest of
     * the input is the request body. A missing, empty or over-long boundary is
     * a request an application rejects before parsing, so the method returns.
     * The library's default buffer size is used; header bytes are decoded as
     * ISO-8859-1 so that the returned string has one char per header byte.
     *
     * Check: every header section readHeaders() returns must be at most
     * PART_HEADER_SIZE_MAX (512) characters long.
     */
    @Fuzz
    public void fuzzMultipartStreamReadHeaders(InputStream input) throws IOException {
        byte[] data = readAll(input);
        int lf = -1;
        for (int i = 0; i < data.length && i <= MAX_BOUNDARY_LENGTH + 1; i++) {
            if (data[i] == '\n') {
                lf = i;
                break;
            }
        }
        if (lf < 0) {
            return;
        }
        int boundaryEnd = (lf > 0 && data[lf - 1] == '\r') ? lf - 1 : lf;
        if (boundaryEnd == 0 || boundaryEnd > MAX_BOUNDARY_LENGTH) {
            return;
        }
        byte[] boundary = Arrays.copyOfRange(data, 0, boundaryEnd);
        byte[] body = Arrays.copyOfRange(data, lf + 1, data.length);

        MultipartStream ms = new MultipartStream(new ByteArrayInputStream(body), boundary,
                DEFAULT_BUFFER_SIZE, null);
        ms.setHeaderEncoding("ISO-8859-1");
        boolean hasNext = ms.skipPreamble();
        while (hasNext) {
            String headers = ms.readHeaders();
            if (headers.length() > PART_HEADER_SIZE_MAX) {
                throw new AssertionError("part header section of " + headers.length()
                        + " bytes accepted; the limit is "
                        + PART_HEADER_SIZE_MAX);
            }
            ms.discardBodyData();
            hasNext = ms.readBoundary();
        }
    }

    /**
     * Body-data reading of the first part: skipPreamble(), readHeaders(), then
     * readBodyData() into a discarding output stream.
     *
     * Input model: the first min(32, length - 1) bytes are the boundary, the
     * rest is the body. The buffer is the smallest size the constructor
     * accepts (boundary length + 5).
     */
    @Fuzz
    public void fuzzMultipartStreamReadBodyData(InputStream input) throws IOException {
        byte[] data = readAll(input);
        if (data.length == 0) {
            data = new byte[]{0x41, 0x42};
        }
        int boundaryLen = Math.max(1, Math.min(32, data.length - 1));
        byte[] boundary = Arrays.copyOfRange(data, 0, boundaryLen);
        byte[] body = Arrays.copyOfRange(data, Math.min(boundaryLen, data.length), data.length);

        MultipartStream ms = new MultipartStream(new ByteArrayInputStream(body), boundary,
                boundaryLen + 5, null);
        ms.skipPreamble();
        ms.readHeaders();
        ms.readBodyData(OutputStream.nullOutputStream());
    }
}
