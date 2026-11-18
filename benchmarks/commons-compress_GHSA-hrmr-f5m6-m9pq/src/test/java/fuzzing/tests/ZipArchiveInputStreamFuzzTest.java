package fuzzing.tests;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipException;

import static org.junit.Assume.assumeTrue;

/**
 * Fuzz tests for commons-compress ZipArchiveInputStream.
 * The whole fuzz input is read and parsed as a ZIP stream; every method reads all entries it can.
 *
 * fuzzZipArchiveInputStreamReadAllowStoredDataDescriptor: entries read with allowStoredEntriesWithDataDescriptor=true
 * fuzzZipArchiveInputStreamReadBytes: entries read with the default settings, as bytes
 * fuzzZipArchiveInputStreamReadText: entries read with the default settings, as text
 *
 * Declared exceptions are the library's rejections of malformed archives: IOException (ZipException,
 * EOFException, UnsupportedZipFeatureException) and IllegalArgumentException (ZipArchiveEntry.setSize rejects
 * a negative size). ZipArchiveEntry.setExtra reports unparseable extra fields as a plain RuntimeException
 * wrapping a ZipException; {@link #nextEntry} rethrows that ZipException and nothing else.
 */
@RunWith(JQF.class)
public class ZipArchiveInputStreamFuzzTest {

    /**
     * ZipArchiveInputStream(in, "UTF-8", useUnicodeExtraFields=true,
     * allowStoredEntriesWithDataDescriptor=true); every readable entry is read to its end with read(byte[]).
     */
    @Fuzz
    public void fuzzZipArchiveInputStreamReadAllowStoredDataDescriptor(InputStream rawInput) throws IOException, IllegalArgumentException {
        byte[] data = rawInput.readAllBytes();
        assumeTrue(data.length >= 4);

        try (ZipArchiveInputStream zis = new ZipArchiveInputStream(
                new ByteArrayInputStream(data), "UTF-8", true, true)) {
            ZipArchiveEntry entry;
            byte[] buf = new byte[4096];
            while ((entry = nextEntry(zis)) != null) {
                if (!zis.canReadEntryData(entry)) continue;
                while (zis.read(buf) != -1) {
                    // consume the entry
                }
            }
        }
    }

    /**
     * ZipArchiveInputStream with default settings; every readable entry (STORED, DEFLATED, ...) is read to
     * its end with read(byte[]).
     */
    @Fuzz
    public void fuzzZipArchiveInputStreamReadBytes(InputStream rawInput) throws IOException, IllegalArgumentException {
        byte[] data = rawInput.readAllBytes();
        assumeTrue(data.length >= 4);

        try (ZipArchiveInputStream zis = new ZipArchiveInputStream(new ByteArrayInputStream(data))) {
            ZipArchiveEntry entry;
            byte[] buf = new byte[8192];
            while ((entry = nextEntry(zis)) != null) {
                if (!zis.canReadEntryData(entry)) continue;
                while (zis.read(buf) != -1) {
                    // consume the entry
                }
            }
        }
    }

    /**
     * ZipArchiveInputStream with default settings; every readable entry is consumed as UTF-8 text through
     * java.io.InputStreamReader until the reader reports the end of the entry.
     */
    @Fuzz
    public void fuzzZipArchiveInputStreamReadText(InputStream rawInput) throws IOException, IllegalArgumentException {
        byte[] data = rawInput.readAllBytes();

        try (ZipArchiveInputStream zis = new ZipArchiveInputStream(new ByteArrayInputStream(data))) {
            ZipArchiveEntry entry;
            char[] chars = new char[4096];
            while ((entry = nextEntry(zis)) != null) {
                if (!zis.canReadEntryData(entry)) continue;
                // not closed: closing the reader would close the archive stream
                Reader reader = new InputStreamReader(zis, StandardCharsets.UTF_8);
                while (reader.read(chars) != -1) {
                    // consume the entry
                }
            }
        }
    }

    /** getNextZipEntry, with the library's wrapped extra-field ZipException rethrown as itself. */
    private static ZipArchiveEntry nextEntry(ZipArchiveInputStream zis) throws IOException {
        try {
            return zis.getNextZipEntry();
        } catch (RuntimeException e) {
            if (e.getClass() == RuntimeException.class && e.getCause() instanceof ZipException) {
                throw (ZipException) e.getCause();
            }
            throw e;
        }
    }
}
