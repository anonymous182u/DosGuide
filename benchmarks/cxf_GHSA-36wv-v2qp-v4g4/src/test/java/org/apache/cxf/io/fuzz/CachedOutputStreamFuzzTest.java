package org.apache.cxf.io.fuzz;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.common.logging.LogUtils;
import org.apache.cxf.io.CachedConstants;
import org.apache.cxf.io.CachedOutputStream;
import org.apache.cxf.io.CachedOutputStreamCleaner;
import org.apache.cxf.io.DelayedCachedOutputStreamCleaner;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * JQF fuzz tests for Apache CXF's CachedOutputStream (cxf-core).
 *
 * The streams of fuzzCachedOutputStreamWriteRange, fuzzCachedOutputStreamToString and
 * fuzzCachedOutputStreamWriteChunks use CXF's default settings (default threshold, no maximum size).
 * fuzzCachedOutputStreamCleanerForceClean runs under a bus whose spill threshold is set to 1 KB (see there).
 */
@RunWith(JQF.class)
public class CachedOutputStreamFuzzTest {

    /**
     * Spill threshold of the bus used by fuzzCachedOutputStreamCleanerForceClean
     * (bus.io.CachedOutputStream.Threshold; CXF's default is 128 KB): above it a stream is cached in a temporary
     * file and registered with the bus's cleaner. Also the bound on the length of a cleaner log message checked in
     * that method.
     */
    private static final int SPILL_THRESHOLD = 1024;

    /** Default CXF bus (default extensions, including the cached-stream cleaner), created once. */
    private static final Bus BUS = BusFactory.newInstance().createBus();

    /** What the cleaner logs during one execution of fuzzCachedOutputStreamCleanerForceClean. */
    private static final List<String> CLEANER_LOG = new ArrayList<>();
    private static final Logger CLEANER_LOGGER = Logger.getLogger(DelayedCachedOutputStreamCleaner.class.getName());

    static {
        BUS.setProperty(CachedConstants.THRESHOLD_BUS_PROP, String.valueOf(SPILL_THRESHOLD));
        CLEANER_LOGGER.setUseParentHandlers(false);
        CLEANER_LOGGER.addHandler(new Handler() {
            @Override
            public void publish(LogRecord record) {
                CLEANER_LOG.add(record.getMessage());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        });
        // CXF logs through java.util.logging unless an SLF4J binding is on the class path; the check in
        // fuzzCachedOutputStreamCleanerForceClean needs the former, so stop here if the cleaner's messages cannot
        // be observed.
        LogUtils.getL7dLogger(DelayedCachedOutputStreamCleaner.class).warning("harness probe");
        if (!CLEANER_LOG.remove("harness probe")) {
            throw new IllegalStateException("CXF does not log through java.util.logging; "
                    + "fuzzCachedOutputStreamCleanerForceClean cannot observe the cleaner");
        }
    }

    /**
     * Under the bus (set as the thread default bus, as CXF does while it processes a message), the whole input is
     * written to a CachedOutputStream, which the code then leaves unclosed. The bus's CachedOutputStreamCleaner
     * extension (DelayedCachedOutputStreamCleaner) then cleans up all streams still registered with it via
     * forceClean(), which is what it does at bus shutdown (or, for expired entries, from its timer).
     *
     * Check: every message the cleaner logs during the execution must be at most SPILL_THRESHOLD (1,024)
     * characters long.
     */
    @Fuzz
    public void fuzzCachedOutputStreamCleanerForceClean(InputStream input) throws IOException {
        CLEANER_LOG.clear();
        Bus previous = BusFactory.getAndSetThreadDefaultBus(BUS);
        try {
            CachedOutputStream cos = new CachedOutputStream();
            input.transferTo(cos);
            cos.flush();
        } finally {
            BusFactory.setThreadDefaultBus(previous);
            ((DelayedCachedOutputStreamCleaner) BUS.getExtension(CachedOutputStreamCleaner.class)).forceClean();
        }
        for (String message : CLEANER_LOG) {
            if (message != null && message.length() > SPILL_THRESHOLD) {
                throw new AssertionError("the cleaner logged " + message.length()
                        + " characters in one message");
            }
        }
    }

    /**
     * CachedOutputStream.write(byte[], int, int).
     *
     * Input: first byte = chunk size (0 is treated as 1), remaining bytes = payload,
     * written in chunks of that size to a default CachedOutputStream.
     */
    @Fuzz
    public void fuzzCachedOutputStreamWriteRange(InputStream input) throws IOException {
        writeInChunks(input.readAllBytes());
    }

    /**
     * CachedOutputStream.toString().
     *
     * Input: the whole input is written to a default CachedOutputStream, then
     * toString() is called.
     */
    @Fuzz
    public void fuzzCachedOutputStreamToString(InputStream input) throws IOException {
        byte[] raw = input.readAllBytes();
        try (CachedOutputStream cos = new CachedOutputStream()) {
            cos.write(raw);
            cos.flush();
            cos.toString();
        }
    }

    /**
     * CachedOutputStream.write(byte[], int, int), the same input model as fuzzCachedOutputStreamWriteRange.
     *
     * Input: first byte = chunk size (0 is treated as 1), remaining bytes = payload,
     * written in chunks of that size to a default CachedOutputStream.
     */
    @Fuzz
    public void fuzzCachedOutputStreamWriteChunks(InputStream input) throws IOException {
        writeInChunks(input.readAllBytes());
    }

    private static void writeInChunks(byte[] raw) throws IOException {
        if (raw.length < 2) {
            return;
        }
        int chunkSize = Math.max(1, raw[0] & 0xFF);
        try (CachedOutputStream cos = new CachedOutputStream()) {
            for (int off = 1; off < raw.length; off += chunkSize) {
                cos.write(raw, off, Math.min(chunkSize, raw.length - off));
            }
            cos.flush();
        }
    }
}
