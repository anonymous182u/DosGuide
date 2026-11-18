package com.fuzzer.guidance;

import com.fuzzer.agent.V1Counters;
import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * Custom Guidance for target V1: Deflate decompression bomb causing DOM memory
 * exhaustion in SAML redirect binding parsing (CWE-409).
 *
 * Strategy: VDF + DAG — maximizes the decompressedBytes signal measured by
 * the Java agent instrumenting DeflateUtil.decode().
 *
 * Input model [R25][R31]: The Guidance operates on XML plaintext internally
 * and encodes it via DEFLATE [R45c] before returning raw compressed bytes
 * as an InputStream. The harness base64-encodes them, the library decodes
 * and decompresses, then DOM-parses the result.
 *
 * Mutation [R45]: repetition (a), dictionary from attack path source (b),
 * DEFLATE encoder (c), plus byte-level and cross-splice operators.
 *
 * Key design: bestInner is tracked as a dedicated field OUTSIDE the corpus
 * and is NEVER subject to eviction. 70% of iterations double bestInner via
 * the repetition operator, chaining doublings exponentially. From "&lt;a/&gt;"
 * (4 bytes), 23 doublings yield ~32 MB plaintext which compresses to ~30 KB,
 * exceeding input_bytes (25600) in under 5 seconds.
 *
 * The Guidance never declares failures and never writes failure files [R6].
 */
public class V1Guidance implements Guidance, SignalSource {

    // ---- Configuration ----
    private final int maxInputSize;
    private final long maxDurationMs;
    private final File outputDir;
    private final PrintStream log;
    private final Random random = new Random();

    // ---- Corpus for diversity mutations ----
    private final List<byte[]> corpus = new ArrayList<>();
    private static final int MAX_CORPUS_SIZE = 50;
    /** Corpus entries larger than this are not stored (bestInner handles growth). */
    private static final int MAX_CORPUS_ENTRY_SIZE = 65536;

    /** Seed inner content: a single self-closing XML element. NOT an exploit [R23]. */
    private static final byte[] SEED_INNER =
            "<a/>".getBytes(StandardCharsets.UTF_8);

    // ---- Best-so-far inner content (NEVER evicted, tracked outside corpus) ----
    /**
     * The inner content that produced the best signal or largest compressed size.
     * Tracked as a dedicated field — never subject to corpus eviction.
     * 70% of iterations use this as the base for the repetition operator,
     * ensuring exponential growth chains without interruption.
     */
    private byte[] bestInner = SEED_INNER.clone();

    /** Best decompressedBytes signal observed so far. */
    private long bestSignal = 0;

    /** Largest compressed output size achieved so far. */
    private int bestCompressedSize = 0;

    // ---- Dictionary tokens from the attack path source code [R45b] ----
    // Tokens are syntactic units found in the SAML/XML parser source:
    // DeflateUtil, DocumentUtil, RedirectBindingUtil, SAMLRequestParser
    private static final byte[][] DICT_TOKENS = {
        "<a/>".getBytes(StandardCharsets.UTF_8),   // self-closing element (DOM amplifier)
        "<b/>".getBytes(StandardCharsets.UTF_8),   // variant element name
        "<c/>".getBytes(StandardCharsets.UTF_8),   // variant element name
        "<r>".getBytes(StandardCharsets.UTF_8),    // root open tag
        "</r>".getBytes(StandardCharsets.UTF_8),   // root close tag
        " ".getBytes(StandardCharsets.UTF_8),      // whitespace (XML inter-element)
        "\n".getBytes(StandardCharsets.UTF_8),     // newline separator
    };

    // ---- XML wrapper bytes ----
    private static final byte[] XML_PREFIX = "<r>".getBytes(StandardCharsets.UTF_8);
    private static final byte[] XML_SUFFIX = "</r>".getBytes(StandardCharsets.UTF_8);

    // ---- Execution state ----
    private long startTimeMs;
    private long totalExecs;

    /** Signal from the most recent execution (per-execution, not cumulative) [SignalSource]. */
    private volatile double lastDecompressedBytes;

    /** Inner content of the current execution (for retention). */
    private byte[] currentInner;
    /** Compressed bytes of the current execution (for saveBest). */
    private byte[] currentCompressed;
    /** Compressed size of the current execution's input. */
    private int currentCompressedSize;
    /** Wall-clock of last log emission. */
    private long lastLogTimeMs;

    /**
     * @param outputDir   corpus output directory (out/V1/)
     * @param maxDurationMs  maximum fuzzing duration in ms (0 = infinite) [R8]
     * @param log         log stream for structured logging [R5]
     */
    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.outputDir = outputDir;
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        // Read max input size from system property set by DoSGuide [R41]
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = startTimeMs;

        // Initialize corpus with seed [R23]: not an exploit, just a starting point
        corpus.add(SEED_INNER.clone());

        // Create corpus directory
        new File(outputDir, "corpus").mkdirs();
    }

    // ======== Guidance interface ========

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset decompressed-byte counter before each execution [R24]
        V1Counters.reset();
        totalExecs++;

        byte[] inner;
        double r = random.nextDouble();

        if (r < 0.70) {
            // [R45a] Repetition on bestInner — chain doublings for exponential growth.
            // bestInner is NEVER evicted from the corpus, so each successful doubling
            // chains directly into the next. From "<a/>" (4 bytes), 23 doublings
            // reach ~32 MB plaintext = ~30 KB compressed > input_bytes (25600).
            try {
                inner = repeat(bestInner);
            } catch (OutOfMemoryError oom) {
                // Allocation too large for current heap — fall back to small corpus entry
                inner = corpus.get(random.nextInt(corpus.size())).clone();
            }
        } else if (r < 0.85) {
            // [R45b] Dictionary insert on corpus entry — diversity
            byte[] base = corpus.get(random.nextInt(corpus.size()));
            inner = dictInsert(base);
        } else if (r < 0.95) {
            // Byte-level mutation on corpus entry — diversity
            byte[] base = corpus.get(random.nextInt(corpus.size()));
            inner = byteMutate(base);
        } else {
            // Cross-splice — diversity
            byte[] base = corpus.get(random.nextInt(corpus.size()));
            inner = crossSplice(base);
        }

        // Cap inner size to avoid OOM in the Guidance itself
        // Conservative: maxInputSize * 1100 based on measured ~1000:1 compression ratio
        int maxPlaintext = maxInputSize * 1100;
        if (maxPlaintext < 0) maxPlaintext = Integer.MAX_VALUE / 2; // overflow guard
        if (inner.length > maxPlaintext) {
            inner = Arrays.copyOf(inner, maxPlaintext);
        }

        // Wrap in root XML tags and compress with DEFLATE [R45c]
        byte[] xml = wrapXml(inner);
        byte[] compressed;
        try {
            compressed = deflateCompress(xml);
        } catch (OutOfMemoryError oom) {
            // Compression OOM (huge plaintext) — fall back to seed
            inner = SEED_INNER.clone();
            xml = wrapXml(inner);
            compressed = deflateCompress(xml);
        }

        // Shrink if compressed exceeds maxInputSize
        while (compressed.length > maxInputSize && inner.length > 4) {
            inner = Arrays.copyOf(inner, (int) (inner.length * 0.75));
            xml = wrapXml(inner);
            compressed = deflateCompress(xml);
        }

        // Final hard truncate (for very small maxInputSize)
        if (compressed.length > maxInputSize) {
            compressed = Arrays.copyOf(compressed, maxInputSize);
        }

        this.currentInner = inner;
        this.currentCompressed = compressed;
        this.currentCompressedSize = compressed.length;

        return new ByteArrayInputStream(compressed);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs > 0) {
            return System.currentTimeMillis() - startTimeMs < maxDurationMs;
        }
        return true; // infinite [R8]
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        // Read the actual decompressed-byte signal from the agent [R24][R30]
        long decompressed = V1Counters.getDecompressedBytes();
        // Store per-execution value for SignalSource contract
        this.lastDecompressedBytes = (double) decompressed;

        // ---- Retention logic [R46] ----
        boolean retained = false;

        // Primary: maximize decompressedBytes (the DoS amplification signal)
        if (decompressed > bestSignal) {
            bestSignal = decompressed;
            bestInner = currentInner; // safe — currentInner overwritten next getInput()
            saveBest();
            if (currentInner.length <= MAX_CORPUS_ENTRY_SIZE) {
                addToCorpus(currentInner);
            }
            retained = true;
        }

        // Secondary [R46]: track best compressed size for monitoring.
        // IMPORTANT: Do NOT update bestInner here. Diversity mutations (byte flips,
        // dict insertions) produce non-repetitive content that compresses poorly
        // (ratio ~3:1 vs ~1000:1 for repetitive <a/>). Their compressed output is
        // LARGER than the repeat path's output at the same plaintext size, so they
        // would win the compressed-size comparison and pollute bestInner with
        // non-repetitive content, breaking the repeat-doubling chain and destroying
        // the decompression amplification ratio that the scale series depends on.
        // bestInner is ONLY updated by primary retention (signal improvement).
        if (currentCompressedSize > bestCompressedSize) {
            bestCompressedSize = currentCompressedSize;
            if (!retained && currentInner.length <= MAX_CORPUS_ENTRY_SIZE) {
                addToCorpus(currentInner);
                retained = true;
            }
        }

        // Tertiary: random keep for diversity (1%)
        if (!retained && random.nextDouble() < 0.01
                && currentInner.length <= MAX_CORPUS_ENTRY_SIZE) {
            addToCorpus(currentInner);
        }

        // Structured log every 1 second [R5]
        maybeLog();
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No coverage feedback needed — VDF strategy uses decompressedBytes signal only
        return (event) -> { };
    }

    // ======== SignalSource interface ========

    @Override
    public Map<String, Double> lastSignals() {
        // Per-execution value, not running total or best-so-far
        return Collections.singletonMap("decompressedBytes", lastDecompressedBytes);
    }

    // ======== Mutation operators ========

    /**
     * [R45a] Repetition: double the inner content to grow element count
     * exponentially. Each doubling doubles the decompressed XML size while
     * adding only a few bytes to the compressed DEFLATE output (LZ77 back-refs).
     * From seed "&lt;a/&gt;" (4 bytes), 23 doublings reach ~33 MB plaintext = ~33 KB
     * compressed, exceeding input_bytes (25600) in well under a minute [R46].
     */
    private byte[] repeat(byte[] inner) {
        if (inner.length == 0) return SEED_INNER.clone();

        long targetLen = (long) inner.length * 2;
        int maxPlaintext = maxInputSize * 1100;
        if (maxPlaintext < 0) maxPlaintext = Integer.MAX_VALUE / 2;

        if (targetLen > maxPlaintext) {
            targetLen = maxPlaintext;
        }
        if (targetLen > Integer.MAX_VALUE - 16) {
            targetLen = Integer.MAX_VALUE - 16;
        }

        byte[] result = new byte[(int) targetLen];
        int filled = 0;
        while (filled + inner.length <= result.length) {
            System.arraycopy(inner, 0, result, filled, inner.length);
            filled += inner.length;
        }
        if (filled == 0) {
            return inner.clone();
        }
        return filled < result.length ? Arrays.copyOf(result, filled) : result;
    }

    /**
     * [R45b] Dictionary: insert an XML token from the attack-path source code
     * at a random position in the inner content. Tokens are syntactic units
     * (element tags, delimiters) found in DeflateUtil, DocumentUtil, etc.
     */
    private byte[] dictInsert(byte[] inner) {
        byte[] token = DICT_TOKENS[random.nextInt(DICT_TOKENS.length)];
        int pos = random.nextInt(inner.length + 1);
        byte[] result = new byte[inner.length + token.length];
        System.arraycopy(inner, 0, result, 0, pos);
        System.arraycopy(token, 0, result, pos, token.length);
        System.arraycopy(inner, pos, result, pos + token.length, inner.length - pos);
        return result;
    }

    /** Byte-level mutation: flip 1-4 random bytes for diversity. */
    private byte[] byteMutate(byte[] inner) {
        byte[] result = inner.clone();
        int mutations = 1 + random.nextInt(4);
        for (int i = 0; i < mutations; i++) {
            int pos = random.nextInt(result.length);
            result[pos] = (byte) random.nextInt(256);
        }
        return result;
    }

    /** Cross-splice: take a chunk from another corpus entry and insert it. */
    private byte[] crossSplice(byte[] inner) {
        if (corpus.size() < 2) return repeat(inner);
        byte[] other = corpus.get(random.nextInt(corpus.size()));
        if (other.length == 0) return inner.clone();

        int chunkStart = random.nextInt(other.length);
        int chunkLen = 1 + random.nextInt(Math.min(other.length - chunkStart, 256));
        int insertPos = random.nextInt(inner.length + 1);

        byte[] result = new byte[inner.length + chunkLen];
        System.arraycopy(inner, 0, result, 0, insertPos);
        System.arraycopy(other, chunkStart, result, insertPos, chunkLen);
        System.arraycopy(inner, insertPos, result, insertPos + chunkLen,
                         inner.length - insertPos);
        return result;
    }

    // ======== Helpers ========

    /**
     * [R45c] Encoder: compress XML plaintext with raw DEFLATE (nowrap=true),
     * matching the target's Inflater(true) in DeflateUtil.decode().
     */
    private static byte[] deflateCompress(byte[] plaintext) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater);
            dos.write(plaintext);
            dos.finish();
            dos.close();
            deflater.end();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("DEFLATE compression failed", e);
        }
    }

    /** Wrap inner content in root XML element: &lt;r&gt;INNER&lt;/r&gt; */
    private static byte[] wrapXml(byte[] inner) {
        byte[] result = new byte[XML_PREFIX.length + inner.length + XML_SUFFIX.length];
        System.arraycopy(XML_PREFIX, 0, result, 0, XML_PREFIX.length);
        System.arraycopy(inner, 0, result, XML_PREFIX.length, inner.length);
        System.arraycopy(XML_SUFFIX, 0, result, XML_PREFIX.length + inner.length,
                         XML_SUFFIX.length);
        return result;
    }

    /** Add an inner-content entry to the corpus, evicting if full. */
    private void addToCorpus(byte[] inner) {
        if (inner == null) return;
        if (corpus.size() >= MAX_CORPUS_SIZE) {
            // Evict a random entry (not the first = seed)
            int idx = 1 + random.nextInt(corpus.size() - 1);
            corpus.remove(idx);
        }
        corpus.add(inner.clone());
    }

    /** Save the best compressed artifact to the corpus directory for reproduction. */
    private void saveBest() {
        if (currentCompressed == null) return;
        try {
            File corpusDir = new File(outputDir, "corpus");
            try (FileOutputStream fos = new FileOutputStream(new File(corpusDir, "best.bin"))) {
                fos.write(currentCompressed);
            }
        } catch (IOException ignored) {
            // Best-effort save; do not fail the fuzzer
        }
    }

    /** Structured logging every 1 second [R5]. */
    private void maybeLog() {
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            lastLogTimeMs = now;
            long elapsed = (now - startTimeMs) / 1000;
            log.printf("[V1] t=%ds execs=%d corpus=%d best_signal=%d "
                            + "best_comp=%d last_decomp=%.0f input_sz=%d bestInner=%d%n",
                    elapsed, totalExecs, corpus.size(), bestSignal,
                    bestCompressedSize, lastDecompressedBytes,
                    currentCompressedSize, bestInner.length);
        }
    }
}
