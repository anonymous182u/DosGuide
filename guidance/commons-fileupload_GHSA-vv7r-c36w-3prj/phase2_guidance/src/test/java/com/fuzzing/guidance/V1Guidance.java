package com.fuzzing.guidance;

import com.fuzzing.agent.V1Counters;
import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

/**
 * Coverage-guided fuzzing guidance for target V1 (readHeaders oversized header).
 *
 * Signals:
 *   boundaryIterations — readBoundary() call count
 *   headerBytes        — readByte() calls while inside readHeaders()
 *   multipartWork      — 0.5*(boundaryIterations/10) + 0.5*(headerBytes/512)
 *
 * Retention: keep if multipartWork exceeds corpus max.
 * Secondary (while flat): grow input length toward the input size limit.
 *
 * Mutation: byte-flip, byte-insert, byte-delete, byte-overwrite, havoc,
 *           repetition, dictionary-insert, splice, header-grow.
 *
 * Seeds: well-formed multipart inputs that reach readHeaders from the start.
 */
public class V1Guidance implements Guidance, SignalSource {

    /* ------------------------------------------------------------------ */
    /*  Configuration                                                      */
    /* ------------------------------------------------------------------ */
    private final File outputDir;
    private final long maxDurationMs;
    private final PrintStream log;
    private final int maxInputSize;
    private final long startTimeMs;

    /* ------------------------------------------------------------------ */
    /*  Corpus                                                             */
    /* ------------------------------------------------------------------ */
    private final List<CorpusEntry> corpus = new ArrayList<>();
    private final Random rng = new Random();
    private double maxMultipartWork = 0.0;
    private long maxCorpusLength   = 0;

    /* ------------------------------------------------------------------ */
    /*  Seed queue: served unmutated before switching to mutation           */
    /* ------------------------------------------------------------------ */
    private final Deque<byte[]> pendingSeeds = new ArrayDeque<>();

    /* ------------------------------------------------------------------ */
    /*  Current execution                                                  */
    /* ------------------------------------------------------------------ */
    private byte[] currentInput;
    private long executions = 0;
    private int retainedCount = 0;

    /* ------------------------------------------------------------------ */
    /*  Signal snapshot (for SignalSource)                                  */
    /* ------------------------------------------------------------------ */
    private final Map<String, Double> lastSignalsMap = new LinkedHashMap<>();

    /* ------------------------------------------------------------------ */
    /*  Constants                                                           */
    /* ------------------------------------------------------------------ */
    private static final double ALPHA = 0.5;
    private static final double BETA  = 0.5;
    private static final double B_REF = 10.0;   // boundary-iterations reference
    private static final double H_REF = 512.0;  // header-bytes reference (PART_HEADER_SIZE_MAX)

    /** Dictionary tokens extracted from the MultipartStream protocol. */
    private static final byte[][] DICT_TOKENS = {
        {0x0D},                             // CR
        {0x0A},                             // LF
        {0x0D, 0x0A},                       // CRLF
        {0x0D, 0x0A, 0x0D, 0x0A},           // CRLFCRLF
        {0x2D, 0x2D},                       // DASHDASH (--)
        {0x0D, 0x0A, 0x2D, 0x2D},           // CRLF-DASHDASH (\r\n--)
        {0x3A},                             // COLON (:)
        {0x20},                             // SPACE
    };

    /* ================================================================== */

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.outputDir     = outputDir;
        this.maxDurationMs = maxDurationMs;
        this.log           = log;
        this.maxInputSize  = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.startTimeMs   = System.currentTimeMillis();

        outputDir.mkdirs();
        buildSeeds();
    }

    /* ------------------------------------------------------------------ */
    /*  Seed generation: well-formed multipart inputs                      */
    /* ------------------------------------------------------------------ */

    /**
     * Build a one-part multipart input.
     * Format: boundary + LF + "--" + boundary + CRLF + headerContent + CRLF CRLF
     * headerContent may be empty; if non-empty it should NOT end with CRLF
     * (the method adds the CRLF before the terminator blank line).
     */
    private static byte[] buildSeed(String boundary, String headerContent) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(boundary.getBytes(StandardCharsets.ISO_8859_1));
            bos.write('\n');                     // end of boundary line
            bos.write('-'); bos.write('-');       // delimiter dash-dash
            bos.write(boundary.getBytes(StandardCharsets.ISO_8859_1));
            bos.write('\r'); bos.write('\n');     // delimiter CRLF
            // Header content (may be empty string = zero bytes written)
            bos.write(headerContent.getBytes(StandardCharsets.ISO_8859_1));
            // Always write CRLFCRLF: the header terminator that readHeaders
            // scans for.  For non-empty content the first CRLF also serves as
            // the last header-line ending.
            bos.write('\r'); bos.write('\n');
            bos.write('\r'); bos.write('\n');
        } catch (IOException ignored) { }
        return bos.toByteArray();
    }

    /**
     * Build a two-part multipart input (exercises readBoundary).
     */
    private static byte[] buildTwoPartSeed(String boundary,
                                            String hdr1, String hdr2) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] bnd = boundary.getBytes(StandardCharsets.ISO_8859_1);
        try {
            bos.write(bnd);
            bos.write('\n');
            // Part 1 delimiter
            bos.write('-'); bos.write('-');
            bos.write(bnd);
            bos.write('\r'); bos.write('\n');
            // Part 1 header + CRLFCRLF terminator
            bos.write(hdr1.getBytes(StandardCharsets.ISO_8859_1));
            bos.write('\r'); bos.write('\n');
            bos.write('\r'); bos.write('\n');
            // Part 1 body (empty) → next boundary
            bos.write('\r'); bos.write('\n');
            bos.write('-'); bos.write('-');
            bos.write(bnd);
            bos.write('\r'); bos.write('\n');
            // Part 2 header + CRLFCRLF terminator
            bos.write(hdr2.getBytes(StandardCharsets.ISO_8859_1));
            bos.write('\r'); bos.write('\n');
            bos.write('\r'); bos.write('\n');
            // Part 2 body (empty) → close delimiter
            bos.write('\r'); bos.write('\n');
            bos.write('-'); bos.write('-');
            bos.write(bnd);
            bos.write('-'); bos.write('-');
        } catch (IOException ignored) { }
        return bos.toByteArray();
    }

    /**
     * Populate the pending-seeds queue with well-formed multipart inputs
     * of varying sizes, all within the current maxInputSize.
     */
    private void buildSeeds() {
        // Smallest possible: boundary "B", empty header → 11 bytes
        addSeedIfFits(buildSeed("B", ""));
        // Small header → 14 bytes
        addSeedIfFits(buildSeed("B", "K:V"));
        // Medium header
        addSeedIfFits(buildSeed("AB", "Name: Value"));
        // Multiple header lines (uses literal \r\n in the string for line breaks)
        addSeedIfFits(buildSeed("XY", "A: B\r\nC: D"));
        // Two-part input exercising readBoundary
        addSeedIfFits(buildTwoPartSeed("B", "K:V", "X:Y"));
        // Longer header approaching typical sizes
        addSeedIfFits(buildSeed("BND",
                "Content-Disposition: form-data\r\n" +
                "Content-Type: text/plain"));
    }

    private void addSeedIfFits(byte[] seed) {
        if (seed.length <= maxInputSize) {
            pendingSeeds.add(seed);
        }
    }

    /* ================================================================== */
    /*  Guidance interface                                                 */
    /* ================================================================== */

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        V1Counters.reset();
        executions++;

        if (!pendingSeeds.isEmpty()) {
            // Serve well-formed seeds first (unmutated)
            currentInput = pendingSeeds.poll();
        } else if (corpus.isEmpty()) {
            // Fallback: minimal valid multipart
            currentInput = buildSeed("B", "");
        } else {
            CorpusEntry parent = selectParent();
            currentInput = mutate(parent.input);
        }

        // Enforce max input size
        if (currentInput.length > maxInputSize) {
            currentInput = Arrays.copyOf(currentInput, maxInputSize);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        // Read counters from agent instrumentation
        long boundaryIterations = V1Counters.getBoundaryIterations();
        long headerBytes        = V1Counters.getHeaderBytes();

        // Compute composite signal
        double multipartWork = ALPHA * (boundaryIterations / B_REF)
                             + BETA  * (headerBytes / H_REF);

        // Snapshot signals for SignalSource
        lastSignalsMap.clear();
        lastSignalsMap.put("boundaryIterations", (double) boundaryIterations);
        lastSignalsMap.put("headerBytes",        (double) headerBytes);
        lastSignalsMap.put("multipartWork",      multipartWork);

        // --- Retention decisions ---
        // [R6] We never decide an execution "failed"; all results are treated equally.
        boolean retain = false;

        // Primary: keep if multipartWork exceeds corpus maximum
        if (multipartWork > maxMultipartWork) {
            retain = true;
            maxMultipartWork = multipartWork;
        }

        // Secondary (while multipartWork is flat): grow input length
        if (!retain && currentInput != null) {
            int len = currentInput.length;
            // Retain if longer than longest in corpus
            if (len > maxCorpusLength) {
                retain = true;
            }
            // 10 % chance: retain if longer than a randomly chosen corpus member
            if (!retain && !corpus.isEmpty() && rng.nextDouble() < 0.10) {
                CorpusEntry randomMember = corpus.get(rng.nextInt(corpus.size()));
                if (len > randomMember.input.length) {
                    retain = true;
                }
            }
        }

        if (retain && currentInput != null) {
            CorpusEntry entry = new CorpusEntry(currentInput.clone(), multipartWork);
            corpus.add(entry);
            if (currentInput.length > maxCorpusLength) {
                maxCorpusLength = currentInput.length;
            }
            retainedCount++;
            saveInput(currentInput, retainedCount, multipartWork);
        }

        // Periodic status
        if (executions % 1000 == 0) {
            long elapsed = System.currentTimeMillis() - startTimeMs;
            log.printf("[V1] exec=%d elapsed=%ds corpus=%d maxWork=%.4f maxLen=%d%n",
                    executions, elapsed / 1000, corpus.size(),
                    maxMultipartWork, maxCorpusLength);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // We use our own javaagent instrumentation, not JQF's tracing.
        return event -> { };
    }

    /* ================================================================== */
    /*  SignalSource interface                                              */
    /* ================================================================== */

    @Override
    public Map<String, Double> lastSignals() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(lastSignalsMap));
    }

    /* ================================================================== */
    /*  Parent selection — proportional to multipartWork                    */
    /* ================================================================== */

    private CorpusEntry selectParent() {
        double totalWork = 0;
        for (CorpusEntry e : corpus) {
            totalWork += e.multipartWork;
        }

        if (totalWork <= 0) {
            // Uniform random when no signal yet
            return corpus.get(rng.nextInt(corpus.size()));
        }

        double pick = rng.nextDouble() * totalWork;
        double running = 0;
        for (CorpusEntry e : corpus) {
            running += e.multipartWork;
            if (running >= pick) return e;
        }
        return corpus.get(corpus.size() - 1);
    }

    /* ================================================================== */
    /*  Mutation operators                                                  */
    /* ================================================================== */

    private byte[] mutate(byte[] parent) {
        int op = rng.nextInt(100);

        if      (op <  10) return byteFlip(parent);
        else if (op <  18) return byteInsert(parent);
        else if (op <  24) return byteDelete(parent);
        else if (op <  34) return byteOverwrite(parent);
        else if (op <  46) return havoc(parent);
        else if (op <  60) return repetition(parent);
        else if (op <  72) return dictionaryInsert(parent);
        else if (op <  82) return splice(parent);
        else               return headerGrow(parent);  // 18 %: structure-aware growth
    }

    /** Flip a random bit in a random byte. */
    private byte[] byteFlip(byte[] input) {
        if (input.length == 0) return input;
        byte[] r = input.clone();
        int pos = rng.nextInt(r.length);
        r[pos] ^= (byte) (1 << rng.nextInt(8));
        return r;
    }

    /** Insert a random byte at a random position. */
    private byte[] byteInsert(byte[] input) {
        if (input.length >= maxInputSize) return byteFlip(input);
        int pos = rng.nextInt(input.length + 1);
        byte[] r = new byte[input.length + 1];
        System.arraycopy(input, 0, r, 0, pos);
        r[pos] = (byte) rng.nextInt(256);
        System.arraycopy(input, pos, r, pos + 1, input.length - pos);
        return r;
    }

    /** Remove a byte at a random position. */
    private byte[] byteDelete(byte[] input) {
        if (input.length <= 1) return input;
        int pos = rng.nextInt(input.length);
        byte[] r = new byte[input.length - 1];
        System.arraycopy(input, 0, r, 0, pos);
        System.arraycopy(input, pos + 1, r, pos, input.length - pos - 1);
        return r;
    }

    /** Replace a byte at a random position with a random value. */
    private byte[] byteOverwrite(byte[] input) {
        if (input.length == 0) return input;
        byte[] r = input.clone();
        r[rng.nextInt(r.length)] = (byte) rng.nextInt(256);
        return r;
    }

    /** Apply 1–8 randomly chosen byte-level mutations in sequence. */
    private byte[] havoc(byte[] input) {
        byte[] r = input.clone();
        int n = 1 + rng.nextInt(8);
        for (int i = 0; i < n; i++) {
            switch (rng.nextInt(4)) {
                case 0: r = byteFlip(r);      break;
                case 1: r = byteInsert(r);     break;
                case 2: r = byteDelete(r);     break;
                case 3: r = byteOverwrite(r);  break;
            }
            if (r.length > maxInputSize) {
                r = Arrays.copyOf(r, maxInputSize);
            }
        }
        return r;
    }

    /**
     * Select a random region (1 byte to half the input), repeat it k times
     * so the result approaches the input size limit.
     */
    private byte[] repetition(byte[] input) {
        if (input.length == 0) return input;
        int regionLen   = 1 + rng.nextInt(Math.max(1, input.length / 2));
        int regionStart = rng.nextInt(input.length);
        regionLen = Math.min(regionLen, input.length - regionStart);

        byte[] region = Arrays.copyOfRange(input, regionStart, regionStart + regionLen);

        int remaining = maxInputSize - input.length;
        int k = (remaining > 0 && regionLen > 0)
                ? Math.max(2, remaining / regionLen + 1)
                : 2;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(input, 0, regionStart + regionLen);
            for (int i = 1; i < k; i++) {
                bos.write(region);
                if (bos.size() >= maxInputSize) break;
            }
            if (regionStart + regionLen < input.length) {
                bos.write(input, regionStart + regionLen,
                        input.length - regionStart - regionLen);
            }
        } catch (IOException ignored) { }

        byte[] r = bos.toByteArray();
        if (r.length > maxInputSize) r = Arrays.copyOf(r, maxInputSize);
        return r;
    }

    /**
     * Insert or overwrite one of the 8 dictionary tokens at a random position.
     */
    private byte[] dictionaryInsert(byte[] input) {
        byte[] token = DICT_TOKENS[rng.nextInt(DICT_TOKENS.length)];

        if (input.length + token.length > maxInputSize) {
            // Overwrite instead of insert
            if (input.length == 0) return token.length <= maxInputSize ? token.clone() : input;
            byte[] r = input.clone();
            int pos = rng.nextInt(Math.max(1, r.length - token.length + 1));
            int copyLen = Math.min(token.length, r.length - pos);
            System.arraycopy(token, 0, r, pos, copyLen);
            return r;
        }

        int pos = rng.nextInt(input.length + 1);
        byte[] r = new byte[input.length + token.length];
        System.arraycopy(input, 0, r, 0, pos);
        System.arraycopy(token, 0, r, pos, token.length);
        System.arraycopy(input, pos, r, pos + token.length, input.length - pos);
        return r;
    }

    /** Take a prefix of one corpus parent and a suffix of another at random cut points. */
    private byte[] splice(byte[] parent) {
        if (corpus.size() < 2) return byteFlip(parent);

        CorpusEntry other = corpus.get(rng.nextInt(corpus.size()));
        byte[] otherInput = other.input;

        if (parent.length == 0 || otherInput.length == 0) return byteFlip(parent);

        int cut1 = rng.nextInt(parent.length);
        int cut2 = rng.nextInt(otherInput.length);

        int newLen = Math.min(cut1 + (otherInput.length - cut2), maxInputSize);
        if (newLen <= 0) return parent;

        byte[] r = new byte[newLen];
        int prefixLen = Math.min(cut1, newLen);
        System.arraycopy(parent, 0, r, 0, prefixLen);
        int suffixLen = newLen - prefixLen;
        int available  = otherInput.length - cut2;
        if (suffixLen > 0 && available > 0) {
            System.arraycopy(otherInput, cut2, r, prefixLen,
                    Math.min(available, suffixLen));
        }
        return r;
    }

    /**
     * Structure-aware header growth: find the CRLFCRLF header terminator in
     * the parent and insert random content just before it, keeping the
     * boundary line and delimiter intact.  This directly grows the header
     * section that readHeaders() scans.
     */
    private byte[] headerGrow(byte[] input) {
        // Find the CRLFCRLF header terminator
        int termPos = findHeaderTerminator(input);
        if (termPos < 0) {
            // No recognisable structure — fall back to repetition
            return repetition(input);
        }

        // How many bytes can we insert?
        int room = maxInputSize - input.length;
        if (room <= 0) {
            // Already at max size — overwrite a random header byte
            return byteOverwrite(input);
        }

        // Insert 1 .. room random content bytes just before the terminator
        int insertLen = 1 + rng.nextInt(Math.min(room, 256));
        byte[] filler = new byte[insertLen];
        rng.nextBytes(filler);
        // Avoid accidental CRLFCRLF in filler (would create a premature terminator)
        for (int i = 0; i < filler.length; i++) {
            if (filler[i] == 0x0D || filler[i] == 0x0A) {
                filler[i] = (byte) (0x41 + rng.nextInt(26)); // replace with A-Z
            }
        }

        byte[] r = new byte[input.length + insertLen];
        System.arraycopy(input, 0, r, 0, termPos);
        System.arraycopy(filler, 0, r, termPos, insertLen);
        System.arraycopy(input, termPos, r, termPos + insertLen,
                input.length - termPos);

        if (r.length > maxInputSize) r = Arrays.copyOf(r, maxInputSize);
        return r;
    }

    /**
     * Scan for the first occurrence of CRLFCRLF (0D 0A 0D 0A) in the input.
     * Returns the byte offset of the first CR, or -1 if not found.
     */
    private static int findHeaderTerminator(byte[] input) {
        for (int i = 0; i <= input.length - 4; i++) {
            if (input[i]     == 0x0D && input[i + 1] == 0x0A
             && input[i + 2] == 0x0D && input[i + 3] == 0x0A) {
                return i;
            }
        }
        return -1;
    }

    /* ================================================================== */
    /*  Persistence                                                        */
    /* ================================================================== */

    private void saveInput(byte[] input, int id, double work) {
        try {
            File f = new File(outputDir, String.format("id_%06d.bin", id));
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(input);
            }
            File meta = new File(outputDir, String.format("id_%06d.meta", id));
            try (PrintWriter pw = new PrintWriter(meta)) {
                pw.printf("multipartWork=%.6f%n", work);
                pw.printf("length=%d%n", input.length);
                pw.printf("executions=%d%n", executions);
            }
        } catch (IOException e) {
            log.println("[V1] Failed to save input: " + e.getMessage());
        }
    }

    /* ================================================================== */
    /*  Corpus entry                                                       */
    /* ================================================================== */

    private static final class CorpusEntry {
        final byte[] input;
        final double multipartWork;

        CorpusEntry(byte[] input, double multipartWork) {
            this.input         = input;
            this.multipartWork = multipartWork;
        }
    }
}
