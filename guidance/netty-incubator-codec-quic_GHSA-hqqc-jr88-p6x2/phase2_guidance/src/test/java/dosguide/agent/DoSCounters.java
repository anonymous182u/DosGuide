package dosguide.agent;

/**
 * Measurement-only counters written by bytecode injected by {@link DoSMeasureAgent}.
 *
 * <p>When the agent is attached, this class is loaded by the bootstrap class loader (the agent appends a
 * jar containing only this class to the bootstrap search path before anything loads it), so that code
 * inside {@code java.util.HashMap$TreeNode} and {@code java.nio.ByteBuffer} can call it, and the
 * application class loader (parent-first) resolves the very same class for the Guidance.</p>
 *
 * <p>Without the agent the class is loaded from target/test-classes and all counters stay 0.</p>
 *
 * <p>Must not use any JDK collection or ByteBuffer method: it is called from inside HashMap/ByteBuffer.</p>
 */
public final class DoSCounters {

    private DoSCounters() {
    }

    /** Set by the agent once instrumentation is installed. */
    public static volatile boolean agentActive;
    /** Number of classes the agent rewrote. */
    public static volatile int transformedClasses;

    /** The thread whose execution is measured (set by reset). Other threads are ignored. */
    public static volatile Thread owner;

    // ---- scopes ----
    /** depth of QuicheQuicCodec#getChannel frames. */
    public static int v1Scope;
    /** depth of QuicheQuicCodec#addChannel frames. */
    public static int addScope;
    /** depth of HashMap$TreeNode#putTreeVal frames. */
    public static int putScope;

    // ---- V1 (lookup sink: QuicheQuicCodec#getChannel) ----
    public static long v1TreeVisits;
    public static long v1KeyEquals;
    public static long v1MaxPerLookup;
    private static long v1Mark;

    // ---- PkgRisk1 (insertion sink: HashMap$TreeNode#find under putTreeVal under addChannel) ----
    public static long p1TreeVisits;
    public static long p1KeyEquals;
    public static long p1Treeify;

    // ---- shared ----
    public static long channelsAdded;
    /** bytes of datagram content received by QuicheQuicCodec#channelRead (denominator of p1VisitsPerKB). */
    public static long datagramBytes;
    /** names of the classes the agent rewrote (diagnostics). */
    public static volatile String transformedNames = "";

    // ---- hook: QuicheQuicCodec#channelRead ----
    public static void onDatagramBytes(int n) {
        if (owner == null || !mine()) {
            return;
        }
        datagramBytes += n;
    }

    /** Resets all per-execution counters and binds them to the given thread. */
    public static void reset(Thread t) {
        owner = t;
        v1Scope = 0;
        addScope = 0;
        putScope = 0;
        v1TreeVisits = 0;
        v1KeyEquals = 0;
        v1MaxPerLookup = 0;
        v1Mark = 0;
        p1TreeVisits = 0;
        p1KeyEquals = 0;
        p1Treeify = 0;
        channelsAdded = 0;
        datagramBytes = 0;
    }

    private static boolean mine() {
        return Thread.currentThread() == owner;
    }

    // ---- hooks: QuicheQuicCodec#getChannel ----
    public static void v1Enter() {
        if (!mine()) {
            return;
        }
        if (v1Scope++ == 0) {
            v1Mark = v1TreeVisits;
        }
    }

    public static void v1Exit() {
        if (!mine()) {
            return;
        }
        if (v1Scope > 0 && --v1Scope == 0) {
            long d = v1TreeVisits - v1Mark;
            if (d > v1MaxPerLookup) {
                v1MaxPerLookup = d;
            }
        }
    }

    // ---- hooks: QuicheQuicCodec#addChannel ----
    public static void addEnter() {
        if (!mine()) {
            return;
        }
        addScope++;
        channelsAdded++;
    }

    public static void addExit() {
        if (!mine()) {
            return;
        }
        if (addScope > 0) {
            addScope--;
        }
    }

    // ---- hooks: HashMap$TreeNode#putTreeVal ----
    public static void putEnter() {
        if (owner == null || !mine()) {
            return;
        }
        putScope++;
    }

    public static void putExit() {
        if (owner == null || !mine()) {
            return;
        }
        if (putScope > 0) {
            putScope--;
        }
    }

    // ---- hook: HashMap$TreeNode#find, once per node visited (read of TreeNode.hash) ----
    public static void onTreeVisit() {
        if (owner == null || !mine()) {
            return;
        }
        if (v1Scope > 0) {
            v1TreeVisits++;
        }
        if (addScope > 0 && putScope > 0) {
            p1TreeVisits++;
        }
    }

    // ---- hook: HashMap$TreeNode#treeify ----
    public static void onTreeify() {
        if (owner == null || !mine()) {
            return;
        }
        if (addScope > 0) {
            p1Treeify++;
        }
    }

    // ---- hook: ByteBuffer#equals ----
    public static void onKeyEquals() {
        if (owner == null || !mine()) {
            return;
        }
        if (v1Scope > 0) {
            v1KeyEquals++;
        }
        if (addScope > 0) {
            p1KeyEquals++;
        }
    }
}
