package dosguide.agent;

/**
 * A {@link CharSequence} wrapper that counts {@code charAt()} accesses.
 * Each access approximates one regex-engine node evaluation or
 * backtracking step (R36 — mechanism-aligned instrumentation for
 * CWE-1333 regex backtracking).
 *
 * <p>The agent instruments
 * {@code BeginningOrEndMatchTransorm#transform(String)} to wrap the
 * {@code CharSequence} argument of {@code Pattern.matcher()} with this
 * proxy <em>before</em> the matcher runs.  Every subsequent character
 * read by the regex engine increments {@link V2Counter#findNanos}.
 */
public final class CharSequenceProxy implements CharSequence {

    private final CharSequence delegate;

    public CharSequenceProxy(CharSequence delegate) {
        this.delegate = delegate;
    }

    @Override
    public int length() {
        return delegate.length();
    }

    @Override
    public char charAt(int index) {
        V2Counter.increment();           // one regex-VM step
        return delegate.charAt(index);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return new CharSequenceProxy(delegate.subSequence(start, end));
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    /**
     * Called by instrumented bytecode just before
     * {@code Pattern.matcher(CharSequence)}.  Returns a counting proxy
     * unless the input is already wrapped.
     */
    public static CharSequence wrap(CharSequence cs) {
        if (cs instanceof CharSequenceProxy) return cs;
        return new CharSequenceProxy(cs);
    }
}
