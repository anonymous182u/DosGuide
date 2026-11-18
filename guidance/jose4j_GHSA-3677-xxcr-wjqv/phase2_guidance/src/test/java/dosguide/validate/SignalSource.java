package dosguide.validate;

import java.util.Map;

/**
 * Implemented by every synthesized Guidance so that ValidateArtifact can read its signal.
 * Copied into the run directory by DoSGuide; do not modify.
 */
public interface SignalSource {

    /**
     * The signal values measured during the most recent execution, read after
     * {@code handleResult}: one entry per measured quantity, e.g. {@code {"allocBytes": 4096.0}}.
     * Return the value of that execution only, not a running total or a best-so-far value.
     */
    Map<String, Double> lastSignals();
}
