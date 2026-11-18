package dosguide.replay;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.agent.SignalCollector;
import dosguide.validate.SignalSource;

/**
 * Replay guidance: reads a saved input file and replays it exactly once
 * through the fuzz harness, printing signal values and result metadata.
 */
public class ReplayGuidance implements Guidance, SignalSource {

    private final byte[] inputData;
    private final String targetId;
    private final PrintStream log;
    private boolean executed = false;
    private double lastSignalValue = 0.0;

    public ReplayGuidance(File inputFile, String targetId, PrintStream log) throws IOException {
        this.inputData = Files.readAllBytes(inputFile.toPath());
        this.targetId = targetId;
        this.log = log;
        log.printf("[Replay] Loaded %d bytes from %s for target %s%n",
            inputData.length, inputFile.getAbsolutePath(), targetId);
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        SignalCollector.reset();
        return new ByteArrayInputStream(inputData);
    }

    @Override
    public boolean hasInput() {
        if (executed) return false;
        executed = true;
        return true;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        String signalName;
        double signalValue;

        switch (targetId) {
            case "V1":
                signalName = "allocBytes";
                signalValue = (double) SignalCollector.getAllocBytes();
                break;
            case "V2":
                signalName = "throwableDepth";
                signalValue = (double) SignalCollector.getThrowableDepth();
                break;
            case "V3":
                signalName = "nestingDepth";
                signalValue = (double) SignalCollector.getNestingDepth();
                break;
            default:
                signalName = "unknown";
                signalValue = 0.0;
        }

        this.lastSignalValue = signalValue;

        log.println("=== REPLAY RESULT ===");
        log.printf("  Target:       %s%n", targetId);
        log.printf("  Input size:   %d bytes%n", inputData.length);
        log.printf("  Result:       %s%n", result);
        log.printf("  Signal (%s): %.0f%n", signalName, signalValue);
        if (error != null) {
            log.printf("  Error:        %s: %s%n", error.getClass().getName(), error.getMessage());
        }
        log.printf("  Input hex:    ");
        for (int i = 0; i < Math.min(inputData.length, 32); i++) {
            log.printf("%02x ", inputData[i]);
        }
        if (inputData.length > 32) log.print("...");
        log.println();
        log.println("=====================");
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return event -> {};
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        switch (targetId) {
            case "V1":
                signals.put("allocBytes", lastSignalValue);
                break;
            case "V2":
                signals.put("throwableDepth", lastSignalValue);
                break;
            case "V3":
                signals.put("nestingDepth", lastSignalValue);
                break;
        }
        return signals;
    }
}
