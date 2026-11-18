package org.xnio.fuzz;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;

import org.junit.runner.RunWith;

import org.xnio.Cancellable;
import org.xnio.FutureResult;
import org.xnio.IoFuture;

import java.io.IOException;
import java.io.InputStream;

/**
 * Fuzz tests for XNIO's future implementation (FutureResult / AbstractIoFuture).
 *
 * The input is read as a sequence of operations on one future (see
 * {@link RegistrationInput}); each method then completes or cancels the future
 * through its public API.
 */
@RunWith(JQF.class)
public class XnioFuzzTest {

    /**
     * Registers notifiers on a FutureResult's IoFuture with
     * IoFuture.addNotifier as directed by the input, then completes the future
     * with FutureResult.setResult, which runs the registered notifiers.
     */
    @Fuzz
    public void fuzzIoFutureAddNotifier(InputStream data) throws IOException {
        FutureResult<String> futureResult = new FutureResult<>();
        IoFuture<String> future = futureResult.getIoFuture();
        IoFuture.Notifier<String, Void> notifier = new IoFuture.Notifier<String, Void>() {
            @Override
            public void notify(IoFuture<? extends String> ioFuture, Void attachment) {
            }
        };

        int added = RegistrationInput.addNotifiers(data, future, notifier);
        if (added == 0) return;

        futureResult.setResult("done");
    }

    /**
     * Registers cancel handlers with FutureResult.addCancelHandler as
     * directed by the input, then requests cancellation through
     * IoFuture.cancel, which runs the registered handlers.
     */
    @Fuzz
    public void fuzzFutureResultAddCancelHandler(InputStream data) throws IOException {
        FutureResult<String> futureResult = new FutureResult<>();
        Cancellable noop = new Cancellable() {
            @Override
            public Cancellable cancel() { return this; }
        };

        int added = RegistrationInput.addCancelHandlers(data, futureResult, noop);
        if (added == 0) return;

        futureResult.getIoFuture().cancel();
    }
}
