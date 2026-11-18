package org.xnio.fuzz;

import org.xnio.Cancellable;
import org.xnio.FutureResult;
import org.xnio.IoFuture;

import java.io.IOException;
import java.io.InputStream;

/**
 * Input decoding shared by the XNIO fuzz tests.
 *
 * The input is read byte by byte. A byte whose high bit is set registers one
 * more notifier (or cancel handler) on the future; other bytes register
 * nothing.
 */
final class RegistrationInput {

    private RegistrationInput() {}

    static int addNotifiers(InputStream data, IoFuture<String> future,
                            IoFuture.Notifier<String, Void> notifier) throws IOException {
        int added = 0;
        int value;
        while ((value = data.read()) != -1) {
            if (isRegistrationByte(value)) {
                future.addNotifier(notifier, null);
                added++;
            }
        }
        return added;
    }

    static int addCancelHandlers(InputStream data, FutureResult<String> futureResult,
                                 Cancellable cancellable) throws IOException {
        int added = 0;
        int value;
        while ((value = data.read()) != -1) {
            if (isRegistrationByte(value)) {
                futureResult.addCancelHandler(cancellable);
                added++;
            }
        }
        return added;
    }

    static boolean isRegistrationByte(int value) {
        return (value & 0x80) != 0;
    }
}
