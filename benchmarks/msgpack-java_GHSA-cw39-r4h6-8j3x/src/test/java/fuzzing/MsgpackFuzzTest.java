package fuzzing;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;

import org.msgpack.core.MessagePack;
import org.msgpack.core.MessagePackException;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.io.InputStream;

/**
 * JQF fuzz tests for msgpack-java's {@link MessageUnpacker}.
 *
 * <p>Each method reads the raw input bytes and gives them to an unpacker created with
 * {@link MessagePack#newDefaultUnpacker(byte[])} (default configuration).
 * {@link MessagePackException} (and its subclasses) is how the unpacker rejects malformed input,
 * so it is a normal result, as is {@link IOException}. Anything else is a failure.</p>
 */
@RunWith(JQF.class)
public class MsgpackFuzzTest {

    /**
     * MessageUnpacker.unpackValue() on the first value of the input.
     */
    @Fuzz
    public void fuzzMessageUnpackerUnpackValue(InputStream data) throws IOException, MessagePackException {
        byte[] bytes = data.readAllBytes();
        try (MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(bytes)) {
            if (unpacker.hasNext()) {
                unpacker.unpackValue();
            }
        }
    }

    /**
     * MessageUnpacker.unpackValue() on the first value of the input.
     */
    @Fuzz
    public void fuzzMessageUnpackerUnpackValue2(InputStream data) throws IOException, MessagePackException {
        byte[] bytes = data.readAllBytes();
        try (MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(bytes)) {
            if (unpacker.hasNext()) {
                unpacker.unpackValue();
            }
        }
    }

    /**
     * MessageUnpacker.skipValue() on the first value of the input, then on the next
     * one if there is one.
     */
    @Fuzz
    public void fuzzMessageUnpackerSkipValue(InputStream data) throws IOException, MessagePackException {
        byte[] bytes = data.readAllBytes();
        try (MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(bytes)) {
            if (unpacker.hasNext()) {
                unpacker.skipValue();
                if (unpacker.hasNext()) {
                    unpacker.skipValue();
                }
            }
        }
    }
}
