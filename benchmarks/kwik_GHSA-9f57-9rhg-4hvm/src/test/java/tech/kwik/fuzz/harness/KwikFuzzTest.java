package tech.kwik.fuzz.harness;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import org.junit.runner.RunWith;
import tech.kwik.core.log.Logger;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.server.impl.ServerConnectionProxy;
import tech.kwik.core.server.impl.ServerConnectionRegistryImpl;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * JQF fuzz tests for kwik's server-side connection registry.
 * <p>
 * Both tests drive kwik's server-side connection registry ({@link ServerConnectionRegistryImpl}) the way
 * the server connector does when Initial packets arrive: {@code ServerConnectorImpl.processInitial} looks the
 * packet's destination connection ID up with {@code isExistingConnection} and, if no connection exists yet,
 * {@code createNewConnection} registers a new connection candidate under that ID with
 * {@code registerConnection}.
 * <p>
 * The registry's constructor and {@code isExistingConnection} are package-private (only the server connector
 * calls them), so they are invoked reflectively; everything else is the registry's public API.
 * <p>
 * Input format (both tests): the whole input is read first, then split into a sequence of destination
 * connection IDs, one per Initial packet, each encoded as one length byte (mapped to the QUIC v1 range 1..20)
 * followed by that many connection-ID bytes. A trailing incomplete connection ID is ignored.
 */
@RunWith(JQF.class)
public class KwikFuzzTest {

    private static final InetSocketAddress CLIENT = new InetSocketAddress(InetAddress.getLoopbackAddress(), 4433);

    private static final Constructor<ServerConnectionRegistryImpl> REGISTRY_CTOR;
    private static final Method IS_EXISTING_CONNECTION;

    static {
        try {
            REGISTRY_CTOR = ServerConnectionRegistryImpl.class.getDeclaredConstructor(Logger.class);
            REGISTRY_CTOR.setAccessible(true);
            IS_EXISTING_CONNECTION = ServerConnectionRegistryImpl.class.getDeclaredMethod(
                    "isExistingConnection", InetSocketAddress.class, byte[].class);
            IS_EXISTING_CONNECTION.setAccessible(true);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("kwik registry API not found", e);
        }
    }

    /** No-op connection value; the registry only stores it. */
    private static final ServerConnectionProxy DUMMY_PROXY = new ServerConnectionProxy() {
        @Override
        public byte[] getOriginalDestinationConnectionId() {
            return new byte[0];
        }

        @Override
        public void parsePackets(int datagramNumber, Instant timeReceived,
                                 ByteBuffer data, InetSocketAddress sourceAddress) {
        }

        @Override
        public boolean isClosed() {
            return false;
        }

        @Override
        public void closeConnection() {
        }

        @Override
        public void dispose() {
        }
    };

    /**
     * Connection registration.
     * For every connection ID read from the input, performs the registry calls of
     * {@code ServerConnectorImpl.processInitial}: look the ID up and register a new connection under it
     * if none exists.
     */
    @Fuzz
    public void fuzzServerConnectionRegistryRegisterConnection(InputStream data) throws IOException {
        List<byte[]> dcids = connectionIds(data.readAllBytes());
        ServerConnectionRegistryImpl registry = createRegistry();
        for (byte[] dcid : dcids) {
            processInitial(registry, dcid);
        }
    }

    /**
     * Connection registration and deregistration.
     * Performs the registry calls of {@code ServerConnectorImpl.processInitial} for every connection ID read
     * from the input, then removes the registered connections again with
     * {@link ServerConnectionRegistryImpl#deregisterConnection(ServerConnectionProxy, byte[])}, as the server
     * does for connection candidates that do not lead to a connection.
     */
    @Fuzz
    public void fuzzServerConnectionRegistryRegisterAndDeregister(InputStream data) throws IOException {
        List<byte[]> dcids = connectionIds(data.readAllBytes());
        ServerConnectionRegistryImpl registry = createRegistry();
        List<byte[]> registered = new ArrayList<>();
        for (byte[] dcid : dcids) {
            if (processInitial(registry, dcid)) {
                registered.add(dcid);
            }
        }
        for (byte[] id : registered) {
            registry.deregisterConnection(DUMMY_PROXY, id);
        }
    }

    /** Looks the connection ID up and registers it if it is new; returns whether it was registered. */
    private static boolean processInitial(ServerConnectionRegistryImpl registry, byte[] dcid) {
        if (isExistingConnection(registry, dcid).isPresent()) {
            return false;
        }
        registry.registerConnection(DUMMY_PROXY, dcid);
        return true;
    }

    /** Splits the input into length-prefixed connection IDs; a trailing incomplete ID is dropped. */
    private static List<byte[]> connectionIds(byte[] raw) {
        List<byte[]> ids = new ArrayList<>();
        int pos = 0;
        while (pos < raw.length) {
            int len = ((raw[pos] & 0xff) % 20) + 1;
            pos++;
            if (pos + len > raw.length) {
                break;
            }
            ids.add(Arrays.copyOfRange(raw, pos, pos + len));
            pos += len;
        }
        return ids;
    }

    private static ServerConnectionRegistryImpl createRegistry() {
        try {
            return REGISTRY_CTOR.newInstance(new NullLogger());
        } catch (InvocationTargetException e) {
            throw rethrow(e.getCause());
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Optional<ServerConnectionProxy> isExistingConnection(ServerConnectionRegistryImpl registry,
                                                                        byte[] dcid) {
        try {
            return (Optional<ServerConnectionProxy>) IS_EXISTING_CONNECTION.invoke(registry, CLIENT, dcid);
        } catch (InvocationTargetException e) {
            throw rethrow(e.getCause());
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Rethrows what the library threw, unchanged. */
    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException) {
            throw (RuntimeException) t;
        }
        if (t instanceof Error) {
            throw (Error) t;
        }
        throw new IllegalStateException(t);
    }
}
