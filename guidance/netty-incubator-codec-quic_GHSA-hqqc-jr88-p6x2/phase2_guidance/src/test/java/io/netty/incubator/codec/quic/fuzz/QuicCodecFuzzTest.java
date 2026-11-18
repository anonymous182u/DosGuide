package io.netty.incubator.codec.quic.fuzz;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.socket.DatagramPacket;
import io.netty.incubator.codec.quic.Quic;
import io.netty.incubator.codec.quic.QuicException;
import io.netty.incubator.codec.quic.QuicHeaderParser;
import io.netty.incubator.codec.quic.QuicPacketType;
import io.netty.incubator.codec.quic.QuicServerCodecBuilder;
import io.netty.incubator.codec.quic.QuicSslContext;
import io.netty.incubator.codec.quic.QuicSslContextBuilder;
import org.junit.Assume;
import org.junit.runner.RunWith;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * JQF fuzz tests for netty-incubator-codec-quic.
 *
 * <p>The server-side methods build a QUIC server codec with {@link QuicServerCodecBuilder} in its
 * default configuration (only the mandatory TLS context and connection handler are set), put it in
 * an {@link EmbeddedChannel} and deliver UDP datagrams to it, as the datagram channel of a server
 * would. The input is read as a sequence of records; each record is one length byte followed by
 * that many bytes, which are used as the destination connection id of one client Initial packet.
 * The harness builds each Initial packet the way a QUIC v1 client does (RFC 9001 initial packet
 * protection; the payload is a PING frame padded to 1200 bytes) and delivers it as one datagram.
 * Datagrams the server sends back are released, as if sent on the network. At the end the channel
 * is closed.</p>
 */
@RunWith(JQF.class)
public class QuicCodecFuzzTest {

    private static final InetSocketAddress SENDER = new InetSocketAddress("127.0.0.1", 12345);
    private static final InetSocketAddress RECIPIENT = new InetSocketAddress("127.0.0.1", 443);

    /**
     * The server codec's channelRead for client Initial packets built from the input records.
     */
    @Fuzz
    public void fuzzQuicServerCodecChannelRead(InputStream input) throws IOException, QuicException {
        serveInitialPackets(input.readAllBytes());
    }

    /**
     * QuicHeaderParser.parse on one raw datagram, with a processor that accepts every
     * parsed header.
     */
    @Fuzz
    public void fuzzQuicHeaderParserParse(InputStream input) throws IOException, QuicException {
        byte[] data = input.readAllBytes();
        ByteBuf packet = Unpooled.wrappedBuffer(data);
        try (QuicHeaderParser parser = new QuicHeaderParser(Quic.MAX_CONN_ID_LEN)) {
            parser.parse(SENDER, RECIPIENT, packet,
                    (sender, recipient, buf, type, version, scid, dcid, token) -> { });
        } catch (QuicException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        } finally {
            packet.release();
        }
    }

    /**
     * The server codec's channelRead for client Initial packets built from the input records
     * (the same calls as {@link #fuzzQuicServerCodecChannelRead}).
     */
    @Fuzz
    public void fuzzQuicServerCodecChannelRead2(InputStream input) throws IOException, QuicException {
        serveInitialPackets(input.readAllBytes());
    }

    // ------------------------------------------------------------------------------------------

    private static void serveInitialPackets(byte[] data) {
        Assume.assumeTrue(Quic.isAvailable());
        ChannelHandler codec = new QuicServerCodecBuilder()
                .sslContext(ServerTls.CONTEXT)
                .handler(new ConnectionHandler())
                .build();
        EmbeddedChannel channel = new EmbeddedChannel(codec);
        int offset = 0;
        while (offset < data.length) {
            int len = Math.min(data[offset] & 0xff, data.length - offset - 1);
            byte[] dcid = Arrays.copyOfRange(data, offset + 1, offset + 1 + len);
            offset += 1 + len;
            channel.writeInbound(new DatagramPacket(
                    Unpooled.wrappedBuffer(ClientInitial.packet(dcid)), RECIPIENT, SENDER));
            channel.releaseOutbound();
        }
        channel.finishAndReleaseAll();
    }

    /** Application handler for accepted QUIC connections; it does nothing. */
    @ChannelHandler.Sharable
    private static final class ConnectionHandler extends ChannelInboundHandlerAdapter {
    }

    /** Self-signed EC P-256 certificate and key of the test server. */
    private static final class ServerTls {
        private static final String KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+1Q7NJ+HJEYXFArPDL7aI4Q9jx7y4SvAJvBPdgadsFihRANC" +
                "AAQmIwIb7ohnAi5DLhF5+1s/29QfdqIgNMmOjW1ZIR6KKeJgEhQs5WClLpatSJXWZd/GQvpqHC9suKM7WinGszUC";
        private static final String CERT = "MIIBXjCCAQSgAwIBAgIUf9P/BSES62bu8JBqG9TvBKm/3dgwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAX" +
                "DTI2MTAyMzEyMjUzOFoYDzIxMjYwOTI5MTIyNTM4WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO" +
                "PQMBBwNCAAQmIwIb7ohnAi5DLhF5+1s/29QfdqIgNMmOjW1ZIR6KKeJgEhQs5WClLpatSJXWZd/GQvpqHC9suKM7WinGszUC" +
                "ozIwMDAdBgNVHQ4EFgQUZbZifLbt2v8eRt8DS1mD+noZMl4wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA" +
                "wUyUcU6eXhYCzDF4p8JUjktcU247mLbjAC4UV0UOD1sCIEqJfgHMWfATD92iq2WG/uMJGEPB4x7ToxYcrRm54zQj";
        static final QuicSslContext CONTEXT;

        static {
            try {
                PrivateKey key = KeyFactory.getInstance("EC")
                        .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(KEY)));
                X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(CERT)));
                CONTEXT = Quic.isAvailable() ? QuicSslContextBuilder.forServer(key, null, cert).build() : null;
            } catch (GeneralSecurityException e) {
                throw new ExceptionInInitializerError(e);
            }
        }
    }

    /**
     * Builds a QUIC version 1 client Initial packet for a destination connection id
     * (RFC 9000 section 17.2.2, RFC 9001 section 5).
     */
    private static final class ClientInitial {
        private static final byte[] INITIAL_SALT = {
                0x38, 0x76, 0x2c, (byte) 0xf7, (byte) 0xf5, 0x59, 0x34, (byte) 0xb3, 0x4d, 0x17,
                (byte) 0x9a, (byte) 0xe6, (byte) 0xa4, (byte) 0xc8, 0x0c, (byte) 0xad, (byte) 0xcc, (byte) 0xbb,
                0x7f, 0x0a};
        private static final byte[] CLIENT_SCID = {1, 2, 3, 4, 5, 6, 7, 8};
        private static final int DATAGRAM_SIZE = 1200;
        private static final int PN_LENGTH = 4;
        private static final int TAG_LENGTH = 16;

        static byte[] packet(byte[] dcid) {
            try {
                byte[] secret = expandLabel(hmac(INITIAL_SALT, dcid), "client in", 32);
                byte[] key = expandLabel(secret, "quic key", 16);
                byte[] iv = expandLabel(secret, "quic iv", 12);
                byte[] hp = expandLabel(secret, "quic hp", 16);

                ByteBuf header = Unpooled.buffer();
                header.writeByte(0xC0 | (PN_LENGTH - 1));  // long header, Initial
                header.writeInt(1);                         // version 1
                header.writeByte(dcid.length);
                header.writeBytes(dcid);
                header.writeByte(CLIENT_SCID.length);
                header.writeBytes(CLIENT_SCID);
                header.writeByte(0);                        // no token
                int payloadLength = Math.max(DATAGRAM_SIZE - header.readableBytes() - 2 - PN_LENGTH - TAG_LENGTH,
                        TAG_LENGTH);
                header.writeShort(0x4000 | (PN_LENGTH + payloadLength + TAG_LENGTH));
                header.writeInt(0);                         // packet number 0
                byte[] head = new byte[header.readableBytes()];
                header.readBytes(head);

                byte[] payload = new byte[payloadLength];   // PING, then PADDING
                payload[0] = 0x01;
                Cipher aead = Cipher.getInstance("AES/GCM/NoPadding");
                aead.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
                aead.updateAAD(head);
                byte[] sealed = aead.doFinal(payload);

                Cipher hpCipher = Cipher.getInstance("AES/ECB/NoPadding");
                hpCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(hp, "AES"));
                byte[] mask = hpCipher.doFinal(sealed, 4 - PN_LENGTH, 16);
                head[0] ^= mask[0] & 0x0f;
                for (int i = 0; i < PN_LENGTH; i++) {
                    head[head.length - PN_LENGTH + i] ^= mask[1 + i];
                }
                byte[] datagram = Arrays.copyOf(head, head.length + sealed.length);
                System.arraycopy(sealed, 0, datagram, head.length, sealed.length);
                return datagram;
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        }

        /** HKDF-Expand-Label with an empty context (RFC 8446 section 7.1), for lengths up to 32. */
        private static byte[] expandLabel(byte[] secret, String label, int length) throws GeneralSecurityException {
            byte[] fullLabel = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
            byte[] info = new byte[2 + 1 + fullLabel.length + 1 + 1];
            info[0] = (byte) (length >>> 8);
            info[1] = (byte) length;
            info[2] = (byte) fullLabel.length;
            System.arraycopy(fullLabel, 0, info, 3, fullLabel.length);
            info[info.length - 2] = 0;                 // empty context
            info[info.length - 1] = 1;                 // HKDF counter
            return Arrays.copyOf(hmac(secret, info), length);
        }
    }
}
