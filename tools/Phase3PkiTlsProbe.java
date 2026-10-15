/* Isolated loopback-only Java 11 packaging/TLS controls, not an AAF API test. */
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.concurrent.*;
import javax.net.ssl.*;

class Phase3PkiTlsProbe {
    static KeyStore load(Path file, String kind, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance(kind);
        try (InputStream input = Files.newInputStream(file)) { store.load(input, password); }
        return store;
    }
    static SSLContext context(KeyStore keys, KeyStore trust, char[] password) throws Exception {
        KeyManager[] km = null;
        if (keys != null) {
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(keys, password); km = factory.getKeyManagers();
        }
        TrustManagerFactory tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tm.init(trust);
        SSLContext result = SSLContext.getInstance("TLS");
        result.init(km, tm.getTrustManagers(), new SecureRandom());
        return result;
    }
    static void probe(SSLContext serverContext, SSLContext clientContext, String hostname,
                      boolean expectedSuccess) throws Exception {
        try (SSLServerSocket listener = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            listener.setSoTimeout(10000);
            Thread server = new Thread(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                    accepted.setSoTimeout(10000); accepted.startHandshake();
                } catch (Exception expectedNegativeControl) { /* client result is asserted below */ }
            });
            server.setDaemon(true); server.start();
            boolean succeeded = false;
            try (Socket transport = new Socket("127.0.0.1", listener.getLocalPort());
                 SSLSocket client = (SSLSocket) clientContext.getSocketFactory()
                     .createSocket(transport, hostname, listener.getLocalPort(), true)) {
                client.setSoTimeout(10000);
                SSLParameters parameters = client.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                client.setSSLParameters(parameters); client.startHandshake(); succeeded = true;
            } catch (SSLException expectedNegativeControl) {
                if (expectedSuccess) throw expectedNegativeControl;
            }
            server.join(11000);
            if (server.isAlive() || succeeded != expectedSuccess) {
                throw new IllegalStateException("Unexpected isolated TLS control result");
            }
        }
    }
    public static void main(String[] arguments) throws Exception {
        Path directory = Paths.get(arguments[0]);
        char[] password = Files.readString(directory.resolve("store-password")).toCharArray();
        KeyStore keys = load(directory.resolve("server.p12"), "PKCS12", password);
        KeyStore trust = load(directory.resolve("truststoreONAPall.jks"), "JKS", "changeit".toCharArray());
        KeyStore p12Trust = load(directory.resolve("truststoreONAP.p12"), "PKCS12", "changeit".toCharArray());
        if (!trust.isCertificateEntry("onaptestca") || !p12Trust.isCertificateEntry("onaptestca")) {
            throw new IllegalStateException("Missing Java trusted-certificate entry");
        }
        SSLContext server = context(keys, trust, password);
        probe(server, context(null, trust, null), "aaf-locate.onap", true);
        probe(server, context(null, p12Trust, null), "aaf-locate.onap", true);
        probe(server, context(null, trust, null), "wrong.invalid", false);
        KeyStore empty = KeyStore.getInstance("JKS"); empty.load(null, null);
        probe(server, context(null, empty, null), "aaf-locate.onap", false);
        System.out.println("Isolated Java TLS controls passed: JKS/PKCS12, hostname and trust rejection");
    }
}
