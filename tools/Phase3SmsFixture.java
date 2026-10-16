/* Isolated synthetic SMS API fixture. No live API, credentials or persistent data. */
import com.sun.net.httpserver.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;

class Phase3SmsFixture {
    public static void main(String[] args) throws Exception {
        Path dir = Paths.get("/fixture");
        KeyStore keys = KeyStore.getInstance("PKCS12");
        char[] password = "fixture-only".toCharArray();
        try (InputStream input = Files.newInputStream(dir.resolve("server.p12"))) { keys.load(input, password); }
        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        km.init(keys, password);
        SSLContext tls = SSLContext.getInstance("TLS"); tls.init(km.getKeyManagers(), null, null);
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 10443), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        server.createContext("/", exchange -> {
            String method = exchange.getRequestMethod(), path = exchange.getRequestURI().getPath();
            // Drain request bodies without logging them, even for synthetic inputs.
            while (exchange.getRequestBody().read() != -1) { }
            synchronized (Phase3SmsFixture.class) {
                Files.write(dir.resolve("requests.txt"), (method+" "+path+"\n").getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
            int status = 200;
            String body = "{}";
            if (method.equals("GET")) body = "{\"sealstatus\":false}";
            else if (!method.equals("POST")) status = 405;
            else if (args[0].equals("write-error")) { status = 500; body = "fixture write failure"; }
            else if (args[0].equals("existing-domain") && path.equals("/v1/sms/domain")) {
                status = 500; body = "existing domain";
            } else if (args[0].equals("ambiguous")) { exchange.close(); return; }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream output = exchange.getResponseBody()) { output.write(bytes); }
        });
        server.start(); Files.write(dir.resolve("ready"), new byte[]{1});
    }
}
