# Java HTTP server. JDK's networking (java.net.Socket, sun.nio.ch.*)
# bottoms out in JNI → libc on Linux, so the LD_PRELOAD interceptors
# should fire the same as for Python/Rust. We use the bundled
# `com.sun.net.httpserver.HttpServer` (jdk.httpserver module, no
# external deps).
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/javaapp && cat > /opt/javaapp/Server.java <<'EOF'
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import java.net.InetSocketAddress;
import java.io.OutputStream;

public class Server {
    public static void main(String[] args) throws Exception {
        String host = System.getenv("HTTP_HOST");
        if (host == null) host = "127.0.0.1";
        int port = Integer.parseInt(
            System.getenv().getOrDefault("HTTP_PORT", "8086"));
        HttpServer server = HttpServer.create(
            new InetSocketAddress(host, port), 0);
        server.createContext("/", (HttpExchange ex) -> {
            byte[] body = "nfl-java-ok\n".getBytes();
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(body); }
        });
        server.setExecutor(null);  // synchronous, single-thread handling
        System.err.println("listening on " + host + ":" + port);
        server.start();
    }
}
EOF
RUN cd /opt/javaapp && javac Server.java

COPY test/integration/docker/java-http/run.sh /opt/nfl/targets/java-http/run.sh
RUN chmod +x /opt/nfl/targets/java-http/run.sh

ENV NFL_TARGET_NAME=java-http \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/java-http/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
