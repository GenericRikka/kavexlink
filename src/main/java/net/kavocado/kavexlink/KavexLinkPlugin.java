package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.event.Listener;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import io.papermc.paper.event.player.AsyncChatEvent;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.bukkit.event.EventHandler;
import org.bukkit.entity.Player;

// Gson for robust JSON parsing
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

// Player lifecycle & death events
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.entity.PlayerDeathEvent;

public class KavexLinkPlugin extends JavaPlugin implements Listener {

    private Path dataDir;
    private Path secretFile;
    private String token;
    private String serverName;
    private String wsUrl; // e.g. wss://bot.kavocado.net/mcws

    // SSL config (mode etc.)
    private String sslMode;           // system | ca-pem | pinned (currently informational)
    private String sslCaPemPath;      // for ca-pem
    private String sslPinnedSha256;   // for pinned (hex, with/without colons)
    private String sslHostname;       // optional SNI/hostname override (currently unused)
    private boolean sslDebug;         // NEW: enable javax.net debug
    private boolean sslForceTls12;    // NEW: force TLS 1.2 via system props

    private HttpClient http;
    private final AtomicReference<WebSocket> socketRef = new AtomicReference<>();
    private final AtomicBoolean running = new AtomicBoolean(false);

    @Override
    public void onEnable() {
        running.set(true);

        saveDefaultConfig();
        this.dataDir = getDataFolder().toPath();
        this.secretFile = dataDir.resolve("secret.txt");

        String motd = Bukkit.getServer().getMotd();
        this.serverName = getConfig().getString("server-name",
                (motd != null && !motd.isEmpty()) ? motd : "Minecraft");

        // IMPORTANT: use wss here to go through Apache TLS
        this.wsUrl = getConfig().getString("ws-url", "wss://bot.kavocado.net/mcws");

        // SSL config
        this.sslMode         = getConfig().getString("ssl.mode", "system").trim().toLowerCase();
        this.sslCaPemPath    = getConfig().getString("ssl.ca-pem", "ca.pem");
        this.sslPinnedSha256 = getConfig().getString("ssl.pinned-sha256", "");
        this.sslHostname     = getConfig().getString("ssl.hostname", "").trim();
        if (this.sslHostname.isEmpty()) this.sslHostname = null;

        // NEW: debug + TLS 1.2 forcing
        this.sslDebug      = getConfig().getBoolean("ssl.debug", false);
        this.sslForceTls12 = getConfig().getBoolean("ssl.force-tls12", false);

        // Apply system properties for TLS if requested
        if (sslForceTls12) {
            try {
                System.setProperty("https.protocols", "TLSv1.2");
                System.setProperty("jdk.tls.client.protocols", "TLSv1.2");
                getLogger().info("SSL: forcing client protocols to TLSv1.2");
            } catch (Exception e) {
                getLogger().warning("SSL: failed to set TLSv1.2 system properties: " + e);
            }
        }

        if (sslDebug) {
            try {
                System.setProperty("javax.net.debug", "ssl,handshake");
                getLogger().info("SSL: javax.net.debug=ssl,handshake enabled (expect a LOT of TLS debug output)");
            } catch (Exception e) {
                getLogger().warning("SSL: failed to enable javax.net.debug: " + e);
            }
        }

        try {
            Files.createDirectories(dataDir);
        } catch (Exception ignored) {
        }

        if (!Files.exists(secretFile)) {
            token = generateToken();
            try {
                Files.writeString(secretFile, token, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
            } catch (Exception e) {
                getLogger().severe("Failed to write secret.txt: " + e);
            }
        }
        try {
            token = Files.readString(secretFile).trim();
        } catch (Exception e) {
            token = generateToken();
        }

        // Build HttpClient – SIMPLE VERSION (no custom SSLContext/pinning)
        this.http = buildHttpClientWithSsl();

        Bukkit.getPluginManager().registerEvents(this, this);
        connectWithRetry();
    }

    @Override
    public void onDisable() {
        running.set(false);
        WebSocket ws = socketRef.getAndSet(null);
        if (ws != null) ws.abort();
    }

    private String generateToken() {
        return UUID.randomUUID().toString().replace("-", "") +
                Long.toHexString(new Random().nextLong());
    }

    /**
     * Super simple HttpClient builder that uses the default JVM trust store and
     * default hostname verification. No pinning, no hostname override right now.
     */
    private HttpClient buildHttpClientWithSsl() {
        try {
            getLogger().info("SSL: using default JVM trust store and hostname verification (mode="
                    + sslMode + ", hostname="
                    + (sslHostname != null ? sslHostname : "<ws-url host>")
                    + ", debug=" + sslDebug + ", forceTls12=" + sslForceTls12 + ")");
            return HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
        } catch (Exception e) {
            getLogger().severe("Failed to initialize HttpClient: " + e);
            return HttpClient.newBuilder().build();
        }
    }

    // ---------- Helpers for future advanced SSL modes (currently unused) ----------

    private static X509TrustManager pickX509(TrustManagerFactory tmf) {
        for (TrustManager t : tmf.getTrustManagers()) {
            if (t instanceof X509TrustManager) return (X509TrustManager) t;
        }
        throw new IllegalStateException("No X509TrustManager provided by TrustManagerFactory");
    }

    private TrustManagerFactory trustFromPem(Path pemFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);

        try (InputStream in = new BufferedInputStream(Files.newInputStream(pemFile))) {
            int idx = 0;
            while (in.available() > 0) {
                X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                ks.setCertificateEntry("pem-" + (idx++), cert);
                if (in.available() == 0) break;
            }
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        return tmf;
    }
    
    private String hexToMinecraftColor(String hex) {
        if (hex == null) return "§f";
        hex = hex.trim();
        if (hex.length() != 7 || !hex.startsWith("#")) return "§f";
        String digits = hex.substring(1); // RRGGBB
        StringBuilder sb = new StringBuilder("§x");
        for (char c : digits.toCharArray()) {
            sb.append('§').append(Character.toLowerCase(c));
        }
        return sb.toString();
    }

    private Path resolvePath(String p) {
        Path path = Paths.get(p);
        if (!path.isAbsolute()) {
            path = dataDir.resolve(p);
        }
        return path.normalize();
    }

    private static String normalizeHex(String hex) {
        return hex.replace(":", "").replace(" ", "").toUpperCase();
    }

    static class PinningTrustManager implements X509TrustManager {
        private final X509TrustManager base;
        private final String expectedSpkiSha256Hex;

        PinningTrustManager(X509TrustManager base, String expectedHex) {
            this.base = base;
            this.expectedSpkiSha256Hex = expectedHex;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            base.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            base.checkServerTrusted(chain, authType);
            if (chain == null || chain.length == 0) {
                throw new java.security.cert.CertificateException("Empty server cert chain");
            }
            X509Certificate leaf = chain[0];
            String spkiHex = sha256Hex(leaf.getPublicKey().getEncoded());
            if (!spkiHex.equalsIgnoreCase(expectedSpkiSha256Hex)) {
                throw new java.security.cert.CertificateException(
                        "SPKI pin mismatch. Got " + spkiHex + ", expected " + expectedSpkiSha256Hex
                );
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return base.getAcceptedIssuers();
        }

        private static String sha256Hex(byte[] data) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] d = md.digest(data);
                StringBuilder sb = new StringBuilder(d.length * 2);
                for (byte b : d) sb.append(String.format("%02X", b));
                return sb.toString();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    static class HostnameOverrideTrustManager implements X509TrustManager {
        private final X509TrustManager base;
        private final String expectedHost;

        HostnameOverrideTrustManager(X509TrustManager base, String expectedHost) {
            this.base = base;
            this.expectedHost = expectedHost.toLowerCase();
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            base.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            base.checkServerTrusted(chain, authType);

            if (chain == null || chain.length == 0) {
                throw new java.security.cert.CertificateException("Empty server certificate chain");
            }

            X509Certificate leaf = chain[0];
            if (!certificateMatchesHostname(leaf, expectedHost)) {
                throw new java.security.cert.CertificateException(
                        "Hostname verification failed: expected certificate for " + expectedHost
                );
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return base.getAcceptedIssuers();
        }

        private static boolean certificateMatchesHostname(X509Certificate cert, String host)
                throws java.security.cert.CertificateException {
            try {
                java.util.Collection<java.util.List<?>> altNames =
                        cert.getSubjectAlternativeNames();
                if (altNames != null) {
                    for (java.util.List<?> entry : altNames) {
                        if (entry == null || entry.size() < 2) continue;
                        Integer type = (Integer) entry.get(0);
                        if (type != 2) continue; // 2 = dNSName
                        String dns = ((String) entry.get(1)).toLowerCase();
                        if (hostnameMatchesPattern(dns, host)) {
                            return true;
                        }
                    }
                }
            } catch (Exception ignored) {
            }

            String dn = cert.getSubjectX500Principal().getName();
            String cn = extractCn(dn);
            return cn != null && hostnameMatchesPattern(cn.toLowerCase(), host);
        }

        private static String extractCn(String dn) {
            String[] parts = dn.split(",");
            for (String p : parts) {
                p = p.trim();
                if (p.toUpperCase().startsWith("CN=")) {
                    return p.substring(3);
                }
            }
            return null;
        }

        private static boolean hostnameMatchesPattern(String pattern, String host) {
            pattern = pattern.toLowerCase();
            host = host.toLowerCase();

            if (pattern.equals(host)) {
                return true;
            }

            if (pattern.startsWith("*.") && pattern.indexOf('*', 1) == -1) {
                String suffix = pattern.substring(1);
                if (!host.endsWith(suffix)) return false;
                String prefix = host.substring(0, host.length() - suffix.length());
                return !prefix.isEmpty() && !prefix.contains(".");
            }

            return false;
        }
    }

    // ---------- WebSocket connection / retry ----------

    private void connectWithRetry() {
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            while (running.get()) {
                try {
                    HttpClient client = this.http;

                    WebSocket.Builder wsBuilder = client.newWebSocketBuilder()
                            .connectTimeout(Duration.ofSeconds(5));

                    WebSocket ws = wsBuilder
                            .buildAsync(URI.create(wsUrl), new WSListener())
                            .join();
                    socketRef.set(ws);

                    String auth = "{\"op\":\"auth\",\"token\":\"" + token + "\",\"server\":\""
                            + escape(serverName) + "\"}";
                    ws.sendText(auth, true);
                    getLogger().info("Connected to " + wsUrl);
                    return;
                } catch (Exception e) {
                    if (!running.get()) break;

                    // MORE VERBOSE LOGGING
                    getLogger().warning("WS connect failed: " + e.getClass().getName() + ": " + e.getMessage());
                    Throwable cause = e.getCause();
                    while (cause != null) {
                        getLogger().warning("  cause: " + cause.getClass().getName() + ": " + cause.getMessage());
                        cause = cause.getCause();
                    }
                    e.printStackTrace(); // full stack trace to console

                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException ignored) {
                    }
                }
            }
        });
    }

    class WSListener implements WebSocket.Listener {
        private StringBuilder buffer = new StringBuilder();

        @Override
        public void onOpen(WebSocket webSocket) {
            getLogger().info("WS open; requesting messages");
            webSocket.request(1);
        }

        @Override
        public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
            buffer.append(data);
            if (last) {
                String msg = buffer.toString();
                buffer.setLength(0);
                handleMessage(msg);
            }
            webSocket.request(1);
            return null;
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            getLogger().warning("WS error: " + error.getClass().getName() + ": " + error.getMessage());
            Throwable cause = error.getCause();
            while (cause != null) {
                getLogger().warning("  cause: " + cause.getClass().getName() + ": " + cause.getMessage());
                cause = cause.getCause();
            }
            error.printStackTrace();
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            getLogger().warning("WS closed: " + statusCode + " " + reason);
            socketRef.set(null);
            if (!running.get()) return null;
            Bukkit.getScheduler().runTaskLater(
                    KavexLinkPlugin.this,
                    KavexLinkPlugin.this::connectWithRetry,
                    20L * 5
            );
            return null;
        }
    }

    private void handleMessage(String json) {
        getLogger().info("[WS RECV] " + json);

        JsonObject obj;
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (Exception e) {
            getLogger().warning("Bad JSON from WS: " + e + " :: " + json);
            return;
        }

        String op = obj.has("op") && !obj.get("op").isJsonNull()
                ? obj.get("op").getAsString()
                : "";
        getLogger().info("WS op=" + op);

        switch (op) {
            case "dc_chat": {
                String user = obj.has("user") && !obj.get("user").isJsonNull()
                    ? obj.get("user").getAsString()
                    : "discord";
                String guild = obj.has("guild") && !obj.get("guild").isJsonNull()
                    ? obj.get("guild").getAsString()
                    : "guild";
                String text = obj.has("text") && !obj.get("text").isJsonNull()
                    ? obj.get("text").getAsString()
                    : "";

                String prefix = obj.has("prefix") && !obj.get("prefix").isJsonNull()
                    ? obj.get("prefix").getAsString()
                    : "";
                String colorHex = obj.has("color") && !obj.get("color").isJsonNull()
                    ? obj.get("color").getAsString()
                    : null;

                String colorCode = hexToMinecraftColor(colorHex);
                String prefixPart = prefix.isEmpty() ? "" : prefix + " ";

                final String finalMsg =
                    colorCode
                    + prefixPart
                    + user
                    + "§r§7@" + guild + ": "
                    + text;

                Bukkit.getScheduler().runTask(this,
                    () -> Bukkit.broadcastMessage(finalMsg));
                getLogger().info("Broadcasted dc_chat from " + user + "@" + guild);
                break;
            }
	    case "auth": {
                getLogger().info("WS auth ack: " + json);
                break;
            }
            case "dc_admin": {
                handleDcAdmin(obj);
                break;
            }
	    default: {
                getLogger().info("WS unknown op: " + op);
                break;
            }
        }
    }

    // ---- Events → Discord (mc_event) ----

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent e) {
        Player p = e.getPlayer();
        sendEvent("join", p, "connected");
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent e) {
        Player p = e.getPlayer();
        sendEvent("quit", p, "disconnected");
    }

    @EventHandler
    public void onPlayerDeath(PlayerDeathEvent e) {
        Player p = e.getEntity();
        String msg = PlainTextComponentSerializer.plainText().serialize(e.deathMessage());
        String name = p.getName();
        String text = msg;
        if (msg != null && msg.startsWith(name + " ")) {
            text = msg.substring((name + " ").length());
        }
        if (text == null || text.isEmpty()) text = "died";
        sendEvent("death", p, text);
    }

    private void sendEvent(String etype, Player player, String text) {
        WebSocket ws = socketRef.get();
        if (ws == null) return;

        final String name = player.getName();
        final String uuid = player.getUniqueId().toString().replace("-", "");
        final String safe = text.replace("\"", "\\\"");

        final String payload = "{\"op\":\"mc_event\",\"etype\":\"" + etype + "\","
                + "\"player\":\"" + name + "\","
                + "\"uuid\":\"" + uuid + "\","
                + "\"text\":\"" + safe + "\"}";

        try {
            ws.sendText(payload, true);
        } catch (Exception ignored) {
        }
    }

    // ---- Admin commands ----
    
    private void handleDcAdmin(JsonObject obj) {
        String action = obj.has("action") && !obj.get("action").isJsonNull()
                ? obj.get("action").getAsString().toLowerCase()
                : "";
        String player = obj.has("player") && !obj.get("player").isJsonNull()
                ? obj.get("player").getAsString()
                : "";
        String reason = obj.has("reason") && !obj.get("reason").isJsonNull()
                ? obj.get("reason").getAsString()
                : "";
        String issuedBy = obj.has("issued_by") && !obj.get("issued_by").isJsonNull()
                ? obj.get("issued_by").getAsString()
                : "Discord";

        if (player.isEmpty()) {
            getLogger().warning("dc_admin: empty player in payload: " + obj);
            return;
        }

        // Log on the MC side
        getLogger().info("dc_admin: action=" + action + " player=" + player
                + " reason=" + reason + " issued_by=" + issuedBy);

        // Run on main thread
        Bukkit.getScheduler().runTask(this, () -> {
            switch (action) {
                case "kick": {
                    String msg = "Kicked by " + issuedBy;
                    if (!reason.isEmpty()) msg += " (" + reason + ")";
                    Bukkit.dispatchCommand(
                            Bukkit.getConsoleSender(),
                            "kick " + player + " " + msg
                    );
                    break;
                }
                case "ban": {
                    String msg = "Banned by " + issuedBy;
                    if (!reason.isEmpty()) msg += " (" + reason + ")";
                    Bukkit.dispatchCommand(
                            Bukkit.getConsoleSender(),
                            "ban " + player + " " + msg
                    );
                    break;
                }
                // easy to extend:
                case "pardon": {
                    Bukkit.dispatchCommand(
                            Bukkit.getConsoleSender(),
                            "pardon " + player
                    );
                    break;
                }
                case "command": {
                    // OPTIONAL: allow arbitrary console commands from Discord
                    if (obj.has("console") && !obj.get("console").isJsonNull()) {
                        String cmd = obj.get("console").getAsString();
                        getLogger().info("dc_admin console command from " + issuedBy + ": " + cmd);
                        Bukkit.dispatchCommand(Bukkit.getConsoleSender(), cmd);
                    }
                    break;
                }
                default: {
                    getLogger().warning("dc_admin: unknown action '" + action + "'");
                    break;
                }
            }
        });
    }

        private String generateLinkCode() {
        // Simple 8-char alphanumeric code
        String chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(8);
        for (int i = 0; i < 8; i++) {
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return sb.toString();
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!cmd.getName().equalsIgnoreCase("linkdiscord")) {
            return false;
        }

        if (!(sender instanceof Player p)) {
            sender.sendMessage("Only players can use this.");
            return true;
        }

        if (!sender.hasPermission("kavexlink.link")) {
            sender.sendMessage("You don't have permission to link your account.");
            return true;
        }

        WebSocket ws = socketRef.get();
        if (ws == null) {
            sender.sendMessage("The Discord bridge is currently offline. Try again later.");
            return true;
        }

        String code = generateLinkCode();
        String uuid = p.getUniqueId().toString().replace("-", "");
        String name = p.getName();

        // Send link request over WS
        String payload = "{\"op\":\"mc_link_request\","
                + "\"uuid\":\"" + uuid + "\","
                + "\"name\":\"" + escape(name) + "\","
                + "\"code\":\"" + code + "\"}";

        try {
            ws.sendText(payload, true);
        } catch (Exception e) {
            getLogger().warning("Failed to send mc_link_request: " + e);
            sender.sendMessage("Failed to contact the Discord bridge. Try again later.");
            return true;
        }

        sender.sendMessage("§aYour link code is §e" + code + "§a.");
        sender.sendMessage("§7Open the Discord server and run §b/linkdiscord " + code + "§7.");

        return true;
    }



    // ---- Chat capture to Discord ----

    @EventHandler
    public void onChat(AsyncChatEvent e) {
        WebSocket ws = socketRef.get();
        if (ws == null) return;

        final String player = e.getPlayer().getName();
        final String uuid = e.getPlayer().getUniqueId().toString().replace("-", "");
        final String text = PlainTextComponentSerializer.plainText()
                .serialize(e.message())
                .replace("\"", "\\\"");

        final String payload = "{\"op\":\"mc_chat\",\"player\":\"" + player + "\","
                + "\"uuid\":\"" + uuid + "\","
                + "\"text\":\"" + text + "\"}";
        try {
            ws.sendText(payload, true);
        } catch (Exception ignored) {
        }
    }

    private static String escape(String s) {
        return s.replace("\"", "\\\"");
    }
}

