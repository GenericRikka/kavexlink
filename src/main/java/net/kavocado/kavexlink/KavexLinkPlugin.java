package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.event.Listener;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent.Result;

import java.io.BufferedInputStream;
import java.io.File;
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
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import io.papermc.paper.event.player.AsyncChatEvent;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
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

    private final Map<String, PlayerStyle> playerStyles = new ConcurrentHashMap<>();

    private FriendManager friendManager;

    private static class PlayerStyle {
        final String prefix;
        final String colorHex;
        final boolean canKick;
        final boolean canBan;
        final boolean canTimeout;
        final boolean isStaff;

        PlayerStyle(String prefix,
                    String colorHex,
                    boolean canKick,
                    boolean canBan,
                    boolean canTimeout,
                    boolean isStaff) {
            this.prefix = prefix;
            this.colorHex = colorHex;
            this.canKick = canKick;
            this.canBan = canBan;
            this.canTimeout = canTimeout;
            this.isStaff = isStaff;
        }
    }

    // Moderation storage
    private File moderationFile;
    private FileConfiguration moderationConfig;

    private final Map<String, BanEntry> bans = new ConcurrentHashMap<>();
    private final Map<String, MuteEntry> mutes = new ConcurrentHashMap<>();

    private static class BanEntry {
        final String uuid;
        final String name;
        final long createdAt;
        final long expiresAt; // 0 = permanent
        final String reason;
        final String source;

        BanEntry(String uuid, String name, long createdAt, long expiresAt,
                 String reason, String source) {
            this.uuid = uuid;
            this.name = name;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.reason = reason;
            this.source = source;
        }

        boolean isActive() {
            return expiresAt == 0L || expiresAt > System.currentTimeMillis();
        }
    }

    private static class MuteEntry {
        final String uuid;
        final String name;
        final long createdAt;
        final long expiresAt; // 0 = permanent
        final String reason;
        final String source;

        MuteEntry(String uuid, String name, long createdAt, long expiresAt,
                  String reason, String source) {
            this.uuid = uuid;
            this.name = name;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.reason = reason;
            this.source = source;
        }

        boolean isActive() {
            return expiresAt == 0L || expiresAt > System.currentTimeMillis();
        }
    }

    @Override
    public void onEnable() {
        running.set(true);

        saveDefaultConfig();
        this.dataDir = getDataFolder().toPath();
        this.secretFile = dataDir.resolve("secret.txt");

	new FriendCompassTask(this).runTaskTimer(this, 20L, 20L);

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

	// Moderation storage
        this.moderationFile = dataDir.resolve("moderation.yml").toFile();
        this.moderationConfig = YamlConfiguration.loadConfiguration(moderationFile);
        loadModerationData();

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

        connectWithRetry();
        this.friendManager = new FriendManager(this);

        getCommand("friendrequest").setExecutor(new FriendRequestCommand(this));
        getCommand("friend").setExecutor(new FriendCommand(this));
        getCommand("friends").setExecutor(new FriendsGuiCommand(this));

        getServer().getPluginManager().registerEvents(this, this);
        getServer().getPluginManager().registerEvents(new FriendsListener(this), this);
    }

    public FriendManager getFriendManager() {
        return friendManager;
    }

    @Override
    public void onDisable() {
	saveModerationData();
	if (friendManager != null) {
            friendManager.saveToDisk();
        }
        running.set(false);
        WebSocket ws = socketRef.getAndSet(null);
        if (ws != null) ws.abort();
    }

    private void requestPermStyle(Player player) {
        WebSocket ws = socketRef.get();
        if (ws == null) return;

        String uuid = player.getUniqueId().toString().replace("-", "");
        String name = player.getName().replace("\"", "\\\"");

        final String payload = "{\"op\":\"mc_perm_query\",\"uuid\":\"" + uuid + "\","
                + "\"name\":\"" + name + "\"}";

        try {
            ws.sendText(payload, true);
        } catch (Exception ignored) {
        }
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

    private void loadModerationData() {
        bans.clear();
        mutes.clear();

        if (!moderationFile.exists()) {
            return;
        }

        moderationConfig = YamlConfiguration.loadConfiguration(moderationFile);

        ConfigurationSection bansSec = moderationConfig.getConfigurationSection("bans");
        if (bansSec != null) {
            for (String uuid : bansSec.getKeys(false)) {
                String path = "bans." + uuid + ".";
                String name = bansSec.getString(uuid + ".name", "Unknown");
                long createdAt = bansSec.getLong(uuid + ".createdAt", 0L);
                long expiresAt = bansSec.getLong(uuid + ".expiresAt", 0L);
                String reason = bansSec.getString(uuid + ".reason", "You are banned from this server.");
                String source = bansSec.getString(uuid + ".source", "System");

                BanEntry entry = new BanEntry(uuid, name, createdAt, expiresAt, reason, source);
                if (entry.isActive()) {
                    bans.put(uuid, entry);
                }
            }
        }

        ConfigurationSection mutesSec = moderationConfig.getConfigurationSection("mutes");
        if (mutesSec != null) {
            for (String uuid : mutesSec.getKeys(false)) {
                String path = "mutes." + uuid + ".";
                String name = mutesSec.getString(uuid + ".name", "Unknown");
                long createdAt = mutesSec.getLong(uuid + ".createdAt", 0L);
                long expiresAt = mutesSec.getLong(uuid + ".expiresAt", 0L);
                String reason = mutesSec.getString(uuid + ".reason", "You are muted on this server.");
                String source = mutesSec.getString(uuid + ".source", "System");

                MuteEntry entry = new MuteEntry(uuid, name, createdAt, expiresAt, reason, source);
                if (entry.isActive()) {
                    mutes.put(uuid, entry);
                }
            }
        }

        getLogger().info("Loaded " + bans.size() + " active bans and " + mutes.size() + " active mutes.");
    }

    private void saveModerationData() {
        if (moderationConfig == null) {
            moderationConfig = new YamlConfiguration();
        }

        moderationConfig.set("bans", null);
        moderationConfig.set("mutes", null);

        for (BanEntry b : bans.values()) {
            String base = "bans." + b.uuid + ".";
            moderationConfig.set(base + "name", b.name);
            moderationConfig.set(base + "createdAt", b.createdAt);
            moderationConfig.set(base + "expiresAt", b.expiresAt);
            moderationConfig.set(base + "reason", b.reason);
            moderationConfig.set(base + "source", b.source);
        }

        for (MuteEntry m : mutes.values()) {
            String base = "mutes." + m.uuid + ".";
            moderationConfig.set(base + "name", m.name);
            moderationConfig.set(base + "createdAt", m.createdAt);
            moderationConfig.set(base + "expiresAt", m.expiresAt);
            moderationConfig.set(base + "reason", m.reason);
            moderationConfig.set(base + "source", m.source);
        }

        try {
            moderationConfig.save(moderationFile);
        } catch (Exception e) {
            getLogger().severe("Failed to save moderation.yml: " + e);
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
                    + "§l" + user
                    + "§r§7@" + guild + "§r"  + ": "
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
	    case "mc_permset": {
                String uuid = obj.has("uuid") && !obj.get("uuid").isJsonNull()
                        ? obj.get("uuid").getAsString()
                        : null;
                String prefix = obj.has("prefix") && !obj.get("prefix").isJsonNull()
                        ? obj.get("prefix").getAsString()
                        : null;
                String colorHex = obj.has("color") && !obj.get("color").isJsonNull()
                        ? obj.get("color").getAsString()
                        : null;

                boolean canKick = obj.has("can_kick") && !obj.get("can_kick").isJsonNull()
                        && obj.get("can_kick").getAsInt() != 0;
                boolean canBan = obj.has("can_ban") && !obj.get("can_ban").isJsonNull()
                        && obj.get("can_ban").getAsInt() != 0;
                boolean canTimeout = obj.has("can_timeout") && !obj.get("can_timeout").isJsonNull()
                        && obj.get("can_timeout").getAsInt() != 0;
                boolean isStaff = obj.has("is_staff") && !obj.get("is_staff").isJsonNull()
                        && obj.get("is_staff").getAsInt() != 0;

                if (uuid != null && !uuid.isEmpty()) {
                    playerStyles.put(uuid, new PlayerStyle(prefix, colorHex,
                            canKick, canBan, canTimeout, isStaff));
                    getLogger().info("Updated style for uuid=" + uuid
                            + " prefix=" + prefix + " color=" + colorHex
                            + " perms: kick=" + canKick + " ban=" + canBan + " timeout=" + canTimeout);
                } else {
                    getLogger().info("mc_permset without uuid, ignoring");
                }
                break;
            }
	    case "dc_notify": {
                String mcName = obj.has("mc_name") && !obj.get("mc_name").isJsonNull()
                        ? obj.get("mc_name").getAsString()
                        : "";
                if (mcName != null && !mcName.isEmpty()) {
                    notifyPing(mcName);
                }
                break;
            } 
	    default: {
                getLogger().info("WS unknown op: " + op);
                break;
            }
        }
    }

    private boolean handleLinkdiscord(org.bukkit.command.CommandSender sender, String[] args) {
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
   
    private PlayerStyle requireStyleWithMessage(Player player, boolean checkKick, boolean checkBan, boolean checkTimeout) {
        String uuid = player.getUniqueId().toString().replace("-", "");
        PlayerStyle style = playerStyles.get(uuid);
        if (style == null) {
            player.sendMessage("§cYour Discord account is not linked or permissions have not been synced yet.");
            return null;
        }

        if (checkKick && !style.canKick) {
            player.sendMessage("§cYou are not allowed to kick players (Discord Kick Members required).");
            return null;
        }
        if (checkBan && !style.canBan) {
            player.sendMessage("§cYou are not allowed to ban players (Discord Ban Members required).");
            return null;
        }
        if (checkTimeout && !style.canTimeout) {
            player.sendMessage("§cYou are not allowed to mute players (Discord Timeout/Moderate Members required).");
            return null;
        }
        return style;
    }

    private boolean handleKavexKick(org.bukkit.command.CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (args.length < 1) {
            player.sendMessage("Usage: /kavexkick <player> [reason]");
            return true;
        }

        PlayerStyle style = requireStyleWithMessage(player, true, false, false);
        if (style == null) return true;

        String targetName = args[0];
        Player target = Bukkit.getPlayerExact(targetName);
        if (target == null) {
            player.sendMessage("§cPlayer not found: " + targetName);
            return true;
        }

        String reason = (args.length > 1)
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 1, args.length))
                : "Kicked by " + player.getName();

        target.kick(Component.text("You were kicked: " + reason, NamedTextColor.RED));
        Bukkit.broadcastMessage("§c" + target.getName() + " was kicked by " + player.getName() + ".");
	sendModEvent("kick", target.getName(), player.getName(), reason, 0);
	return true;
    }

    private boolean handleKavexBan(org.bukkit.command.CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (args.length < 1) {
            player.sendMessage("Usage: /kavexban <player> [reason]");
            return true;
        }

        PlayerStyle style = requireStyleWithMessage(player, false, true, false);
        if (style == null) return true;

        String targetName = args[0];
        Player target = Bukkit.getPlayerExact(targetName);
        if (target == null) {
            player.sendMessage("§cPlayer not found: " + targetName);
            return true;
        }

        String uuid = target.getUniqueId().toString().replace("-", "");
        String reason = (args.length > 1)
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 1, args.length))
                : "Banned by " + player.getName();

        long now = System.currentTimeMillis();
        BanEntry entry = new BanEntry(
                uuid,
                target.getName(),
                now,
                0L, // permanent
                reason,
                player.getName()
        );
        bans.put(uuid, entry);
        saveModerationData();

        target.kick(Component.text("You are banned: " + reason, NamedTextColor.RED));
        Bukkit.broadcastMessage("§c" + target.getName() + " was banned by " + player.getName() + ".");
	sendModEvent("ban", target.getName(), player.getName(), reason, 0);
	return true;
    }

    private boolean handleKavexTempBan(org.bukkit.command.CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (args.length < 2) {
            player.sendMessage("Usage: /kavextempban <player> <minutes> [reason]");
            return true;
        }

        PlayerStyle style = requireStyleWithMessage(player, false, true, false);
        if (style == null) return true;

        String targetName = args[0];
        Player target = Bukkit.getPlayerExact(targetName);
        if (target == null) {
            player.sendMessage("§cPlayer not found: " + targetName);
            return true;
        }

        int minutes;
        try {
            minutes = Integer.parseInt(args[1]);
        } catch (NumberFormatException ex) {
            player.sendMessage("§cInvalid minutes: " + args[1]);
            return true;
        }
        if (minutes <= 0) {
            player.sendMessage("§cMinutes must be > 0.");
            return true;
        }

        String reason = (args.length > 2)
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length))
                : "Temporarily banned by " + player.getName();

        long now = System.currentTimeMillis();
        long expiresAt = now + minutes * 60_000L;

        String uuid = target.getUniqueId().toString().replace("-", "");
        BanEntry entry = new BanEntry(
                uuid,
                target.getName(),
                now,
                expiresAt,
                reason,
                player.getName()
        );
        bans.put(uuid, entry);
        saveModerationData();

        target.kick(Component.text(
            "You are temporarily banned for " + minutes + " minute(s): " + reason,
                NamedTextColor.RED
        ));
        Bukkit.broadcastMessage("§c" + target.getName() + " was tempbanned for " + minutes
            + " minute(s) by " + player.getName() + ".");
	sendModEvent("tempban", target.getName(), player.getName(), reason, minutes);
	return true;
    }

    private boolean handleKavexMute(org.bukkit.command.CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (args.length < 2) {
            player.sendMessage("Usage: /kavexmute <player> <minutes> [reason]");
            return true;
        }

        PlayerStyle style = requireStyleWithMessage(player, false, false, true);
        if (style == null) return true;

        String targetName = args[0];
        Player target = Bukkit.getPlayerExact(targetName);
        if (target == null) {
            player.sendMessage("§cPlayer not found: " + targetName);
            return true;
        }

        int minutes;
        try {
            minutes = Integer.parseInt(args[1]);
        } catch (NumberFormatException ex) {
            player.sendMessage("§cInvalid minutes: " + args[1]);
            return true;
        }
        if (minutes <= 0) {
            player.sendMessage("§cMinutes must be > 0.");
            return true;
        }

        String reason = (args.length > 2)
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length))
                : "Muted by " + player.getName();

        long now = System.currentTimeMillis();
        long expiresAt = now + minutes * 60_000L;

        String uuid = target.getUniqueId().toString().replace("-", "");
        MuteEntry entry = new MuteEntry(
                uuid,
                target.getName(),
                now,
                expiresAt,
                reason,
                player.getName()
        );
        mutes.put(uuid, entry);
        saveModerationData();

        target.sendMessage(org.bukkit.ChatColor.RED + "You are muted for " + minutes
                + " minute(s): " + reason);
        Bukkit.broadcastMessage("§e" + target.getName() + " was muted for " + minutes
                + " minute(s) by " + player.getName() + ".");
	sendModEvent("mute", target.getName(), player.getName(), reason, minutes);
        return true;
    }

    // ---- Events → Discord (mc_event) ----

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent e) {
        Player p = e.getPlayer();
        sendEvent("join", p, "connected");
        requestPermStyle(p);

        UUID uuid = p.getUniqueId();
        for (String msg : friendManager.drainNotifications(uuid)) {
            p.sendMessage(msg);
        }

        // Notify their friends
        Set<UUID> friends = friendManager.getFriends(uuid);
        for (UUID friendId : friends) {
            Player friend = Bukkit.getPlayer(friendId);
            if (friend != null && friend.isOnline()) {
                friend.sendMessage("§aYour friend §e" + p.getName() + " §ahas joined the game.");
            }
        }
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent e) {
        Player p = e.getPlayer();
        sendEvent("quit", p, "disconnected");

        UUID uuid = p.getUniqueId();
        Set<UUID> friends = friendManager.getFriends(uuid);
        for (UUID friendId : friends) {
            Player friend = Bukkit.getPlayer(friendId);
            if (friend != null && friend.isOnline()) {
                friend.sendMessage("§cYour friend §e" + p.getName() + " §chas left the game.");
            }
        }
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

    private void sendModEvent(String action,
                              String targetName,
                              String issuedBy,
                              String reason,
                              int minutes) {
        WebSocket ws = socketRef.get();
        if (ws == null) return;

        String safeTarget = escape(targetName != null ? targetName : "");
        String safeIssued = escape(issuedBy != null ? issuedBy : "System");
        String safeReason = escape(reason != null ? reason : "");

        String payload = "{\"op\":\"mc_mod\","
                + "\"action\":\"" + action + "\","
                + "\"target\":\"" + safeTarget + "\","
                + "\"issued_by\":\"" + safeIssued + "\","
                + "\"reason\":\"" + safeReason + "\","
                + "\"minutes\":" + minutes + "}";

        try {
            ws.sendText(payload, true);
        } catch (Exception e) {
            getLogger().warning("Failed to send mc_mod event: " + e);
        }
    }

    private void notifyPing(String mcName) {
        org.bukkit.entity.Player target = Bukkit.getPlayerExact(mcName);
        if (target == null || !target.isOnline()) {
            return;
        }

        // play two note-block chimes as a "ping"
        // 1st now
        target.playSound(
                target.getLocation(),
                org.bukkit.Sound.BLOCK_NOTE_BLOCK_PLING,
                1.0f,
                1.0f
        );
        // 2nd a short time later (3 ticks ≈ 0.15s)
        Bukkit.getScheduler().runTaskLater(
                this,
                () -> target.playSound(
                        target.getLocation(),
                        org.bukkit.Sound.BLOCK_NOTE_BLOCK_PLING,
                        1.0f,
                        1.5f
                ),
                3L
        );
    }

    private boolean handleKavexPardon(org.bukkit.command.CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (args.length < 1) {
            player.sendMessage("Usage: /kavexpardon <player> [reason]");
            return true;
        }

        // Requires Discord Ban perms (same as /kavexban)
        PlayerStyle style = requireStyleWithMessage(player, false, true, false);
        if (style == null) return true;

        String targetName = args[0];

        // Try by online player, then by stored name
        String banUuid = null;
        BanEntry entry = null;

        Player target = Bukkit.getPlayerExact(targetName);
        if (target != null) {
            banUuid = target.getUniqueId().toString().replace("-", "");
            entry = bans.get(banUuid);
        }

        if (entry == null) {
            for (BanEntry b : bans.values()) {
                if (b.name.equalsIgnoreCase(targetName)) {
                    entry = b;
                    banUuid = b.uuid;
                    break;
                }
            }
        }

        if (entry == null) {
            player.sendMessage("§cNo active ban found for " + targetName + ".");
            return true;
        }

        String reason = (args.length > 1)
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 1, args.length))
                : "Unbanned by " + player.getName();

        bans.remove(banUuid);
        saveModerationData();

        Bukkit.broadcastMessage("§a" + entry.name + " was unbanned by " + player.getName() + ".");
        sendModEvent("pardon", entry.name, player.getName(), reason, 0);
        return true;
    }

    private boolean handleKavexUnmute(org.bukkit.command.CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (args.length < 1) {
            player.sendMessage("Usage: /kavexunmute <player> [reason]");
            return true;
        }

        // Requires Discord timeout/mod perms (same as /kavexmute)
        PlayerStyle style = requireStyleWithMessage(player, false, false, true);
        if (style == null) return true;

        String targetName = args[0];

        String muteUuid = null;
        MuteEntry entry = null;

        Player target = Bukkit.getPlayerExact(targetName);
        if (target != null) {
            muteUuid = target.getUniqueId().toString().replace("-", "");
            entry = mutes.get(muteUuid);
        }

        if (entry == null) {
            for (MuteEntry m : mutes.values()) {
                if (m.name.equalsIgnoreCase(targetName)) {
                    entry = m;
                    muteUuid = m.uuid;
                    break;
                }
            }
        }

        if (entry == null) {
            player.sendMessage("§cNo active mute found for " + targetName + ".");
            return true;
        }

        String reason = (args.length > 1)
                ? String.join(" ", java.util.Arrays.copyOfRange(args, 1, args.length))
                : "Unmuted by " + player.getName();

        mutes.remove(muteUuid);
        saveModerationData();

        if (target != null) {
            target.sendMessage("§aYou have been unmuted by " + player.getName() + ".");
        }
        Bukkit.broadcastMessage("§a" + entry.name + " was unmuted by " + player.getName() + ".");
        sendModEvent("unmute", entry.name, player.getName(), reason, 0);
        return true;
    }


    @EventHandler
    public void onPreLogin(AsyncPlayerPreLoginEvent e) {
        String uuid = e.getUniqueId().toString().replace("-", "");
        BanEntry ban = bans.get(uuid);
        if (ban != null && ban.isActive()) {
            String msg = org.bukkit.ChatColor.RED + "You are banned from this server.\n"
                    + org.bukkit.ChatColor.GRAY + "Reason: " + ban.reason;
            e.disallow(Result.KICK_BANNED, msg);
        }
    }

    // ---- Admin commands ----

    private void handleDcAdmin(JsonObject obj) {
        String action = obj.has("action") && !obj.get("action").isJsonNull()
                ? obj.get("action").getAsString().toLowerCase()
                : "";
        String playerName = obj.has("player") && !obj.get("player").isJsonNull()
                ? obj.get("player").getAsString()
                : "";
        String reason = obj.has("reason") && !obj.get("reason").isJsonNull()
                ? obj.get("reason").getAsString()
                : "";
        String issuedBy = obj.has("issued_by") && !obj.get("issued_by").isJsonNull()
                ? obj.get("issued_by").getAsString()
                : "Discord";
        int minutes = obj.has("minutes") && !obj.get("minutes").isJsonNull()
                ? obj.get("minutes").getAsInt()
                : 0;
        String consoleCmd = obj.has("console") && !obj.get("console").isJsonNull()
                ? obj.get("console").getAsString()
                : null;

        if (playerName.isEmpty() && !"command".equals(action)) {
            getLogger().warning("dc_admin: empty player in payload: " + obj);
            return;
        }

        getLogger().info("dc_admin: action=" + action + " player=" + playerName
                + " reason=" + reason + " issued_by=" + issuedBy + " minutes=" + minutes);

        Bukkit.getScheduler().runTask(this, () -> {
            Player target = (playerName.isEmpty() ? null : Bukkit.getPlayerExact(playerName));

            switch (action) {
                case "kick": {
                    if (target == null) {
                        getLogger().info("dc_admin kick: player not online: " + playerName);
                        return;
                    }
                    String msg = reason.isEmpty()
                            ? "Kicked by " + issuedBy
                            : reason;
                    target.kick(Component.text("You were kicked: " + msg, NamedTextColor.RED));
                    Bukkit.broadcastMessage("§c" + target.getName() + " was kicked by " + issuedBy + ".");
                    sendModEvent("kick", target.getName(), issuedBy, msg, 0);
                    break;
                }
                case "ban": {
                    if (target == null) {
                        getLogger().info("dc_admin ban: player not online: " + playerName);
                        return;
                    }
                    String uuid = target.getUniqueId().toString().replace("-", "");
                    long now = System.currentTimeMillis();
                    String banReason = reason.isEmpty()
                            ? "Banned by " + issuedBy
                            : reason;
                    BanEntry entry = new BanEntry(
                            uuid,
                            target.getName(),
                            now,
                            0L,
                            banReason,
                            issuedBy
                    );
                    bans.put(uuid, entry);
                    saveModerationData();

                    target.kick(Component.text("You are banned: " + banReason, NamedTextColor.RED));
                    Bukkit.broadcastMessage("§c" + target.getName() + " was banned by " + issuedBy + ".");
                    sendModEvent("ban", target.getName(), issuedBy, banReason, 0);
                    break;
                }
                case "tempban": {
                    if (target == null) {
                        getLogger().info("dc_admin tempban: player not online: " + playerName);
                        return;
                    }
                    // minutes is effectively final; derive a local effectiveMinutes
                    int effectiveMinutes = (minutes <= 0) ? 1 : minutes;

                    String uuid = target.getUniqueId().toString().replace("-", "");
                    long now = System.currentTimeMillis();
                    long expiresAt = now + effectiveMinutes * 60_000L;

                    String banReason = reason.isEmpty()
                            ? "Temporarily banned by " + issuedBy
                            : reason;

                    BanEntry entry = new BanEntry(
                            uuid,
                            target.getName(),
                            now,
                            expiresAt,
                            banReason,
                            issuedBy
                    );
                    bans.put(uuid, entry);
                    saveModerationData();

                    target.kick(Component.text(
                            "You are temporarily banned for " + effectiveMinutes + " minute(s): " + banReason,
                            NamedTextColor.RED
                    ));
                    Bukkit.broadcastMessage("§c" + target.getName() + " was tempbanned for "
                            + effectiveMinutes + " minute(s) by " + issuedBy + ".");
                    sendModEvent("tempban", target.getName(), issuedBy, banReason, effectiveMinutes);
                    break;
                }
                case "mute": {
                    if (target == null) {
                        getLogger().info("dc_admin mute: player not online: " + playerName);
                        return;
                    }
                    int effectiveMinutes = (minutes <= 0) ? 1 : minutes;

                    String uuid = target.getUniqueId().toString().replace("-", "");
                    long now = System.currentTimeMillis();
                    long expiresAt = now + effectiveMinutes * 60_000L;
                    String muteReason = reason.isEmpty()
                            ? "Muted by " + issuedBy
                            : reason;

                    MuteEntry entry = new MuteEntry(
                            uuid,
                            target.getName(),
                            now,
                            expiresAt,
                            muteReason,
                            issuedBy
                    );
                    mutes.put(uuid, entry);
                    saveModerationData();

                    target.sendMessage(org.bukkit.ChatColor.RED + "You are muted for "
                            + effectiveMinutes + " minute(s): " + muteReason);
                    Bukkit.broadcastMessage("§e" + target.getName() + " was muted for "
                            + effectiveMinutes + " minute(s) by " + issuedBy + ".");
                    sendModEvent("mute", target.getName(), issuedBy, muteReason, effectiveMinutes);
                    break;
                }
                case "pardon": {
                    String banUuid = null;
                    BanEntry entry = null;
                    for (BanEntry b : bans.values()) {
                        if (b.name.equalsIgnoreCase(playerName)) {
                            entry = b;
                            banUuid = b.uuid;
                            break;
                        }
                    }
                    if (entry == null) {
                        getLogger().info("dc_admin pardon: no active ban for " + playerName);
                        return;
                    }
                    String r = reason.isEmpty()
                            ? "Unbanned by " + issuedBy
                            : reason;
                    bans.remove(banUuid);
                    saveModerationData();
                    Bukkit.broadcastMessage("§a" + entry.name + " was unbanned by " + issuedBy + ".");
                    sendModEvent("pardon", entry.name, issuedBy, r, 0);
                    break;
                }
                case "unmute": {
                    String muteUuid = null;
                    MuteEntry entry = null;
                    for (MuteEntry m : mutes.values()) {
                        if (m.name.equalsIgnoreCase(playerName)) {
                            entry = m;
                            muteUuid = m.uuid;
                            break;
                        }
                    }
                    if (entry == null) {
                        getLogger().info("dc_admin unmute: no active mute for " + playerName);
                        return;
                    }
                    String r = reason.isEmpty()
                            ? "Unmuted by " + issuedBy
                            : reason;
                    mutes.remove(muteUuid);
                    saveModerationData();

                    if (target != null) {
                        target.sendMessage("§aYou have been unmuted by " + issuedBy + ".");
                    }
                    Bukkit.broadcastMessage("§a" + entry.name + " was unmuted by " + issuedBy + ".");
                    sendModEvent("unmute", entry.name, issuedBy, r, 0);
                    break;
                }
                case "command": {
                    if (consoleCmd != null && !consoleCmd.isEmpty()) {
                        getLogger().info("dc_admin console command from " + issuedBy + ": " + consoleCmd);
                        Bukkit.dispatchCommand(Bukkit.getConsoleSender(), consoleCmd);
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
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String name = command.getName().toLowerCase();
        switch (name) {
            case "linkdiscord":
                return handleLinkdiscord(sender, args);
            case "kavexkick":
                return handleKavexKick(sender, args);
            case "kavexban":
                return handleKavexBan(sender, args);
            case "kavextempban":
                return handleKavexTempBan(sender, args);
            case "kavexmute":
                return handleKavexMute(sender, args);
            case "kavexpardon":
                return handleKavexPardon(sender, args);
            case "kavexunmute":
                return handleKavexUnmute(sender, args);
	    default:
                return false;
        }
    }


    // ---- Chat capture to Discord ----

    @EventHandler
    public void onChat(AsyncChatEvent e) {
        WebSocket ws = socketRef.get();

        final Player player = e.getPlayer();
        final String playerName = player.getName();
        final String uuid = player.getUniqueId().toString().replace("-", "");

        // Raw plain text as the player typed it (e.message() is an Adventure Component)
        final String rawText = PlainTextComponentSerializer.plainText()
                .serialize(e.message());

        // ---- NEW: convert MC formatting -> Discord markdown (drop colors) ----
        final String discordFormatted = MarkdownUtil.minecraftToDiscord(rawText);

        // Text escaped for JSON payload to Discord
        final String text = escape(discordFormatted);

        // Check for active mute
        MuteEntry mute = mutes.get(uuid);
        if (mute != null && mute.isActive()) {
            e.setCancelled(true);

            long remainingMs = (mute.expiresAt == 0L)
                    ? -1L
                    : (mute.expiresAt - System.currentTimeMillis());
            String remainingStr;
            if (remainingMs < 0L) {
                remainingStr = "permanently";
            } else {
                long minutes = Math.max(1L, remainingMs / 60000L);
                remainingStr = "for about " + minutes + " minute(s)";
            }

            Bukkit.getScheduler().runTask(this, () -> {
                player.sendMessage(org.bukkit.ChatColor.RED + "You are muted "
                        + remainingStr + ". Reason: " + mute.reason);
            });
            return;
        }

        // Send to Discord (now using markdown-formatted text)
        if (ws != null) {
            final String payload = "{\"op\":\"mc_chat\",\"player\":\"" + playerName + "\","
                    + "\"uuid\":\"" + uuid + "\","
                    + "\"text\":\"" + text + "\"}";
            try {
                ws.sendText(payload, true);
            } catch (Exception ignored) {
            }
        }

        // Look up style for this player
        PlayerStyle style = playerStyles.get(uuid);
        String prefix = (style != null && style.prefix != null && !style.prefix.isEmpty())
                ? style.prefix + " "
                : "";
        String colorCode = (style != null) ? hexToMinecraftColor(style.colorHex) : "§f";

        // ---- NEW: apply &-codes inside the message for in-game display ----
        // Example: "&l&2Test&r Lol" becomes colored/bold in MC
        final String coloredMessage =
            MinecraftFormatUtil.applyPersistentFormatting(rawText);

        final String finalMsg = colorCode + prefix + "§l" + playerName + "§r: " + coloredMessage;

        // Override default chat formatting
        e.setCancelled(true);
        Bukkit.getScheduler().runTask(this,
                () -> Bukkit.broadcastMessage(finalMsg));
    }

    private static String escape(String s) {
        return s.replace("\"", "\\\"");
    }
}

