package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.event.Listener;
import org.bukkit.plugin.java.JavaPlugin;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Random;

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
    private String wsUrl; // e.g. ws://BOT_IP:8765/mcws
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
        this.serverName = getConfig().getString("server-name", (motd != null && !motd.isEmpty()) ? motd : "Minecraft");

        this.wsUrl = getConfig().getString("ws-url", "ws://127.0.0.1:8765/mcws");
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

        try { Files.createDirectories(dataDir); } catch (Exception ignored) {}

        if (!Files.exists(secretFile)) {
            token = generateToken();
            try {
                Files.writeString(secretFile, token, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
            } catch (Exception e) { getLogger().severe("Failed to write secret.txt: " + e); }
        }
        try { token = Files.readString(secretFile).trim(); } catch (Exception e) { token = generateToken(); }

        Bukkit.getPluginManager().registerEvents(this, this);
        connectWithRetry();
    }

    @Override
    public void onDisable() {
        running.set(false);
        WebSocket ws = socketRef.getAndSet(null);
        if (ws != null) ws.abort();
    }

    /** keep only ONE generateToken() in the class */
    private String generateToken() {
        return UUID.randomUUID().toString().replace("-", "") + Long.toHexString(new Random().nextLong());
    }

    private void connectWithRetry() {
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            while (running.get()) {
                try {
                    WebSocket ws = http.newWebSocketBuilder()
                            .connectTimeout(Duration.ofSeconds(5))
                            .buildAsync(URI.create(wsUrl), new WSListener())
                            .join();
                    socketRef.set(ws);
                    // auth frame
                    String auth = "{\"op\":\"auth\",\"token\":\"" + token + "\",\"server\":\"" + escape(serverName) + "\"}";
                    ws.sendText(auth, true);
                    getLogger().info("Connected to " + wsUrl);
                    return;
                } catch (Exception e) {
                    if (!running.get()) break;
                    getLogger().warning("WS connect failed: " + e.getMessage());
                    try { Thread.sleep(5000); } catch (InterruptedException ignored) {}
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
            getLogger().warning("WS error: " + error.getMessage());
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            getLogger().warning("WS closed: " + statusCode + " " + reason);
            socketRef.set(null);
            if (!running.get()) return null;
            Bukkit.getScheduler().runTaskLater(KavexLinkPlugin.this, KavexLinkPlugin.this::connectWithRetry, 20L * 5);
            return null;
        }
    }

    private void handleMessage(String json) {
        // DEBUG: log every incoming frame
        getLogger().info("[WS RECV] " + json);

        JsonObject obj;
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (Exception e) {
            getLogger().warning("Bad JSON from WS: " + e + " :: " + json);
            return;
        }

        String op = obj.has("op") && !obj.get("op").isJsonNull() ? obj.get("op").getAsString() : "";
        getLogger().info("WS op=" + op);

        switch (op) {
            case "dc_chat": {
                String user = obj.has("user") && !obj.get("user").isJsonNull() ? obj.get("user").getAsString() : "discord";
                String guild = obj.has("guild") && !obj.get("guild").isJsonNull() ? obj.get("guild").getAsString() : "guild";
                String text = obj.has("text") && !obj.get("text").isJsonNull() ? obj.get("text").getAsString() : "";

                // user in pink (§d), '@' in dark blue (§1), server in violet (§5), then reset
                final String finalMsg =
                        "§d" + user + "§r" + "§1@" + "§r" + "§5" + guild + "§r" + ": " + text;

                // Push to main thread
                Bukkit.getScheduler().runTask(this, () -> Bukkit.broadcastMessage(finalMsg));
                getLogger().info("Broadcasted dc_chat from " + user + "@" + guild);
                break;
            }
            case "auth": {
                getLogger().info("WS auth ack: " + json);
                break;
            }
            default: {
                getLogger().info("WS unknown op: " + op);
                break;
            }
        }
    }

    // ---- New: event hooks → Discord (mc_event) ----

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
        // Get a plain death message and try to strip leading "PlayerName "
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
        final String safe = text.replace("\"", "\\\""); // escape quotes

        final String payload = "{\"op\":\"mc_event\",\"etype\":\"" + etype + "\","
                + "\"player\":\"" + name + "\","
                + "\"uuid\":\"" + uuid + "\","
                + "\"text\":\"" + safe + "\"}";

        try { ws.sendText(payload, true); } catch (Exception ignored) {}
    }

    // ---- Chat capture to Discord (unchanged) ----
    @EventHandler
    public void onChat(AsyncChatEvent e) {
        WebSocket ws = socketRef.get();
        if (ws == null) return;

        final String player = e.getPlayer().getName();
        final String uuid = e.getPlayer().getUniqueId().toString().replace("-", "");
        final String text = PlainTextComponentSerializer.plainText().serialize(e.message()).replace("\"", "\\\"");

        final String payload = "{\"op\":\"mc_chat\",\"player\":\"" + player + "\","
                + "\"uuid\":\"" + uuid + "\","
                + "\"text\":\"" + text + "\"}";
        try { ws.sendText(payload, true); } catch (Exception ignored) {}
    }

    private static String escape(String s) { return s.replace("\"","\\\""); }
}

