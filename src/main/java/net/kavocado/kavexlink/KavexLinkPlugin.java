package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.World;
import org.bukkit.GameMode;
import org.bukkit.boss.BarColor;
import org.bukkit.boss.BarStyle;
import org.bukkit.boss.BossBar;
import org.bukkit.event.Listener;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent.Result;
import org.bukkit.event.player.PlayerAdvancementDoneEvent;
import org.bukkit.event.player.PlayerChangedWorldEvent;
import org.bukkit.advancement.Advancement;
import io.papermc.paper.advancement.AdvancementDisplay;
import org.bukkit.NamespacedKey;
import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.Sound;
import org.bukkit.inventory.ItemStack;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.event.player.PlayerTeleportEvent;

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
import java.util.List;
import java.util.Locale;
import java.util.ArrayList;
import java.util.Collections;
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
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.format.TextDecoration;
import org.bukkit.event.EventHandler;
import org.bukkit.entity.Player;

// Gson for robust JSON parsing
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

// Player lifecycle & death events
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.entity.PlayerDeathEvent;

public class KavexLinkPlugin extends JavaPlugin implements Listener, TabCompleter {

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
    private WarpManager warpManager;
    private WorldManager worldManager;
    private NamespacedKey warpKey;
    private NamespacedKey worldKey;
    private NamespacedKey pageActionKey;
    private PortalManager portalManager;
    private WorldProfileManager worldProfileManager;
    private BackManager backManager;


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

    public WarpManager getWarpManager() {
        return warpManager;
    }

    public WorldManager getWorldManager() {
        return worldManager;
    }

    public NamespacedKey getWarpKey() {
        return warpKey;
    }

    public NamespacedKey getWorldKey() {
        return worldKey;
    }

    public NamespacedKey getPageActionKey() {
        return pageActionKey;
    }

    public BackManager getBackManager() {
        return backManager;
    }

    /**
     * The raw server-name from config.yml, trimmed, or null if it's left unset/blank.
     * Unlike the `serverName` field used for Discord status messages (which falls
     * back to the MOTD or "Minecraft"), this is for callers like the warps GUI
     * title that want to omit the server name entirely rather than show a guessed
     * one when it isn't configured.
     */
    public String getConfiguredServerName() {
        String configured = getConfig().getString("server-name", "");
        if (configured != null && !configured.trim().isEmpty()) {
            return configured.trim();
        }
        return null;
    }

    // ---------- Join-teleport ("jointp") config ----------

    public boolean isJoinTeleportEnabled() {
        return getConfig().getBoolean("join-teleport.enabled", false);
    }

    public void setJoinTeleportEnabled(boolean enabled) {
        getConfig().set("join-teleport.enabled", enabled);
        saveConfig();
    }

    public String getJoinTeleportWarpName() {
        return getConfig().getString("join-teleport.warp", "spawn");
    }

    public void setJoinTeleportWarpName(String name) {
        getConfig().set("join-teleport.warp", name);
        saveConfig();
    }

    public PortalManager getPortalManager() {
        return portalManager;
    }

    public WorldProfileManager getWorldProfileManager() {
        return worldProfileManager;
    }


    public boolean hasWorldAdmin(Player p) {
        // Bukkit permission override
        if (p.hasPermission("kavexlink.worlds.admin")) {
            return true;
        }
        // Fallback: use Discord-based staff flag
        String uuid = p.getUniqueId().toString().replace("-", "");
        PlayerStyle style = playerStyles.get(uuid);
        return style != null && style.isStaff;
    }

    // --- Direct messaging state ---

    // Last DM partner per player, used by /reply
    private final Map<UUID, UUID> lastDmPartner = new ConcurrentHashMap<>();
    // Active DM mode target per player (chat messages -> DM)
    private final Map<UUID, UUID> activeDmTarget = new ConcurrentHashMap<>();
    // BossBars that show “Direct messaging with X”
    private final Map<UUID, BossBar> dmBossBars = new ConcurrentHashMap<>();

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

        // Warps & Worlds
        this.warpManager = new WarpManager(this);
        this.worldManager = new WorldManager(this);

        this.warpKey = new NamespacedKey(this, "warp_id");
        this.worldKey = new NamespacedKey(this, "world_id");
        this.pageActionKey = new NamespacedKey(this, "page_action");

	this.portalManager = new PortalManager(this);
        getServer().getPluginManager().registerEvents(portalManager, this);

	this.worldProfileManager = new WorldProfileManager(this);

        this.backManager = new BackManager(this);
        if (getCommand("back") != null) {
            getCommand("back").setExecutor(this);
        }

        // /back writes happen far more often than warp edits, so flush periodically
        // instead of on every single teleport.
        getServer().getScheduler().runTaskTimerAsynchronously(
                this,
                () -> backManager.autoSaveIfDirty(),
                6000L, // 5 minutes
                6000L
        );

        // Listeners for GUIs
        getServer().getPluginManager().registerEvents(new WarpsGuiListener(this), this);
        getServer().getPluginManager().registerEvents(new WorldsGuiListener(this), this);

        // Fells the rest of a tree's trunk when a player breaks one of its logs
        getServer().getPluginManager().registerEvents(new TreeFellListener(this), this);

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
        getCommand("ftp").setExecutor(this);

        getServer().getPluginManager().registerEvents(this, this);
        getServer().getPluginManager().registerEvents(new FriendsListener(this), this);

	// Register this plugin as TabCompleter for commands handled via onCommand
	String[] tabbedCommands = {
        	"setwarp",
        	"warp",
        	"warps",
        	"world",
        	"worlds",
        	"portal",
        	"portals",
        	"notifyping",
        	"dm",
        	"kavexkick",
        	"kavexban",
        	"kavextempban",
        	"kavexmute",
        	"kavexpardon",
        	"kavexunmute",
		"friend"
	};

	for (String cmdName : tabbedCommands) {
    		if (getCommand(cmdName) != null) {
        		getCommand(cmdName).setTabCompleter(this);
    		}
	}
    }

    @Override
    public List<String> onTabComplete(CommandSender sender,
                                      Command command,
                                      String alias,
                                      String[] args) {
        String name = command.getName().toLowerCase(Locale.ROOT);

        switch (name) {
            case "setwarp":
                return tabCompleteSetWarp(sender, args);
            case "warp":
                return tabCompleteWarp(sender, args);
            case "warps":
                return tabCompleteWarps(sender, args);
            case "world":
                return tabCompleteWorld(sender, args);
            case "worlds":
                return Collections.emptyList(); // GUI only, no args
            case "portal":
                return tabCompletePortal(sender, args);
            case "portals":
                return tabCompletePortals(sender, args);
            case "notifyping":
                return tabCompleteNotifyPing(sender, args);
            case "dm":
                return tabCompleteDm(sender, args);
	    case "friend":
                return tabCompleteFriend(sender, args);
            case "kavexkick":
            case "kavexban":
            case "kavextempban":
            case "kavexmute":
            case "kavexpardon":
            case "kavexunmute":
                return tabCompletePlayerFirstArg(sender, args);
            default:
                return Collections.emptyList();
        }
    }

    public FriendManager getFriendManager() {
        return friendManager;
    }

    private PlayerStyle requireStaffStyle(Player player) {
        String uuid = player.getUniqueId().toString().replace("-", "");
        PlayerStyle style = playerStyles.get(uuid);
        if (style == null) {
            player.sendMessage("§cYour Discord account is not linked or permissions have not been synced yet.");
            return null;
        }
        if (!style.isStaff) {
            player.sendMessage("§cYou must have Discord administrator/staff permissions to manage public warps.");
            return null;
        }
        return style;
    }

    @Override
    public void onDisable() {
        saveModerationData();
        if (friendManager != null) {
            friendManager.saveToDisk();
        }

        if (warpManager != null) {
            warpManager.save();
        }
        if (worldManager != null) {
            worldManager.saveSafely();
	}

	 if (worldProfileManager != null) {
            worldProfileManager.saveAllToDisk();
        }

        if (backManager != null) {
            backManager.save();
        }


        // Clean up bossbars
        for (BossBar bar : dmBossBars.values()) {
            bar.removeAll();
        }
        dmBossBars.clear();
        activeDmTarget.clear();
        lastDmPartner.clear();

        running.set(false);
        WebSocket ws = socketRef.getAndSet(null);
        if (ws != null) ws.abort();
    
	if (portalManager != null) {
            portalManager.saveSafely();
        }
    }

    private void updateTabListName(Player p) {
        String key = p.getUniqueId().toString().replace("-", "");
        PlayerStyle style = playerStyles.get(key);

        // World label in gray: [world]
        String worldName = p.getWorld().getName();
        Component worldPart = Component.text("[" + worldName + "] ", NamedTextColor.GRAY);

        if (style == null) {
            // No special style -> just world + plain name
            Component namePart = Component.text(p.getName(), NamedTextColor.WHITE);
            p.playerListName(worldPart.append(namePart));
            return;
        }

        String prefix = (style.prefix != null && !style.prefix.isEmpty())
                ? style.prefix + " "
                : "";

        // Convert hex color to Adventure TextColor
        TextColor tc = NamedTextColor.WHITE;
        if (style.colorHex != null) {
            String hex = style.colorHex.trim();
            if (hex.matches("^#([0-9a-fA-F]{6})$")) {
                try {
                    int rgb = Integer.parseInt(hex.substring(1), 16);
                    tc = TextColor.color(rgb);
                } catch (NumberFormatException ignored) {
                }
            }
        }

        Component base = worldPart;
        if (!prefix.isEmpty()) {
            base = base.append(Component.text(prefix, tc));
        }

        Component namePart = Component.text(p.getName(), tc)
                .decorate(TextDecoration.BOLD);

        p.playerListName(base.append(namePart));
    }


    // ----------------- DM BossBar helpers -----------------

    private void showDmBossBar(Player p, String friendName) {
        UUID id = p.getUniqueId();
        BossBar bar = dmBossBars.get(id);

        String title = "§bDirect messaging with §f" + friendName + " §7(/exit to leave)";

        if (bar == null) {
            bar = Bukkit.createBossBar(title, BarColor.BLUE, BarStyle.SOLID);
            bar.setProgress(1.0);
            bar.addPlayer(p);
            dmBossBars.put(id, bar);
        } else {
            bar.setTitle(title);
            bar.addPlayer(p);
            bar.setVisible(true);
        }
    }

    private void hideDmBossBar(Player p) {
        UUID id = p.getUniqueId();
        BossBar bar = dmBossBars.remove(id);
        if (bar != null) {
            bar.removeAll();
        }
    }

    private void enterDmMode(Player p, UUID friendId, String friendName) {
        UUID pid = p.getUniqueId();
        activeDmTarget.put(pid, friendId);
        showDmBossBar(p, friendName);
    }

    private void exitDmMode(Player p) {
        UUID pid = p.getUniqueId();
        activeDmTarget.remove(pid);
        hideDmBossBar(p);
    }

    public void applyWorldGamemode(Player p, WorldManager.WorldEntry entry) {
        if (entry == null) return;
        GameMode gm = entry.getDefaultGamemode();
        if (gm == null) return; // inherit server default
        p.setGameMode(gm);
    }

    // ----------------- DM core helpers -----------------

    /**
     * Start / open a DM session from a viewer to a friend.
     * Shows recent history and puts viewer into DM mode.
     */
    public void openDmSession(Player viewer, UUID friendId) {
        UUID viewerId = viewer.getUniqueId();

        if (!friendManager.areFriends(viewerId, friendId)) {
            viewer.sendMessage("§cYou can only direct-message players who are your friends.");
            return;
        }

        OfflinePlayer op = Bukkit.getOfflinePlayer(friendId);
        String friendName = (op.getName() != null ? op.getName() : friendId.toString());

        lastDmPartner.put(viewerId, friendId);
        friendManager.clearUnread(viewerId, friendId);
        enterDmMode(viewer, friendId, friendName);

        int days = getConfig().getInt("friends.dm-history-days", 30);
        java.util.List<FriendManager.DmMessage> history =
                friendManager.getRecentMessages(viewerId, friendId, days);

        viewer.sendMessage("§7=== Direct messages with §e" + friendName
                + " §7(last " + days + " day(s)) ===");
        if (history.isEmpty()) {
            viewer.sendMessage("§7No recent messages.");
        } else {
            history.sort(java.util.Comparator.comparingLong(FriendManager.DmMessage::getTimestamp));
            for (FriendManager.DmMessage m : history) {
                boolean fromViewer = m.getFrom().equals(viewerId);
                String prefix = fromViewer
                        ? "§d[You → " + friendName + "] §r"
                        : "§d[" + friendName + " → You] §r";
                viewer.sendMessage(prefix + m.getText());
            }
        }
        viewer.sendMessage("§7You are now in direct-message mode with §e" + friendName
                + "§7. Type messages to DM them, or use §e/exit §7to go back to public chat.");
    }

    /**
     * Send a direct message from 'from' to 'targetId'.
     * Also persists the message, updates unread counts, and handles notifications/pings.
     */
    private void sendDirectMessage(Player from, UUID targetId, String text) {
        UUID fromId = from.getUniqueId();

        if (fromId.equals(targetId)) {
            from.sendMessage("§cYou cannot direct-message yourself.");
            return;
        }

        if (!friendManager.areFriends(fromId, targetId)) {
            from.sendMessage("§cYou can only direct-message players who are your friends.");
            exitDmMode(from);
            return;
        }

        OfflinePlayer targetOp = Bukkit.getOfflinePlayer(targetId);
        String targetName = (targetOp.getName() != null ? targetOp.getName() : targetId.toString());

        text = text.trim();
        if (text.isEmpty()) {
            from.sendMessage("§7Your message was empty.");
            return;
        }

        // Persist & unread count
        friendManager.storeDirectMessage(fromId, targetId, text);
        friendManager.incrementUnread(targetId, fromId);

        // remember last partner for both sides
        lastDmPartner.put(fromId, targetId);

        Player targetOnline = Bukkit.getPlayer(targetId);
        if (targetOnline != null && targetOnline.isOnline()) {
            lastDmPartner.put(targetId, fromId);
        }

        // sender view
        from.sendMessage("§d[DM to " + targetName + "] §r" + text);

        // receiver view
        if (targetOnline != null && targetOnline.isOnline()) {
            targetOnline.sendMessage("§d[DM from " + from.getName() + "] §r" + text);
            // DM ping
            notifyPing(targetOnline.getName());
        } else {
            friendManager.queueNotification(
                    targetId,
                    "§bYou have a new direct message from §e" + from.getName()
                            + "§b. Use §e/friends §bto view & reply."
            );
        }

        // keep DM mode active with bossbar
        enterDmMode(from, targetId, targetName);
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

    private List<String> tabCompleteMaterials(String partial) {
        String p = partial == null ? "" : partial.toUpperCase();
        List<String> result = new ArrayList<>();

        for (Material m : Material.values()) {
            if (!m.isItem()) continue;              // only things you can hold as an item
            String name = m.name();                 // e.g. DIAMOND_SWORD
            if (p.isEmpty() || name.startsWith(p)) {
                result.add(name);
            }
        }
        return result;
    }

    private List<String> tabCompleteParticles(String partial) {
    String p = partial == null ? "" : partial.toUpperCase(Locale.ROOT);
    List<String> result = new ArrayList<>();

    for (org.bukkit.Particle particle : org.bukkit.Particle.values()) {
        String name = particle.name();
        if (p.isEmpty() || name.startsWith(p)) {
            result.add(name);
        }
    }
    Collections.sort(result, String.CASE_INSENSITIVE_ORDER);
    return result;
}

    /**
     * Same as tabCompleteMaterials, but also offers "hand" - used only for warp
     * icon completion (/setwarp, /warp edit icon), not for consumers like
     * /world create|edit icon which only ever accept a plain Material.
     */
    private List<String> tabCompleteWarpIcon(String partial) {
        String p = partial == null ? "" : partial.toUpperCase(Locale.ROOT);
        List<String> result = new ArrayList<>();
        if ("HAND".startsWith(p)) {
            result.add("hand");
        }
        result.addAll(tabCompleteMaterials(partial));
        return result;
    }

    private List<String> tabCompleteCategories(String partial) {
        if (warpManager == null) {
            return Collections.emptyList();
        }
        String p = partial == null ? "" : partial.toLowerCase(Locale.ROOT);
        List<String> result = new ArrayList<>();
        for (String category : warpManager.getKnownCategories()) {
            if (p.isEmpty() || category.toLowerCase(Locale.ROOT).startsWith(p)) {
                result.add(category);
            }
        }
        return result;
    }

    private List<String> tabCompleteSetWarp(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            return Collections.emptyList();
        }

        // /setwarp <name> <public|private> [icon|hand] [category]
        if (args.length == 2) {
            String partial = args[1].toLowerCase();
            List<String> options = new ArrayList<>();
            if ("public".startsWith(partial))  options.add("public");
            if ("private".startsWith(partial)) options.add("private");
            return options;
        }

        if (args.length == 3) {
            return tabCompleteWarpIcon(args[2]);
        }

        if (args.length == 4) {
            return tabCompleteCategories(args[3]);
        }

        return Collections.emptyList();
    }

    private List<String> tabCompleteWarp(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            return Collections.emptyList();
        }

        // /warp edit <name> <rename|relocate|icon|order|category|delete> ...
        // /warp jointp <on|off>
        // /warp jointp warp <name>
        if (args.length == 1) {
            String partial = args[0].toLowerCase();
            List<String> subs = new ArrayList<>();
            if ("edit".startsWith(partial)) subs.add("edit");
            if ("jointp".startsWith(partial)) subs.add("jointp");
            return subs;
        }

        if ("jointp".equalsIgnoreCase(args[0])) {
            if (args.length == 2) {
                String partial = args[1].toLowerCase(Locale.ROOT);
                List<String> options = new ArrayList<>();
                if ("on".startsWith(partial)) options.add("on");
                if ("off".startsWith(partial)) options.add("off");
                if ("warp".startsWith(partial)) options.add("warp");
                return options;
            }
            if (args.length == 3 && "warp".equalsIgnoreCase(args[1])) {
                String partial = args[2].toLowerCase(Locale.ROOT);
                List<String> names = new ArrayList<>();
                if (warpManager != null) {
                    for (WarpManager.Warp w : warpManager.getPublicWarps()) {
                        if (w.getName().toLowerCase(Locale.ROOT).startsWith(partial)) {
                            names.add(w.getName());
                        }
                    }
                }
                return names;
            }
            return Collections.emptyList();
        }

        if (args.length == 3 && "edit".equalsIgnoreCase(args[0])) {
            // edit subcommand name: <rename|relocate|icon|order|category|delete>
            String partial = args[2].toLowerCase();
            List<String> subs = new ArrayList<>();
            if ("rename".startsWith(partial))   subs.add("rename");
            if ("relocate".startsWith(partial)) subs.add("relocate");
            if ("icon".startsWith(partial))     subs.add("icon");
            if ("order".startsWith(partial))    subs.add("order");
            if ("category".startsWith(partial)) subs.add("category");
            if ("delete".startsWith(partial))   subs.add("delete");
            return subs;
        }

        if (args.length == 4
                && "edit".equalsIgnoreCase(args[0])
                && "icon".equalsIgnoreCase(args[2])) {
            // /warp edit <name> icon <material|hand>
            return tabCompleteWarpIcon(args[3]);
        }

        if (args.length == 4
                && "edit".equalsIgnoreCase(args[0])
                && "category".equalsIgnoreCase(args[2])) {
            return tabCompleteCategories(args[3]);
        }

        return Collections.emptyList();
    }

    private List<String> tabCompleteWorld(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            return Collections.emptyList();
        }

        if (args.length == 1) {
            // subcommand: create|tp|import|edit
            String partial = args[0].toLowerCase(Locale.ROOT);
            List<String> subs = new ArrayList<>();
            if ("create".startsWith(partial)) subs.add("create");
            if ("tp".startsWith(partial))     subs.add("tp");
            if ("import".startsWith(partial)) subs.add("import");
            if ("edit".startsWith(partial))   subs.add("edit");
            return subs;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);

        // /world create <name> <mode> <access> [icon] [seed...]
        if (sub.equals("create")) {
            if (args.length == 3) {
                // mode: default|flat|large
                String partial = args[2].toLowerCase(Locale.ROOT);
                List<String> modes = new ArrayList<>();
                if ("default".startsWith(partial)) modes.add("default");
                if ("flat".startsWith(partial))    modes.add("flat");
                if ("large".startsWith(partial))   modes.add("large");
                return modes;
            }

            if (args.length == 4) {
                // access: public|private
                String partial = args[3].toLowerCase(Locale.ROOT);
                List<String> access = new ArrayList<>();
                if ("public".startsWith(partial))  access.add("public");
                if ("private".startsWith(partial)) access.add("private");
                return access;
            }

            if (args.length == 5) {
                // icon material
                return tabCompleteMaterials(args[4]);
            }

            // seed (args.length >= 6) -> free text
            return Collections.emptyList();
        }

        // /world tp <name> [player]
        if (sub.equals("tp")) {
            if (args.length == 2) {
                // suggest world names from loaded Bukkit worlds
                String partial = args[1].toLowerCase(Locale.ROOT);
                List<String> worlds = new ArrayList<>();
                for (World w : Bukkit.getWorlds()) {
                    String n = w.getName();
                    if (n.toLowerCase(Locale.ROOT).startsWith(partial)) {
                        worlds.add(n);
                    }
                }
                Collections.sort(worlds, String.CASE_INSENSITIVE_ORDER);
                return worlds;
            }
            // player argument: could add player completion later if you like
            return Collections.emptyList();
        }

        // /world import <folderName>  -> no good generic completion for folders
        if (sub.equals("import")) {
            return Collections.emptyList();
        }

        // /world edit <name> <rename|access|icon|order|delete|inv|stats|reset|gamemode|position> ...
        if (sub.equals("edit")) {
            if (args.length == 3) {
                // action
                String partial = args[2].toLowerCase(Locale.ROOT);
                List<String> actions = new ArrayList<>();
                if ("rename".startsWith(partial))   actions.add("rename");
                if ("access".startsWith(partial))   actions.add("access");
                if ("icon".startsWith(partial))     actions.add("icon");
                if ("order".startsWith(partial))    actions.add("order");
                if ("delete".startsWith(partial))   actions.add("delete");
                if ("inv".startsWith(partial))      actions.add("inv");
                if ("stats".startsWith(partial))    actions.add("stats");
                if ("reset".startsWith(partial))    actions.add("reset");
                if ("gamemode".startsWith(partial)) actions.add("gamemode");
                if ("position".startsWith(partial)) actions.add("position");
                return actions;
            }

            if (args.length == 4) {
                // value depending on action
                String action = args[2].toLowerCase(Locale.ROOT);
                String partial = args[3].toLowerCase(Locale.ROOT);
                List<String> out = new ArrayList<>();

                switch (action) {
                    case "access" -> {
                        if ("public".startsWith(partial))  out.add("public");
                        if ("private".startsWith(partial)) out.add("private");
                    }
                    case "icon" -> {
                        return tabCompleteMaterials(args[3]);
                    }
                    case "inv", "stats" -> {
                        if ("shared".startsWith(partial))   out.add("shared");
                        if ("separate".startsWith(partial)) out.add("separate");
                    }
                    case "reset" -> {
                        if ("health".startsWith(partial)) out.add("health");
                        if ("hunger".startsWith(partial)) out.add("hunger");
                        if ("both".startsWith(partial))   out.add("both");
                        if ("off".startsWith(partial))    out.add("off");
                    }
                    case "gamemode" -> {
                        if ("survival".startsWith(partial))  out.add("survival");
                        if ("creative".startsWith(partial))  out.add("creative");
                        if ("adventure".startsWith(partial)) out.add("adventure");
                        if ("spectator".startsWith(partial)) out.add("spectator");
                        if ("inherit".startsWith(partial))   out.add("inherit");
                    }
                    case "position" -> {
                        if ("last".startsWith(partial))  out.add("last");
                        if ("spawn".startsWith(partial)) out.add("spawn");
                    }
                    default -> {
                        // rename/order/delete don't really have good completions here
                    }
                }
                return out;
            }

            return Collections.emptyList();
        }

        return Collections.emptyList();
    }

    private List<String> tabCompleteWarps(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            return Collections.emptyList();
        }

        if (args.length == 1) {
            String partial = args[0].toLowerCase(Locale.ROOT);
            List<String> options = new ArrayList<>();
            if ("public".startsWith(partial))  options.add("public");
            if ("private".startsWith(partial)) options.add("private");
            return options;
        }

        return Collections.emptyList();
    }

    private List<String> tabCompleteNotifyPing(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            return Collections.emptyList();
        }

        if (args.length == 1) {
            String partial = args[0].toLowerCase(Locale.ROOT);
            List<String> options = new ArrayList<>();
            if ("on".startsWith(partial))  options.add("on");
            if ("off".startsWith(partial)) options.add("off");
            return options;
        }

        return Collections.emptyList();
    }

    private List<String> tabCompletePlayerFirstArg(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            return Collections.emptyList();
        }
        if (args.length != 1) {
            return Collections.emptyList();
        }

        String partial = args[0].toLowerCase(Locale.ROOT);
        List<String> names = new ArrayList<>();
        for (Player p : Bukkit.getOnlinePlayers()) {
            String n = p.getName();
            if (n.toLowerCase(Locale.ROOT).startsWith(partial)) {
                names.add(n);
            }
        }
        Collections.sort(names, String.CASE_INSENSITIVE_ORDER);
        return names;
    }

    private static final List<String> FRIEND_SUBCOMMANDS = Arrays.asList(
            "list", "accept", "deny", "remove", "unfriend", "block", "unblock", "blocked");

    private List<String> tabCompleteFriend(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            return Collections.emptyList();
        }

        if (args.length == 1) {
            String partial = args[0].toLowerCase(Locale.ROOT);
            List<String> out = new ArrayList<>();
            for (String sub : FRIEND_SUBCOMMANDS) {
                if (sub.startsWith(partial)) out.add(sub);
            }
            return out;
        }

        if (args.length == 2) {
            String sub = args[0].toLowerCase(Locale.ROOT);
            String partial = args[1].toLowerCase(Locale.ROOT);
            List<String> names = new ArrayList<>();

            if (sub.equals("accept") || sub.equals("deny")) {
                // Only suggest players who actually have a pending request with us.
                for (UUID id : friendManager.getIncomingRequests(p.getUniqueId())) {
                    OfflinePlayer op = Bukkit.getOfflinePlayer(id);
                    String n = op.getName();
                    if (n != null && n.toLowerCase(Locale.ROOT).startsWith(partial)) {
                        names.add(n);
                    }
                }
            } else if (sub.equals("remove") || sub.equals("unfriend")) {
                for (UUID id : friendManager.getFriends(p.getUniqueId())) {
                    OfflinePlayer op = Bukkit.getOfflinePlayer(id);
                    String n = op.getName();
                    if (n != null && n.toLowerCase(Locale.ROOT).startsWith(partial)) {
                        names.add(n);
                    }
                }
            } else if (sub.equals("block")) {
                for (Player online : Bukkit.getOnlinePlayers()) {
                    String n = online.getName();
                    if (n.toLowerCase(Locale.ROOT).startsWith(partial)) names.add(n);
                }
            } else if (sub.equals("unblock")) {
                for (UUID id : friendManager.getBlocked(p.getUniqueId())) {
                    OfflinePlayer op = Bukkit.getOfflinePlayer(id);
                    String n = op.getName();
                    if (n != null && n.toLowerCase(Locale.ROOT).startsWith(partial)) {
                        names.add(n);
                    }
                }
            } else {
                return Collections.emptyList();
            }

            Collections.sort(names, String.CASE_INSENSITIVE_ORDER);
            return names;
        }

        return Collections.emptyList();
    }


    private List<String> tabCompleteDm(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            return Collections.emptyList();
        }
        if (friendManager == null) {
            return Collections.emptyList();
        }
        if (args.length != 1) {
            return Collections.emptyList();
        }

        String partial = args[0].toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>();
        UUID self = p.getUniqueId();
        Set<UUID> friends = friendManager.getFriends(self);
        if (friends == null || friends.isEmpty()) {
            return Collections.emptyList();
        }

        for (UUID fid : friends) {
            Player fp = Bukkit.getPlayer(fid);
            if (fp == null || !fp.isOnline()) continue;
            String n = fp.getName();
            if (n.toLowerCase(Locale.ROOT).startsWith(partial)) {
                out.add(n);
            }
        }
        Collections.sort(out, String.CASE_INSENSITIVE_ORDER);
        return out;
    }

    private List<String> tabCompletePortal(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            return Collections.emptyList();
        }
        if (portalManager == null) {
            return Collections.emptyList();
        }

        if (args.length == 1) {
            String partial = args[0].toLowerCase(Locale.ROOT);
            List<String> subs = new ArrayList<>();
            if ("wand".startsWith(partial))    subs.add("wand");
            if ("create".startsWith(partial))  subs.add("create");
            if ("rebuild".startsWith(partial)) subs.add("rebuild");
            return subs;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);

        // /portal create <name> <world-or-warp>
        if (sub.equals("create") && args.length == 3) {
            // Suggest world names for the target
            String partial = args[2].toLowerCase(Locale.ROOT);
            List<String> worlds = new ArrayList<>();
            for (World w : Bukkit.getWorlds()) {
                String n = w.getName();
                if (n.toLowerCase(Locale.ROOT).startsWith(partial)) {
                    worlds.add(n);
                }
            }
            Collections.sort(worlds, String.CASE_INSENSITIVE_ORDER);
            return worlds;
        }

        return Collections.emptyList();
    }

    private List<String> tabCompletePortals(CommandSender sender, String[] args) {
        if (portalManager == null) {
            return Collections.emptyList();
        }

        if (args.length == 1) {
            String partial = args[0].toLowerCase(Locale.ROOT);
            List<String> subs = new ArrayList<>();
            if ("list".startsWith(partial)) subs.add("list");
            if ("edit".startsWith(partial)) subs.add("edit");
            return subs;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);

        // /portals edit <name> <...>
        if (sub.equals("edit")) {
            if (args.length == 2) {
                // portal name
                String partial = args[1].toLowerCase(Locale.ROOT);
                List<String> names = new ArrayList<>();
                for (PortalManager.PortalEntry e : portalManager.getAllPortalsSorted()) {
                    String n = e.getName();
                    if (n.toLowerCase(Locale.ROOT).startsWith(partial)) {
                        names.add(n);
                    }
                }
                Collections.sort(names, String.CASE_INSENSITIVE_ORDER);
                return names;
            }

            if (args.length == 3) {
                // action: activate|deactivate|changetarget|changearea|delete
                String partial = args[2].toLowerCase(Locale.ROOT);
                List<String> actions = new ArrayList<>();
                if ("activate".startsWith(partial))    actions.add("activate");
                if ("deactivate".startsWith(partial))  actions.add("deactivate");
                if ("changetarget".startsWith(partial)) actions.add("changetarget");
                if ("changearea".startsWith(partial))   actions.add("changearea");
                if ("delete".startsWith(partial))      actions.add("delete");
		if ("particle".startsWith(partial))     actions.add("particle");
                return actions;
            }

	    if (args.length == 4 && "particle".equalsIgnoreCase(args[2])) {
                // User typed: /portals edit <name> particle [tab]
                return tabCompleteParticles(args[3]);
            }

            // no further structured args worth completing here
            return Collections.emptyList();
        }

        return Collections.emptyList();
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

                    getLogger().warning("WS connect failed: " + e.getClass().getName() + ": " + e.getMessage());
                    Throwable cause = e.getCause();
                    while (cause != null) {
                        getLogger().warning("  cause: " + cause.getClass().getName() + ": " + cause.getMessage());
                        cause = cause.getCause();
                    }
                    e.printStackTrace();

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
                                + "§r§7@" + guild + "§r" + ": "
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
                    // Try to update tablist style for this player if they are online
                    try {
                        if (uuid != null && uuid.length() == 32) {
                            String dashed = uuid.replaceFirst(
                                "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)",
                                "$1-$2-$3-$4-$5"
                            );
                            java.util.UUID u = java.util.UUID.fromString(dashed);
                            Player p = Bukkit.getPlayer(u);
                            if (p != null && p.isOnline()) {
                                Bukkit.getScheduler().runTask(this, () -> updateTabListName(p));
                            }
                        }
                    } catch (Exception ex) {
                        getLogger().warning("Failed to apply tablist style: " + ex);
                    }
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

    /**
     * Resolves an icon argument for /setwarp or /warp edit icon: either the special
     * "hand" keyword - which captures whatever item the player is holding, including
     * a custom head's skin or a banner's color/pattern layers - or a plain material
     * name as before. Returns null (after messaging the player) if it's invalid.
     */
    private ItemStack resolveIconArg(Player p, String arg) {
        if (arg.equalsIgnoreCase("hand")) {
            ItemStack held = p.getInventory().getItemInMainHand();
            if (held.getType() == Material.AIR) {
                p.sendMessage("§cYou're not holding anything to use as an icon.");
                return null;
            }
            return held.clone();
        }

        Material m = Material.matchMaterial(arg);
        if (m == null) {
            p.sendMessage("§cUnknown material: §f" + arg);
            p.sendMessage("§7Example: §eDIAMOND_SWORD§7, §eSTONE§7, or §ehand§7 to use your held item.");
            return null;
        }
        if (!m.isItem()) {
            p.sendMessage("§c" + m.name() + " is not a valid item (e.g. fluids like LAVA cannot be icons).");
            p.sendMessage("§7Try something like §eLAVA_BUCKET§7 instead, or §ehand§7 to use your held item.");
            return null;
        }
        return new ItemStack(m);
    }

    private boolean handleSetWarp(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }

        if (args.length < 2) {
            p.sendMessage("§7Usage: §e/setwarp <name> <public|private> [icon|hand] [category]");
            return true;
        }

        String name = args[0];
        if (name.length() > 32) {
            p.sendMessage("§cWarp name is too long (max 32 characters).");
            return true;
        }

        String visibility = args[1].toLowerCase();
        boolean isPublic;
        if (visibility.startsWith("pub")) {
            isPublic = true;
        } else if (visibility.startsWith("pri")) {
            isPublic = false;
        } else {
            p.sendMessage("§cVisibility must be either 'public' or 'private'.");
            return true;
        }

        if (isPublic) {
            if (requireStaffStyle(p) == null) {
                return true;
            }
        }

        ItemStack icon = new ItemStack(Material.DIRT);
        if (args.length >= 3) {
            ItemStack resolved = resolveIconArg(p, args[2]);
            if (resolved == null) return true;
            icon = resolved;
        }

        String category = WarpManager.DEFAULT_CATEGORY;
        if (args.length >= 4) {
            category = String.join(" ", Arrays.copyOfRange(args, 3, args.length)).trim();
            if (category.length() > 32) {
                p.sendMessage("§cCategory name is too long (max 32 characters).");
                return true;
            }
        }

        if (warpManager == null) {
            p.sendMessage("§cWarp system is not initialized.");
            return true;
        }

        if (isPublic) {
            WarpManager.Warp existing = warpManager.getPublicWarp(name);
            if (existing != null) {
                warpManager.updateWarpLocation(existing, p.getLocation());
                warpManager.updateWarpIcon(existing, icon);
                warpManager.updateWarpCategory(existing, category);
                p.sendMessage("§aUpdated public warp §e" + name + "§a at your current location.");
            } else {
                warpManager.createWarp(p.getUniqueId(), true, name, p.getLocation(), icon, category);
                p.sendMessage("§aCreated new public warp §e" + name + "§a in category §e" + category + "§a.");
            }
        } else {
            WarpManager.Warp existing = warpManager.getPrivateWarp(p.getUniqueId(), name);
            if (existing != null) {
                warpManager.updateWarpLocation(existing, p.getLocation());
                warpManager.updateWarpIcon(existing, icon);
                warpManager.updateWarpCategory(existing, category);
                p.sendMessage("§aUpdated your private warp §e" + name + "§a.");
            } else {
                warpManager.createWarp(p.getUniqueId(), false, name, p.getLocation(), icon, category);
                p.sendMessage("§aCreated new private warp §e" + name + "§a in category §e" + category + "§a.");
            }
        }

        warpManager.save();
        return true;
    }

    private boolean handleWarps(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }

        if (warpManager == null) {
            p.sendMessage("§cWarp system is not initialized.");
            return true;
        }

        if (args.length == 0 || args[0].equalsIgnoreCase("public")) {
            WarpsGui.openPublicWarps(this, p);
        } else if (args[0].equalsIgnoreCase("private")) {
            WarpsGui.openPrivateWarps(this, p);
        } else {
            p.sendMessage("§7Usage: §e/warps [public|private]");
        }
        return true;
    }

    private boolean handleWarpCommand(CommandSender sender, String[] args) {
        if (args.length >= 1 && args[0].equalsIgnoreCase("jointp")) {
            return handleJoinTp(sender, args);
        }
        return handleWarpEdit(sender, args);
    }

    private boolean handleJoinTp(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (requireStaffStyle(p) == null) {
            return true;
        }

        // /warp jointp                -> show status
        // /warp jointp <on|off>       -> toggle
        // /warp jointp warp <name>    -> set target public warp
        if (args.length == 1) {
            p.sendMessage("§7Join-teleport is currently: "
                    + (isJoinTeleportEnabled() ? "§aON" : "§cOFF")
                    + "§7, target warp: §e" + getJoinTeleportWarpName());
            p.sendMessage("§7Usage: §e/warp jointp <on|off>§7 or §e/warp jointp warp <name>");
            return true;
        }

        String sub = args[1].toLowerCase(Locale.ROOT);

        if (sub.equals("on") || sub.equals("off")) {
            boolean enable = sub.equals("on");
            setJoinTeleportEnabled(enable);
            p.sendMessage("§aJoin-teleport is now " + (enable ? "§aON" : "§cOFF") + "§a.");
            return true;
        }

        if (sub.equals("warp")) {
            if (args.length < 3) {
                p.sendMessage("§7Usage: §e/warp jointp warp <name>");
                return true;
            }
            String warpName = args[2];
            if (warpManager == null || warpManager.getPublicWarp(warpName) == null) {
                p.sendMessage("§cNo public warp named §e" + warpName + "§c found. Join-teleport must target a public warp.");
                return true;
            }
            setJoinTeleportWarpName(warpName);
            p.sendMessage("§aJoin-teleport target warp set to §e" + warpName + "§a.");
            return true;
        }

        p.sendMessage("§7Usage: §e/warp jointp <on|off>§7 or §e/warp jointp warp <name>");
        return true;
    }

    private boolean handleWarpEdit(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }

        if (warpManager == null) {
            p.sendMessage("§cWarp system is not initialized.");
            return true;
        }

        if (args.length < 2 || !args[0].equalsIgnoreCase("edit")) {
            p.sendMessage("§7Usage: §e/warp edit <name> <rename|relocate|icon|order|category|delete> ...");
            return true;
        }

        String name = args[1];

        boolean isStaff = false;
        PlayerStyle style = playerStyles.get(p.getUniqueId().toString().replace("-", ""));
        if (style != null && style.isStaff) {
            isStaff = true;
        }

        WarpManager.Warp warp = null;
        boolean editingPublic = false;

        if (isStaff) {
            WarpManager.Warp publicWarp = warpManager.getPublicWarp(name);
            if (publicWarp != null) {
                warp = publicWarp;
                editingPublic = true;
            }
        }

        if (warp == null) {
            warp = warpManager.getPrivateWarp(p.getUniqueId(), name);
            editingPublic = false;
        }

        if (warp == null) {
            p.sendMessage("§cNo warp named §e" + name + "§c found.");
            return true;
        }

        if (editingPublic && !isStaff) {
            if (requireStaffStyle(p) == null) return true;
        }

        if (args.length < 3) {
            p.sendMessage("§7Usage: §e/warp edit " + name + " <rename|relocate|icon|order|category|delete> ...");
            return true;
        }

        String sub = args[2].toLowerCase();
        switch (sub) {
            case "rename": {
                if (args.length < 4) {
                    p.sendMessage("§7Usage: §e/warp edit " + name + " rename <newName>");
                    return true;
                }
                String newName = args[3];
                if (newName.length() > 32) {
                    p.sendMessage("§cNew warp name is too long (max 32 characters).");
                    return true;
                }

                if (warp.isPublicWarp()) {
                    WarpManager.Warp conflict = warpManager.getPublicWarp(newName);
                    if (conflict != null && conflict != warp) {
                        p.sendMessage("§cAnother public warp with that name already exists.");
                        return true;
                    }
                } else {
                    WarpManager.Warp conflict = warpManager.getPrivateWarp(p.getUniqueId(), newName);
                    if (conflict != null && conflict != warp) {
                        p.sendMessage("§cYou already have a private warp with that name.");
                        return true;
                    }
                }

                warpManager.renameWarp(warp, newName);
                warpManager.save();
                p.sendMessage("§aWarp renamed to §e" + newName + "§a.");
                break;
            }
            case "relocate": {
                warpManager.updateWarpLocation(warp, p.getLocation());
                warpManager.save();
                p.sendMessage("§aWarp §e" + warp.getName() + "§a moved to your current location.");
                break;
            }
            case "icon": {
                if (args.length < 4) {
                    p.sendMessage("§7Usage: §e/warp edit " + name + " icon <material|hand>");
                    return true;
                }
                ItemStack resolved = resolveIconArg(p, args[3]);
                if (resolved == null) return true;
                warpManager.updateWarpIcon(warp, resolved);
                warpManager.save();
                p.sendMessage("§aUpdated icon for warp §e" + warp.getName() + "§a.");
                break;
            }
            case "order": {
                if (args.length < 4) {
                    p.sendMessage("§7Usage: §e/warp edit " + name + " order <number>");
                    return true;
                }
                int order;
                try {
                    order = Integer.parseInt(args[3]);
                } catch (NumberFormatException ex) {
                    p.sendMessage("§cOrder must be an integer.");
                    return true;
                }
                if (order < 0) order = 0;
                warpManager.updateWarpOrder(warp, order);
                warpManager.save();
                p.sendMessage("§aUpdated GUI order for warp §e" + warp.getName() + "§a to §e" + order + "§a.");
                break;
            }
            case "category": {
                if (args.length < 4) {
                    p.sendMessage("§7Usage: §e/warp edit " + name + " category <categoryName>");
                    return true;
                }
                String newCategory = String.join(" ", Arrays.copyOfRange(args, 3, args.length)).trim();
                if (newCategory.length() > 32) {
                    p.sendMessage("§cCategory name is too long (max 32 characters).");
                    return true;
                }
                warpManager.updateWarpCategory(warp, newCategory);
                warpManager.save();
                p.sendMessage("§aWarp §e" + warp.getName() + "§a moved to category §e" + warp.getCategory() + "§a.");
                break;
            }
            case "delete": {
                warpManager.deleteWarp(warp);
                warpManager.save();
                p.sendMessage("§cDeleted warp §e" + name + "§c.");
                break;
            }
            default: {
                p.sendMessage("§7Usage: §e/warp edit " + name + " <rename|relocate|icon|order|category|delete> ...");
                break;
            }
        }

        return true;
    }

    private boolean handleBack(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (backManager == null) {
            p.sendMessage("§cBack-location tracking is not initialized.");
            return true;
        }

        Location loc = backManager.getBackLocation(p.getUniqueId());
        if (loc == null) {
            p.sendMessage("§7You have no previous location to return to.");
            return true;
        }

        p.addPotionEffect(new PotionEffect(
                PotionEffectType.BLINDNESS,
                25,
                1,
                false,
                false,
                false
        ));
        p.playSound(p.getLocation(), Sound.BLOCK_NOTE_BLOCK_BELL, 1.0f, 1.0f);

        getServer().getScheduler().runTaskLater(this, () -> {
            p.teleport(loc);
            p.sendMessage("§aTeleported back to your previous location.");
        }, 3L);

        return true;
    }

    private boolean handleFriendTeleport(Player p, String[] args) {
        if (!getConfig().getBoolean("friends.allow-friend-teleport", false)) {
            p.sendMessage("§cFriend-to-friend teleportation is disabled on this server.");
            return true;
        }

        if (args.length < 1) {
            p.sendMessage("§7Usage: §e/ftp <player_name>");
            return true;
        }

        String targetName = args[0];
        Player target = Bukkit.getPlayer(targetName);

        if (target == null || !target.isOnline()) {
            p.sendMessage("§cThat player is not online right now.");
            return true;
        }

        if (target.getUniqueId().equals(p.getUniqueId())) {
            p.sendMessage("§cYou cannot teleport to yourself.");
            return true;
        }

        if (this.friendManager == null || !this.friendManager.areMutuallyFriends(p.getUniqueId(), target.getUniqueId())) {
            p.sendMessage("§cYou can only teleport to players if you are mutually registered as friends.");
            return true;
        }

        // Blindness + Enderman chimes
        p.addPotionEffect(new org.bukkit.potion.PotionEffect(org.bukkit.potion.PotionEffectType.BLINDNESS, 25, 1, false, false, false));
        p.playSound(p.getLocation(), org.bukkit.Sound.ENTITY_ENDERMAN_TELEPORT, 1.0f, 1.0f);
    
        getServer().getScheduler().runTaskLater(this, () -> {
            p.teleport(target.getLocation());
            p.sendMessage("§aTeleported via friend link to §e" + target.getName() + "§a.");
            target.sendMessage("§e" + p.getName() + " §7teleported to your location.");
        }, 3L);

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
        updateTabListName(p);

        // NEW: apply per-world profile on first join
        if (worldProfileManager != null) {
            worldProfileManager.handleJoin(p);
        }

        maybeJoinTeleport(p);

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

    /**
     * If join-teleport is enabled (see /warp jointp), teleports a freshly-joined
     * player to the configured public warp, with the same blindness+bell effect
     * used for the warps GUI. Silently does nothing if it's disabled, or if the
     * configured warp doesn't exist / its world isn't loaded (logged instead of
     * spamming the player with an error on every join).
     */
    private void maybeJoinTeleport(Player p) {
        if (warpManager == null || !isJoinTeleportEnabled()) return;

        String warpName = getJoinTeleportWarpName();
        WarpManager.Warp warp = warpManager.getPublicWarp(warpName);
        if (warp == null) {
            getLogger().warning("join-teleport is enabled but public warp '" + warpName + "' does not exist.");
            return;
        }

        Location loc = warpManager.toLocation(warp);
        if (loc == null) {
            getLogger().warning("join-teleport target warp '" + warpName + "' is in a world that isn't loaded.");
            return;
        }

        p.addPotionEffect(new PotionEffect(
                PotionEffectType.BLINDNESS,
                25,
                1,
                false,
                false,
                false
        ));
        p.playSound(p.getLocation(), Sound.BLOCK_NOTE_BLOCK_BELL, 1.0f, 0.7f);

        getServer().getScheduler().runTaskLater(
                this,
                () -> p.teleport(loc),
                3L
        );
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlayerTeleport(PlayerTeleportEvent e) {
        // Spectate-mode "teleports" fire continuously while clicking through players -
        // recording those would make /back (and world-return) useless, since they'd
        // just point at wherever you were last spectating from a moment ago.
        if (e.getCause() == PlayerTeleportEvent.TeleportCause.SPECTATE) return;

        Location from = e.getFrom();
        if (from.getWorld() == null) return;

        if (backManager != null) {
            backManager.recordBackLocation(e.getPlayer().getUniqueId(), from);
        }

        // Remember exactly where the player was in the world they're leaving,
        // so a later /worlds or /world tp visit to that world can put them back
        // there instead of always defaulting to world spawn. Covers portal use
        // as well as /worlds and /world tp, since all of those go through a
        // normal teleport.
        if (worldProfileManager != null) {
            Location to = e.getTo();
            boolean crossedWorlds = to == null || to.getWorld() == null
                    || !to.getWorld().equals(from.getWorld());
            if (crossedWorlds) {
                worldProfileManager.recordWorldLocation(e.getPlayer().getUniqueId(), from);
            }
        }
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent e) {
        Player p = e.getPlayer();
        sendEvent("quit", p, "disconnected");

	 // Snapshot + persist the player's current world profile so a
        // reconnect restores exactly what they had, instead of an old
        // in-memory snapshot from their last world change.
        if (worldProfileManager != null) {
            worldProfileManager.handleQuit(p);
        }


        UUID uuid = p.getUniqueId();
        Set<UUID> friends = friendManager.getFriends(uuid);
        for (UUID friendId : friends) {
            Player friend = Bukkit.getPlayer(friendId);
            if (friend != null && friend.isOnline()) {
                friend.sendMessage("§cYour friend §e" + p.getName() + " §chas left the game.");
            }
        }

        // clean DM state on quit
        exitDmMode(p);
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

    @EventHandler
    public void onAdvancement(PlayerAdvancementDoneEvent e) {
        Player p = e.getPlayer();
        Advancement adv = e.getAdvancement();
        if (adv == null) return;

        NamespacedKey key = adv.getKey();
        String path = key.getKey();
        // Skip recipe advancements to avoid spam
        if (path.startsWith("recipes/") || path.startsWith("recipe/")) {
            return;
        }

        AdvancementDisplay display = adv.getDisplay();
        String title = null;

        if (display != null) {
            // Paper 1.21: title() is an Adventure Component
            title = PlainTextComponentSerializer.plainText().serialize(display.title());
        }

        if (title == null || title.isEmpty()) {
            // Fallback to key if no nice title
            title = path.replace('_', ' ');
        }

        String text = "made the advancement [" + title + "]";
        sendEvent("advancement", p, text);
    }

    @EventHandler
    public void onWorldChange(PlayerChangedWorldEvent e) {
        Player p = e.getPlayer();
        String from = e.getFrom().getName();
        String to = p.getWorld().getName();

        // NEW: switch per-world profile
        if (worldProfileManager != null) {
            worldProfileManager.handleWorldChange(p, e.getFrom(), p.getWorld());
        }

        String text = "switched from world \"" + from + "\" to \"" + to + "\"";
        sendEvent("world_change", p, text);
        updateTabListName(p);
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

        // Respect per-player ping preference
        try {
            if (friendManager != null &&
                    !friendManager.isPingEnabled(target.getUniqueId())) {
                return;
            }
        } catch (Exception ignored) {
            // fail open (play sound) if something goes wrong
        }

        // play two note-block chimes as a "ping"
        target.playSound(
                target.getLocation(),
                org.bukkit.Sound.BLOCK_NOTE_BLOCK_PLING,
                1.0f,
                1.0f
        );
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

        PlayerStyle style = requireStyleWithMessage(player, false, true, false);
        if (style == null) return true;

        String targetName = args[0];

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

    // ---- Admin commands from Discord ----

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
        String chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(8);
        for (int i = 0; i < 8; i++) {
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return sb.toString();
    }

    // ---- Commands ----

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
            case "dm":
                return handleDm(sender, args);
            case "reply":
                return handleReply(sender, args);
            case "exit":
                return handleExitDm(sender, args);
            case "notifyping":
                return handleNotifyPing(sender, args);
            case "setwarp":
                return handleSetWarp(sender, args);
            case "warps":
                return handleWarps(sender, args);
            case "warp":
                return handleWarpCommand(sender, args);
            case "back":
                return handleBack(sender, args);
            case "worlds":
                return handleWorlds(sender, args);
            case "world":
                return handleWorld(sender, args);
            case "portal":
                return handlePortal(sender, args);
            case "portals":
                return handlePortals(sender, args);
            case "exit_mode":
                return handleExitMode(sender, args);
            case "ftp":
                if (!(sender instanceof Player p)) {
                    sender.sendMessage("This command can only be used in-game.");
                    return true;
                }
                return handleFriendTeleport(p, args);
	    default:
                return false;
        }
    }

    private boolean handleDm(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (args.length < 2) {
            p.sendMessage("§7Usage: §e/dm <player> <message>");
            return true;
        }

        String targetName = args[0];
        Player online = Bukkit.getPlayerExact(targetName);
        OfflinePlayer op = (online != null) ? online : Bukkit.getOfflinePlayer(targetName);

        if (op == null || (op.getName() == null && !op.isOnline())) {
            p.sendMessage("§cCould not find player '" + targetName + "'.");
            return true;
        }

        UUID targetId = op.getUniqueId();
        UUID fromId = p.getUniqueId();
        if (fromId.equals(targetId)) {
            p.sendMessage("§cYou cannot direct-message yourself.");
            return true;
        }

        if (!friendManager.areFriends(fromId, targetId)) {
            p.sendMessage("§cYou can only direct-message players who are your friends.");
            return true;
        }

        String msg = String.join(" ", Arrays.copyOfRange(args, 1, args.length)).trim();
        if (msg.isEmpty()) {
            p.sendMessage("§7Your message was empty.");
            return true;
        }

        sendDirectMessage(p, targetId, msg);
        p.sendMessage("§7You are in direct-message mode with §e"
                + (op.getName() != null ? op.getName() : targetName)
                + "§7. Use §e/exit §7to go back to public chat.");
        return true;
    }

    private boolean handleReply(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        UUID pId = p.getUniqueId();
        UUID partner = lastDmPartner.get(pId);
        if (partner == null) {
            p.sendMessage("§7You have no one to reply to yet.");
            return true;
        }
        if (args.length < 1) {
            p.sendMessage("§7Usage: §e/reply <message>");
            return true;
        }

        String msg = String.join(" ", args).trim();
        if (msg.isEmpty()) {
            p.sendMessage("§7Your message was empty.");
            return true;
        }

        sendDirectMessage(p, partner, msg);
        p.sendMessage("§7You are in direct-message mode with your last DM partner. Use §e/exit §7to go back to public chat.");
        return true;
    }

    private boolean handleExitDm(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        UUID id = p.getUniqueId();
        if (activeDmTarget.containsKey(id)) {
            exitDmMode(p);
            p.sendMessage("§7You have left direct-message mode. Chat is public again.");
        } else {
            p.sendMessage("§7You are not currently in direct-message mode.");
        }
        return true;
    }

    private boolean handleNotifyPing(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (friendManager == null) {
            p.sendMessage("§cFriend system is not initialized yet.");
            return true;
        }

        UUID id = p.getUniqueId();

        if (args.length == 0) {
            boolean enabled = friendManager.isPingEnabled(id);
            p.sendMessage("§7Ping sounds are currently: " +
                    (enabled ? "§aON" : "§cOFF"));
            p.sendMessage("§7Use §e/notifyping on§7 or §e/notifyping off§7 to change.");
            return true;
        }

        String sub = args[0].toLowerCase();
        Boolean enable = null;
        if (sub.equals("on") || sub.equals("enable") || sub.equals("enabled")) {
            enable = Boolean.TRUE;
        } else if (sub.equals("off") || sub.equals("disable") || sub.equals("disabled")) {
            enable = Boolean.FALSE;
        }

        if (enable == null) {
            p.sendMessage("§7Usage: §e/notifyping <on|off>");
            return true;
        }

        friendManager.setPingEnabled(id, enable);
        if (enable) {
            p.sendMessage("§aPing sounds enabled. You will hear chimes on mentions and DMs.");
        } else {
            p.sendMessage("§cPing sounds disabled. You will no longer hear chimes on mentions or DMs.");
        }

        return true;
    }

    private boolean handleWorlds(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        WorldsGui.open(this, p);
        return true;
    }

    private boolean handleWorld(CommandSender sender, String[] args) {
        if (args.length == 0) {
            sender.sendMessage("§7World commands:");
            sender.sendMessage("§e/world create <name> <mode> <access> [icon] [seed...]");
            sender.sendMessage("§e/world tp <name> [player]");
            sender.sendMessage("§e/world edit <name> <rename|access|icon|order|delete|inv|stats|reset|gamemode|position> ...");
            sender.sendMessage("§7  mode: §fdefault|flat|large (or 1/2/3)");
            sender.sendMessage("§7  access: §fpublic|private");
            return true;
        }

        String sub = args[0].toLowerCase();

        switch (sub) {
            case "create": {
                if (!(sender instanceof Player p)) {
                    sender.sendMessage("This command can only be used in-game.");
                    return true;
                }
                if (!hasWorldAdmin(p)) {
                    sender.sendMessage("§cYou are not allowed to create worlds.");
                    return true;
                }
                if (args.length < 4) {
                    sender.sendMessage("§7Usage: §e/world create <name> <mode> <access> [icon] [seed...]");
                    return true;
                }

                String name = args[1];
                String modeArg = args[2];
                String accessArg = args[3];

                WorldManager.Mode mode = WorldManager.Mode.fromStringOrId(modeArg);
                WorldManager.Access access = WorldManager.Access.fromString(accessArg, WorldManager.Access.PUBLIC);

                Material icon = Material.GRASS_BLOCK;
                String seedText = null;

                if (args.length >= 5) {
                    String iconArg = args[4];
                    Material m = Material.matchMaterial(iconArg);
                    if (m != null) {
                        icon = m;
                    } else {
                        sender.sendMessage("§cUnknown icon material '" + iconArg + "', using GRASS_BLOCK.");
                    }
                }

                if (args.length >= 6) {
                    seedText = String.join(" ", java.util.Arrays.copyOfRange(args, 5, args.length)).trim();
                    if (seedText.isEmpty()) seedText = null;
                }

                WorldManager.WorldEntry entry = worldManager.createWorld(name, mode, access, icon, seedText);
                World world = worldManager.ensureWorldLoaded(entry);
                if (world == null) {
                    sender.sendMessage("§cFailed to create/load world.");
                    return true;
                }

                p.teleport(world.getSpawnLocation());
                sender.sendMessage("§aCreated world §e" + entry.getName()
                        + " §7(mode §f" + entry.getMode().name()
                        + "§7, access "
                        + (entry.getAccess() == WorldManager.Access.PUBLIC ? "§aPUBLIC" : "§cPRIVATE")
                        + "§7).");
                return true;
            }

            case "import": {
                if (!(sender instanceof Player p)) {
                    sender.sendMessage("This command can only be used in-game.");
                    return true;
                }
                if (!hasWorldAdmin(p)) {
                    sender.sendMessage("§cYou are not allowed to import worlds.");
                    return true;
                }
                if (args.length < 2) {
                    sender.sendMessage("§7Usage: §e/world import <folderName>");
                    return true;
                }

                String folderName = args[1];
                WorldManager.WorldEntry entry = worldManager.importWorld(folderName);

                if (entry == null) {
                    sender.sendMessage("§cFailed to import world folder §e" + folderName + "§c. Check console for details.");
                    return true;
                }

                World world = worldManager.ensureWorldLoaded(entry);
                if (world == null) {
                    sender.sendMessage("§cWorld entry was created but the world could not be loaded.");
                    return true;
                }

                p.teleport(world.getSpawnLocation());
                sender.sendMessage("§aImported world folder §e" + folderName
                        + "§a as world §e" + entry.getName()
                        + "§a (default access: "
                        + (entry.getAccess() == WorldManager.Access.PUBLIC ? "§aPUBLIC" : "§cPRIVATE")
                        + "§a).");
                return true;
            }

            case "tp": {
                if (!(sender instanceof Player p)) {
                    sender.sendMessage("This command can only be used in-game.");
                    return true;
                }
                if (args.length < 2) {
                    sender.sendMessage("§7Usage: §e/world tp <name> [player]");
                    return true;
                }

                String worldName = args[1];
                WorldManager.WorldEntry entry = worldManager.getWorldByName(worldName);
                if (entry == null) {
                    sender.sendMessage("§cUnknown world '" + worldName + "'.");
                    return true;
                }

                Player target = p;
                if (args.length >= 3) {
                    if (!hasWorldAdmin(p)) {
                        p.sendMessage("§cYou are not allowed to send other players to worlds.");
                        return true;
                    }
                    String targetName = args[2];
                    target = Bukkit.getPlayerExact(targetName);
                    if (target == null) {
                        p.sendMessage("§cPlayer not found: " + targetName);
                        return true;
                    }
                }

                // access check (always, regardless of who is executing)
                boolean isAdmin = hasWorldAdmin(target);
                if (entry.getAccess() == WorldManager.Access.PRIVATE && !isAdmin) {
                    p.sendMessage("§cThat world is private, and the target is not allowed to access it.");
                    return true;
                }

                World world = worldManager.ensureWorldLoaded(entry);
                if (world == null) {
                    sender.sendMessage("§cFailed to load world.");
                    return true;
                }

                org.bukkit.Location loc = null;
                if (entry.isReturnToLastLocation() && worldProfileManager != null) {
                    loc = worldProfileManager.getLastLocation(target.getUniqueId(), world);
                }
                if (loc == null) {
                    loc = world.getSpawnLocation();
                }

                // same motion-sickness-friendly teleport as in WarpsGuiListener
                target.addPotionEffect(new org.bukkit.potion.PotionEffect(
                        org.bukkit.potion.PotionEffectType.BLINDNESS,
                        25,
                        1,
                        false,
                        false,
                        false
                ));
                target.playSound(
                        target.getLocation(),
                        org.bukkit.Sound.ENTITY_ENDERMAN_TELEPORT,
                        1.0f,
                        1.0f
                );
                final Player finalTarget = target;
                final org.bukkit.Location finalLoc = loc;
                getServer().getScheduler().runTaskLater(
                        this,
                        () -> {
                            finalTarget.teleport(finalLoc);
                            finalTarget.sendMessage("§aSwitched to world §e" + entry.getName() + "§a.");
                        },
                        3L
                );

                if (target != p) {
                    p.sendMessage("§aSent §e" + target.getName() + " §ato world §e" + entry.getName() + "§a.");
                }
                return true;
            }

            case "edit": {
                if (!(sender instanceof Player p)) {
                    sender.sendMessage("This command can only be used in-game.");
                    return true;
                }
                if (!hasWorldAdmin(p)) {
                    sender.sendMessage("§cYou are not allowed to edit worlds.");
                    return true;
                }
                if (args.length < 3) {
                    sender.sendMessage("§7Usage: §e/world edit <name> <rename|access|icon|order|delete|inv|stats|reset|gamemode|position> ...");
                    return true;
                }

                String worldName = args[1];
                WorldManager.WorldEntry entry = worldManager.getWorldByName(worldName);
                if (entry == null) {
                    sender.sendMessage("§cUnknown world '" + worldName + "'.");
                    return true;
                }

                String action = args[2].toLowerCase();

                switch (action) {
                    case "rename": {
                        if (args.length < 4) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " rename <newName>");
                            return true;
                        }
                        String newName = args[3];
                        if (newName.length() > 32) {
                            sender.sendMessage("§cNew world name is too long (max 32 characters).");
                            return true;
                        }

                        WorldManager.WorldEntry conflict = worldManager.getWorldByName(newName);
                        if (conflict != null && conflict != entry) {
                            sender.sendMessage("§cAnother world with that name already exists.");
                            return true;
                        }

                        worldManager.renameWorld(entry, newName);
                        worldManager.saveSafely();
                        sender.sendMessage("§aWorld renamed to §e" + newName + "§a.");
                        return true;
                    }

                    case "access": {
                        if (args.length < 4) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " access <public|private>");
                            return true;
                        }
                        String accessArg = args[3].toLowerCase();
                        WorldManager.Access access;
                        if (accessArg.startsWith("pub")) {
                            access = WorldManager.Access.PUBLIC;
                        } else if (accessArg.startsWith("pri")) {
                            access = WorldManager.Access.PRIVATE;
                        } else {
                            sender.sendMessage("§cAccess must be either 'public' or 'private'.");
                            return true;
                        }

                        worldManager.setWorldAccess(entry, access);
                        worldManager.saveSafely();
                        sender.sendMessage("§aWorld §e" + entry.getName() + " §aaccess set to "
                                + (access == WorldManager.Access.PUBLIC ? "§aPUBLIC" : "§cPRIVATE") + "§a.");
                        return true;
                    }

                    case "icon": {
                        if (args.length < 4) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " icon <material>");
                            return true;
                        }
                        String matName = args[3];
                        Material mat = Material.matchMaterial(matName);
                        if (mat == null) {
                            sender.sendMessage("§cUnknown material: §f" + matName);
                            return true;
                        }
                        if (!mat.isItem()) {
                            sender.sendMessage("§c" + mat.name() + " is not a valid item (e.g. fluids like LAVA cannot be icons).");
                            sender.sendMessage("§7Use an actual item like §eGRASS_BLOCK§7, §eSTONE§7, etc.");
                            return true;
                        }

                        worldManager.updateWorldIcon(entry, mat);
                        worldManager.saveSafely();
                        sender.sendMessage("§aUpdated icon for world §e" + entry.getName() + "§a.");
                        return true;
                    }

                    case "order": {
                        if (args.length < 4) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " order <number>");
                            return true;
                        }
                        int order;
                        try {
                            order = Integer.parseInt(args[3]);
                        } catch (NumberFormatException ex) {
                            sender.sendMessage("§cOrder must be an integer.");
                            return true;
                        }
                        if (order < 0) order = 0;

                        worldManager.updateWorldOrder(entry, order);
                        worldManager.saveSafely();
                        sender.sendMessage("§aUpdated GUI order for world §e" + entry.getName()
                                + "§a to §e" + order + "§a.");
                        return true;
                    }

                    case "delete": {
                        if (!worldManager.canDelete(entry)) {
                            sender.sendMessage("§cThis world cannot be deleted (likely a default/vanilla world).");
                            return true;
                        }

                        worldManager.deleteWorld(entry);
                        worldManager.saveSafely();
                        sender.sendMessage("§cDeleted world entry §e" + worldName + "§c.");
                        return true;
                    }

                    case "inv": {
                        if (args.length < 4) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " inv <shared|separate>");
                            return true;
                        }
                        String modeArg = args[3].toLowerCase();
                        Boolean separate = null;
                        if (modeArg.startsWith("share")) {
                            separate = Boolean.FALSE;
                        } else if (modeArg.startsWith("sep")) {
                            separate = Boolean.TRUE;
                        }
                        if (separate == null) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " inv <shared|separate>");
                            return true;
                        }

                        entry.setSeparateInventory(separate);
                        worldManager.saveSafely();
                        sender.sendMessage("§aInventory mode for world §e" + entry.getName() + "§a set to "
                                + (separate ? "§cSEPARATE" : "§aSHARED") + "§a.");
                        return true;
                    }

                    case "stats": {
                        if (args.length < 4) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " stats <shared|separate>");
                            return true;
                        }
                        String modeArg = args[3].toLowerCase();
                        Boolean separate = null;
                        if (modeArg.startsWith("share")) {
                            separate = Boolean.FALSE;
                        } else if (modeArg.startsWith("sep")) {
                            separate = Boolean.TRUE;
                        }
                        if (separate == null) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " stats <shared|separate>");
                            return true;
                        }

                        entry.setSeparateStats(separate);
                        worldManager.saveSafely();
                        sender.sendMessage("§aStats mode for world §e" + entry.getName() + "§a set to "
                                + (separate ? "§cSEPARATE" : "§aSHARED") + "§a.");
                        return true;
                    }

                    case "reset": {
                        if (args.length < 4) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " reset <health|hunger|both|off>");
                            return true;
                        }
                        String what = args[3].toLowerCase();
                        boolean resetHealth, resetHunger;

                        switch (what) {
                            case "health" -> {
                                resetHealth = true;
                                resetHunger = false;
                            }
                            case "hunger" -> {
                                resetHealth = false;
                                resetHunger = true;
                            }
                            case "both" -> {
                                resetHealth = true;
                                resetHunger = true;
                            }
                            case "off" -> {
                                resetHealth = false;
                                resetHunger = false;
                            }
                            default -> {
                                sender.sendMessage("§7Usage: §e/world edit " + worldName + " reset <health|hunger|both|off>");
                                return true;
                            }
                        }

                        entry.setResetHealthOnEnter(resetHealth);
                        entry.setResetHungerOnEnter(resetHunger);
                        worldManager.saveSafely();

                        String desc;
                        if (!resetHealth && !resetHunger) {
                            desc = "§7no automatic stat resets";
                        } else if (resetHealth && resetHunger) {
                            desc = "§areset HEALTH and HUNGER on enter";
                        } else if (resetHealth) {
                            desc = "§areset HEALTH on enter";
                        } else {
                            desc = "§areset HUNGER on enter";
                        }

                        sender.sendMessage("§aWorld §e" + entry.getName() + "§a now uses: " + desc + "§a.");
                        return true;
                    }

                    case "gamemode": {
                        if (args.length < 4) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " gamemode <survival|creative|adventure|spectator|inherit>");
                            return true;
                        }
                        String gmArg = args[3].toLowerCase();
                        org.bukkit.GameMode gm = null;

                        if (gmArg.startsWith("surv")) {
                            gm = org.bukkit.GameMode.SURVIVAL;
                        } else if (gmArg.startsWith("creat")) {
                            gm = org.bukkit.GameMode.CREATIVE;
                        } else if (gmArg.startsWith("adven")) {
                            gm = org.bukkit.GameMode.ADVENTURE;
                        } else if (gmArg.startsWith("spect")) {
                            gm = org.bukkit.GameMode.SPECTATOR;
                        } else if (gmArg.startsWith("inherit")) {
                            gm = null; // inherit
                        } else {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " gamemode <survival|creative|adventure|spectator|inherit>");
                            return true;
                        }

                        entry.setDefaultGamemode(gm);
                        worldManager.saveSafely();

                        String label = (gm == null ? "§7INHERIT server default" : "§e" + gm.name());
                        sender.sendMessage("§aDefault gamemode for world §e" + entry.getName() + "§a set to " + label + "§a.");
                        return true;
                    }

                    case "position": {
                        if (args.length < 4) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " position <last|spawn>");
                            return true;
                        }
                        String posArg = args[3].toLowerCase();
                        Boolean returnToLast = null;
                        if (posArg.startsWith("last")) {
                            returnToLast = Boolean.TRUE;
                        } else if (posArg.startsWith("spawn")) {
                            returnToLast = Boolean.FALSE;
                        }
                        if (returnToLast == null) {
                            sender.sendMessage("§7Usage: §e/world edit " + worldName + " position <last|spawn>");
                            return true;
                        }

                        entry.setReturnToLastLocation(returnToLast);
                        worldManager.saveSafely();
                        sender.sendMessage("§aWorld §e" + entry.getName() + "§a now returns players to their "
                                + (returnToLast ? "§alast known position§a." : "§cworld spawn§a."));
                        return true;
                    }

                    default: {
                        sender.sendMessage("§7Usage: §e/world edit " + worldName
                                + " <rename|access|icon|order|delete|inv|stats|reset|gamemode|position> ...");
                        return true;
                    }
                }
            }

            default: {
                sender.sendMessage("§7World commands:");
                sender.sendMessage("§e/world create <name> <mode> <access> [icon] [seed...]");
                sender.sendMessage("§e/world tp <name> [player]");
                sender.sendMessage("§e/world edit <name> <rename|access|icon|order|delete|inv|stats|reset|gamemode|position> ...");
                return true;
            }
        }
    }

    private boolean handlePortal(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (portalManager == null) {
            p.sendMessage("§cPortal system is not initialized.");
            return true;
        }

        // Only Discord-staff (is_staff) may manage portals
        String key = p.getUniqueId().toString().replace("-", "");
        PlayerStyle style = playerStyles.get(key);
        if (style == null || !style.isStaff) {
            p.sendMessage("§cYou are not allowed to manage portals.");
            return true;
        }

        if (args.length == 0) {
            p.sendMessage("§7Portal commands:");
            p.sendMessage("§e/portal wand §7- get portal wand");
            p.sendMessage("§e/portal create <name> <world-or-warp> §7- create portal from selection");
            p.sendMessage("§e/portal rebuild §7- enter portal rebuild mode");
            p.sendMessage("§e/exit_mode §7- exit portal rebuild mode");
            p.sendMessage("§e/portals list §7- list portals");
            p.sendMessage("§e/portals edit <name> <activate|deactivate|changetarget|changearea|delete> [...]");
            return true;
        }

        String sub = args[0].toLowerCase(Locale.ROOT);

	switch (sub) {
            case "wand" -> {
                if (!hasWorldAdmin(p)) {
                    p.sendMessage("§cYou are not allowed to manage portals.");
                    return true;
                }
                portalManager.giveWand(p);
                portalManager.clearSelection(p);
                return true;
            }
            case "create" -> {
                if (!hasWorldAdmin(p)) {
                    p.sendMessage("§cYou are not allowed to create portals.");
                    return true;
                }
                if (args.length < 3) {
                    p.sendMessage("§7Usage: §e/portal create <name> <world-or-warp>");
                    return true;
                }
                String portalName = args[1];
                String target = args[2];
                PortalManager.PortalEntry entry =
                        portalManager.createPortalFromSelection(p, portalName, target);
                // errors are already messaged from inside; nothing else to do
                return true;
            }
            case "rebuild" -> {
                if (!hasWorldAdmin(p)) {
                    p.sendMessage("§cYou are not allowed to rebuild portals.");
                    return true;
                }
                portalManager.enableRebuildMode(p);
                portalManager.giveWand(p);
                return true;
            }
            default -> {
                p.sendMessage("§cUnknown subcommand. Use §e/portal§c for help.");
                return true;
            }
        }
    }

    private boolean handlePortals(CommandSender sender, String[] args) {
        if (portalManager == null) {
            sender.sendMessage("§cPortal system is not initialized.");
            return true;
        }

        boolean isStaff;
        if (sender instanceof Player p) {
            String key = p.getUniqueId().toString().replace("-", "");
            PlayerStyle style = playerStyles.get(key);
            if (style == null || !style.isStaff) {
                p.sendMessage("§cYou are not allowed to manage portals.");
                return true;
            }
            isStaff = true;
        } else {
            isStaff = true;
        }

        if (args.length == 0 || args[0].equalsIgnoreCase("list")) {
            java.util.List<PortalManager.PortalEntry> list = portalManager.getAllPortalsSorted();
            if (list.isEmpty()) {
                sender.sendMessage("§7No portals defined.");
                return true;
            }

            sender.sendMessage("§7Portals:");
            for (PortalManager.PortalEntry e : list) {
                if (!isStaff && !e.isActive()) {
                    continue; 
                }
                String status = e.isActive() ? "§aACTIVE" : "§cINACTIVE";
                sender.sendMessage("  §e" + e.getName() + "§7 -> "
                        + (e.getTargetType() == PortalManager.TargetType.WORLD ? "world " : "warp ")
                        + "§f" + e.getTargetName()
                        + " §7[" + status + "§7]"
                        + " in §f" + e.getWorldName());
            }
            return true;
        }

        if (!args[0].equalsIgnoreCase("edit")) {
            sender.sendMessage("§7Usage: §e/portals list §7or §e/portals edit <name> <...>");
            return true;
        }

        if (args.length < 3) {
            sender.sendMessage("§7Usage: §e/portals edit <name> <activate|deactivate|changetarget|changearea|delete|particle> [...]");
            return true;
        }

        if (!(sender instanceof Player p)) {
            sender.sendMessage("Only players may edit portals.");
            return true;
        }
        if (!hasWorldAdmin(p)) {
            p.sendMessage("§cYou are not allowed to edit portals.");
            return true;
        }

        String portalName = args[1];
        String action = args[2].toLowerCase(Locale.ROOT);

        PortalManager.PortalEntry entry = portalManager.getPortalByName(portalName);
        if (entry == null) {
            p.sendMessage("§cNo portal named §e" + portalName + "§c found.");
            return true;
        }

        switch (action) {
            case "activate" -> {
                portalManager.setPortalActive(entry, true);
                p.sendMessage("§aPortal §e" + entry.getName() + "§a activated.");
                return true;
            }
            case "deactivate" -> {
                portalManager.setPortalActive(entry, false);
                p.sendMessage("§aPortal §e" + entry.getName() + "§a deactivated.");
                return true;
            }
            case "changetarget" -> {
                if (args.length < 4) {
                    p.sendMessage("§7Usage: §e/portals edit " + portalName + " changetarget <world-or-warp>");
                    return true;
                }
                String newTarget = args[3];
                portalManager.updatePortalTarget(p, entry, newTarget);
                return true;
            }
            case "changearea" -> {
                portalManager.changePortalAreaFromSelection(p, entry);
                return true;
            }
            case "delete" -> {
                portalManager.deletePortal(entry);
                p.sendMessage("§cDeleted portal §e" + portalName + "§c and cleared its blocks.");
                return true;
            }
            case "particle" -> {
                if (args.length < 4) {
                    p.sendMessage("§7Usage: §e/portals edit " + portalName + " particle <type> [strength]");
                    return true;
                }
                String particleName = args[3].toUpperCase(Locale.ROOT);
                int strength = 2;
                if (args.length >= 5) {
                    try {
                        strength = Integer.parseInt(args[4]);
                    } catch (NumberFormatException ex) {
                        p.sendMessage("§cStrength must be an integer mapping.");
                        return true;
                    }
                }
                try {
                    org.bukkit.Particle.valueOf(particleName);
                } catch (IllegalArgumentException ex) {
                    p.sendMessage("§cUnknown particle type: §f" + particleName);
                    return true;
                }
                portalManager.setPortalParticle(entry, particleName, strength);
                p.sendMessage("§aPortal §e" + entry.getName() + "§a particle ambiance set to §e" + particleName + " §7(strength: " + strength + ").");
                return true;
            }
            default -> {
                p.sendMessage("§7Usage: §e/portals edit " + portalName
                        + " <activate|deactivate|changetarget|changearea|delete|particle> [...]");
                return true;
            }
        }
    }

    private boolean handleExitMode(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (portalManager == null) {
            p.sendMessage("§cPortal system is not initialized.");
            return true;
        }
        if (!portalManager.isInRebuildMode(p)) {
            p.sendMessage("§7You are not currently in portal rebuild mode.");
            return true;
        }
        portalManager.disableRebuildMode(p);
        return true;
    }

    // ---- Chat capture to Discord + DM routing + @Name ping ----

    @EventHandler
    public void onChat(AsyncChatEvent e) {
        WebSocket ws = socketRef.get();

        final Player player = e.getPlayer();
        final String playerName = player.getName();
        final UUID playerUuid = player.getUniqueId();
        final String uuidStr = playerUuid.toString().replace("-", "");

        final String rawText = PlainTextComponentSerializer.plainText()
                .serialize(e.message());

        // Check for active mute
        MuteEntry mute = mutes.get(uuidStr);
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

        // DM mode: if active and not a command, treat as DM
        UUID dmTarget = activeDmTarget.get(playerUuid);
        if (dmTarget != null && !rawText.startsWith("/")) {
            e.setCancelled(true);
            String msg = rawText.trim();
            if (!msg.isEmpty()) {
                Bukkit.getScheduler().runTask(this,
                        () -> sendDirectMessage(player, dmTarget, msg));
            }
            return;
        }

        // Normal public chat → Discord bridge
        final String discordFormatted = MarkdownUtil.minecraftToDiscord(rawText);
        final String text = escape(discordFormatted);

        if (ws != null) {
            final String payload = "{\"op\":\"mc_chat\",\"player\":\"" + playerName + "\","
                    + "\"uuid\":\"" + uuidStr + "\","
                    + "\"text\":\"" + text + "\"}";
            try {
                ws.sendText(payload, true);
            } catch (Exception ignored) {
            }
        }

        PlayerStyle style = playerStyles.get(uuidStr);
        String prefix = (style != null && style.prefix != null && !style.prefix.isEmpty())
                ? style.prefix + " "
                : "";
        String colorCode = (style != null) ? hexToMinecraftColor(style.colorHex) : "§f";

        final String coloredMessage =
                MinecraftFormatUtil.applyPersistentFormatting(rawText);

        final String finalMsg = colorCode + prefix + "§l" + playerName + "§r: " + coloredMessage;

        e.setCancelled(true);
        Bukkit.getScheduler().runTask(this, () -> {
            Bukkit.broadcastMessage(finalMsg);
            // MC -> MC @Name ping
            pingMentionedPlayers(rawText, playerName);
        });
    }

    private void pingMentionedPlayers(String rawText, String senderName) {
        java.util.Set<String> seen = new java.util.HashSet<>();
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("@([A-Za-z0-9_]{3,16})")
                .matcher(rawText);

        while (m.find()) {
            String name = m.group(1);
            if (name.equalsIgnoreCase(senderName)) continue;
            String key = name.toLowerCase();
            if (!seen.add(key)) continue;

            Player target = Bukkit.getPlayerExact(name);
            if (target != null && target.isOnline()) {
                notifyPing(target.getName());
            }
        }
    }

    private static String escape(String s) {
        return s.replace("\"", "\\\"");
    }
}

