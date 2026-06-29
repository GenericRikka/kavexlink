package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import java.util.*;

public class FriendManager {

    private final KavexLinkPlugin plugin;

    private final Map<UUID, Set<UUID>> friends = new HashMap<>();
    private final Map<UUID, Set<UUID>> incomingRequests = new HashMap<>();
    private final Map<UUID, Set<UUID>> outgoingRequests = new HashMap<>();
    private final Map<UUID, List<String>> pendingNotifications = new HashMap<>();
    private final Map<UUID, Map<UUID, Integer>> unreadCounts = new HashMap<>();

    // Canonical per-conversation message log:
    // key = sorted "uuid1|uuid2", value = list of messages
    private final Map<String, List<DmMessage>> dmMessages = new HashMap<>();

    // Per-player ping sound preference: true = opted out (no ping sounds)
    private final Map<UUID, Boolean> pingOptOut = new HashMap<>();

    // Block list: blocker -> set of blocked UUIDs
    private final Map<UUID, Set<UUID>> blocked = new HashMap<>();

    private final Path storageFile;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public FriendManager(KavexLinkPlugin plugin) {
        this.plugin = plugin;
        this.storageFile = plugin.getDataFolder().toPath().resolve("friends.json");
        loadFromDisk();
    }

    // -------------------------------------------------------
    // DM message model
    // -------------------------------------------------------

    public static class DmMessage {
        private final UUID from;
        private final UUID to;
        private final long timestamp;
        private final String text;

        public DmMessage(UUID from, UUID to, long timestamp, String text) {
            this.from = from;
            this.to = to;
            this.timestamp = timestamp;
            this.text = text;
        }

        public UUID getFrom() {
            return from;
        }

        public UUID getTo() {
            return to;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public String getText() {
            return text;
        }
    }

    private String convKey(UUID a, UUID b) {
        String sa = a.toString();
        String sb = b.toString();
        return (sa.compareTo(sb) <= 0) ? sa + "|" + sb : sb + "|" + sa;
    }

    // -------------------------------------------------------
    // Friend request system
    // -------------------------------------------------------

    public boolean sendFriendRequest(UUID requester, UUID target) {
        if (requester.equals(target)) return false;
        if (areFriends(requester, target)) return false;

        // Block rules:
        // - if requester blocked target, they clearly don't want to interact
        if (isBlocked(requester, target)) {
            return false;
        }
        // - if target blocked requester, silently drop
        if (isBlocked(target, requester)) {
            return false;
        }

        Set<UUID> inc = incomingRequests.computeIfAbsent(target, k -> new HashSet<>());
        Set<UUID> out = outgoingRequests.computeIfAbsent(requester, k -> new HashSet<>());

        if (inc.contains(requester)) return false;

        inc.add(requester);
        out.add(target);

        Player tp = Bukkit.getPlayer(target);
        if (tp != null && tp.isOnline()) {
            OfflinePlayer op = Bukkit.getOfflinePlayer(requester);
            tp.sendMessage("§aYou received a friend request from §e" + op.getName());
            tp.sendMessage("§7Use §e/friendrequest view §7to manage it.");
        }

        saveToDisk();
        return true;
    }

    public boolean areMutuallyFriends(UUID uuidA, UUID uuidB) {
        if (uuidA == null || uuidB == null) return false;

        // Query your real memory map variable directly
        if (this.friends.containsKey(uuidA)) {
            Set<UUID> playerFriends = this.friends.get(uuidA);
            return playerFriends != null && playerFriends.contains(uuidB);
        }

        return false;
    }

    public Set<UUID> getIncomingRequests(UUID player) {
        return incomingRequests.getOrDefault(player, Collections.emptySet());
    }

    public boolean acceptRequest(UUID target, UUID requester) {
        Set<UUID> inc = incomingRequests.get(target);
        if (inc == null || !inc.remove(requester)) return false;

        Set<UUID> out = outgoingRequests.get(requester);
        if (out != null) out.remove(target);

        addFriendInternal(target, requester);
        addFriendInternal(requester, target);

        notifyPlayer(requester,
                "§aYour friend request to §e" + nameOf(target) + " §ahas been accepted!");

        Player tp = Bukkit.getPlayer(target);
        if (tp != null) tp.sendMessage("§aYou are now friends with §e" + nameOf(requester));

        saveToDisk();
        return true;
    }

    public boolean denyRequest(UUID target, UUID requester) {
        Set<UUID> inc = incomingRequests.get(target);
        if (inc == null || !inc.remove(requester)) return false;

        Set<UUID> out = outgoingRequests.get(requester);
        if (out != null) out.remove(target);

        notifyPlayer(requester,
                "§cYour friend request to §e" + nameOf(target) + " §cwas denied.");

        Player tp = Bukkit.getPlayer(target);
        if (tp != null) tp.sendMessage("§7You denied the friend request from §e" + nameOf(requester));

        saveToDisk();
        return true;
    }

    // -------------------------------------------------------
    // Friends list + unfriend
    // -------------------------------------------------------

    private void addFriendInternal(UUID a, UUID b) {
        friends.computeIfAbsent(a, k -> new HashSet<>()).add(b);
    }

    public boolean areFriends(UUID a, UUID b) {
        return friends.getOrDefault(a, Collections.emptySet()).contains(b);
    }

    public Set<UUID> getFriends(UUID p) {
        return friends.getOrDefault(p, Collections.emptySet());
    }

    /**
     * Remove friendship between a and b on both sides.
     * Returns true if anything was changed.
     */
    public boolean removeFriendship(UUID a, UUID b) {
        boolean changed = false;

        Set<UUID> sa = friends.get(a);
        if (sa != null && sa.remove(b)) {
            changed = true;
            if (sa.isEmpty()) friends.remove(a);
        }

        Set<UUID> sb = friends.get(b);
        if (sb != null && sb.remove(a)) {
            changed = true;
            if (sb.isEmpty()) friends.remove(b);
        }

        // Clear unread counts between them
        Map<UUID, Integer> ma = unreadCounts.get(a);
        if (ma != null) {
            ma.remove(b);
            if (ma.isEmpty()) unreadCounts.remove(a);
        }
        Map<UUID, Integer> mb = unreadCounts.get(b);
        if (mb != null) {
            mb.remove(a);
            if (mb.isEmpty()) unreadCounts.remove(b);
        }

        if (changed) {
            saveToDisk();
        }
        return changed;
    }

    // -------------------------------------------------------
    // Block system
    // -------------------------------------------------------

    public boolean isBlocked(UUID blocker, UUID other) {
        return blocked.getOrDefault(blocker, Collections.emptySet()).contains(other);
    }

    public Set<UUID> getBlocked(UUID blocker) {
        return blocked.getOrDefault(blocker, Collections.emptySet());
    }

    /**
     * Block target for blocker.
     * Also removes friendship in both directions.
     */
    public boolean block(UUID blocker, UUID target) {
        if (blocker.equals(target)) return false;

        Set<UUID> set = blocked.computeIfAbsent(blocker, k -> new HashSet<>());
        if (!set.add(target)) {
            return false; // already blocked
        }

        // Remove friendship
        removeFriendship(blocker, target);

        saveToDisk();
        return true;
    }

    public boolean unblock(UUID blocker, UUID target) {
        Set<UUID> set = blocked.get(blocker);
        if (set == null || !set.remove(target)) {
            return false;
        }
        if (set.isEmpty()) {
            blocked.remove(blocker);
        }
        saveToDisk();
        return true;
    }

    // -------------------------------------------------------
    // Notification system
    // -------------------------------------------------------

    private void notifyPlayer(UUID uuid, String msg) {
        Player p = Bukkit.getPlayer(uuid);
        if (p != null && p.isOnline()) {
            p.sendMessage(msg);
        } else {
            pendingNotifications.computeIfAbsent(uuid, k -> new ArrayList<>()).add(msg);
            saveToDisk();
        }
    }

    public void queueNotification(UUID uuid, String msg) {
        notifyPlayer(uuid, msg);
    }

    public List<String> drainNotifications(UUID uuid) {
        List<String> list = pendingNotifications.remove(uuid);
        return (list != null) ? list : Collections.emptyList();
    }

    private String nameOf(UUID uuid) {
        OfflinePlayer op = Bukkit.getOfflinePlayer(uuid);
        return (op.getName() != null ? op.getName() : uuid.toString());
    }

    // -------------------------------------------------------
    // Unread message counts
    // -------------------------------------------------------

    public int getUnreadCount(UUID owner, UUID friend) {
        return unreadCounts.getOrDefault(owner, Collections.emptyMap())
                .getOrDefault(friend, 0);
    }

    public void clearUnread(UUID owner, UUID friend) {
        Map<UUID, Integer> map = unreadCounts.get(owner);
        if (map != null) {
            map.remove(friend);
            if (map.isEmpty()) unreadCounts.remove(owner);
        }
        saveToDisk();
    }

    public void incrementUnread(UUID owner, UUID friend) {
        unreadCounts.computeIfAbsent(owner, k -> new HashMap<>())
                .put(friend, getUnreadCount(owner, friend) + 1);
        saveToDisk();
    }

    // -------------------------------------------------------
    // Direct message storage + history
    // -------------------------------------------------------

    public synchronized void storeDirectMessage(UUID from, UUID to, String text) {
        String key = convKey(from, to);
        List<DmMessage> list = dmMessages.computeIfAbsent(key, k -> new ArrayList<>());

        long now = System.currentTimeMillis();
        list.add(new DmMessage(from, to, now, text));

        int days = plugin.getConfig().getInt("friends.dm-history-days", 30);
        long cutoff = now - days * 24L * 60L * 60L * 1000L;

        list.removeIf(m -> m.getTimestamp() < cutoff);

        saveToDisk();
    }

    public synchronized List<DmMessage> getRecentMessages(UUID viewer, UUID friend, int days) {
        String key = convKey(viewer, friend);
        List<DmMessage> list = dmMessages.getOrDefault(key, Collections.emptyList());
        if (list.isEmpty()) return Collections.emptyList();

        long cutoff = System.currentTimeMillis() - days * 24L * 60L * 60L * 1000L;
        List<DmMessage> result = new ArrayList<>();
        for (DmMessage m : list) {
            if (m.getTimestamp() >= cutoff) {
                result.add(m);
            }
        }
        return result;
    }

    // -------------------------------------------------------
    // Ping sound preference
    // -------------------------------------------------------

    /**
     * True = ping sounds allowed; default is true if no entry.
     */
    public boolean isPingEnabled(UUID uuid) {
        return !Boolean.TRUE.equals(pingOptOut.get(uuid));
    }

    /**
     * Set ping preference. enabled=true means allow pings.
     * We store only opt-outs in the map to keep the JSON small.
     */
    public void setPingEnabled(UUID uuid, boolean enabled) {
        if (enabled) {
            pingOptOut.remove(uuid);
        } else {
            pingOptOut.put(uuid, Boolean.TRUE);
        }
        saveToDisk();
    }

    // -------------------------------------------------------
    // JSON save/load
    // -------------------------------------------------------

    public synchronized void saveToDisk() {
        try {
            JsonObject root = new JsonObject();

            // friends
            JsonObject fObj = new JsonObject();
            for (var e : friends.entrySet()) {
                JsonArray arr = new JsonArray();
                e.getValue().forEach(uuid -> arr.add(uuid.toString()));
                fObj.add(e.getKey().toString(), arr);
            }
            root.add("friends", fObj);

            // incoming
            JsonObject incObj = new JsonObject();
            for (var e : incomingRequests.entrySet()) {
                JsonArray arr = new JsonArray();
                e.getValue().forEach(uuid -> arr.add(uuid.toString()));
                incObj.add(e.getKey().toString(), arr);
            }
            root.add("incoming", incObj);

            // outgoing
            JsonObject outObj = new JsonObject();
            for (var e : outgoingRequests.entrySet()) {
                JsonArray arr = new JsonArray();
                e.getValue().forEach(uuid -> arr.add(uuid.toString()));
                outObj.add(e.getKey().toString(), arr);
            }
            root.add("outgoing", outObj);

            // notifications
            JsonObject notifObj = new JsonObject();
            for (var e : pendingNotifications.entrySet()) {
                JsonArray arr = new JsonArray();
                e.getValue().forEach(arr::add);
                notifObj.add(e.getKey().toString(), arr);
            }
            root.add("notifications", notifObj);

            // unread
            JsonObject unreadObj = new JsonObject();
            for (var e : unreadCounts.entrySet()) {
                JsonObject per = new JsonObject();
                for (var f : e.getValue().entrySet()) {
                    per.addProperty(f.getKey().toString(), f.getValue());
                }
                unreadObj.add(e.getKey().toString(), per);
            }
            root.add("unread", unreadObj);

            // messages (DMs)
            JsonObject msgObj = new JsonObject();
            for (var e : dmMessages.entrySet()) {
                JsonArray arr = new JsonArray();
                for (DmMessage m : e.getValue()) {
                    JsonObject mo = new JsonObject();
                    mo.addProperty("from", m.getFrom().toString());
                    mo.addProperty("to", m.getTo().toString());
                    mo.addProperty("timestamp", m.getTimestamp());
                    mo.addProperty("text", m.getText());
                    arr.add(mo);
                }
                msgObj.add(e.getKey(), arr);
            }
            root.add("messages", msgObj);

            // pingOptOut
            JsonObject pingObj = new JsonObject();
            for (var e : pingOptOut.entrySet()) {
                pingObj.addProperty(e.getKey().toString(), e.getValue());
            }
            root.add("pingOptOut", pingObj);

            // blocked
            JsonObject blockObj = new JsonObject();
            for (var e : blocked.entrySet()) {
                JsonArray arr = new JsonArray();
                e.getValue().forEach(uuid -> arr.add(uuid.toString()));
                blockObj.add(e.getKey().toString(), arr);
            }
            root.add("blocked", blockObj);

            Files.writeString(storageFile, gson.toJson(root), StandardCharsets.UTF_8);

        } catch (Exception ex) {
            plugin.getLogger().warning("Failed to save friends.json: " + ex);
        }
    }

    private synchronized void loadFromDisk() {
        friends.clear();
        incomingRequests.clear();
        outgoingRequests.clear();
        pendingNotifications.clear();
        unreadCounts.clear();
        dmMessages.clear();
        pingOptOut.clear();
        blocked.clear();

        try {
            if (!Files.exists(storageFile)) return;

            String json = Files.readString(storageFile, StandardCharsets.UTF_8);
            if (json == null || json.isBlank()) return;

            JsonObject root = JsonParser.parseString(json).getAsJsonObject();

            // friends
            if (root.has("friends")) {
                JsonObject obj = root.getAsJsonObject("friends");
                for (String key : obj.keySet()) {
                    UUID u = UUID.fromString(key);
                    Set<UUID> set = new HashSet<>();
                    obj.getAsJsonArray(key)
                            .forEach(e -> set.add(UUID.fromString(e.getAsString())));
                    friends.put(u, set);
                }
            }

            // incoming
            if (root.has("incoming")) {
                JsonObject obj = root.getAsJsonObject("incoming");
                for (String key : obj.keySet()) {
                    UUID u = UUID.fromString(key);
                    Set<UUID> set = new HashSet<>();
                    obj.getAsJsonArray(key)
                            .forEach(e -> set.add(UUID.fromString(e.getAsString())));
                    incomingRequests.put(u, set);
                }
            }

            // outgoing
            if (root.has("outgoing")) {
                JsonObject obj = root.getAsJsonObject("outgoing");
                for (String key : obj.keySet()) {
                    UUID u = UUID.fromString(key);
                    Set<UUID> set = new HashSet<>();
                    obj.getAsJsonArray(key)
                            .forEach(e -> set.add(UUID.fromString(e.getAsString())));
                    outgoingRequests.put(u, set);
                }
            }

            // notifications
            if (root.has("notifications")) {
                JsonObject obj = root.getAsJsonObject("notifications");
                for (String key : obj.keySet()) {
                    UUID u = UUID.fromString(key);
                    List<String> list = new ArrayList<>();
                    obj.getAsJsonArray(key).forEach(e -> list.add(e.getAsString()));
                    pendingNotifications.put(u, list);
                }
            }

            // unread
            if (root.has("unread")) {
                JsonObject obj = root.getAsJsonObject("unread");
                for (String key : obj.keySet()) {
                    UUID u = UUID.fromString(key);
                    JsonObject per = obj.getAsJsonObject(key);
                    Map<UUID, Integer> map = new HashMap<>();
                    for (String fk : per.keySet()) {
                        map.put(UUID.fromString(fk), per.get(fk).getAsInt());
                    }
                    unreadCounts.put(u, map);
                }
            }

            // messages (DMs)
            if (root.has("messages")) {
                JsonObject obj = root.getAsJsonObject("messages");
                for (String key : obj.keySet()) {
                    JsonArray arr = obj.getAsJsonArray(key);
                    List<DmMessage> list = new ArrayList<>();
                    for (JsonElement el : arr) {
                        JsonObject mo = el.getAsJsonObject();
                        UUID from = UUID.fromString(mo.get("from").getAsString());
                        UUID to = UUID.fromString(mo.get("to").getAsString());
                        long ts = mo.get("timestamp").getAsLong();
                        String text = mo.has("text") ? mo.get("text").getAsString() : "";
                        list.add(new DmMessage(from, to, ts, text));
                    }
                    dmMessages.put(key, list);
                }
            }

            // pingOptOut
            if (root.has("pingOptOut")) {
                JsonObject obj = root.getAsJsonObject("pingOptOut");
                for (String key : obj.keySet()) {
                    UUID u = UUID.fromString(key);
                    boolean val = obj.get(key).getAsBoolean();
                    if (val) {
                        pingOptOut.put(u, Boolean.TRUE);
                    }
                }
            }

            // blocked
            if (root.has("blocked")) {
                JsonObject obj = root.getAsJsonObject("blocked");
                for (String key : obj.keySet()) {
                    UUID u = UUID.fromString(key);
                    Set<UUID> set = new HashSet<>();
                    obj.getAsJsonArray(key)
                            .forEach(e -> set.add(UUID.fromString(e.getAsString())));
                    blocked.put(u, set);
                }
            }

        } catch (Exception ex) {
            plugin.getLogger().warning("Failed to load friends.json: " + ex);
        }
    }
}

