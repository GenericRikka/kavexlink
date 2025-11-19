package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
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

    private final Path storageFile;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public FriendManager(KavexLinkPlugin plugin) {
        this.plugin = plugin;
        this.storageFile = plugin.getDataFolder().toPath().resolve("friends.json");
        loadFromDisk();
    }

    // -------------------------------------------------------
    // Friend request system
    // -------------------------------------------------------

    public boolean sendFriendRequest(UUID requester, UUID target) {
        if (requester.equals(target)) return false;
        if (areFriends(requester, target)) return false;

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
    // Friends list
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

        try {
            if (!Files.exists(storageFile)) return;

            String json = Files.readString(storageFile, StandardCharsets.UTF_8);
            if (json == null || json.isBlank()) return;

            JsonObject root = JsonParser.parseString(json).getAsJsonObject();

            // Load friends
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

        } catch (Exception ex) {
            plugin.getLogger().warning("Failed to load friends.json: " + ex);
        }
    }
}

