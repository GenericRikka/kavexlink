package net.kavocado.kavexwarp;

import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.World;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks, per player, the location they were at immediately before their most
 * recent teleport; used by /back. Kept in memory (teleports can happen a lot
 * more often than warp edits do) and flushed to back.yml periodically plus on
 * shutdown.
 */
public class BackManager {

    private final KavexWarpPlugin plugin;
    private final File file;
    private final Map<UUID, StoredLocation> backLocations = new ConcurrentHashMap<>();
    private volatile boolean dirty = false;

    public BackManager(KavexWarpPlugin plugin) {
        this.plugin = plugin;
        this.file = new File(plugin.getDataFolder(), "back.yml");
        load();
    }

    public void load() {
        backLocations.clear();

        if (!file.exists()) {
            return;
        }

        YamlConfiguration config = YamlConfiguration.loadConfiguration(file);
        ConfigurationSection sec = config.getConfigurationSection("back");
        if (sec == null) {
            return;
        }

        for (String uuidStr : sec.getKeys(false)) {
            UUID uuid;
            try {
                uuid = UUID.fromString(uuidStr);
            } catch (IllegalArgumentException ex) {
                continue; // skip malformed keys rather than failing the whole load
            }

            String base = "back." + uuidStr + ".";
            String world = config.getString(base + "world");
            if (world == null) {
                continue;
            }

            double x = config.getDouble(base + "x");
            double y = config.getDouble(base + "y");
            double z = config.getDouble(base + "z");
            float yaw = (float) config.getDouble(base + "yaw", 0.0D);
            float pitch = (float) config.getDouble(base + "pitch", 0.0D);

            backLocations.put(uuid, new StoredLocation(world, x, y, z, yaw, pitch));
        }

        plugin.getLogger().info("Loaded " + backLocations.size() + " /back location(s).");
    }

    /**
     * Unconditional save -> used on shutdown, regardless of the dirty flag.
     */
    public void save() {
        YamlConfiguration out = new YamlConfiguration();

        for (Map.Entry<UUID, StoredLocation> entry : backLocations.entrySet()) {
            String base = "back." + entry.getKey() + ".";
            StoredLocation loc = entry.getValue();
            out.set(base + "world", loc.world());
            out.set(base + "x", loc.x());
            out.set(base + "y", loc.y());
            out.set(base + "z", loc.z());
            out.set(base + "yaw", loc.yaw());
            out.set(base + "pitch", loc.pitch());
        }

        try {
            out.save(file);
            dirty = false;
        } catch (Exception e) {
            plugin.getLogger().severe("Failed to save back.yml: " + e);
        }
    }

    /**
     * Save only if something changed since the last save. Used by the periodic
     * autosave task so idle periods don't churn the disk for no reason.
     */
    public void autoSaveIfDirty() {
        if (dirty) {
            save();
        }
    }

    public void recordBackLocation(UUID uuid, Location loc) {
        if (loc == null || loc.getWorld() == null) {
            return;
        }
        backLocations.put(uuid, new StoredLocation(
                loc.getWorld().getName(), loc.getX(), loc.getY(), loc.getZ(), loc.getYaw(), loc.getPitch()));
        dirty = true;
    }

    public Location getBackLocation(UUID uuid) {
        StoredLocation loc = backLocations.get(uuid);
        if (loc == null) {
            return null;
        }
        World world = Bukkit.getWorld(loc.world());
        if (world == null) {
            return null;
        }
        return new Location(world, loc.x(), loc.y(), loc.z(), loc.yaw(), loc.pitch());
    }

    private record StoredLocation(String world, double x, double y, double z, float yaw, float pitch) {
    }
}
