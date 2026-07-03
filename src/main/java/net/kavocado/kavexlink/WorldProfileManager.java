package net.kavocado.kavexlink;

import org.bukkit.World;
import org.bukkit.GameMode;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handles per-world player profiles (inventory + stats) and simple resets.
 *
 * New semantics:
 *
 *  - We distinguish between a GLOBAL "shared" profile and per-world profiles:
 *      * Inventory:
 *          - If world.separateInventory == true:
 *                -> Player has an inventory profile for that specific world only
 *                   (key: "world:<worldName>").
 *          - If world.separateInventory == false:
 *                -> Player uses the global shared inventory profile (key: "shared")
 *                   across all non-separated worlds.
 *
 *      * Stats (health, hunger, saturation, xp, level):
 *          - If world.separateStats == true:
 *                -> Player has world-specific stats profile ("world:<worldName>").
 *          - If world.separateStats == false:
 *                -> Player uses the global shared stats profile ("shared").
 *
 *  - When changing worlds:
 *      * We always save the current inventory/stats into the profile of the world
 *        we are leaving (either that world’s own profile or the shared one).
 *      * We then load the appropriate profile for the world we are entering.
 *
 *  - This guarantees:
 *      * Items/XP from an isolated world (separateInventory / separateStats)
 *        cannot leak into shared worlds: when you leave an isolated world and
 *        enter a shared one, we swap back to the shared profile.
 *
 *  - If separateStats == false but resetHealthOnEnter / resetHungerOnEnter are true:
 *      * We keep using the shared stats profile, but normalize health/hunger on enter.
 *      * After applying resets, we update the shared stats profile to reflect them.
 */
public class WorldProfileManager {

    private static final String SHARED_KEY = "shared";

    private final KavexLinkPlugin plugin;

    // player UUID -> (profileKey -> inventory profile)
    private final Map<UUID, Map<String, InventoryProfile>> inventoryProfiles = new ConcurrentHashMap<>();

    // player UUID -> (profileKey -> stats profile)
    private final Map<UUID, Map<String, StatsProfile>> statsProfiles = new ConcurrentHashMap<>();

    // Tracks which players' on-disk profile data has already been loaded into
    // the maps above this session, so we only hit disk once per player.
    private final Set<UUID> loadedFromDisk = ConcurrentHashMap.newKeySet();

    private final File playerDataDir;

    public WorldProfileManager(KavexLinkPlugin plugin) {
        this.plugin = plugin;
        this.playerDataDir = new File(plugin.getDataFolder(), "playerprofiles");
    }

    // --------- Data containers ---------

    static class InventoryProfile {
        ItemStack[] inventory;
        ItemStack[] armor;
        ItemStack offhand;
    }

    static class StatsProfile {
        double health;
        int food;
        float saturation;
        int totalExp;
        float exp;
        int level;
    }

    // --------- Helpers ---------

    private WorldManager worldManager() {
        return plugin.getWorldManager();
    }

    private Map<String, InventoryProfile> inventoriesFor(UUID id) {
        loadFromDiskIfNeeded(id);
        return inventoryProfiles.computeIfAbsent(id, k -> new ConcurrentHashMap<>());
    }

    private Map<String, StatsProfile> statsFor(UUID id) {
        loadFromDiskIfNeeded(id);
        return statsProfiles.computeIfAbsent(id, k -> new ConcurrentHashMap<>());
    }

    private String inventoryProfileKey(WorldManager.WorldEntry entry) {
        if (entry != null && entry.isSeparateInventory()) {
            return "world:" + entry.getName().toLowerCase(Locale.ROOT);
        }
        return SHARED_KEY;
    }

    private String statsProfileKey(WorldManager.WorldEntry entry) {
        if (entry != null && entry.isSeparateStats()) {
            return "world:" + entry.getName().toLowerCase(Locale.ROOT);
        }
        return SHARED_KEY;
    }

    // --------- Public entry points ---------

    /** Called when a player first joins the server. */
    public void handleJoin(Player p) {
        World current = p.getWorld();
        if (current == null) return;
        handleEnterOnly(p, current);
    }

    /** Called when Bukkit fires a world change event (from -> to). */
    public void handleWorldChange(Player p, World from, World to) {
        if (from != null) {
            handleLeave(p, from);
        }
        if (to != null) {
            handleEnterOnly(p, to);
        }
    }

    /**
     * Called when a player disconnects. This is the fix for the "inventory
     * gets reset on reconnect" bug: previously nothing re-captured the
     * player's live inventory/stats before they left, so the next join would
     * blindly re-apply whatever (possibly very stale) profile snapshot
     * happened to be cached in memory from the last world-change event -
     * silently rolling the player back and discarding anything they'd done
     * since. We now always snapshot their current world's profile on quit,
     * and persist all of their profile data to disk so nothing is lost even
     * across a server restart.
     */
    public void handleQuit(Player p) {
        World current = p.getWorld();
        if (current != null) {
            WorldManager wm = worldManager();
            WorldManager.WorldEntry entry = (wm != null) ? wm.getWorldByName(current.getName()) : null;
            if (entry != null) {
                saveInventoryProfile(p, inventoryProfileKey(entry));
                saveStatsProfile(p, statsProfileKey(entry));
            }
        }
        savePlayerDataToDisk(p.getUniqueId());
    }

    /** Flush every currently-known player's profile data to disk (used on plugin disable). */
    public void saveAllToDisk() {
        for (UUID id : inventoryProfiles.keySet()) {
            savePlayerDataToDisk(id);
        }
        for (UUID id : statsProfiles.keySet()) {
            savePlayerDataToDisk(id);
        }
    }

    // --------- Internals: leaving a world ---------

    private void handleLeave(Player p, World from) {
        WorldManager wm = worldManager();
        if (wm == null) return;

        WorldManager.WorldEntry entry = wm.getWorldByName(from.getName());
        if (entry == null) return;

        // Always save current state into the appropriate profile:
        //  - isolated worlds: "world:<name>"
        //  - shared worlds: "shared"
        String invKey = inventoryProfileKey(entry);
        String statKey = statsProfileKey(entry);

        saveInventoryProfile(p, invKey);
        saveStatsProfile(p, statKey);
    }

    // --------- Internals: entering a world ---------

    private void handleEnterOnly(Player p, World to) {
        WorldManager wm = worldManager();
        if (wm == null) return;

        WorldManager.WorldEntry entry = wm.getWorldByName(to.getName());
        if (entry == null) return;

        GameMode gm = entry.getDefaultGamemode();
        if (gm != null && p.getGameMode() != gm) {
            p.setGameMode(gm);
        }

        boolean separateInv = entry.isSeparateInventory();
        boolean separateStats = entry.isSeparateStats();

        String invKey = inventoryProfileKey(entry);
        String statKey = statsProfileKey(entry);

        Map<String, InventoryProfile> invMap = inventoriesFor(p.getUniqueId());
        Map<String, StatsProfile> statMap = statsFor(p.getUniqueId());

        InventoryProfile invProf = invMap.get(invKey);
        StatsProfile statProf = statMap.get(statKey);

        // ----- Inventory handling -----
        if (invProf == null) {
            if (separateInv) {
                // First time in an isolated-inventory world:
                // Start with a clean empty inventory.
                invProf = createEmptyInventoryProfile(p);
                invMap.put(invKey, invProf);
                applyInventoryProfile(p, invProf);
            } else {
                // First time touching the shared inventory profile:
                // Use whatever the player currently has as the base "shared" state.
                invProf = captureInventoryProfile(p);
                invMap.put(invKey, invProf);
                // Do NOT modify player's inventory here.
            }
        } else {
            // We already have a profile - always apply it,
            // both for shared and isolated inventories.
            applyInventoryProfile(p, invProf);
        }

        // ----- Stats handling -----
        if (statProf == null) {
            if (separateStats) {
                // First time in an isolated-stats world:
                // Start with default fresh stats (full health, full hunger, 0 xp).
                statProf = createDefaultStatsProfile(p);
                statMap.put(statKey, statProf);
                applyStatsProfile(p, statProf);
            } else {
                // First time using the shared stats profile:
                // Apply simple resets if requested, then store that as shared.
                applySimpleResets(p, entry);
                statProf = captureStatsProfile(p);
                statMap.put(statKey, statProf);
            }
        } else {
            if (separateStats) {
                // Isolated stats: just apply that world's stats.
                applyStatsProfile(p, statProf);
            } else {
                // Shared stats:
                //  1) Restore the shared stats profile
                //  2) Apply optional resets (health/hunger)
                //  3) Update the shared profile to reflect resets
                applyStatsProfile(p, statProf);
                applySimpleResets(p, entry);
                statProf = captureStatsProfile(p);
                statMap.put(statKey, statProf);
            }
        }
    }

    // --------- Capture/apply helpers ---------

    // Inventory

    private InventoryProfile captureInventoryProfile(Player p) {
        InventoryProfile prof = new InventoryProfile();
        prof.inventory = p.getInventory().getContents();
        prof.armor = p.getInventory().getArmorContents();
        prof.offhand = p.getInventory().getItemInOffHand();
        return prof;
    }

    private InventoryProfile createEmptyInventoryProfile(Player p) {
        InventoryProfile prof = new InventoryProfile();
        prof.inventory = new ItemStack[p.getInventory().getSize()];
        prof.armor = new ItemStack[p.getInventory().getArmorContents().length];
        prof.offhand = null;
        return prof;
    }

    private void applyInventoryProfile(Player p, InventoryProfile prof) {
        if (prof == null) return;
        if (prof.inventory != null) {
            p.getInventory().setContents(prof.inventory);
        }
        if (prof.armor != null) {
            p.getInventory().setArmorContents(prof.armor);
        }
        p.getInventory().setItemInOffHand(prof.offhand);
    }

    private void saveInventoryProfile(Player p, String key) {
        Map<String, InventoryProfile> map = inventoriesFor(p.getUniqueId());
        InventoryProfile prof = captureInventoryProfile(p);
        map.put(key, prof);
    }

    // Stats

    private StatsProfile captureStatsProfile(Player p) {
        StatsProfile prof = new StatsProfile();
        prof.health = safeMaxHealthBound(p, p.getHealth());
        prof.food = p.getFoodLevel();
        prof.saturation = p.getSaturation();
        prof.totalExp = p.getTotalExperience();
        prof.exp = p.getExp();
        prof.level = p.getLevel();
        return prof;
    }

    private StatsProfile createDefaultStatsProfile(Player p) {
        StatsProfile prof = new StatsProfile();
        double maxHealth = getMaxHealth(p);
        prof.health = maxHealth;
        prof.food = 20;
        prof.saturation = 5.0f;
        prof.totalExp = 0;
        prof.exp = 0.0f;
        prof.level = 0;
        return prof;
    }

    private void applyStatsProfile(Player p, StatsProfile prof) {
        if (prof == null) return;

        double maxHealth = getMaxHealth(p);
        double health = prof.health;
        if (health <= 0.0 || health > maxHealth) {
            health = maxHealth;
        }

        p.setHealth(health);
        p.setFoodLevel(Math.max(0, Math.min(20, prof.food)));
        p.setSaturation(Math.max(0.0f, prof.saturation));

        // Reset and re-apply XP:
        p.setTotalExperience(0);
        p.setLevel(0);
        p.setExp(0.0f);
        p.giveExp(prof.totalExp);

        // Set level/exp bar shape explicitly:
        p.setLevel(prof.level);
        p.setExp(prof.exp);
    }

    private void saveStatsProfile(Player p, String key) {
        Map<String, StatsProfile> map = statsFor(p.getUniqueId());
        StatsProfile prof = captureStatsProfile(p);
        map.put(key, prof);
    }

    // --------- Simple reset helpers (for non-separated stats) ---------

    private void applySimpleResets(Player p, WorldManager.WorldEntry entry) {
        if (!entry.isResetHealthOnEnter() && !entry.isResetHungerOnEnter()) {
            return;
        }

        double maxHealth = getMaxHealth(p);

        if (entry.isResetHealthOnEnter()) {
            p.setHealth(maxHealth);
        }

        if (entry.isResetHungerOnEnter()) {
            p.setFoodLevel(20);
            p.setSaturation(5.0f);
        }
    }

    private double getMaxHealth(Player p) {
        double maxHealth;
        try {
            maxHealth = p.getMaxHealth();
        } catch (Exception e) {
            maxHealth = 20.0;
        }
        return maxHealth;
    }

    private double safeMaxHealthBound(Player p, double value) {
        double max = getMaxHealth(p);
        if (value <= 0.0 || value > max) {
            return max;
        }
        return value;
    }

    // --------- Disk persistence ---------
    //
    // Every profile (shared "global" inventory/stats, plus one entry per
    // isolated world) is kept in memory for the running session, but is also
    // mirrored to a per-player YAML file so that:
    //   - a plain reconnect never loses progress (we always save-then-load
    //     the exact same state back), and
    //   - items/stats stashed away in an isolated world's profile survive a
    //     full server restart instead of only living in a ConcurrentHashMap.

    private File playerFile(UUID id) {
        return new File(playerDataDir, id.toString() + ".yml");
    }

    private void loadFromDiskIfNeeded(UUID id) {
        if (!loadedFromDisk.add(id)) {
            return; // already loaded (or currently being loaded) this session
        }

        File f = playerFile(id);
        if (!f.exists()) {
            return;
        }

        YamlConfiguration cfg = YamlConfiguration.loadConfiguration(f);

        ConfigurationSection invSec = cfg.getConfigurationSection("inventories");
        if (invSec != null) {
            Map<String, InventoryProfile> map =
                    inventoryProfiles.computeIfAbsent(id, k -> new ConcurrentHashMap<>());
            for (String key : invSec.getKeys(false)) {
                ConfigurationSection ksec = invSec.getConfigurationSection(key);
                if (ksec == null) continue;

                InventoryProfile prof = new InventoryProfile();
                prof.inventory = toItemArray(ksec.getList("inventory"));
                prof.armor = toItemArray(ksec.getList("armor"));
                Object offhand = ksec.get("offhand");
                prof.offhand = (offhand instanceof ItemStack) ? (ItemStack) offhand : null;
                map.put(key, prof);
            }
        }

        ConfigurationSection statSec = cfg.getConfigurationSection("stats");
        if (statSec != null) {
            Map<String, StatsProfile> map =
                    statsProfiles.computeIfAbsent(id, k -> new ConcurrentHashMap<>());
            for (String key : statSec.getKeys(false)) {
                ConfigurationSection ksec = statSec.getConfigurationSection(key);
                if (ksec == null) continue;

                StatsProfile prof = new StatsProfile();
                prof.health = ksec.getDouble("health", 20.0);
                prof.food = ksec.getInt("food", 20);
                prof.saturation = (float) ksec.getDouble("saturation", 5.0);
                prof.totalExp = ksec.getInt("totalExp", 0);
                prof.exp = (float) ksec.getDouble("exp", 0.0);
                prof.level = ksec.getInt("level", 0);
                map.put(key, prof);
            }
        }
    }

    private void savePlayerDataToDisk(UUID id) {
        Map<String, InventoryProfile> invMap = inventoryProfiles.get(id);
        Map<String, StatsProfile> statMap = statsProfiles.get(id);

        boolean hasInv = invMap != null && !invMap.isEmpty();
        boolean hasStats = statMap != null && !statMap.isEmpty();
        if (!hasInv && !hasStats) {
            return;
        }

        YamlConfiguration cfg = new YamlConfiguration();

        if (hasInv) {
            for (Map.Entry<String, InventoryProfile> e : invMap.entrySet()) {
                String base = "inventories." + e.getKey() + ".";
                InventoryProfile prof = e.getValue();
                cfg.set(base + "inventory", itemArrayToList(prof.inventory));
                cfg.set(base + "armor", itemArrayToList(prof.armor));
                cfg.set(base + "offhand", prof.offhand);
            }
        }

        if (hasStats) {
            for (Map.Entry<String, StatsProfile> e : statMap.entrySet()) {
                String base = "stats." + e.getKey() + ".";
                StatsProfile prof = e.getValue();
                cfg.set(base + "health", prof.health);
                cfg.set(base + "food", prof.food);
                cfg.set(base + "saturation", (double) prof.saturation);
                cfg.set(base + "totalExp", prof.totalExp);
                cfg.set(base + "exp", (double) prof.exp);
                cfg.set(base + "level", prof.level);
            }
        }

        try {
            if (!playerDataDir.exists()) {
                playerDataDir.mkdirs();
            }
            cfg.save(playerFile(id));
        } catch (IOException e) {
            plugin.getLogger().warning("[WorldProfileManager] Failed to save profile data for "
                    + id + ": " + e.getMessage());
        }
    }

    private ItemStack[] toItemArray(List<?> list) {
        if (list == null) return new ItemStack[0];
        ItemStack[] arr = new ItemStack[list.size()];
        for (int i = 0; i < list.size(); i++) {
            Object o = list.get(i);
            arr[i] = (o instanceof ItemStack) ? (ItemStack) o : null;
        }
        return arr;
    }

    private List<ItemStack> itemArrayToList(ItemStack[] arr) {
        List<ItemStack> list = new ArrayList<>();
        if (arr == null) return list;
        for (ItemStack it : arr) {
            list.add(it);
        }
        return list;
    }
}

