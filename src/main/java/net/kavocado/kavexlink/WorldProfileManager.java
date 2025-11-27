package net.kavocado.kavexlink;

import org.bukkit.World;
import org.bukkit.GameMode;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;

import java.util.Locale;
import java.util.Map;
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

    public WorldProfileManager(KavexLinkPlugin plugin) {
        this.plugin = plugin;
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
        return inventoryProfiles.computeIfAbsent(id, k -> new ConcurrentHashMap<>());
    }

    private Map<String, StatsProfile> statsFor(UUID id) {
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
}

