package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.World;
import org.bukkit.WorldCreator;
import org.bukkit.WorldType;
import org.bukkit.GameMode;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Manages the list of "warpable" worlds and their visibility (PUBLIC/PRIVATE).
 * - Auto-detects all currently loaded Bukkit worlds (including default overworld/nether/end)
 *   and adds them as built-in entries if missing.
 * - Stores per-world metadata in worlds.yml:
 *   - mode (DEFAULT / FLAT / LARGE)
 *   - access (PUBLIC / PRIVATE)
 *   - icon (Material)
 *   - seed (optional, mainly for created worlds)
 *   - builtin (true for default/server worlds)
 *   - order (int, for GUI ordering)
 *   - default_gamemode (INHERIT / SURVIVAL / CREATIVE / ADVENTURE / SPECTATOR)
 *   - reset_health_on_enter (boolean)
 *   - reset_hunger_on_enter (boolean)
 *   - separate_inventory (boolean)
 *   - separate_stats (boolean)
 */
public class WorldManager {

    public enum Mode {
        DEFAULT,
        FLAT,
        LARGE;

        public static Mode fromStringOrId(String s) {
            if (s == null) return DEFAULT;
            s = s.trim().toLowerCase();
            if (s.equals("1") || s.equals("default") || s.equals("normal")) {
                return DEFAULT;
            }
            if (s.equals("2") || s.equals("flat") || s.equals("superflat")) {
                return FLAT;
            }
            if (s.equals("3") || s.equals("large") || s.equals("large_biomes") || s.equals("largebiomes")) {
                return LARGE;
            }
            return DEFAULT;
        }
    }

    public enum Access {
        PUBLIC,
        PRIVATE;

        public static Access fromString(String s, Access def) {
            if (s == null) return def;
            s = s.trim().toLowerCase();
            if (s.startsWith("pub")) return PUBLIC;
            if (s.startsWith("pri")) return PRIVATE;
            return def;
        }
    }

    public static class WorldEntry {
        private final String name;
        private boolean builtin;
        private Mode mode;
        private Access access;
        private Material icon;
        private String seed; // free-form; numeric or text
        private int order;   // GUI sort order (0 = default)

        // Extended behaviour flags
        private GameMode defaultGamemode;      // null = inherit server default
        private boolean resetHealthOnEnter;    // simple reset variant
        private boolean resetHungerOnEnter;    // simple reset variant
        private boolean separateInventory;     // full separate inventory
        private boolean separateStats;         // full separate health/hunger/xp
        private boolean returnToLastLocation;  // true = remember last position in this world; false = always spawn

        public WorldEntry(String name,
                          boolean builtin,
                          Mode mode,
                          Access access,
                          Material icon,
                          String seed) {
            this.name = name;
            this.builtin = builtin;
            this.mode = (mode != null ? mode : Mode.DEFAULT);
            this.access = (access != null ? access : Access.PRIVATE);
            this.icon = (icon != null ? icon : Material.GRASS_BLOCK);
            this.seed = seed;
            this.order = 0;

            // defaults for new worlds
            this.defaultGamemode = null;          // inherit
            this.resetHealthOnEnter = false;
            this.resetHungerOnEnter = false;
            this.separateInventory = false;
            this.separateStats = false;
            this.returnToLastLocation = true;     // keep last known position unless configured otherwise
        }

        public String getName() {
            return name;
        }

        public boolean isBuiltin() {
            return builtin;
        }

        public Mode getMode() {
            return mode;
        }

        public Access getAccess() {
            return access;
        }

        public Material getIcon() {
            return icon;
        }

        public String getSeed() {
            return seed;
        }

        public int getOrder() {
            return order;
        }

        void setBuiltin(boolean builtin) {
            this.builtin = builtin;
        }

        void setMode(Mode mode) {
            this.mode = (mode != null ? mode : Mode.DEFAULT);
        }

        void setAccess(Access access) {
            this.access = (access != null ? access : Access.PRIVATE);
        }

        void setIcon(Material icon) {
            this.icon = (icon != null ? icon : Material.GRASS_BLOCK);
        }

        void setSeed(String seed) {
            this.seed = seed;
        }

        public GameMode getDefaultGamemode() {
            return defaultGamemode;
        }

        public void setDefaultGamemode(GameMode gm) {
            this.defaultGamemode = gm;
        }

        public boolean isResetHealthOnEnter() {
            return resetHealthOnEnter;
        }

        public void setResetHealthOnEnter(boolean resetHealthOnEnter) {
            this.resetHealthOnEnter = resetHealthOnEnter;
        }

        public boolean isResetHungerOnEnter() {
            return resetHungerOnEnter;
        }

        public void setResetHungerOnEnter(boolean resetHungerOnEnter) {
            this.resetHungerOnEnter = resetHungerOnEnter;
        }

        public boolean isSeparateInventory() {
            return separateInventory;
        }

        public void setSeparateInventory(boolean separateInventory) {
            this.separateInventory = separateInventory;
        }

        public boolean isSeparateStats() {
            return separateStats;
        }

        public void setSeparateStats(boolean separateStats) {
            this.separateStats = separateStats;
        }

        public boolean isReturnToLastLocation() {
            return returnToLastLocation;
        }

        public void setReturnToLastLocation(boolean returnToLastLocation) {
            this.returnToLastLocation = returnToLastLocation;
        }

        void setOrder(int order) {
            if (order < 0) order = 0;
            this.order = order;
        }
    }

    private final KavexLinkPlugin plugin;
    private final File metaFile;

    // key = world name (lowercase)
    private final Map<String, WorldEntry> worlds = new HashMap<>();

    public WorldManager(KavexLinkPlugin plugin) {
        this.plugin = plugin;
        this.metaFile = new File(plugin.getDataFolder(), "worlds.yml");

        load();
        detectBuiltinWorlds();  // add overworld/nether/end/default worlds if missing
        saveSafely();           // persist any new default entries
    }

    private String key(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    // ----------------- Load / Save -----------------

    private void load() {
        worlds.clear();
        if (!metaFile.exists()) {
            return;
        }

        YamlConfiguration cfg = YamlConfiguration.loadConfiguration(metaFile);
        ConfigurationSection sec = cfg.getConfigurationSection("worlds");
        if (sec == null) return;

        for (String name : sec.getKeys(false)) {
            ConfigurationSection wsec = sec.getConfigurationSection(name);
            if (wsec == null) continue;

            String modeStr   = wsec.getString("mode",   "DEFAULT");
            String accessStr = wsec.getString("access", "PRIVATE");
            String iconStr   = wsec.getString("icon",   "GRASS_BLOCK");
            String seed      = wsec.getString("seed",   null);
            boolean builtin  = wsec.getBoolean("builtin", false);
            int order        = wsec.getInt("order", 0);

            // NEW: extra fields
            String gmStr            = wsec.getString("gamemode", "INHERIT");
            boolean resetHealth     = wsec.getBoolean("reset_health_on_enter", false);
            boolean resetHunger     = wsec.getBoolean("reset_hunger_on_enter", false);
            boolean separateInv     = wsec.getBoolean("separate_inventory", false);
            boolean separateStats   = wsec.getBoolean("separate_stats", false);
            boolean returnToLast    = wsec.getBoolean("return_to_last_location", true);

               
	    Mode mode = Mode.fromStringOrId(modeStr);
            Access access = Access.fromString(accessStr, Access.PRIVATE);
            Material icon = Material.matchMaterial(iconStr);
            if (icon == null) icon = Material.GRASS_BLOCK;

            WorldEntry entry = new WorldEntry(name, builtin, mode, access, icon, seed);
            entry.setOrder(order);

            // parse gamemode (INHERIT = null)
            if (gmStr != null) {
                gmStr = gmStr.trim().toUpperCase(Locale.ROOT);
                if (!gmStr.equals("INHERIT")) {
                    try {
                        org.bukkit.GameMode gm = org.bukkit.GameMode.valueOf(gmStr);
                        entry.setDefaultGamemode(gm);
                    } catch (IllegalArgumentException ignored) {
                        // invalid -> keep inherit (null)
                    }
                }
            }

            entry.setResetHealthOnEnter(resetHealth);
            entry.setResetHungerOnEnter(resetHunger);
            entry.setSeparateInventory(separateInv);
            entry.setSeparateStats(separateStats);
            entry.setReturnToLastLocation(returnToLast);

            worlds.put(key(name), entry);
        }

        plugin.getLogger().info("Loaded " + worlds.size() + " world entries from worlds.yml.");
    }

    public void save() throws IOException {
        YamlConfiguration cfg = new YamlConfiguration();
        ConfigurationSection sec = cfg.createSection("worlds");

        for (WorldEntry e : worlds.values()) {
            ConfigurationSection wsec = sec.createSection(e.getName());
            wsec.set("mode", e.getMode().name());
            wsec.set("access", e.getAccess().name());
            wsec.set("icon", e.getIcon().name());
            if (e.getSeed() != null && !e.getSeed().isEmpty()) {
                wsec.set("seed", e.getSeed());
            }
            if (e.isBuiltin()) {
                wsec.set("builtin", true);
            }
            wsec.set("order", e.getOrder());

            // NEW: extra fields
            if (e.getDefaultGamemode() != null) {
                wsec.set("gamemode", e.getDefaultGamemode().name());
            } else {
                wsec.set("gamemode", "INHERIT");
            }
            wsec.set("reset_health_on_enter", e.isResetHealthOnEnter());
            wsec.set("reset_hunger_on_enter", e.isResetHungerOnEnter());
            wsec.set("separate_inventory", e.isSeparateInventory());
            wsec.set("separate_stats", e.isSeparateStats());
            wsec.set("return_to_last_location", e.isReturnToLastLocation());
        }

        cfg.save(metaFile);
    }

    public void saveSafely() {
        try {
            save();
        } catch (IOException e) {
            plugin.getLogger().severe("Failed to save worlds.yml: " + e);
        }
    }

    // ----------------- Detection of default / builtin worlds -----------------

    /**
     * Ensure that all currently loaded Bukkit worlds have a WorldEntry.
     * These will typically include:
     *   - the default overworld
     *   - its nether dimension
     *   - its end dimension
     * plus any other loaded worlds.
     *
     * They are added as "builtin" and PRIVATE by default, so only staff can
     * use them until visibility is toggled to PUBLIC.
     */
    private void detectBuiltinWorlds() {
        for (World bw : Bukkit.getWorlds()) {
            String name = bw.getName();
            String k = key(name);

            WorldEntry entry = worlds.get(k);
            if (entry == null) {
                Material icon;
                switch (bw.getEnvironment()) {
                    case NETHER -> icon = Material.NETHERRACK;
                    case THE_END -> icon = Material.END_STONE;
                    default -> icon = Material.GRASS_BLOCK;
                }

                entry = new WorldEntry(
                        name,
                        true,              // builtin
                        Mode.DEFAULT,
                        Access.PRIVATE,    // default to PRIVATE for safety; staff can toggle to PUBLIC
                        icon,
                        null
                );
                entry.setOrder(0);
                worlds.put(k, entry);
            } else {
                // Mark already-known entries as builtin if they exist as actual Bukkit worlds
                entry.setBuiltin(true);

                // If icon is missing, choose a sensible default based on environment
                if (entry.getIcon() == null || entry.getIcon() == Material.AIR) {
                    Material icon;
                    switch (bw.getEnvironment()) {
                        case NETHER -> icon = Material.NETHERRACK;
                        case THE_END -> icon = Material.END_STONE;
                        default -> icon = Material.GRASS_BLOCK;
                    }
                    entry.setIcon(icon);
                }
            }
        }
    }

    // ----------------- Public API used by the plugin / GUI -----------------

    public List<WorldEntry> getAllWorldsSorted() {
        List<WorldEntry> list = new ArrayList<>(worlds.values());
        // Sort by order first, then by name (case-insensitive)
        list.sort(
                Comparator.comparingInt(WorldEntry::getOrder)
                        .thenComparing(WorldEntry::getName, String.CASE_INSENSITIVE_ORDER)
        );
        return list;
    }

    public WorldEntry getWorldByName(String name) {
        if (name == null) return null;
        return worlds.get(key(name));
    }

    /**
     * Create or update a world entry from /world create.
     * The actual world creation/loading is performed by ensureWorldLoaded().
     */
    public WorldEntry createWorld(String name,
                                  Mode mode,
                                  Access access,
                                  Material icon,
                                  String seed) {
        String k = key(name);
        WorldEntry entry = worlds.get(k);
        if (entry == null) {
            entry = new WorldEntry(
                    name,
                    false,        // user-created/custom
                    mode,
                    access,
                    icon,
                    seed
            );
            worlds.put(k, entry);
        } else {
            entry.setBuiltin(false);   // treat as custom explicitly created
            entry.setMode(mode);
            entry.setAccess(access);
            entry.setIcon(icon);
            entry.setSeed(seed);
        }
        saveSafely();
        return entry;
    }

    /** Old helper, still used internally. */
    public void setAccess(WorldEntry entry, Access access) {
        if (entry == null) return;
        entry.setAccess(access);
        saveSafely();
    }

    /**
     * Ensure the given world is loaded in Bukkit. For builtin worlds this usually
     * just returns the existing Bukkit world. For custom worlds, this creates
     * a new world with the stored mode/seed if not loaded yet.
     */
    public World ensureWorldLoaded(WorldEntry entry) {
        if (entry == null) return null;

        World world = Bukkit.getWorld(entry.getName());
        if (world != null) {
            return world;
        }

        WorldCreator creator = new WorldCreator(entry.getName());

        switch (entry.getMode()) {
            case FLAT -> creator.type(WorldType.FLAT);
            case LARGE -> creator.type(WorldType.LARGE_BIOMES);
            default -> creator.type(WorldType.NORMAL);
        }

        String seedStr = entry.getSeed();
        if (seedStr != null && !seedStr.isEmpty()) {
            try {
                long seedLong = Long.parseLong(seedStr);
                creator.seed(seedLong);
            } catch (NumberFormatException ex) {
                // non-numeric seed -> derive a deterministic seed from hash
                creator.seed(seedStr.hashCode());
            }
        }

        return Bukkit.createWorld(creator);
    }

    // ----------------- New helpers for /world edit -----------------

    /**
     * Rename a world metadata entry.
     *
     * NOTE: This only renames the "warpable world" entry, not the actual
     * Bukkit world folder on disk. After renaming, /world tp <newName> will
     * load/create a world with the new name + same mode/seed.
     */
    public void renameWorld(WorldEntry entry, String newName) {
        if (entry == null) return;
        if (newName == null || newName.trim().isEmpty()) return;

        String newKey = key(newName);
        // Avoid accidental overwrite if somehow already present
        WorldEntry conflict = worlds.get(newKey);
        if (conflict != null && conflict != entry) {
            // Caller should check for conflicts beforehand; just bail out silently here
            return;
        }

        String oldKey = key(entry.getName());

        WorldEntry replacement = new WorldEntry(
                newName,
                entry.isBuiltin(),
                entry.getMode(),
                entry.getAccess(),
                entry.getIcon(),
                entry.getSeed()
        );
        replacement.setOrder(entry.getOrder());

        // copy extended flags
        replacement.setDefaultGamemode(entry.getDefaultGamemode());
        replacement.setResetHealthOnEnter(entry.isResetHealthOnEnter());
        replacement.setResetHungerOnEnter(entry.isResetHungerOnEnter());
        replacement.setSeparateInventory(entry.isSeparateInventory());
        replacement.setSeparateStats(entry.isSeparateStats());
        replacement.setReturnToLastLocation(entry.isReturnToLastLocation());

        worlds.remove(oldKey);
        worlds.put(newKey, replacement);
        saveSafely();
    }

    /** Wrapper used by plugin to make semantics clearer. */
    public void setWorldAccess(WorldEntry entry, Access access) {
        setAccess(entry, access);
    }

    public void updateWorldIcon(WorldEntry entry, Material icon) {
        if (entry == null || icon == null) return;
        entry.setIcon(icon);
        saveSafely();
    }

    public void updateWorldOrder(WorldEntry entry, int order) {
        if (entry == null) return;
        entry.setOrder(order);
        saveSafely();
    }

    /**
     * Whether the given world entry is allowed to be deleted via /world edit delete.
     * Currently we disallow deleting builtin worlds (overworld/nether/end/etc.),
     * and allow deletion of custom entries.
     *
     * NOTE: deleteWorld() only removes metadata; it does not delete world folders.
     */
    public boolean canDelete(WorldEntry entry) {
        return entry != null && !entry.isBuiltin();
    }

    /**
     * Delete a world entry from the metadata map.
     *
     * NOTE: This does NOT unload or remove any actual world folders; it only
     * removes the entry from the worlds.yml data used by the GUI and commands.
     */
    public void deleteWorld(WorldEntry entry) {
        if (entry == null) return;
        worlds.remove(key(entry.getName()));
        saveSafely();
    }

    // ----------------- New: import existing world folders -----------------

    /**
     * Import an existing world folder located in the server's world container
     * (usually the server root). The folder must contain a valid level.dat.
     *
     * This:
     *  - validates the folder
     *  - loads the world via Bukkit
     *  - registers a WorldEntry (PRIVATE by default)
     *
     * Usage from command: /world import <folderName>
     */
    public WorldEntry importWorld(String folderName) {
        if (folderName == null || folderName.trim().isEmpty()) {
            return null;
        }

        String name = folderName.trim();
        String k = key(name);

        // If already registered, just ensure it's loaded and return the entry.
        WorldEntry existing = worlds.get(k);
        if (existing != null) {
            World w = ensureWorldLoaded(existing);
            if (w == null) {
                plugin.getLogger().warning("[Worlds] Import: entry for '" + name + "' exists but world failed to load.");
            }
            return existing;
        }

        File container = Bukkit.getWorldContainer();
        File worldDir = new File(container, name);

        if (!worldDir.exists() || !worldDir.isDirectory()) {
            plugin.getLogger().warning("[Worlds] Import failed: folder " + worldDir.getPath() + " does not exist or is not a directory.");
            return null;
        }

        File levelDat = new File(worldDir, "level.dat");
        if (!levelDat.exists()) {
            plugin.getLogger().warning("[Worlds] Import failed: " + worldDir.getPath() + " has no level.dat (not a valid world?).");
            return null;
        }

        // Load the world. If it already exists, this just returns it.
        WorldCreator creator = new WorldCreator(name);
        World world = Bukkit.createWorld(creator);
        if (world == null) {
            plugin.getLogger().warning("[Worlds] Import failed: Bukkit could not create/load world '" + name + "'.");
            return null;
        }

        // Choose icon based on environment
        Material icon;
        switch (world.getEnvironment()) {
            case NETHER -> icon = Material.NETHERRACK;
            case THE_END -> icon = Material.END_STONE;
            default -> icon = Material.GRASS_BLOCK;
        }

        String seedStr = Long.toString(world.getSeed());

        WorldEntry entry = new WorldEntry(
                name,
                false,                // imported, not builtin
                Mode.DEFAULT,         // we load existing folder; mode is mostly relevant for new creation
                Access.PRIVATE,       // default PRIVATE; you can /world edit to PUBLIC
                icon,
                seedStr
        );
        entry.setOrder(0);
        worlds.put(k, entry);
        saveSafely();

        plugin.getLogger().info("[Worlds] Imported existing world folder '" + name + "' as world entry.");
        return entry;
    }
}

