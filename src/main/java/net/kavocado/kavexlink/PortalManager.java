package net.kavocado.kavexlink;

import org.bukkit.Axis;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.World;
import org.bukkit.block.Block;
import org.bukkit.block.data.Orientable;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.block.Action;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerPortalEvent;
import org.bukkit.inventory.EquipmentSlot;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Portal system:
 * - /portal wand   : give END_ROD "Portal Wand"
 * - Wand left/right click (normal mode): select 2D area (plane only).
 * - /portal create <name> <world-or-warp>
 *      -> horizontal area -> END_PORTAL blocks
 *      -> vertical area   -> NETHER_PORTAL blocks
 * - Walking into those blocks teleports you to target world/warp.
 * - /portals list
 * - /portals edit <name> <activate|deactivate|changetarget|changearea|delete>
 * - /portal rebuild : wand enters rebuild mode
 *      - left-click portal block: break that block, bind wand to that portal
 *      - right-click with wand: place same portal block as part of that portal
 * - /exit_mode : leave rebuild mode
 */
public class PortalManager implements Listener {

    public enum TargetType {
        WORLD,
        WARP
    }

    public enum Orientation {
        HORIZONTAL,   // y fixed -> END_PORTAL
        VERTICAL_X,   // x fixed -> NETHER_PORTAL (axis X)
        VERTICAL_Z    // z fixed -> NETHER_PORTAL (axis Z)
    }

    public static class PortalEntry {
        private final String id;
        private String name;
        private String worldName;
        private int minX, maxX, minY, maxY, minZ, maxZ;
        private TargetType targetType;
        private String targetName;
        private boolean active;

        public PortalEntry(String id,
                           String name,
                           String worldName,
                           int minX, int maxX,
                           int minY, int maxY,
                           int minZ, int maxZ,
                           TargetType targetType,
                           String targetName,
                           boolean active) {
            this.id = id;
            this.name = name;
            this.worldName = worldName;
            this.minX = minX;
            this.maxX = maxX;
            this.minY = minY;
            this.maxY = maxY;
            this.minZ = minZ;
            this.maxZ = maxZ;
            this.targetType = targetType;
            this.targetName = targetName;
            this.active = active;
        }

        public String getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public String getWorldName() {
            return worldName;
        }

        public int getMinX() {
            return minX;
        }

        public int getMaxX() {
            return maxX;
        }

        public int getMinY() {
            return minY;
        }

        public int getMaxY() {
            return maxY;
        }

        public int getMinZ() {
            return minZ;
        }

        public int getMaxZ() {
            return maxZ;
        }

        public TargetType getTargetType() {
            return targetType;
        }

        public String getTargetName() {
            return targetName;
        }

        public boolean isActive() {
            return active;
        }

        public void setName(String name) {
            this.name = name;
        }

        public void setWorldName(String worldName) {
            this.worldName = worldName;
        }

        public void setBounds(int minX, int maxX,
                              int minY, int maxY,
                              int minZ, int maxZ) {
            this.minX = minX;
            this.maxX = maxX;
            this.minY = minY;
            this.maxY = maxY;
            this.minZ = minZ;
            this.maxZ = maxZ;
        }

        public void setTarget(TargetType type, String targetName) {
            this.targetType = type;
            this.targetName = targetName;
        }

        public void setActive(boolean active) {
            this.active = active;
        }

        public Orientation getOrientation() {
            int dx = maxX - minX;
            int dy = maxY - minY;
            int dz = maxZ - minZ;

            if (dy == 0) {
                return Orientation.HORIZONTAL;
            }
            if (dx == 0) {
                return Orientation.VERTICAL_X;
            }
            return Orientation.VERTICAL_Z;
        }

        public boolean containsBlock(String worldName, int x, int y, int z) {
            if (!Objects.equals(this.worldName, worldName)) return false;
            return x >= minX && x <= maxX
                    && y >= minY && y <= maxY
                    && z >= minZ && z <= maxZ;
        }
    }

    /**
     * Per-player selection (like a tiny WorldEdit).
     */
    public static class Selection {
        String worldName;
        int x1, y1, z1;
        int x2, y2, z2;
        boolean hasPos1;
        boolean hasPos2;

        public void setPos1(Location loc) {
            this.worldName = loc.getWorld().getName();
            this.x1 = loc.getBlockX();
            this.y1 = loc.getBlockY();
            this.z1 = loc.getBlockZ();
            this.hasPos1 = true;
        }

        public void setPos2(Location loc) {
            this.worldName = loc.getWorld().getName();
            this.x2 = loc.getBlockX();
            this.y2 = loc.getBlockY();
            this.z2 = loc.getBlockZ();
            this.hasPos2 = true;
        }

        public boolean isComplete() {
            return hasPos1 && hasPos2 && worldName != null;
        }

        public String getWorldName() {
            return worldName;
        }

        public int getMinX() {
            return Math.min(x1, x2);
        }

        public int getMaxX() {
            return Math.max(x1, x2);
        }

        public int getMinY() {
            return Math.min(y1, y2);
        }

        public int getMaxY() {
            return Math.max(y1, y2);
        }

        public int getMinZ() {
            return Math.min(z1, z2);
        }

        public int getMaxZ() {
            return Math.max(z1, z2);
        }

        public Orientation getOrientation() {
            int dx = Math.abs(x1 - x2);
            int dy = Math.abs(y1 - y2);
            int dz = Math.abs(z1 - z2);

            // 2D plane requirement:
            // exactly one axis must be "flat" (diff == 0)
            // and at least one of the others must be > 0.
            boolean flatX = (dx == 0);
            boolean flatY = (dy == 0);
            boolean flatZ = (dz == 0);

            int flats = (flatX ? 1 : 0) + (flatY ? 1 : 0) + (flatZ ? 1 : 0);
            if (flats != 1) {
                return null; // not a clean 2D plane
            }

            if (flatY) {
                // y constant -> horizontal
                if (dx == 0 && dz == 0) return null; // single block -> reject
                return Orientation.HORIZONTAL;
            } else if (flatX) {
                if (dy == 0 && dz == 0) return null;
                return Orientation.VERTICAL_X;
            } else {
                if (dx == 0 && dy == 0) return null;
                return Orientation.VERTICAL_Z;
            }
        }
    }

    private final KavexLinkPlugin plugin;
    private final File file;

    private final Map<String, PortalEntry> portalsById = new HashMap<>();
    private final Map<String, PortalEntry> portalsByName = new HashMap<>();

    private final Map<UUID, Selection> selections = new HashMap<>();
    private final Set<UUID> rebuildModePlayers = new HashSet<>();
    private final Map<UUID, String> boundPortalId = new HashMap<>();

    private final Map<UUID, Long> portalCooldown = new HashMap<>();

    public PortalManager(KavexLinkPlugin plugin) {
        this.plugin = plugin;
        this.file = new File(plugin.getDataFolder(), "portals.yml");

        load();
    }

    // ----------------- Persistence -----------------

    private void load() {
        portalsById.clear();
        portalsByName.clear();

        if (!file.exists()) {
            plugin.getLogger().info("No portals.yml yet (will be created on first save).");
            return;
        }

        YamlConfiguration cfg = YamlConfiguration.loadConfiguration(file);
        ConfigurationSection root = cfg.getConfigurationSection("portals");
        if (root == null) {
            plugin.getLogger().info("Empty portals.yml (no 'portals' section).");
            return;
        }

        for (String id : root.getKeys(false)) {
            ConfigurationSection sec = root.getConfigurationSection(id);
            if (sec == null) continue;

            String name = sec.getString("name");
            String worldName = sec.getString("world");
            if (name == null || worldName == null) {
                plugin.getLogger().warning("Skipping portal id=" + id + ": missing name or world.");
                continue;
            }

            int minX = sec.getInt("minX");
            int maxX = sec.getInt("maxX");
            int minY = sec.getInt("minY");
            int maxY = sec.getInt("maxY");
            int minZ = sec.getInt("minZ");
            int maxZ = sec.getInt("maxZ");

            String typeStr = sec.getString("target_type", "WORLD").toUpperCase(Locale.ROOT);
            TargetType targetType;
            try {
                targetType = TargetType.valueOf(typeStr);
            } catch (IllegalArgumentException ex) {
                plugin.getLogger().warning("Unknown target_type '" + typeStr + "' for portal " + id + ", defaulting to WORLD");
                targetType = TargetType.WORLD;
            }
            String targetName = sec.getString("target_name");
            boolean active = sec.getBoolean("active", true);

            PortalEntry entry = new PortalEntry(
                    id, name, worldName,
                    minX, maxX, minY, maxY, minZ, maxZ,
                    targetType, targetName, active
            );
            portalsById.put(id, entry);
            portalsByName.put(name.toLowerCase(Locale.ROOT), entry);
        }

        plugin.getLogger().info("Loaded " + portalsById.size() + " portals.");
    }

    public void save() throws IOException {
        YamlConfiguration cfg = new YamlConfiguration();
        ConfigurationSection root = cfg.createSection("portals");

        for (PortalEntry p : portalsById.values()) {
            ConfigurationSection sec = root.createSection(p.getId());
            sec.set("name", p.getName());
            sec.set("world", p.getWorldName());
            sec.set("minX", p.getMinX());
            sec.set("maxX", p.getMaxX());
            sec.set("minY", p.getMinY());
            sec.set("maxY", p.getMaxY());
            sec.set("minZ", p.getMinZ());
            sec.set("maxZ", p.getMaxZ());
            sec.set("target_type", p.getTargetType().name());
            sec.set("target_name", p.getTargetName());
            sec.set("active", p.isActive());
        }

        cfg.save(file);
    }

    public void saveSafely() {
        try {
            save();
        } catch (IOException e) {
            plugin.getLogger().severe("Failed to save portals.yml: " + e);
        }
    }

    // ----------------- Selection & Wand -----------------

    private Selection getOrCreateSelection(Player p) {
        return selections.computeIfAbsent(p.getUniqueId(), k -> new Selection());
    }

    public void clearSelection(Player p) {
        selections.remove(p.getUniqueId());
    }

    public void giveWand(Player p) {
        ItemStack wand = new ItemStack(Material.END_ROD, 1);
        ItemMeta meta = wand.getItemMeta();
        if (meta != null) {
            meta.setDisplayName(ChatColor.LIGHT_PURPLE + "Portal Wand");
            List<String> lore = new ArrayList<>();
            lore.add(ChatColor.GRAY + "Left-click block: set position 1");
            lore.add(ChatColor.GRAY + "Right-click block: set position 2");
            lore.add(ChatColor.DARK_AQUA + "In rebuild mode:");
            lore.add(ChatColor.GRAY + "  Left-click portal: bind/break block");
            lore.add(ChatColor.GRAY + "  Right-click: place new portal block");
            meta.setLore(lore);
            wand.setItemMeta(meta);
        }
        p.getInventory().addItem(wand);
        p.sendMessage("§aYou received a §dPortal Wand§a.");
    }

    private boolean isPortalWand(ItemStack item) {
        if (item == null) return false;
        if (item.getType() != Material.END_ROD) return false;
        ItemMeta meta = item.getItemMeta();
        if (meta == null || !meta.hasDisplayName()) return false;
        String stripped = ChatColor.stripColor(meta.getDisplayName());
        return stripped != null && stripped.equalsIgnoreCase("Portal Wand");
    }

    public void enableRebuildMode(Player p) {
        UUID id = p.getUniqueId();
        rebuildModePlayers.add(id);
        boundPortalId.remove(id);
        p.sendMessage("§bPortal wand is now in rebuild mode. Use §e/exit_mode §bto exit.");
    }

    public void disableRebuildMode(Player p) {
        UUID id = p.getUniqueId();
        rebuildModePlayers.remove(id);
        boundPortalId.remove(id);
        p.sendMessage("§7Portal rebuild mode disabled.");
    }

    public boolean isInRebuildMode(Player p) {
        return rebuildModePlayers.contains(p.getUniqueId());
    }

    // ----------------- Portal CRUD API (used by commands) -----------------

    public List<PortalEntry> getAllPortalsSorted() {
        List<PortalEntry> list = new ArrayList<>(portalsById.values());
        list.sort(Comparator.comparing(PortalEntry::getName, String.CASE_INSENSITIVE_ORDER));
        return list;
    }

    public PortalEntry getPortalByName(String name) {
        if (name == null) return null;
        return portalsByName.get(name.toLowerCase(Locale.ROOT));
    }

    /**
     * Create a portal from the player's current selection.
     * Auto-detects whether the target is a WORLD or WARP.
     * Returns null on error (and informs the player).
     */
    public PortalEntry createPortalFromSelection(Player p,
                                                 String portalName,
                                                 String rawTarget) {
        Selection sel = selections.get(p.getUniqueId());
        if (sel == null || !sel.isComplete()) {
            p.sendMessage("§cYou must select an area with the Portal Wand first.");
            return null;
        }

        Orientation orientation = sel.getOrientation();
        if (orientation == null) {
            p.sendMessage("§cSelection must be a 2D area (flat plane). No volume or single-block lines.");
            return null;
        }

        String worldName = sel.getWorldName();
        World bukkitWorld = Bukkit.getWorld(worldName);
        if (bukkitWorld == null) {
            p.sendMessage("§cWorld '" + worldName + "' is not loaded.");
            return null;
        }

        // Determine target type
        TargetType targetType;
        String targetName = rawTarget;

        // Try world first
        WorldManager wm = plugin.getWorldManager();
        WarpManager warpManager = plugin.getWarpManager();

        WorldManager.WorldEntry wEntry = (wm != null ? wm.getWorldByName(rawTarget) : null);
        if (wEntry != null) {
            targetType = TargetType.WORLD;
        } else if (warpManager != null) {
            WarpManager.Warp warp = warpManager.getPublicWarp(rawTarget);
            if (warp == null) {
                warp = warpManager.getPrivateWarp(p.getUniqueId(), rawTarget);
            }
            if (warp == null) {
                p.sendMessage("§cNo world or warp named §e" + rawTarget + "§c found.");
                return null;
            }
            targetType = TargetType.WARP;
        } else {
            p.sendMessage("§cNo world/warp target system available.");
            return null;
        }

        int minX = sel.getMinX();
        int maxX = sel.getMaxX();
        int minY = sel.getMinY();
        int maxY = sel.getMaxY();
        int minZ = sel.getMinZ();
        int maxZ = sel.getMaxZ();

        // Place blocks
        fillPortalBlocks(bukkitWorld, minX, maxX, minY, maxY, minZ, maxZ, orientation);

        String id = UUID.randomUUID().toString().replace("-", "");
        PortalEntry entry = new PortalEntry(
                id,
                portalName,
                worldName,
                minX, maxX,
                minY, maxY,
                minZ, maxZ,
                targetType,
                targetName,
                true
        );

        portalsById.put(id, entry);
        portalsByName.put(portalName.toLowerCase(Locale.ROOT), entry);
        saveSafely();

        p.sendMessage("§aCreated portal §e" + portalName + "§a targeting "
                + (targetType == TargetType.WORLD ? "world" : "warp")
                + " §e" + targetName + "§a.");

        return entry;
    }

    public boolean updatePortalTarget(Player issuer, PortalEntry entry, String rawTarget) {
        if (entry == null) return false;

        WorldManager wm = plugin.getWorldManager();
        WarpManager warpManager = plugin.getWarpManager();

        // Try world first
        WorldManager.WorldEntry wEntry = (wm != null ? wm.getWorldByName(rawTarget) : null);
        if (wEntry != null) {
            entry.setTarget(TargetType.WORLD, rawTarget);
            saveSafely();
            if (issuer != null) {
                issuer.sendMessage("§aPortal §e" + entry.getName() + "§a now targets world §e" + rawTarget + "§a.");
            }
            return true;
        }

        if (warpManager != null) {
            WarpManager.Warp warp = warpManager.getPublicWarp(rawTarget);
            if (warp == null && issuer != null) {
                warp = warpManager.getPrivateWarp(issuer.getUniqueId(), rawTarget);
            }
            if (warp != null) {
                entry.setTarget(TargetType.WARP, rawTarget);
                saveSafely();
                if (issuer != null) {
                    issuer.sendMessage("§aPortal §e" + entry.getName() + "§a now targets warp §e" + rawTarget + "§a.");
                }
                return true;
            }
        }

        if (issuer != null) {
            issuer.sendMessage("§cNo world or warp named §e" + rawTarget + "§c found.");
        }
        return false;
    }

    public boolean changePortalAreaFromSelection(Player p, PortalEntry entry) {
        if (entry == null) return false;

        Selection sel = selections.get(p.getUniqueId());
        if (sel == null || !sel.isComplete()) {
            p.sendMessage("§cYou must select an area with the Portal Wand first.");
            return false;
        }

        Orientation orientation = sel.getOrientation();
        if (orientation == null) {
            p.sendMessage("§cSelection must be a 2D area (flat plane). No volume or single-block lines.");
            return false;
        }

        String newWorldName = sel.getWorldName();
        World newWorld = Bukkit.getWorld(newWorldName);
        if (newWorld == null) {
            p.sendMessage("§cWorld '" + newWorldName + "' is not loaded.");
            return false;
        }

        // Clear old portal blocks (only portal blocks, leave other blocks alone)
        World oldWorld = Bukkit.getWorld(entry.getWorldName());
        if (oldWorld != null) {
            clearPortalBlocks(oldWorld,
                    entry.getMinX(), entry.getMaxX(),
                    entry.getMinY(), entry.getMaxY(),
                    entry.getMinZ(), entry.getMaxZ());
        }

        int minX = sel.getMinX();
        int maxX = sel.getMaxX();
        int minY = sel.getMinY();
        int maxY = sel.getMaxY();
        int minZ = sel.getMinZ();
        int maxZ = sel.getMaxZ();

        // Place new portal blocks
        fillPortalBlocks(newWorld, minX, maxX, minY, maxY, minZ, maxZ, orientation);

        entry.setWorldName(newWorldName);
        entry.setBounds(minX, maxX, minY, maxY, minZ, maxZ);
        saveSafely();

        p.sendMessage("§aPortal §e" + entry.getName() + "§a area updated.");
        return true;
    }

    public boolean deletePortal(PortalEntry entry) {
        if (entry == null) return false;

        World w = Bukkit.getWorld(entry.getWorldName());
        if (w != null) {
            clearPortalBlocks(w,
                    entry.getMinX(), entry.getMaxX(),
                    entry.getMinY(), entry.getMaxY(),
                    entry.getMinZ(), entry.getMaxZ());
        }

        portalsById.remove(entry.getId());
        portalsByName.remove(entry.getName().toLowerCase(Locale.ROOT));
        saveSafely();
        return true;
    }

    public void setPortalActive(PortalEntry entry, boolean active) {
        if (entry == null) return;
        entry.setActive(active);
        saveSafely();
    }

    // ----------------- Block filling helpers -----------------

    private void fillPortalBlocks(World world,
                                  int minX, int maxX,
                                  int minY, int maxY,
                                  int minZ, int maxZ,
                                  Orientation orientation) {
        switch (orientation) {
            case HORIZONTAL -> {
                int y = minY; // minY == maxY
                for (int x = minX; x <= maxX; x++) {
                    for (int z = minZ; z <= maxZ; z++) {
                        Block b = world.getBlockAt(x, y, z);
                        b.setType(Material.END_PORTAL, false);
                    }
                }
            }
            case VERTICAL_X -> {
                int x = minX; // minX == maxX, plane is Y–Z
                for (int y = minY; y <= maxY; y++) {
                    for (int z = minZ; z <= maxZ; z++) {
                        Block b = world.getBlockAt(x, y, z);
                        b.setType(Material.NETHER_PORTAL, false);
                        if (b.getBlockData() instanceof Orientable orientable) {
                            // Portal spans along Z, so axis = Z
                            orientable.setAxis(Axis.Z);
                            b.setBlockData(orientable, false);
                        }
                    }
                }
            }
            case VERTICAL_Z -> {
                int z = minZ; // minZ == maxZ, plane is X–Y
                for (int x = minX; x <= maxX; x++) {
                    for (int y = minY; y <= maxY; y++) {
                        Block b = world.getBlockAt(x, y, z);
                        b.setType(Material.NETHER_PORTAL, false);
                        if (b.getBlockData() instanceof Orientable orientable) {
                            // Portal spans along X, so axis = X
                            orientable.setAxis(Axis.X);
                            b.setBlockData(orientable, false);
                        }
                    }
                }
            }
        }
    }

    private void clearPortalBlocks(World w,
                                   int minX, int maxX,
                                   int minY, int maxY,
                                   int minZ, int maxZ) {
        for (int x = minX; x <= maxX; x++) {
            for (int y = minY; y <= maxY; y++) {
                for (int z = minZ; z <= maxZ; z++) {
                    Block b = w.getBlockAt(x, y, z);
                    Material t = b.getType();
                    if (t == Material.END_PORTAL || t == Material.NETHER_PORTAL) {
                        b.setType(Material.AIR, false);
                    }
                }
            }
        }
    }

    // ----------------- Event helpers -----------------

    private PortalEntry findPortalAtBlock(Block block) {
        if (block == null) return null;
        Location loc = block.getLocation();
        String wName = loc.getWorld().getName();
        int x = loc.getBlockX();
        int y = loc.getBlockY();
        int z = loc.getBlockZ();

        for (PortalEntry p : portalsById.values()) {
            if (p.containsBlock(wName, x, y, z)) {
                return p;
            }
        }
        return null;
    }

    private void teleportPlayerThroughPortal(Player player, PortalEntry portal) {
        if (!portal.isActive()) return;

        UUID id = player.getUniqueId();
        long now = System.currentTimeMillis();
        Long last = portalCooldown.get(id);
        if (last != null && now - last < 2000L) {
            // Less than 2 seconds since last portal teleport -> ignore
            return;
        }
        portalCooldown.put(id, now);

        switch (portal.getTargetType()) {
            case WORLD -> {
                WorldManager wm = plugin.getWorldManager();
                if (wm == null) {
                    player.sendMessage("§cWorld manager is not available.");
                    return;
                }
                WorldManager.WorldEntry wEntry = wm.getWorldByName(portal.getTargetName());
                if (wEntry == null) {
                    player.sendMessage("§cPortal target world §e" + portal.getTargetName() + "§c not found.");
                    return;
                }
                World world = wm.ensureWorldLoaded(wEntry);
                if (world == null) {
                    player.sendMessage("§cFailed to load portal target world.");
                    return;
                }
                Location loc = world.getSpawnLocation();
                doNiceTeleport(player, loc, "world " + wEntry.getName());
            }
            case WARP -> {
                WarpManager warpManager = plugin.getWarpManager();
                if (warpManager == null) {
                    player.sendMessage("§cWarp system is not available.");
                    return;
                }
                WarpManager.Warp warp = warpManager.getPublicWarp(portal.getTargetName());
                if (warp == null) {
                    // allow using a private warp with same name owned by the player
                    warp = warpManager.getPrivateWarp(player.getUniqueId(), portal.getTargetName());
                }
                if (warp == null) {
                    player.sendMessage("§cPortal target warp §e" + portal.getTargetName() + "§c not found.");
                    return;
                }
                Location loc = warp.getLocation();
                if (loc == null) {
                    player.sendMessage("§cWarp target world is not loaded.");
                    return;
                }
                doNiceTeleport(player, loc, "warp " + warp.getName());
            }
        }
    }

    private void doNiceTeleport(Player target, Location dest, String label) {
        // mimic your warp/world tp style: blindness + sound + delayed teleport
        target.addPotionEffect(new PotionEffect(
                PotionEffectType.BLINDNESS,
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
        plugin.getServer().getScheduler().runTaskLater(
                plugin,
                () -> {
                    target.teleport(dest);
                    target.sendMessage("§aTeleported via portal to §e" + label + "§a.");
                },
                3L
        );
    }

    // ----------------- Events -----------------

    @EventHandler(ignoreCancelled = true)
    public void onPlayerInteract(PlayerInteractEvent e) {
        if (e.getHand() != EquipmentSlot.HAND) return;

        Player p = e.getPlayer();
        ItemStack item = p.getInventory().getItemInMainHand();
        if (!isPortalWand(item)) return;

        Action action = e.getAction();
        Block clicked = e.getClickedBlock();

        if (isInRebuildMode(p)) {
            // REBUILD MODE
            if (action == Action.LEFT_CLICK_BLOCK && clicked != null) {
                Material t = clicked.getType();
                if (t != Material.END_PORTAL && t != Material.NETHER_PORTAL) {
                    p.sendMessage("§7That is not a portal block.");
                    return;
                }
                PortalEntry portal = findPortalAtBlock(clicked);
                if (portal == null) {
                    p.sendMessage("§7No portal registered for these blocks.");
                    return;
                }
                // Bind wand to this portal, break that block
                boundPortalId.put(p.getUniqueId(), portal.getId());
                clicked.setType(Material.AIR, false);
                p.sendMessage("§aBound wand to portal §e" + portal.getName() + "§a and removed one block.");
                e.setCancelled(true);
            } else if (action == Action.RIGHT_CLICK_BLOCK && clicked != null) {
                String portalId = boundPortalId.get(p.getUniqueId());
                if (portalId == null) {
                    p.sendMessage("§7No portal bound. Left-click a portal block first.");
                    return;
                }
                PortalEntry portal = portalsById.get(portalId);
                if (portal == null) {
                    p.sendMessage("§7Bound portal no longer exists.");
                    boundPortalId.remove(p.getUniqueId());
                    return;
                }

                Block placeBlock = clicked.getRelative(e.getBlockFace());
                World w = placeBlock.getWorld();
                String portalWorld = portal.getWorldName();
                if (!w.getName().equals(portalWorld)) {
                    p.sendMessage("§cThat block is not in the same world as the portal.");
                    return;
                }

                int x = placeBlock.getX();
                int y = placeBlock.getY();
                int z = placeBlock.getZ();

                Orientation ori = portal.getOrientation();
                // ensure new block stays in the same plane
                boolean okPlane = switch (ori) {
                    case HORIZONTAL -> (y == portal.getMinY());
                    case VERTICAL_X -> (x == portal.getMinX());
                    case VERTICAL_Z -> (z == portal.getMinZ());
                };
                if (!okPlane) {
                    p.sendMessage("§cThat block is not in the same portal plane.");
                    return;
                }

                // Extend portal bounds to include new block
                int minX = Math.min(portal.getMinX(), x);
                int maxX = Math.max(portal.getMaxX(), x);
                int minY = Math.min(portal.getMinY(), y);
                int maxY = Math.max(portal.getMaxY(), y);
                int minZ = Math.min(portal.getMinZ(), z);
                int maxZ = Math.max(portal.getMaxZ(), z);

                portal.setBounds(minX, maxX, minY, maxY, minZ, maxZ);

                // Set block type
                if (ori == Orientation.HORIZONTAL) {
                    placeBlock.setType(Material.END_PORTAL, false);
                } else {
                    placeBlock.setType(Material.NETHER_PORTAL, false);
                    if (placeBlock.getBlockData() instanceof Orientable orientable) {
                        orientable.setAxis(ori == Orientation.VERTICAL_X ? Axis.X : Axis.Z);
                        placeBlock.setBlockData(orientable, false);
                    }
                }

                saveSafely();
                p.sendMessage("§aAdded portal block to §e" + portal.getName() + "§a.");
                e.setCancelled(true);
            }
            return;
        }

        // NORMAL SELECTION MODE
        if (clicked == null) return;

        Selection sel = getOrCreateSelection(p);
        Location loc = clicked.getLocation();

        if (action == Action.LEFT_CLICK_BLOCK) {
            sel.setPos1(loc);
            p.sendMessage("§bPortal pos1 set at §e"
                    + loc.getBlockX() + " " + loc.getBlockY() + " " + loc.getBlockZ()
                    + "§7 in world §e" + loc.getWorld().getName() + "§7.");
            e.setCancelled(true);
        } else if (action == Action.RIGHT_CLICK_BLOCK) {
            sel.setPos2(loc);
            p.sendMessage("§bPortal pos2 set at §e"
                    + loc.getBlockX() + " " + loc.getBlockY() + " " + loc.getBlockZ()
                    + "§7 in world §e" + loc.getWorld().getName() + "§7.");

            Orientation ori = sel.getOrientation();
            if (ori == null) {
                p.sendMessage("§cWarning: selection is not a proper 2D plane (volume or line).");
            } else {
                switch (ori) {
                    case HORIZONTAL -> p.sendMessage("§7Selection is §aHORIZONTAL§7 (END_PORTAL).");
                    case VERTICAL_X, VERTICAL_Z -> p.sendMessage("§7Selection is §aVERTICAL§7 (NETHER_PORTAL).");
                }
            }
            e.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlayerPortal(PlayerPortalEvent e) {
        Player p = e.getPlayer();
        Location from = e.getFrom();
        if (from == null) return;

        Block block = from.getBlock();
        Material t = block.getType();
        if (t != Material.END_PORTAL && t != Material.NETHER_PORTAL) {
            // Not in a portal block -> let vanilla handle
            return;
        }

        // Check if this portal block is part of one of *our* registered portals
        PortalEntry portal = findPortalAtBlock(block);
        if (portal == null) {
            // It’s a normal vanilla portal → do not touch
            return;
        }

        // This is one of OUR portals:
        //  - cancel vanilla teleport to End/Nether
        //  - plugin handles teleport via PlayerMoveEvent / teleportPlayerThroughPortal
        e.setCancelled(true);
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlayerMove(PlayerMoveEvent e) {
        Location to = e.getTo();
        if (to == null) return;

        Block block = to.getBlock();
        Material t = block.getType();
        if (t != Material.END_PORTAL && t != Material.NETHER_PORTAL) return;

        PortalEntry portal = findPortalAtBlock(block);
        if (portal == null) return;

        teleportPlayerThroughPortal(e.getPlayer(), portal);
    }
}

