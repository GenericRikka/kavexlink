package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.World;
import org.bukkit.Particle;
import org.bukkit.block.Block;
import org.bukkit.block.data.BlockData;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.block.Action;
import org.bukkit.event.block.BlockFromToEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.inventory.EquipmentSlot;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitTask;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Static Water Portal system optimized for Paper 26.2.
 * Uses stationary liquid boundaries paired with an asynchronous ambient particle loop.
 */
public class PortalManager implements Listener {

    public enum TargetType {
        WORLD,
        WARP
    }

    public enum Orientation {
        HORIZONTAL,
        VERTICAL_X,
        VERTICAL_Z
    }

    public static class PortalEntry {
        private final String id;
        private String name;
        private String worldName;
        private int minX, maxX, minY, maxY, minZ, maxZ;
        private TargetType targetType;
        private String targetName;
        private boolean active;
        
        // Configurable Particle settings
        private String particleType;
        private int particleStrength;

        public PortalEntry(String id, String name, String worldName,
                           int minX, int maxX, int minY, int maxY, int minZ, int maxZ,
                           TargetType targetType, String targetName, boolean active,
                           String particleType, int particleStrength) {
            this.id = id;
            this.name = name;
            this.worldName = worldName;
            this.minX = minX; this.maxX = maxX;
            this.minY = minY; this.maxY = maxY;
            this.minZ = minZ; this.maxZ = maxZ;
            this.targetType = targetType;
            this.targetName = targetName;
            this.active = active;
            this.particleType = particleType;
            this.particleStrength = particleStrength;
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public String getWorldName() { return worldName; }
        public int getMinX() { return minX; }
        public int getMaxX() { return maxX; }
        public int getMinY() { return minY; }
        public int getMaxY() { return maxY; }
        public int getMinZ() { return minZ; }
        public int getMaxZ() { return maxZ; }
        public TargetType getTargetType() { return targetType; }
        public String getTargetName() { return targetName; }
        public boolean isActive() { return active; }
        public String getParticleType() { return particleType; }
        public int getParticleStrength() { return particleStrength; }

        public void setName(String name) { this.name = name; }
        public void setWorldName(String worldName) { this.worldName = worldName; }
        public void setParticleType(String type) { this.particleType = type; }
        public void setParticleStrength(int strength) { this.particleStrength = strength; }
        
        public void setBounds(int minX, int maxX, int minY, int maxY, int minZ, int maxZ) {
            this.minX = minX; this.maxX = maxX;
            this.minY = minY; this.maxY = maxY;
            this.minZ = minZ; this.maxZ = maxZ;
        }
        public void setTarget(TargetType type, String targetName) {
            this.targetType = type; this.targetName = targetName;
        }
        public void setActive(boolean active) { this.active = active; }

        public Orientation getOrientation() {
            int dy = maxY - minY;
            int dx = maxX - minX;
            if (dy == 0) return Orientation.HORIZONTAL;
            if (dx == 0) return Orientation.VERTICAL_X;
            return Orientation.VERTICAL_Z;
        }

        public boolean containsBlock(String worldName, int x, int y, int z) {
            if (!Objects.equals(this.worldName, worldName)) return false;
            return x >= minX && x <= maxX && y >= minY && y <= maxY && z >= minZ && z <= maxZ;
        }
    }

    public static class Selection {
        String worldName;
        int x1, y1, z1;
        int x2, y2, z2;
        boolean hasPos1;
        boolean hasPos2;

        public void setPos1(Location loc) {
            this.worldName = loc.getWorld().getName();
            this.x1 = loc.getBlockX(); this.y1 = loc.getBlockY(); this.z1 = loc.getBlockZ();
            this.hasPos1 = true;
        }
        public void setPos2(Location loc) {
            this.worldName = loc.getWorld().getName();
            this.x2 = loc.getBlockX(); this.y2 = loc.getBlockY(); this.z2 = loc.getBlockZ();
            this.hasPos2 = true;
        }
        public boolean isComplete() { return hasPos1 && hasPos2 && worldName != null; }
        public String getWorldName() { return worldName; }
        public int getMinX() { return Math.min(x1, x2); }
        public int getMaxX() { return Math.max(x1, x2); }
        public int getMinY() { return Math.min(y1, y2); }
        public int getMaxY() { return Math.max(y1, y2); }
        public int getMinZ() { return Math.min(z1, z2); }
        public int getMaxZ() { return Math.max(z1, z2); }

        public Orientation getOrientation() {
            int dx = Math.abs(x1 - x2);
            int dy = Math.abs(y1 - y2);
            int dz = Math.abs(z1 - z2);
            boolean flatX = (dx == 0);
            boolean flatY = (dy == 0);
            boolean flatZ = (dz == 0);
            if ((flatX ? 1 : 0) + (flatY ? 1 : 0) + (flatZ ? 1 : 0) != 1) return null;

            if (flatY) {
                if (dx == 0 && dz == 0) return null;
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
    private BukkitTask particleTask;

    public PortalManager(KavexLinkPlugin plugin) {
        this.plugin = plugin;
        this.file = new File(plugin.getDataFolder(), "portals.yml");
        load();
        startParticleTicker();
    }

    public void stopParticleTicker() {
        if (particleTask != null) {
            particleTask.cancel();
        }
    }

    private void startParticleTicker() {
        particleTask = Bukkit.getScheduler().runTaskTimer(plugin, () -> {
            for (PortalEntry portal : portalsById.values()) {
                if (!portal.isActive()) continue;

                World world = Bukkit.getWorld(portal.getWorldName());
                if (world == null) continue;

                Particle particle = Particle.PORTAL;
                try {
                    particle = Particle.valueOf(portal.getParticleType());
                } catch (Exception ignored) {}

                int strength = portal.getParticleStrength();
                if (strength <= 0) continue;

                Random rand = new Random();
                for (int i = 0; i < strength; i++) {
                    double x = portal.getMinX() + rand.nextDouble() * (portal.getMaxX() - portal.getMinX() + 1);
                    double y = portal.getMinY() + rand.nextDouble() * (portal.getMaxY() - portal.getMinY() + 1);
                    double z = portal.getMinZ() + rand.nextDouble() * (portal.getMaxZ() - portal.getMinZ() + 1);
                    
                    world.spawnParticle(particle, x, y, z, 1, 0.0, 0.0, 0.0, 0.0);
                }
            }
        }, 0L, 10L); // Execute every 0.5s (10 ticks)
    }

    private void load() {
        portalsById.clear();
        portalsByName.clear();
        if (!file.exists()) return;

        YamlConfiguration cfg = YamlConfiguration.loadConfiguration(file);
        ConfigurationSection root = cfg.getConfigurationSection("portals");
        if (root == null) return;

        for (String id : root.getKeys(false)) {
            ConfigurationSection sec = root.getConfigurationSection(id);
            if (sec == null) continue;

            String name = sec.getString("name");
            String worldName = sec.getString("world");
            if (name == null || worldName == null) continue;

            int minX = sec.getInt("minX"); int maxX = sec.getInt("maxX");
            int minY = sec.getInt("minY"); int maxY = sec.getInt("maxY");
            int minZ = sec.getInt("minZ"); int maxZ = sec.getInt("maxZ");

            String typeStr = sec.getString("target_type", "WORLD").toUpperCase(Locale.ROOT);
            TargetType targetType = TargetType.WORLD;
            try { targetType = TargetType.valueOf(typeStr); } catch (Exception ignored) {}
            String targetName = sec.getString("target_name");
            boolean active = sec.getBoolean("active", true);
            
            String pType = sec.getString("particle_type", "PORTAL").toUpperCase(Locale.ROOT);
            int pStrength = sec.getInt("particle_strength", 2);

            PortalEntry entry = new PortalEntry(id, name, worldName, minX, maxX, minY, maxY, minZ, maxZ, targetType, targetName, active, pType, pStrength);
            portalsById.put(id, entry);
            portalsByName.put(name.toLowerCase(Locale.ROOT), entry);
        }
        plugin.getLogger().info("Loaded " + portalsById.size() + " config entries.");
    }

    public void save() throws IOException {
        YamlConfiguration cfg = new YamlConfiguration();
        ConfigurationSection root = cfg.createSection("portals");
        for (PortalEntry p : portalsById.values()) {
            ConfigurationSection sec = root.createSection(p.getId());
            sec.set("name", p.getName()); sec.set("world", p.getWorldName());
            sec.set("minX", p.getMinX()); sec.set("maxX", p.getMaxX());
            sec.set("minY", p.getMinY()); sec.set("maxY", p.getMaxY());
            sec.set("minZ", p.getMinZ()); sec.set("maxZ", p.getMaxZ());
            sec.set("target_type", p.getTargetType().name());
            sec.set("target_name", p.getTargetName());
            sec.set("active", p.isActive());
            sec.set("particle_type", p.getParticleType());
            sec.set("particle_strength", p.getParticleStrength());
        }
        cfg.save(file);
    }

    public void saveSafely() {
        try { save(); } catch (IOException e) { plugin.getLogger().severe("Failed to save portals.yml: " + e); }
    }

    private Selection getOrCreateSelection(Player p) { return selections.computeIfAbsent(p.getUniqueId(), k -> new Selection()); }
    public void clearSelection(Player p) { selections.remove(p.getUniqueId()); }

    public void giveWand(Player p) {
        ItemStack wand = new ItemStack(Material.END_ROD, 1);
        ItemMeta meta = wand.getItemMeta();
        if (meta != null) {
            meta.setDisplayName(ChatColor.LIGHT_PURPLE + "Portal Wand");
            meta.setLore(Arrays.asList(
                ChatColor.GRAY + "Left-click block: set position 1",
                ChatColor.GRAY + "Right-click block: set position 2",
                ChatColor.DARK_AQUA + "In rebuild mode:",
                ChatColor.GRAY + "  Left-click portal: bind/break block",
                ChatColor.GRAY + "  Right-click: place static water block"
            ));
            wand.setItemMeta(meta);
        }
        p.getInventory().addItem(wand);
        p.sendMessage("§aYou received a §dPortal Wand§a.");
    }

    private boolean isPortalWand(ItemStack item) {
        if (item == null || item.getType() != Material.END_ROD) return false;
        ItemMeta meta = item.getItemMeta();
        if (meta == null || !meta.hasDisplayName()) return false;
        return ChatColor.stripColor(meta.getDisplayName()).equalsIgnoreCase("Portal Wand");
    }

    public void enableRebuildMode(Player p) {
        rebuildModePlayers.add(p.getUniqueId()); boundPortalId.remove(p.getUniqueId());
        p.sendMessage("§bPortal wand is now in rebuild mode. Use §e/exit_mode §bto exit.");
    }

    public void disableRebuildMode(Player p) {
        rebuildModePlayers.remove(p.getUniqueId()); boundPortalId.remove(p.getUniqueId());
        p.sendMessage("§7Portal rebuild mode disabled.");
    }

    public boolean isInRebuildMode(Player p) { return rebuildModePlayers.contains(p.getUniqueId()); }
    public List<PortalEntry> getAllPortalsSorted() {
        List<PortalEntry> list = new ArrayList<>(portalsById.values());
        list.sort(Comparator.comparing(PortalEntry::getName, String.CASE_INSENSITIVE_ORDER));
        return list;
    }
    public PortalEntry getPortalByName(String name) { return portalsByName.get(name.toLowerCase(Locale.ROOT)); }

    public PortalEntry createPortalFromSelection(Player p, String portalName, String rawTarget) {
        Selection sel = selections.get(p.getUniqueId());
        if (sel == null || !sel.isComplete()) {
            p.sendMessage("§cYou must select an area with the Portal Wand first."); return null;
        }
        Orientation orientation = sel.getOrientation();
        if (orientation == null) {
            p.sendMessage("§cSelection must be a 2D area (flat plane)."); return null;
        }

        World bukkitWorld = Bukkit.getWorld(sel.getWorldName());
        if (bukkitWorld == null) { p.sendMessage("§cWorld is not loaded."); return null; }

        TargetType targetType;
        WorldManager wm = plugin.getWorldManager();
        WarpManager warpManager = plugin.getWarpManager();

        if (wm != null && wm.getWorldByName(rawTarget) != null) {
            targetType = TargetType.WORLD;
        } else if (warpManager != null && (warpManager.getPublicWarp(rawTarget) != null || warpManager.getPrivateWarp(p.getUniqueId(), rawTarget) != null)) {
            targetType = TargetType.WARP;
        } else {
            p.sendMessage("§cNo world or warp named §e" + rawTarget + "§c found."); return null;
        }

        int minX = sel.getMinX(); int maxX = sel.getMaxX();
        int minY = sel.getMinY(); int maxY = sel.getMaxY();
        int minZ = sel.getMinZ(); int maxZ = sel.getMaxZ();

        fillPortalBlocks(bukkitWorld, minX, maxX, minY, maxY, minZ, maxZ);

        String id = UUID.randomUUID().toString().replace("-", "");
        PortalEntry entry = new PortalEntry(id, portalName, sel.getWorldName(), minX, maxX, minY, maxY, minZ, maxZ, targetType, rawTarget, true, "PORTAL", 2);
        portalsById.put(id, entry);
        portalsByName.put(portalName.toLowerCase(Locale.ROOT), entry);
        saveSafely();

        p.sendMessage("§aCreated water portal §e" + portalName + "§a targeting " + targetType.name().toLowerCase() + " §e" + rawTarget + "§a.");
        return entry;
    }

    public boolean updatePortalTarget(Player issuer, PortalEntry entry, String rawTarget) {
        if (entry == null) return false;
        WorldManager wm = plugin.getWorldManager();
        WarpManager warpManager = plugin.getWarpManager();

        if (wm != null && wm.getWorldByName(rawTarget) != null) {
            entry.setTarget(TargetType.WORLD, rawTarget);
        } else if (warpManager != null && (warpManager.getPublicWarp(rawTarget) != null || warpManager.getPrivateWarp(issuer.getUniqueId(), rawTarget) != null)) {
            entry.setTarget(TargetType.WARP, rawTarget);
        } else {
            if (issuer != null) issuer.sendMessage("§cNo world or warp named §e" + rawTarget + "§c found.");
            return false;
        }
        saveSafely();
        if (issuer != null) issuer.sendMessage("§aPortal §e" + entry.getName() + "§a now targets §e" + rawTarget + "§a.");
        return true;
    }

    public boolean changePortalAreaFromSelection(Player p, PortalEntry entry) {
        if (entry == null) return false;
        Selection sel = selections.get(p.getUniqueId());
        if (sel == null || !sel.isComplete() || sel.getOrientation() == null) {
            p.sendMessage("§cInvalid selection plane."); return false;
        }

        World newWorld = Bukkit.getWorld(sel.getWorldName());
        World oldWorld = Bukkit.getWorld(entry.getWorldName());
        if (newWorld == null) return false;

        if (oldWorld != null) {
            clearPortalBlocks(oldWorld, entry.getMinX(), entry.getMaxX(), entry.getMinY(), entry.getMaxY(), entry.getMinZ(), entry.getMaxZ());
        }

        int minX = sel.getMinX(); int maxX = sel.getMaxX();
        int minY = sel.getMinY(); int maxY = sel.getMaxY();
        int minZ = sel.getMinZ(); int maxZ = sel.getMaxZ();

        fillPortalBlocks(newWorld, minX, maxX, minY, maxY, minZ, maxZ);
        entry.setWorldName(sel.getWorldName());
        entry.setBounds(minX, maxX, minY, maxY, minZ, maxZ);
        saveSafely();

        p.sendMessage("§aPortal §e" + entry.getName() + "§a layout migrated to stationary water.");
        return true;
    }

    public boolean deletePortal(PortalEntry entry) {
        if (entry == null) return false;
        World w = Bukkit.getWorld(entry.getWorldName());
        if (w != null) {
            clearPortalBlocks(w, entry.getMinX(), entry.getMaxX(), entry.getMinY(), entry.getMaxY(), entry.getMinZ(), entry.getMaxZ());
        }
        portalsById.remove(entry.getId());
        portalsByName.remove(entry.getName().toLowerCase(Locale.ROOT));
        saveSafely();
        return true;
    }

    public void setPortalParticle(PortalEntry entry, String particleType, int strength) {
        if (entry != null) {
            entry.setParticleType(particleType);
            entry.setParticleStrength(strength);
            saveSafely(); // This will call PortalManager's own saveSafely() cleanly!
        }
    }

    public void setPortalActive(PortalEntry entry, boolean active) {
        if (entry != null) { entry.setActive(active); saveSafely(); }
    }

    // ----------------- Static Water Handling Helpers -----------------

    private void fillPortalBlocks(World world, int minX, int maxX, int minY, int maxY, int minZ, int maxZ) {
        for (int x = minX; x <= maxX; x++) {
            for (int y = minY; y <= maxY; y++) {
                for (int z = minZ; z <= maxZ; z++) {
                    world.getBlockAt(x, y, z).setType(Material.WATER, false);
                }
            }
        }
    }

    private void clearPortalBlocks(World w, int minX, int maxX, int minY, int maxY, int minZ, int maxZ) {
        for (int x = minX; x <= maxX; x++) {
            for (int y = minY; y <= maxY; y++) {
                for (int z = minZ; z <= maxZ; z++) {
                    Block b = w.getBlockAt(x, y, z);
                    if (b.getType() == Material.WATER) b.setType(Material.AIR, false);
                }
            }
        }
    }

    // CRITICAL: Forces Paper's block engine to deny physics ticks to water blocks inside portal dimensions
    @EventHandler(priority = org.bukkit.event.EventPriority.HIGHEST, ignoreCancelled = true)
    public void onWaterFlow(BlockFromToEvent e) {
        Block source = e.getBlock();
        if (source.getType() == Material.WATER) {
            Location loc = source.getLocation();
            for (PortalEntry portal : portalsById.values()) {
                if (portal.containsBlock(loc.getWorld().getName(), loc.getBlockX(), loc.getBlockY(), loc.getBlockZ())) {
                    e.setCancelled(true); // Freeze liquid movement physics updates entirely
                    return;
                }
            }
        }
    }

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
        if (last != null && now - last < 2000L) return;
        portalCooldown.put(id, now);

        if (portal.getTargetType() == TargetType.WORLD) {
            WorldManager wm = plugin.getWorldManager();
            if (wm == null) return;
            WorldManager.WorldEntry wEntry = wm.getWorldByName(portal.getTargetName());
            if (wEntry == null) return;
            World world = wm.ensureWorldLoaded(wEntry);
            if (world == null) return;
            doNiceTeleport(player, world.getSpawnLocation(), "world " + wEntry.getName());
        } else {
            WarpManager warpManager = plugin.getWarpManager();
            if (warpManager == null) return;
            WarpManager.Warp warp = warpManager.getPublicWarp(portal.getTargetName());
            if (warp == null) warp = warpManager.getPrivateWarp(player.getUniqueId(), portal.getTargetName());
            if (warp == null || warp.getLocation() == null) return;
            doNiceTeleport(player, warp.getLocation(), "warp " + warp.getName());
        }
    }

    private void doNiceTeleport(Player target, Location dest, String label) {
        target.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, 25, 1, false, false, false));
        target.playSound(target.getLocation(), org.bukkit.Sound.ENTITY_ENDERMAN_TELEPORT, 1.0f, 1.0f);
        plugin.getServer().getScheduler().runTaskLater(plugin, () -> {
            target.teleport(dest);
            target.sendMessage("§aTeleported via portal to §e" + label + "§a.");
        }, 3L);
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlayerInteract(PlayerInteractEvent e) {
        if (e.getHand() != EquipmentSlot.HAND) return;
        Player p = e.getPlayer();
        ItemStack item = p.getInventory().getItemInMainHand();
        if (!isPortalWand(item)) return;

        Action action = e.getAction();
        Block clicked = e.getClickedBlock();

        if (isInRebuildMode(p)) {
            if (action == Action.LEFT_CLICK_BLOCK && clicked != null) {
                if (clicked.getType() != Material.WATER) return;
                PortalEntry portal = findPortalAtBlock(clicked);
                if (portal == null) return;

                boundPortalId.put(p.getUniqueId(), portal.getId());
                clicked.setType(Material.AIR, false);
                p.sendMessage("§aBound wand to portal §e" + portal.getName() + "§a and removed block.");
                e.setCancelled(true);
            } else if (action == Action.RIGHT_CLICK_BLOCK && clicked != null) {
                String portalId = boundPortalId.get(p.getUniqueId());
                PortalEntry portal = portalsById.get(portalId);
                if (portal == null) return;

                Block placeBlock = clicked.getRelative(e.getBlockFace());
                if (!placeBlock.getWorld().getName().equals(portal.getWorldName())) return;

                int x = placeBlock.getX(); int y = placeBlock.getY(); int z = placeBlock.getZ();
                portal.setBounds(Math.min(portal.getMinX(), x), Math.max(portal.getMaxX(), x),
                                 Math.min(portal.getMinY(), y), Math.max(portal.getMaxY(), y),
                                 Math.min(portal.getMinZ(), z), Math.max(portal.getMaxZ(), z));

                placeBlock.setType(Material.WATER, false);
                saveSafely();
                p.sendMessage("§aAdded water boundary block to §e" + portal.getName() + "§a.");
                e.setCancelled(true);
            }
            return;
        }

        if (clicked == null) return;
        Selection sel = getOrCreateSelection(p);
        if (action == Action.LEFT_CLICK_BLOCK) {
            sel.setPos1(clicked.getLocation());
            p.sendMessage("§bPortal pos1 set at §e" + clicked.getX() + " " + clicked.getY() + " " + clicked.getZ() + "§7.");
            e.setCancelled(true);
        } else if (action == Action.RIGHT_CLICK_BLOCK) {
            sel.setPos2(clicked.getLocation());
            p.sendMessage("§bPortal pos2 set at §e" + clicked.getX() + " " + clicked.getY() + " " + clicked.getZ() + "§7.");
            e.setCancelled(true);
        }
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlayerMove(PlayerMoveEvent e) {
        Location to = e.getTo();
        if (to == null) return;

        Block block = to.getBlock();
        if (block.getType() != Material.WATER) return;

        PortalEntry portal = findPortalAtBlock(block);
        if (portal != null) {
            teleportPlayerThroughPortal(e.getPlayer(), portal);
        }
    }
}
