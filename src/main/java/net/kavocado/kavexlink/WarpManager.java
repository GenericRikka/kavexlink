package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.World;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.inventory.ItemStack;

import java.io.File;
import java.util.*;

public class WarpManager {

    public static final String PUBLIC_OWNER = "PUBLIC";
    public static final String DEFAULT_CATEGORY = "General";

    private final KavexLinkPlugin plugin;
    private final File file;

    private final Map<String, Warp> warpsById = new HashMap<>();
    private final Map<String, Warp> warpsByKey = new HashMap<>();

    public WarpManager(KavexLinkPlugin plugin) {
        this.plugin = plugin;
        this.file = new File(plugin.getDataFolder(), "warps.yml");
        load();
    }

    private String makeKey(String ownerId, String name) {
        return ownerId.toLowerCase() + "::" + name.toLowerCase();
    }

    private static String normalizeCategory(String category) {
        if (category == null) return DEFAULT_CATEGORY;
        String trimmed = category.trim();
        return trimmed.isEmpty() ? DEFAULT_CATEGORY : trimmed;
    }

    public void load() {
        warpsById.clear();
        warpsByKey.clear();

        if (!file.exists()) {
            return;
        }

        YamlConfiguration config = YamlConfiguration.loadConfiguration(file);
        ConfigurationSection sec = config.getConfigurationSection("warps");
        if (sec == null) {
            return;
        }

        for (String id : sec.getKeys(false)) {
            String base = "warps." + id + ".";

            String name = config.getString(base + "name");
            String owner = config.getString(base + "owner", PUBLIC_OWNER);
            boolean isPublic = config.getBoolean(base + "public", true);
            String world = config.getString(base + "world");

            double x = config.getDouble(base + "x");
            double y = config.getDouble(base + "y");
            double z = config.getDouble(base + "z");
            float yaw = (float) config.getDouble(base + "yaw", 0.0D);
            float pitch = (float) config.getDouble(base + "pitch", 0.0D);

            // Icons used to be stored as a bare material name (icon: DIRT). Custom
            // heads/banners captured via "hand" are stored as a full serialized
            // ItemStack instead, which YamlConfiguration deserializes for us
            // automatically - so a plain Object read here is either a String
            // (legacy) or already an ItemStack (new format).
            Object rawIcon = config.get(base + "icon");
            ItemStack icon;
            if (rawIcon instanceof ItemStack) {
                icon = (ItemStack) rawIcon;
            } else {
                String iconName = rawIcon instanceof String ? (String) rawIcon : "DIRT";
                Material iconMat = Material.matchMaterial(iconName);
                if (iconMat == null) iconMat = Material.DIRT;
                icon = new ItemStack(iconMat);
            }

            int order = config.getInt(base + "order", 0);

            // Warps saved before category support existed won't have this key -
            // normalizeCategory() falls back to DEFAULT_CATEGORY for those.
            String category = normalizeCategory(config.getString(base + "category"));

            if (name == null || world == null) {
                continue;
            }

            Warp w = new Warp(
                    id, name, owner, isPublic,
                    world, x, y, z, yaw, pitch,
                    icon, order, category
            );
            warpsById.put(id, w);
            warpsByKey.put(makeKey(owner, name), w);
        }

        plugin.getLogger().info("Loaded " + warpsById.size() + " warps.");
    }

    public void save() {
        YamlConfiguration out = new YamlConfiguration();

        for (Warp w : warpsById.values()) {
            String base = "warps." + w.getId() + ".";
            out.set(base + "name", w.getName());
            out.set(base + "owner", w.getOwner());
            out.set(base + "public", w.isPublicWarp());
            out.set(base + "world", w.getWorld());
            out.set(base + "x", w.getX());
            out.set(base + "y", w.getY());
            out.set(base + "z", w.getZ());
            out.set(base + "yaw", w.getYaw());
            out.set(base + "pitch", w.getPitch());
            out.set(base + "icon", w.getIcon());
            out.set(base + "order", w.getOrder());
            out.set(base + "category", w.getCategory());
        }

        try {
            out.save(file);
        } catch (Exception e) {
            plugin.getLogger().severe("Failed to save warps.yml: " + e);
        }
    }

    private int getNextPublicOrder() {
        int max = 0;
        for (Warp w : warpsById.values()) {
            if (w.isPublicWarp() && w.getOrder() > max) {
                max = w.getOrder();
            }
        }
        return max + 1;
    }

    public Warp createWarp(UUID ownerUuid, boolean publicWarp, String name, Location loc, ItemStack icon, String category) {
        String ownerStr = publicWarp ? PUBLIC_OWNER : ownerUuid.toString();
        String key = makeKey(ownerStr, name);
        String normalizedCategory = normalizeCategory(category);

        Warp existing = warpsByKey.get(key);
        if (existing != null) {
            updateWarpLocation(existing, loc);
            updateWarpIcon(existing, icon);
            updateWarpCategory(existing, normalizedCategory);
            return existing;
        }

        String id = UUID.randomUUID().toString().replace("-", "");
        int order = 0;
        if (publicWarp) {
            order = getNextPublicOrder();
        }

        Warp w = new Warp(
                id,
                name,
                ownerStr,
                publicWarp,
                loc.getWorld().getName(),
                loc.getX(), loc.getY(), loc.getZ(),
                loc.getYaw(), loc.getPitch(),
                icon,
                order,
                normalizedCategory
        );
        warpsById.put(id, w);
        warpsByKey.put(key, w);
        return w;
    }

    public Warp getPublicWarp(String name) {
        return warpsByKey.get(makeKey(PUBLIC_OWNER, name));
    }

    public Warp getPrivateWarp(UUID owner, String name) {
        return warpsByKey.get(makeKey(owner.toString(), name));
    }

    /**
     * Orders categories per the config's `category-order` list (case-insensitive,
     * trimmed); any category not listed falls after all listed ones, sorted
     * alphabetically. With an empty/missing list, everything just sorts
     * alphabetically. Built fresh each time so config reloads take effect without
     * needing a restart.
     */
    private Comparator<String> categoryComparator() {
        List<String> configured = plugin.getConfig().getStringList("category-order");
        Map<String, Integer> rank = new HashMap<>();
        int i = 0;
        for (String c : configured) {
            if (c == null) continue;
            String key = c.trim().toLowerCase(Locale.ROOT);
            if (key.isEmpty()) continue;
            rank.putIfAbsent(key, i++);
        }

        return (a, b) -> {
            Integer ra = rank.get(a.toLowerCase(Locale.ROOT));
            Integer rb = rank.get(b.toLowerCase(Locale.ROOT));
            if (ra != null && rb != null) return Integer.compare(ra, rb);
            if (ra != null) return -1; // a is listed, b isn't -> a comes first
            if (rb != null) return 1;  // b is listed, a isn't -> b comes first
            return a.compareToIgnoreCase(b); // neither listed -> alphabetical
        };
    }

    private Comparator<Warp> categoryOrderNameComparator() {
        return Comparator.comparing(Warp::getCategory, categoryComparator())
                .thenComparingInt(Warp::getOrder)
                .thenComparing(Warp::getName, String.CASE_INSENSITIVE_ORDER);
    }

    /**
     * Public warps sorted by category (per config's category-order, or
     * alphabetically), then by order within that category, then by name. Warps
     * sharing a category always end up contiguous in this list, which is what lets
     * the GUI chunk them into category-exclusive pages without any extra bookkeeping.
     */
    public List<Warp> getPublicWarps() {
        List<Warp> list = new ArrayList<>();
        for (Warp w : warpsById.values()) {
            if (w.isPublicWarp()) list.add(w);
        }
        list.sort(categoryOrderNameComparator());
        return list;
    }

    public List<Warp> getPrivateWarps(UUID owner) {
        String ownerStr = owner.toString();
        List<Warp> list = new ArrayList<>();
        for (Warp w : warpsById.values()) {
            if (!w.isPublicWarp() && ownerStr.equalsIgnoreCase(w.getOwner())) {
                list.add(w);
            }
        }
        list.sort(categoryOrderNameComparator());
        return list;
    }

    /**
     * Distinct category names currently in use, across both public and private warps -
     * handy for tab-completing /setwarp and /warp edit category.
     */
    public List<String> getKnownCategories() {
        TreeSet<String> categories = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (Warp w : warpsById.values()) {
            categories.add(w.getCategory());
        }
        return new ArrayList<>(categories);
    }

    public Warp getWarpById(String id) {
        return warpsById.get(id);
    }

    public void deleteWarp(Warp warp) {
        warpsById.remove(warp.getId());
        warpsByKey.remove(makeKey(warp.getOwner(), warp.getName()));
    }

    public void renameWarp(Warp warp, String newName) {
        warpsByKey.remove(makeKey(warp.getOwner(), warp.getName()));
        warp.setName(newName);
        warpsByKey.put(makeKey(warp.getOwner(), newName), warp);
    }

    public void updateWarpLocation(Warp warp, Location loc) {
        warp.setWorld(loc.getWorld().getName());
        warp.setX(loc.getX());
        warp.setY(loc.getY());
        warp.setZ(loc.getZ());
        warp.setYaw(loc.getYaw());
        warp.setPitch(loc.getPitch());
    }

    public void updateWarpIcon(Warp warp, ItemStack icon) {
        warp.setIcon(icon);
    }

    public void updateWarpOrder(Warp warp, int order) {
        warp.setOrder(order);
    }

    public void updateWarpCategory(Warp warp, String category) {
        warp.setCategory(normalizeCategory(category));
    }

    public Location toLocation(Warp warp) {
        World world = plugin.getServer().getWorld(warp.getWorld());
        if (world == null) return null;
        return new Location(world, warp.getX(), warp.getY(), warp.getZ(), warp.getYaw(), warp.getPitch());
    }

    public static class Warp {
        private final String id;
        private String name;
        private final String owner;
        private final boolean publicWarp;
        private String world;
        private double x, y, z;
        private float yaw, pitch;
        private ItemStack icon;
        private int order;
        private String category;

        public Warp(String id,
                    String name,
                    String owner,
                    boolean publicWarp,
                    String world,
                    double x,
                    double y,
                    double z,
                    float yaw,
                    float pitch,
                    ItemStack icon,
                    int order,
                    String category) {
            this.id = id;
            this.name = name;
            this.owner = owner;
            this.publicWarp = publicWarp;
            this.world = world;
            this.x = x;
            this.y = y;
            this.z = z;
            this.yaw = yaw;
            this.pitch = pitch;
            this.icon = icon;
            this.order = order;
            this.category = normalizeCategory(category);
        }

        public String getId() { return id; }
        public String getName() { return name; }
        public String getOwner() { return owner; }
        public boolean isPublicWarp() { return publicWarp; }
        public String getWorld() { return world; }
        public double getX() { return x; }
        public double getY() { return y; }
        public double getZ() { return z; }
        public float getYaw() { return yaw; }
        public float getPitch() { return pitch; }
        public ItemStack getIcon() { return icon; }
        public int getOrder() { return order; }
        public String getCategory() { return category; }

        public Location getLocation() {
            World w = Bukkit.getWorld(this.world);
            if (w == null) {
                return null;
            }
            return new Location(w, x, y, z, yaw, pitch);
        }

        private void setName(String name) { this.name = name; }
        private void setWorld(String world) { this.world = world; }
        private void setX(double x) { this.x = x; }
        private void setY(double y) { this.y = y; }
        private void setZ(double z) { this.z = z; }
        private void setYaw(float yaw) { this.yaw = yaw; }
        private void setPitch(float pitch) { this.pitch = pitch; }
        private void setIcon(ItemStack icon) { this.icon = icon; }
        private void setOrder(int order) { this.order = order; }
        private void setCategory(String category) { this.category = category; }
    }
}
