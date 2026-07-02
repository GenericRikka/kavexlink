package net.kavocado.kavexwarp;

import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.NamespacedKey;
import org.bukkit.Sound;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerTeleportEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class KavexWarpPlugin extends JavaPlugin implements TabCompleter, Listener {

    private Path dataDir;
    private WarpManager warpManager;
    private BackManager backManager;
    private NamespacedKey warpKey;
    private NamespacedKey pageActionKey;

    public WarpManager getWarpManager() {
        return warpManager;
    }

    public BackManager getBackManager() {
        return backManager;
    }

    public NamespacedKey getWarpKey() {
        return warpKey;
    }

    public NamespacedKey getPageActionKey() {
        return pageActionKey;
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

    /**
     * Display name used in the warps GUI title, e.g. "MyServer Warps".
     * Falls back to the server's MOTD, then to "Minecraft", if server-name isn't configured.
     */
    public String getServerDisplayName() {
        String configured = getConfig().getString("server-name", "");
        if (configured != null && !configured.trim().isEmpty()) {
            return configured.trim();
        }
        String motd = getServer().getMotd();
        if (motd != null) {
            motd = org.bukkit.ChatColor.stripColor(motd).trim();
            if (!motd.isEmpty()) {
                return motd;
            }
        }
        return "Minecraft";
    }

    /**
     * Permission gate for /warp edit on PUBLIC warps (rename/relocate/icon/order/delete).
     */
    public boolean hasPublicWarpAdmin(Player p) {
        return p.hasPermission("kavexwarp.admin");
    }

    /**
     * Permission gate specifically for creating/updating PUBLIC warps via /setwarp.
     * Granted directly, or inherited from kavexwarp.admin (see plugin.yml).
     */
    public boolean canSetPublicWarp(Player p) {
        return p.hasPermission("kavexwarp.setwarp.public");
    }

    /**
     * Permission gate specifically for creating/updating PRIVATE warps via /setwarp.
     * Defaults to everyone in plugin.yml, but can be restricted per-server.
     */
    public boolean canSetPrivateWarp(Player p) {
        return p.hasPermission("kavexwarp.setwarp.private");
    }

    private Player requirePublicWarpPermission(Player p) {
        if (!hasPublicWarpAdmin(p)) {
            p.sendMessage("§cYou need the kavexwarp.admin permission to manage public warps.");
            return null;
        }
        return p;
    }

    private Player requireSetPublicWarpPermission(Player p) {
        if (!canSetPublicWarp(p)) {
            p.sendMessage("§cYou don't have permission to create or update public warps.");
            return null;
        }
        return p;
    }

    private Player requireSetPrivateWarpPermission(Player p) {
        if (!canSetPrivateWarp(p)) {
            p.sendMessage("§cYou don't have permission to create or update private warps.");
            return null;
        }
        return p;
    }

    @Override
    public void onEnable() {
        saveDefaultConfig();
        this.dataDir = getDataFolder().toPath();

        try {
            Files.createDirectories(dataDir);
        } catch (Exception ignored) {
        }

        this.warpManager = new WarpManager(this);
        this.backManager = new BackManager(this);
        this.warpKey = new NamespacedKey(this, "warp_id");
        this.pageActionKey = new NamespacedKey(this, "page_action");

        getServer().getPluginManager().registerEvents(new WarpsGuiListener(this), this);
        getServer().getPluginManager().registerEvents(this, this);

        // /back writes happen far more often than warp edits, so flush periodically
        // instead of on every single teleport.
        getServer().getScheduler().runTaskTimerAsynchronously(
                this,
                () -> backManager.autoSaveIfDirty(),
                6000L, // 5 minutes
                6000L
        );

        if (getCommand("setwarp") != null) {
            getCommand("setwarp").setTabCompleter(this);
        }
        if (getCommand("warp") != null) {
            getCommand("warp").setTabCompleter(this);
        }
        if (getCommand("warps") != null) {
            getCommand("warps").setTabCompleter(this);
        }
    }

    @Override
    public void onDisable() {
        if (warpManager != null) {
            warpManager.save();
        }
        if (backManager != null) {
            backManager.save();
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent e) {
        if (!isJoinTeleportEnabled()) return;
        if (warpManager == null) return;

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

        Player p = e.getPlayer();

        p.addPotionEffect(new PotionEffect(
                PotionEffectType.BLINDNESS,
                25,
                1,
                false,
                false,
                false
        ));
        p.playSound(p.getLocation(), Sound.ENTITY_ENDERMAN_TELEPORT, 1.0f, 1.0f);

        getServer().getScheduler().runTaskLater(
                this,
                () -> p.teleport(loc),
                3L
        );
    }

    @EventHandler(ignoreCancelled = true)
    public void onPlayerTeleport(PlayerTeleportEvent e) {
        if (backManager == null) return;

        // Spectate-mode "teleports" fire continuously while clicking through players —
        // recording those would make /back useless (it'd just point at wherever you
        // were last spectating from a moment ago).
        if (e.getCause() == PlayerTeleportEvent.TeleportCause.SPECTATE) return;

        Location from = e.getFrom();
        if (from.getWorld() == null) return;

        backManager.recordBackLocation(e.getPlayer().getUniqueId(), from);
    }

    // ---------- Commands ----------

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String name = command.getName().toLowerCase(Locale.ROOT);
        switch (name) {
            case "setwarp":
                return handleSetWarp(sender, args);
            case "warps":
                return handleWarps(sender, args);
            case "warp":
                return handleWarpCommand(sender, args);
            case "back":
                return handleBack(sender, args);
            default:
                return false;
        }
    }

    private boolean handleBack(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }
        if (!p.hasPermission("kavexwarp.back")) {
            p.sendMessage("§cYou don't have permission to use /back.");
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
        p.playSound(p.getLocation(), Sound.ENTITY_ENDERMAN_TELEPORT, 1.0f, 1.0f);

        getServer().getScheduler().runTaskLater(this, () -> {
            p.teleport(loc);
            p.sendMessage("§aTeleported back to your previous location.");
        }, 3L);

        return true;
    }

    private boolean handleSetWarp(CommandSender sender, String[] args) {
        if (!(sender instanceof Player p)) {
            sender.sendMessage("This command can only be used in-game.");
            return true;
        }

        if (args.length < 2) {
            p.sendMessage("§7Usage: §e/setwarp <name> <public|private> [icon]");
            return true;
        }

        String name = args[0];
        if (name.length() > 32) {
            p.sendMessage("§cWarp name is too long (max 32 characters).");
            return true;
        }

        String visibility = args[1].toLowerCase(Locale.ROOT);
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
            if (requireSetPublicWarpPermission(p) == null) return true;
        } else {
            if (requireSetPrivateWarpPermission(p) == null) return true;
        }

        Material icon = Material.DIRT;
        if (args.length >= 3) {
            Material m = Material.matchMaterial(args[2]);
            if (m == null) {
                p.sendMessage("§cUnknown material: §f" + args[2]);
                p.sendMessage("§7Example: §eDIAMOND_SWORD§7 or §eSTONE");
                return true;
            }
            if (!m.isItem()) {
                p.sendMessage("§c" + m.name() + " is not a valid item (e.g. fluids like LAVA cannot be icons).");
                p.sendMessage("§7Try something like §eLAVA_BUCKET§7 instead.");
                return true;
            }
            icon = m;
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
                p.sendMessage("§aUpdated public warp §e" + name + "§a at your current location.");
            } else {
                warpManager.createWarp(p.getUniqueId(), true, name, p.getLocation(), icon);
                p.sendMessage("§aCreated new public warp §e" + name + "§a.");
            }
        } else {
            WarpManager.Warp existing = warpManager.getPrivateWarp(p.getUniqueId(), name);
            if (existing != null) {
                warpManager.updateWarpLocation(existing, p.getLocation());
                warpManager.updateWarpIcon(existing, icon);
                p.sendMessage("§aUpdated your private warp §e" + name + "§a.");
            } else {
                warpManager.createWarp(p.getUniqueId(), false, name, p.getLocation(), icon);
                p.sendMessage("§aCreated new private warp §e" + name + "§a.");
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
        if (!hasPublicWarpAdmin(p)) {
            p.sendMessage("§cYou need the kavexwarp.admin permission to manage join-teleport.");
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
            p.sendMessage("§7Usage: §e/warp edit <name> <rename|relocate|icon|order|delete> ...");
            return true;
        }

        String name = args[1];
        boolean isAdmin = hasPublicWarpAdmin(p);

        WarpManager.Warp warp = null;
        boolean editingPublic = false;

        if (isAdmin) {
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

        if (editingPublic && !isAdmin) {
            if (requirePublicWarpPermission(p) == null) return true;
        }

        if (args.length < 3) {
            p.sendMessage("§7Usage: §e/warp edit " + name + " <rename|relocate|icon|order|delete> ...");
            return true;
        }

        String sub = args[2].toLowerCase(Locale.ROOT);
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
                    p.sendMessage("§7Usage: §e/warp edit " + name + " icon <material>");
                    return true;
                }
                Material mat = Material.matchMaterial(args[3]);
                if (mat == null) {
                    p.sendMessage("§cUnknown material: §f" + args[3]);
                    return true;
                }
                if (!mat.isItem()) {
                    p.sendMessage("§c" + mat.name() + " is not a valid item (e.g. fluids like LAVA cannot be icons).");
                    p.sendMessage("§7Use an actual item like §eLAVA_BUCKET§7, §eNETHERRACK§7, etc.");
                    return true;
                }
                warpManager.updateWarpIcon(warp, mat);
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
            case "delete": {
                warpManager.deleteWarp(warp);
                warpManager.save();
                p.sendMessage("§cDeleted warp §e" + name + "§c.");
                break;
            }
            default: {
                p.sendMessage("§7Usage: §e/warp edit " + name + " <rename|relocate|icon|order|delete> ...");
                break;
            }
        }

        return true;
    }

    // ---------- Tab completion ----------

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        String name = command.getName().toLowerCase(Locale.ROOT);
        switch (name) {
            case "setwarp":
                return tabCompleteSetWarp(sender, args);
            case "warp":
                return tabCompleteWarp(sender, args);
            case "warps":
                return tabCompleteWarps(sender, args);
            default:
                return Collections.emptyList();
        }
    }

    private List<String> tabCompleteMaterials(String partial) {
        String p = partial == null ? "" : partial.toUpperCase(Locale.ROOT);
        List<String> result = new ArrayList<>();

        for (Material m : Material.values()) {
            if (!m.isItem()) continue;
            String matName = m.name();
            if (p.isEmpty() || matName.startsWith(p)) {
                result.add(matName);
            }
        }
        return result;
    }

    private List<String> tabCompleteSetWarp(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            return Collections.emptyList();
        }

        // /setwarp <name> <public|private> [icon]
        if (args.length == 2) {
            String partial = args[1].toLowerCase(Locale.ROOT);
            List<String> options = new ArrayList<>();
            if ("public".startsWith(partial)) options.add("public");
            if ("private".startsWith(partial)) options.add("private");
            return options;
        }

        if (args.length == 3) {
            return tabCompleteMaterials(args[2]);
        }

        return Collections.emptyList();
    }

    private List<String> tabCompleteWarp(CommandSender sender, String[] args) {
        if (!(sender instanceof Player)) {
            return Collections.emptyList();
        }

        // /warp edit <name> <rename|relocate|icon|order|delete> ...
        // /warp jointp <on|off>
        // /warp jointp warp <name>
        if (args.length == 1) {
            String partial = args[0].toLowerCase(Locale.ROOT);
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
            String partial = args[2].toLowerCase(Locale.ROOT);
            List<String> subs = new ArrayList<>();
            if ("rename".startsWith(partial)) subs.add("rename");
            if ("relocate".startsWith(partial)) subs.add("relocate");
            if ("icon".startsWith(partial)) subs.add("icon");
            if ("order".startsWith(partial)) subs.add("order");
            if ("delete".startsWith(partial)) subs.add("delete");
            return subs;
        }

        if (args.length == 4
                && "edit".equalsIgnoreCase(args[0])
                && "icon".equalsIgnoreCase(args[2])) {
            return tabCompleteMaterials(args[3]);
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
            if ("public".startsWith(partial)) options.add("public");
            if ("private".startsWith(partial)) options.add("private");
            return options;
        }

        return Collections.emptyList();
    }
}
