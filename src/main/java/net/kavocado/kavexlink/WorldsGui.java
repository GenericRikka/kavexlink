package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.entity.Player;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataContainer;
import org.bukkit.persistence.PersistentDataType;

import java.util.ArrayList;
import java.util.List;

/**
 * Opens a simple chest-like GUI listing all worlds the player is allowed to see.
 * - Non-staff: sees only PUBLIC worlds.
 * - Staff: sees all worlds, PUBLIC + PRIVATE.
 * - Right-click (staff only): toggles PUBLIC/PRIVATE for that world.
 */
public class WorldsGui {

    public static final String TITLE = "Worlds";

    public static void open(KavexLinkPlugin plugin, Player p) {
        WorldManager wm = plugin.getWorldManager();
        if (wm == null) {
            p.sendMessage("§cWorld system is not initialized.");
            return;
        }

        boolean isAdmin = plugin.hasWorldAdmin(p);

        List<WorldManager.WorldEntry> all = wm.getAllWorldsSorted();
        List<WorldManager.WorldEntry> visible = new ArrayList<>();

        for (WorldManager.WorldEntry entry : all) {
            if (entry.getAccess() == WorldManager.Access.PUBLIC || isAdmin) {
                visible.add(entry);
            }
        }

        if (visible.isEmpty()) {
            p.sendMessage("§7No worlds to display.");
            return;
        }

        int size = ((visible.size() - 1) / 9 + 1) * 9;
        if (size < 9) size = 9;
        if (size > 54) size = 54;

        Inventory inv = Bukkit.createInventory(null, size, TITLE);

        for (int i = 0; i < visible.size() && i < size; i++) {
            WorldManager.WorldEntry entry = visible.get(i);

            Material icon = entry.getIcon();
            if (icon == null || icon == Material.AIR) {
                icon = Material.GRASS_BLOCK;
            }

            ItemStack item = new ItemStack(icon);
            ItemMeta meta = item.getItemMeta();
            if (meta != null) {
                meta.setDisplayName("§e" + entry.getName());

                List<String> lore = new ArrayList<>();
                lore.add("§7Mode: §f" + entry.getMode().name());
                lore.add("§7Access: " + (entry.getAccess() == WorldManager.Access.PUBLIC
                        ? "§aPUBLIC"
                        : "§cPRIVATE"));
                if (entry.isBuiltin()) {
                    lore.add("§8(Default world)");
                } else {
                    lore.add("§8(Custom world)");
                }
                if (isAdmin) {
                    lore.add("§8Right-click: toggle public/private");
                }
                meta.setLore(lore);

                PersistentDataContainer pdc = meta.getPersistentDataContainer();
                pdc.set(plugin.getWorldKey(), PersistentDataType.STRING, entry.getName());

                item.setItemMeta(meta);
            }

            inv.setItem(i, item);
        }

        p.openInventory(inv);
    }
}

