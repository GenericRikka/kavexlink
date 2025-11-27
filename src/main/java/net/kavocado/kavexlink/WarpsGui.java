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

public class WarpsGui {

    public static void openPublicWarps(KavexLinkPlugin plugin, Player p) {
        List<WarpManager.Warp> warps = plugin.getWarpManager().getPublicWarps();
        open(plugin, p, warps, "Public Warps");
    }

    public static void openPrivateWarps(KavexLinkPlugin plugin, Player p) {
        List<WarpManager.Warp> warps = plugin.getWarpManager().getPrivateWarps(p.getUniqueId());
        open(plugin, p, warps, "Your Private Warps");
    }

    private static void open(KavexLinkPlugin plugin,
                             Player p,
                             List<WarpManager.Warp> warps,
                             String title) {
        if (warps.isEmpty()) {
            p.sendMessage("§7No warps to display.");
            return;
        }

        int size = ((warps.size() - 1) / 9 + 1) * 9;
        size = Math.min(Math.max(9, size), 54); // 1–6 rows

        Inventory inv = Bukkit.createInventory(null, size, title);

        for (int i = 0; i < warps.size() && i < size; i++) {
            WarpManager.Warp w = warps.get(i);

            // We already store a Material in the warp
            Material mat = w.getIcon();
            if (mat == null) {
                mat = Material.DIRT;
            }

            // If this material cannot exist as an inventory item, map it to something that can
            if (!mat.isItem()) {
                switch (mat) {
                    case LAVA -> mat = Material.MAGMA_BLOCK;      // “lava” warp → magma block icon
                    case WATER -> mat = Material.WATER_BUCKET;    // “water” warp → water bucket
                    case VOID_AIR, AIR, CAVE_AIR -> mat = Material.BARRIER;
                    default -> mat = Material.BARRIER;            // any other weird non-item
                }
            }

            ItemStack item = new ItemStack(mat);
            ItemMeta meta = item.getItemMeta();
            if (meta != null) {
                meta.setDisplayName("§e" + w.getName());

                List<String> lore = new ArrayList<>();
                lore.add("§7World: §f" + w.getWorld());
                lore.add(String.format("§7XYZ: §f%.1f / %.1f / %.1f",
                        w.getX(), w.getY(), w.getZ()));
                lore.add(w.isPublicWarp() ? "§8Public warp" : "§8Private warp");
                meta.setLore(lore);

                PersistentDataContainer pdc = meta.getPersistentDataContainer();
                pdc.set(plugin.getWarpKey(), PersistentDataType.STRING, w.getId());

                item.setItemMeta(meta);
            }

            inv.setItem(i, item);
        }

        p.openInventory(inv);
    }
}

