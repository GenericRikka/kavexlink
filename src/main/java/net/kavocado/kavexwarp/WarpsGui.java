package net.kavocado.kavexwarp;

import com.destroystokyo.paper.profile.ProfileProperty;
import io.papermc.paper.datacomponent.DataComponentTypes;
import io.papermc.paper.datacomponent.item.ResolvableProfile;
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
import java.util.UUID;

public class WarpsGui {

    private static final int WARPS_PER_PAGE = 8;

    // Icon slots, in fill order: 5 across the upper row, then 3 across the row below.
    private static final int[] UPPER_ICON_SLOTS = {20, 21, 22, 23, 24};
    private static final int[] LOWER_ICON_SLOTS = {30, 31, 32};

    private static final int PREV_SLOT = 47;
    private static final int NEXT_SLOT = 51;
    private static final int PAGE_INDICATOR_SLOT = 4;

    // One background glass color per row (0-5), top to bottom, forming a rainbow gradient.
    private static final Material[] ROW_GLASS = {
            Material.PURPLE_STAINED_GLASS_PANE,
            Material.LIGHT_BLUE_STAINED_GLASS_PANE,
            Material.LIME_STAINED_GLASS_PANE,
            Material.YELLOW_STAINED_GLASS_PANE,
            Material.ORANGE_STAINED_GLASS_PANE,
            Material.PINK_STAINED_GLASS_PANE,
    };

    // "Cherry Plank Arrow Left" — minecraft-heads.com/custom-heads/head/67012-cherry-plank-arrow-left
    private static final String LEFT_ARROW_TEXTURE =
            "eyJ0ZXh0dXJlcyI6eyJTS0lOIjp7InVybCI6Imh0dHA6Ly90ZXh0dXJlcy5taW5lY3JhZnQubmV0L3RleHR1cmUvNTI4YjhjZjQwNWVhZjYwNmEwMjEwZjAzMDNiMDEzMTc5ZjhmMTJlYWE5NTgyNDEyOWViZWVmOWU0NGI2ODIzMCJ9fX0=";

    // "Cherry Plank Arrow Right" — minecraft-heads.com/custom-heads/head/67011-cherry-plank-arrow-right
    private static final String RIGHT_ARROW_TEXTURE =
            "eyJ0ZXh0dXJlcyI6eyJTS0lOIjp7InVybCI6Imh0dHA6Ly90ZXh0dXJlcy5taW5lY3JhZnQubmV0L3RleHR1cmUvNWRjZGE2ZTNjNmRjYTdlOWI4YjZiYTNmZWJmNWNkMDkxN2Y5OTdiNjRiMmFlZjE4YzNmNzczNzY1ZTNhNTc5In19fQ==";

    public static void openPublicWarps(KavexWarpPlugin plugin, Player p) {
        openPage(plugin, p, true, null, 0);
    }

    public static void openPrivateWarps(KavexWarpPlugin plugin, Player p) {
        openPage(plugin, p, false, p.getUniqueId(), 0);
    }

    /**
     * Opens (or re-opens, for paging) the warps GUI at a specific page.
     */
    public static void openPage(KavexWarpPlugin plugin, Player p, boolean isPublic, UUID owner, int page) {
        List<WarpManager.Warp> warps = isPublic
                ? plugin.getWarpManager().getPublicWarps()
                : plugin.getWarpManager().getPrivateWarps(owner);

        if (warps.isEmpty()) {
            p.sendMessage("§7No warps to display.");
            return;
        }

        int totalPages = Math.max(1, (warps.size() + WARPS_PER_PAGE - 1) / WARPS_PER_PAGE);
        if (page < 0) page = 0;
        if (page >= totalPages) page = totalPages - 1;

        String baseTitle = isPublic
                ? plugin.getServerDisplayName() + " Warps"
                : plugin.getServerDisplayName() + " Private Warps";
        String title = totalPages > 1
                ? baseTitle + " (" + (page + 1) + "/" + totalPages + ")"
                : baseTitle;

        WarpsGuiHolder holder = new WarpsGuiHolder(isPublic, owner, warps, page);
        Inventory inv = Bukkit.createInventory(holder, 54, title);
        holder.setInventory(inv);

        // Rainbow glass background for every slot first...
        for (int slot = 0; slot < 54; slot++) {
            inv.setItem(slot, borderItem(ROW_GLASS[slot / 9]));
        }

        // ...then overwrite with warp icons for this page.
        int[] iconSlots = combinedIconSlots();
        int start = page * WARPS_PER_PAGE;
        for (int i = 0; i < iconSlots.length; i++) {
            int warpIndex = start + i;
            if (warpIndex >= warps.size()) break;
            inv.setItem(iconSlots[i], warpItem(plugin, warps.get(warpIndex)));
        }

        // Nav arrows: only show where there's actually a page to go to.
        if (page > 0) {
            inv.setItem(PREV_SLOT, navItem(plugin, LEFT_ARROW_TEXTURE, "§ePrevious Page", "prev"));
        }
        if (page < totalPages - 1) {
            inv.setItem(NEXT_SLOT, navItem(plugin, RIGHT_ARROW_TEXTURE, "§eNext Page", "next"));
        }

        if (totalPages > 1) {
            inv.setItem(PAGE_INDICATOR_SLOT, pageIndicatorItem(page + 1, totalPages));
        }

        p.openInventory(inv);
    }

    private static int[] combinedIconSlots() {
        int[] combined = new int[UPPER_ICON_SLOTS.length + LOWER_ICON_SLOTS.length];
        System.arraycopy(UPPER_ICON_SLOTS, 0, combined, 0, UPPER_ICON_SLOTS.length);
        System.arraycopy(LOWER_ICON_SLOTS, 0, combined, UPPER_ICON_SLOTS.length, LOWER_ICON_SLOTS.length);
        return combined;
    }

    private static ItemStack borderItem(Material glass) {
        ItemStack item = new ItemStack(glass);
        ItemMeta meta = item.getItemMeta();
        if (meta != null) {
            meta.setDisplayName(" "); // blank name so it doesn't show "Purple Stained Glass Pane" on hover
            item.setItemMeta(meta);
        }
        return item;
    }

    private static ItemStack pageIndicatorItem(int currentPage, int totalPages) {
        ItemStack item = new ItemStack(Material.PAPER);
        ItemMeta meta = item.getItemMeta();
        if (meta != null) {
            meta.setDisplayName("§ePage " + currentPage + " / " + totalPages);
            item.setItemMeta(meta);
        }
        return item;
    }

    private static ItemStack navItem(KavexWarpPlugin plugin, String base64Texture, String displayName, String action) {
        ItemStack item = new ItemStack(Material.PLAYER_HEAD);

        // Modern Paper Data Components API — sidesteps the legacy SkullMeta/PlayerProfile
        // type mismatch entirely. ResolvableProfile.Builder still takes a ProfileProperty
        // (same base64 "textures" value), but everything here is public API, no internal
        // CraftBukkit classes required.
        ResolvableProfile profile = ResolvableProfile.resolvableProfile()
                .addProperty(new ProfileProperty("textures", base64Texture))
                .build();
        item.setData(DataComponentTypes.PROFILE, profile);

        ItemMeta meta = item.getItemMeta();
        if (meta != null) {
            meta.setDisplayName(displayName);

            PersistentDataContainer pdc = meta.getPersistentDataContainer();
            pdc.set(plugin.getPageActionKey(), PersistentDataType.STRING, action);

            item.setItemMeta(meta);
        }
        return item;
    }

    private static ItemStack warpItem(KavexWarpPlugin plugin, WarpManager.Warp w) {
        Material mat = w.getIcon();
        if (mat == null) {
            mat = Material.DIRT;
        }

        if (!mat.isItem()) {
            switch (mat) {
                case LAVA -> mat = Material.MAGMA_BLOCK;
                case WATER -> mat = Material.WATER_BUCKET;
                case VOID_AIR, AIR, CAVE_AIR -> mat = Material.BARRIER;
                default -> mat = Material.BARRIER;
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

        return item;
    }
}
