package net.kavocado.kavexlink;

import com.destroystokyo.paper.profile.ProfileProperty;
import io.papermc.paper.datacomponent.DataComponentTypes;
import io.papermc.paper.datacomponent.item.ResolvableProfile;
import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.entity.Player;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemFlag;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataContainer;
import org.bukkit.persistence.PersistentDataType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

public class WarpsGui {

    // The outermost row (0), bottom row (5), and outermost columns (0 and 8) are the
    // frame - background glass and nav arrows only, never warp icons. That leaves a
    // 4-row (1-4) x 7-column (1-7) inner grid for warps. Rows are capped at 5 icons
    // each (rather than filling all 7 columns) and kept to odd sizes wherever
    // possible, since an odd-length row centers with no left/right offset while an
    // even-length row always looks shifted by half a slot. That puts real capacity
    // at 4 rows x 5 = 20 warps per page.
    private static final int INNER_ROW_START = 1;
    private static final int INNER_ROW_COUNT = 4;
    private static final int INNER_COL_START = 1;
    private static final int INNER_COL_COUNT = 7;
    private static final int MAX_ROW_SIZE = 5;
    private static final int MAX_WARPS_PER_PAGE = INNER_ROW_COUNT * MAX_ROW_SIZE; // 20

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

    // "Cherry Plank Arrow Left" - minecraft-heads.com/custom-heads/head/67012-cherry-plank-arrow-left
    private static final String LEFT_ARROW_TEXTURE =
            "eyJ0ZXh0dXJlcyI6eyJTS0lOIjp7InVybCI6Imh0dHA6Ly90ZXh0dXJlcy5taW5lY3JhZnQubmV0L3RleHR1cmUvNTI4YjhjZjQwNWVhZjYwNmEwMjEwZjAzMDNiMDEzMTc5ZjhmMTJlYWE5NTgyNDEyOWViZWVmOWU0NGI2ODIzMCJ9fX0=";

    // "Cherry Plank Arrow Right" - minecraft-heads.com/custom-heads/head/67011-cherry-plank-arrow-right
    private static final String RIGHT_ARROW_TEXTURE =
            "eyJ0ZXh0dXJlcyI6eyJTS0lOIjp7InVybCI6Imh0dHA6Ly90ZXh0dXJlcy5taW5lY3JhZnQubmV0L3RleHR1cmUvNWRjZGE2ZTNjNmRjYTdlOWI4YjZiYTNmZWJmNWNkMDkxN2Y5OTdiNjRiMmFlZjE4YzNmNzczNzY1ZTNhNTc5In19fQ==";

    public static void openPublicWarps(KavexLinkPlugin plugin, Player p) {
        openPage(plugin, p, true, null, 0);
    }

    public static void openPrivateWarps(KavexLinkPlugin plugin, Player p) {
        openPage(plugin, p, false, p.getUniqueId(), 0);
    }

    /**
     * Opens (or re-opens, for paging) the warps GUI at a specific page.
     */
    public static void openPage(KavexLinkPlugin plugin, Player p, boolean isPublic, UUID owner, int page) {
        // Sorted by category, then order, then name - same-category warps are always
        // contiguous here, which is what makes the page-chunking below trivial.
        List<WarpManager.Warp> warps = isPublic
                ? plugin.getWarpManager().getPublicWarps()
                : plugin.getWarpManager().getPrivateWarps(owner);

        if (warps.isEmpty()) {
            p.sendMessage("§7No warps to display.");
            return;
        }

        List<List<WarpManager.Warp>> pages = buildCategoryPages(warps);
        int totalPages = pages.size();

        if (page < 0) page = 0;
        if (page >= totalPages) page = totalPages - 1;

        List<WarpManager.Warp> pageWarps = pages.get(page);
        String currentCategory = pageWarps.get(0).getCategory();

        // Only prefix the server name when it's actually configured - no falling back
        // to the MOTD or a placeholder like "Minecraft" here, so an unconfigured
        // server-name simply omits that part of the title instead of guessing one.
        String configuredName = plugin.getConfiguredServerName();
        String namePrefix = configuredName != null ? configuredName + " " : "";
        String baseTitle = isPublic
                ? namePrefix + "Warps"
                : namePrefix + "Private Warps";
        String title = totalPages > 1
                ? baseTitle + " - " + currentCategory + " (" + (page + 1) + "/" + totalPages + ")"
                : baseTitle;

        WarpsGuiHolder holder = new WarpsGuiHolder(isPublic, owner, warps, page);
        Inventory inv = Bukkit.createInventory(holder, 54, title);
        holder.setInventory(inv);

        // Rainbow glass background for every slot first...
        for (int slot = 0; slot < 54; slot++) {
            inv.setItem(slot, borderItem(ROW_GLASS[slot / 9]));
        }

        // ...then overwrite with warp icons for this page, centered in the inner grid.
        int[] iconSlots = computeCenteredSlots(pageWarps.size());
        for (int i = 0; i < pageWarps.size(); i++) {
            inv.setItem(iconSlots[i], warpItem(plugin, pageWarps.get(i)));
        }

        // Nav arrows: only show where there's actually a page to go to.
        if (page > 0) {
            inv.setItem(PREV_SLOT, navItem(plugin, LEFT_ARROW_TEXTURE, "§ePrevious Page", "prev"));
        }
        if (page < totalPages - 1) {
            inv.setItem(NEXT_SLOT, navItem(plugin, RIGHT_ARROW_TEXTURE, "§eNext Page", "next"));
        }

        if (totalPages > 1) {
            inv.setItem(PAGE_INDICATOR_SLOT, pageIndicatorItem(currentCategory, page + 1, totalPages));
        }

        p.openInventory(inv);
    }

    /**
     * Chunks a category-sorted warp list into pages: a new page starts whenever the
     * category changes, or the current page hits MAX_WARPS_PER_PAGE - so two different
     * categories never share a page, but one category can spill across several.
     */
    private static List<List<WarpManager.Warp>> buildCategoryPages(List<WarpManager.Warp> sortedWarps) {
        List<List<WarpManager.Warp>> pages = new ArrayList<>();
        List<WarpManager.Warp> current = new ArrayList<>();
        String currentCategory = null;

        for (WarpManager.Warp w : sortedWarps) {
            boolean categoryChanged = currentCategory != null && !currentCategory.equalsIgnoreCase(w.getCategory());
            boolean pageFull = current.size() >= MAX_WARPS_PER_PAGE;

            if (categoryChanged || pageFull) {
                pages.add(current);
                current = new ArrayList<>();
            }

            current.add(w);
            currentCategory = w.getCategory();
        }

        if (!current.isEmpty()) {
            pages.add(current);
        }

        return pages;
    }

    /**
     * Computes `count` slot indices (count &lt;= MAX_WARPS_PER_PAGE) inside the inner
     * 4x7 grid, laid out as centered rows: as few rows as possible, each row odd-sized
     * (so it centers with no left/right offset) and capped at MAX_ROW_SIZE, the whole
     * block centered vertically among the 4 inner rows and each row centered
     * horizontally among the 7 inner columns.
     */
    private static int[] computeCenteredSlots(int count) {
        if (count <= 0) return new int[0];
        if (count > MAX_WARPS_PER_PAGE) count = MAX_WARPS_PER_PAGE; // shouldn't happen, but stay safe

        int[] rowSizes = computeOddRowSizes(count);
        if (rowSizes == null) {
            // Rare edge case (e.g. exactly 17 or 19 items) that can't be split into
            // all-odd rows of at most MAX_ROW_SIZE within the 4 available rows -
            // fall back to the widest possible layout so it still fits, even though
            // a row may end up even.
            rowSizes = computeFallbackRowSizes(count);
        }

        int rows = rowSizes.length;
        // Anchor the block one row below the top border whenever there's room to
        // (a 1-row buffer top and, space permitting, bottom too), rather than
        // splitting the leftover with integer-division rounding - that was pulling
        // odd-leftover layouts (e.g. a 3-row block) flush against the top border
        // with no gap at all. Only when the block uses every inner row (rows ==
        // INNER_ROW_COUNT, i.e. the page is genuinely full) does the buffer
        // disappear entirely.
        int startRow = INNER_ROW_START + Math.min(1, INNER_ROW_COUNT - rows);

        int[] slots = new int[count];
        int idx = 0;
        for (int r = 0; r < rows; r++) {
            int rowCount = rowSizes[r];
            int startCol = INNER_COL_START + (INNER_COL_COUNT - rowCount) / 2;
            int rowIndex = startRow + r;
            for (int c = 0; c < rowCount; c++) {
                slots[idx++] = rowIndex * 9 + (startCol + c);
            }
        }
        return slots;
    }

    /**
     * Tries to split {@code count} into the smallest possible number of rows, each an
     * odd size from 1 to MAX_ROW_SIZE, front-loading the bigger rows first - e.g. 9
     * becomes [5, 3, 1] rather than [1, 3, 5] or [3, 3, 3], and 6 becomes [5, 1]
     * instead of one shifted-looking row of 6. Returns null if no such split exists
     * within INNER_ROW_COUNT rows (only possible for a couple of odd counts near the
     * top of the page capacity, e.g. 17 or 19).
     */
    private static int[] computeOddRowSizes(int count) {
        for (int rows = 1; rows <= INNER_ROW_COUNT; rows++) {
            if (rows % 2 != count % 2) continue; // sum of `rows` odd numbers shares its parity with `rows`
            if (count > rows * MAX_ROW_SIZE) continue; // not enough capacity at this row count
            if (count < rows) continue; // impossible: every row needs at least 1 item

            int[] sizes = new int[rows];
            Arrays.fill(sizes, 1);
            int pairsLeft = (count - rows) / 2; // each "pair" bumps a row size by 2, e.g. 1 -> 3 -> 5
            for (int r = 0; r < rows && pairsLeft > 0; r++) {
                int take = Math.min(2, pairsLeft); // a row can absorb at most 2 pairs (1 -> 5)
                sizes[r] += take * 2;
                pairsLeft -= take;
            }
            return sizes;
        }
        return null;
    }

    /**
     * Fallback for the rare counts that can't be split into all-odd rows (e.g. 17 or
     * 19 items): spreads them as evenly as possible across the minimum number of
     * rows, using the full 7-column width if needed, so the layout still fits.
     */
    private static int[] computeFallbackRowSizes(int count) {
        int rows = (int) Math.ceil(count / (double) INNER_COL_COUNT);
        rows = Math.max(1, Math.min(rows, INNER_ROW_COUNT));
        int base = count / rows;
        int remainder = count % rows;

        int[] sizes = new int[rows];
        for (int r = 0; r < rows; r++) {
            sizes[r] = base + (r < remainder ? 1 : 0);
        }
        return sizes;
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

    private static ItemStack pageIndicatorItem(String category, int currentPage, int totalPages) {
        ItemStack item = new ItemStack(Material.PAPER);
        ItemMeta meta = item.getItemMeta();
        if (meta != null) {
            meta.setDisplayName("§e" + category + " §7(" + currentPage + " / " + totalPages + ")");
            item.setItemMeta(meta);
        }
        return item;
    }

    private static ItemStack navItem(KavexLinkPlugin plugin, String base64Texture, String displayName, String action) {
        ItemStack item = new ItemStack(Material.PLAYER_HEAD);

        // Modern Paper Data Components API - sidesteps the legacy SkullMeta/PlayerProfile
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

    private static ItemStack warpItem(KavexLinkPlugin plugin, WarpManager.Warp w) {
        ItemStack source = w.getIcon();
        Material mat = source != null ? source.getType() : null;

        // Only legacy/edge-case data should ever hit this: a real held item captured
        // via "hand" can't be a non-item type. Substitute something safe and drop
        // whatever meta it had, since it wasn't going to render correctly anyway.
        if (mat == null || !mat.isItem()) {
            Material safe = switch (mat == null ? Material.AIR : mat) {
                case LAVA -> Material.MAGMA_BLOCK;
                case WATER -> Material.WATER_BUCKET;
                default -> Material.BARRIER;
            };
            source = new ItemStack(safe);
        }

        // Clone rather than rebuild from just the Material, so a custom head's skin
        // or a banner's color/pattern layers (or any other meta the icon carries)
        // survives into the rendered item - we only overwrite name/lore/PDC below.
        ItemStack item = source.clone();
        item.setAmount(1);
        ItemMeta meta = item.getItemMeta();
        if (meta != null) {
            meta.setDisplayName("§e" + w.getName());

            // The item itself can carry its own tooltip additions - a banner's
            // pattern list, enchantments, attribute modifiers, dye/trim info, etc.
            // - none of which is relevant here now that the icon is just decoration.
            // Hiding every flag suppresses all of that, leaving only the name we set
            // above (no lore at all, for now - just the warp name).
            meta.addItemFlags(ItemFlag.values());

            PersistentDataContainer pdc = meta.getPersistentDataContainer();
            pdc.set(plugin.getWarpKey(), PersistentDataType.STRING, w.getId());

            item.setItemMeta(meta);
        }

        return item;
    }
}
