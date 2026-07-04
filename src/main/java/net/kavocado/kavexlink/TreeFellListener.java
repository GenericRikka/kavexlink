package net.kavocado.kavexlink;

import org.bukkit.GameMode;
import org.bukkit.Material;
import org.bukkit.Tag;
import org.bukkit.block.Block;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.inventory.ItemStack;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

/**
 * Fells an entire tree trunk when a player breaks any log block that's part of it,
 * so players can't leave half-chopped trunks floating in the air. Only the connected
 * log blocks are removed - leaves are left untouched and decay on their own via
 * vanilla's normal leaf-decay behavior once they're no longer near a log.
 *
 * Every extra log removed still goes through a real (synthetic) BlockBreakEvent
 * first, so protection plugins (WorldGuard, GriefPrevention, etc.) get a normal
 * chance to cancel individual blocks - e.g. if a tree's canopy overhangs into a
 * region the player isn't allowed to build/break in.
 */
public class TreeFellListener implements Listener {

    private final KavexLinkPlugin plugin;

    // Guards against our own synthetic BlockBreakEvents (fired below for every
    // extra trunk log) re-entering this same handler and re-triggering another
    // flood fill of the tree we're already in the middle of felling. Safe as a
    // plain field since Bukkit events are only ever fired on the main thread.
    private boolean processing = false;

    public TreeFellListener(KavexLinkPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onBlockBreak(BlockBreakEvent e) {
        if (processing) return;
        if (!plugin.getConfig().getBoolean("tree-felling.enabled", true)) return;

        Block origin = e.getBlock();
        Material logType = origin.getType();
        if (!Tag.LOGS.isTagged(logType)) return;

        Player p = e.getPlayer();

        if (plugin.getConfig().getBoolean("tree-felling.sneak-to-disable", true) && p.isSneaking()) {
            return;
        }

        if (plugin.getConfig().getBoolean("tree-felling.require-axe", false)
                && !Tag.ITEMS_AXES.isTagged(p.getInventory().getItemInMainHand().getType())) {
            return;
        }

        int maxSize = Math.max(1, plugin.getConfig().getInt("tree-felling.max-tree-size", 128));
        boolean diagonal = plugin.getConfig().getBoolean("tree-felling.diagonal-connections", true);

        Set<Block> connectedLogs = floodFillLogs(origin, logType, maxSize, diagonal);

        // Just the one block the player already broke - nothing extra to do.
        if (connectedLogs.size() <= 1) return;

        if (plugin.getConfig().getBoolean("tree-felling.require-leaves-nearby", true)) {
            int radius = Math.max(0, plugin.getConfig().getInt("tree-felling.leaves-search-radius", 3));
            if (!hasNearbyLeaves(connectedLogs, radius)) {
                // Doesn't look like a natural tree (e.g. a log cabin) - leave the
                // rest of the structure alone and let this be a normal single break.
                return;
            }
        }

        ItemStack tool = p.getInventory().getItemInMainHand();
        boolean creative = p.getGameMode() == GameMode.CREATIVE;

        processing = true;
        try {
            for (Block b : connectedLogs) {
                if (b.equals(origin)) continue; // vanilla already handles the block the player actually broke

                BlockBreakEvent fake = new BlockBreakEvent(b, p);
                plugin.getServer().getPluginManager().callEvent(fake);
                if (fake.isCancelled()) continue; // a protection plugin said no to this specific block

                if (fake.isDropItems() && !creative) {
                    for (ItemStack drop : b.getDrops(tool)) {
                        b.getWorld().dropItemNaturally(b.getLocation(), drop);
                    }
                }
                b.setType(Material.AIR, true);
            }
        } finally {
            processing = false;
        }
    }

    /**
     * BFS outward from the broken block through directly-adjacent blocks of the exact
     * same log material. Restricting to the same species (rather than any Tag.LOGS
     * block) stops two trees of different wood that happen to touch - or a log-built
     * structure standing next to a real tree - from merging into a single fell.
     * Capped at maxSize blocks so an unusual shape (or an accidental match) can't
     * take down an unreasonable number of blocks in one go.
     */
    private Set<Block> floodFillLogs(Block origin, Material logType, int maxSize, boolean diagonal) {
        Set<Block> visited = new HashSet<>();
        Deque<Block> queue = new ArrayDeque<>();
        visited.add(origin);
        queue.add(origin);

        int[][] orthogonal = {
                {1, 0, 0}, {-1, 0, 0},
                {0, 1, 0}, {0, -1, 0},
                {0, 0, 1}, {0, 0, -1},
        };

        while (!queue.isEmpty() && visited.size() < maxSize) {
            Block current = queue.poll();

            if (diagonal) {
                for (int dx = -1; dx <= 1; dx++) {
                    for (int dy = -1; dy <= 1; dy++) {
                        for (int dz = -1; dz <= 1; dz++) {
                            if (dx == 0 && dy == 0 && dz == 0) continue;
                            tryVisit(current, dx, dy, dz, logType, visited, queue, maxSize);
                        }
                    }
                }
            } else {
                for (int[] off : orthogonal) {
                    tryVisit(current, off[0], off[1], off[2], logType, visited, queue, maxSize);
                }
            }
        }

        return visited;
    }

    private void tryVisit(Block current, int dx, int dy, int dz, Material logType,
                           Set<Block> visited, Deque<Block> queue, int maxSize) {
        if (visited.size() >= maxSize) return;
        Block next = current.getRelative(dx, dy, dz);
        if (visited.contains(next)) return;
        if (next.getType() != logType) return;
        visited.add(next);
        queue.add(next);
    }

    /**
     * Whether any leaves block (or nether wart block, for crimson/warped huge fungi)
     * sits within `radius` blocks of any log in the found trunk - our stand-in for
     * "is this an actual tree" versus a player-built log structure, which normally
     * won't have leaves stuck to it.
     */
    private boolean hasNearbyLeaves(Set<Block> logs, int radius) {
        for (Block log : logs) {
            for (int dx = -radius; dx <= radius; dx++) {
                for (int dy = -radius; dy <= radius; dy++) {
                    for (int dz = -radius; dz <= radius; dz++) {
                        Material m = log.getRelative(dx, dy, dz).getType();
                        if (Tag.LEAVES.isTagged(m)
                                || m == Material.NETHER_WART_BLOCK
                                || m == Material.WARPED_WART_BLOCK) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}
