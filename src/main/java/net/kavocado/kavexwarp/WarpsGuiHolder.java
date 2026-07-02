package net.kavocado.kavexwarp;

import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.InventoryHolder;

import java.util.List;
import java.util.UUID;

/**
 * Tracks which warps GUI a player currently has open: whether it's the public
 * or private list, whose private list it is, which page they're on, and the
 * full (unpaginated) warp list backing it, so the click listener can page
 * forward/backward without re-querying WarpManager mid-click.
 */
public class WarpsGuiHolder implements InventoryHolder {

    private final boolean publicWarps;
    private final UUID owner; // null when publicWarps is true
    private final List<WarpManager.Warp> warps;
    private final int page;
    private Inventory inventory;

    public WarpsGuiHolder(boolean publicWarps, UUID owner, List<WarpManager.Warp> warps, int page) {
        this.publicWarps = publicWarps;
        this.owner = owner;
        this.warps = warps;
        this.page = page;
    }

    public boolean isPublicWarps() {
        return publicWarps;
    }

    public UUID getOwner() {
        return owner;
    }

    public List<WarpManager.Warp> getWarps() {
        return warps;
    }

    public int getPage() {
        return page;
    }

    void setInventory(Inventory inventory) {
        this.inventory = inventory;
    }

    @Override
    public Inventory getInventory() {
        return inventory;
    }
}
