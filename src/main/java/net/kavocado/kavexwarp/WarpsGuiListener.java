package net.kavocado.kavexwarp;

import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.Sound;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataContainer;
import org.bukkit.persistence.PersistentDataType;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

public class WarpsGuiListener implements Listener {

    private final KavexWarpPlugin plugin;
    private final WarpManager warpManager;

    public WarpsGuiListener(KavexWarpPlugin plugin) {
        this.plugin = plugin;
        this.warpManager = plugin.getWarpManager();
    }

    @EventHandler
    public void onInventoryClick(InventoryClickEvent e) {
        if (!(e.getWhoClicked() instanceof Player p)) return;

        if (!(e.getView().getTopInventory().getHolder() instanceof WarpsGuiHolder holder)) {
            return; // not one of our warps GUIs
        }

        // Only intercept clicks inside the GUI itself; let the player's own inventory behave normally.
        if (e.getClickedInventory() == null || !e.getClickedInventory().equals(e.getView().getTopInventory())) {
            return;
        }

        // Cancel everything in this GUI - background glass, page indicator, arrows, and warp icons alike.
        e.setCancelled(true);

        ItemStack item = e.getCurrentItem();
        if (item == null) return;

        ItemMeta meta = item.getItemMeta();
        if (meta == null) return;

        PersistentDataContainer pdc = meta.getPersistentDataContainer();

        String pageAction = pdc.get(plugin.getPageActionKey(), PersistentDataType.STRING);
        if (pageAction != null) {
            int newPage = holder.getPage() + ("next".equals(pageAction) ? 1 : -1);
            // Defer a tick so we're not mutating the inventory view from inside its own click event.
            Bukkit.getScheduler().runTask(plugin, () ->
                    WarpsGui.openPage(plugin, p, holder.isPublicWarps(), holder.getOwner(), newPage));
            return;
        }

        String warpId = pdc.get(plugin.getWarpKey(), PersistentDataType.STRING);
        if (warpId == null) return; // background glass or page indicator — no action

        WarpManager.Warp warp = warpManager.getWarpById(warpId);
        if (warp == null) {
            p.sendMessage("§cThis warp no longer exists.");
            return;
        }

        Location loc = warpManager.toLocation(warp);
        if (loc == null) {
            p.sendMessage("§cThe world for this warp is not loaded.");
            return;
        }

        p.closeInventory();

        // 1) Short "black frame" via BLINDNESS
        p.addPotionEffect(new PotionEffect(
                PotionEffectType.BLINDNESS,
                25,   // ticks (~1.25 seconds)
                1,
                false, // ambient (no funky particles)
                false, // showParticles
                false  // showIcon
        ));

        // 2) Enderman teleport sound
        p.playSound(
                p.getLocation(),
                Sound.ENTITY_ENDERMAN_TELEPORT,
                1.0f,
                1.0f
        );

        // 3) Actually teleport a tiny moment later while screen is black
        plugin.getServer().getScheduler().runTaskLater(
                plugin,
                () -> {
                    p.teleport(loc);
                    p.sendMessage("§aWarped to §e" + warp.getName() + "§a.");
                },
                3L // ~0.15s delay
        );
    }
}
