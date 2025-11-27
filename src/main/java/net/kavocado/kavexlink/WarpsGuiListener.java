package net.kavocado.kavexlink;

import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataContainer;
import org.bukkit.persistence.PersistentDataType;
import org.bukkit.Sound;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

public class WarpsGuiListener implements Listener {

    private final KavexLinkPlugin plugin;
    private final WarpManager warpManager;

    public WarpsGuiListener(KavexLinkPlugin plugin) {
        this.plugin = plugin;
        this.warpManager = plugin.getWarpManager();
    }

    @EventHandler
    public void onInventoryClick(InventoryClickEvent e) {
        if (!(e.getWhoClicked() instanceof Player p)) return;

        ItemStack item = e.getCurrentItem();
        if (item == null) return;

        ItemMeta meta = item.getItemMeta();
        if (meta == null) return;

        PersistentDataContainer pdc = meta.getPersistentDataContainer();
        String warpId = pdc.get(plugin.getWarpKey(), PersistentDataType.STRING);
        if (warpId == null) return; // not one of our warp items

        e.setCancelled(true); // don't let them grab the item

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

        if (loc == null) {
            p.sendMessage("§cThis warp has an invalid location.");
            return;
        }

        // 1) Short “black frame” via BLINDNESS
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
                3L // ~0.15s delay; tweak if you like
        );

    }
}
