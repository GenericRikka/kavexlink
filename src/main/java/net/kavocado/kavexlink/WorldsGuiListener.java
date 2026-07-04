package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.World;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.inventory.InventoryView;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.persistence.PersistentDataContainer;
import org.bukkit.persistence.PersistentDataType;
import org.bukkit.Sound;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

/**
 * Handles clicks in the Worlds GUI:
 * - Left-click: teleport to the world's spawn (if allowed).
 * - Right-click (staff only): toggle PUBLIC/PRIVATE visibility.
 */
public class WorldsGuiListener implements Listener {

    private final KavexLinkPlugin plugin;

    public WorldsGuiListener(KavexLinkPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler
    public void onInventoryClick(InventoryClickEvent e) {
        if (!(e.getWhoClicked() instanceof Player p)) {
            return;
        }

        InventoryView view = e.getView();
        if (view == null || view.getTitle() == null
                || !view.getTitle().equals(WorldsGui.TITLE)) {
            return;
        }

        ItemStack item = e.getCurrentItem();
        if (item == null) {
            return;
        }

        ItemMeta meta = item.getItemMeta();
        if (meta == null) {
            return;
        }

        PersistentDataContainer pdc = meta.getPersistentDataContainer();
        String worldName = pdc.get(plugin.getWorldKey(), PersistentDataType.STRING);
        if (worldName == null) {
            return;
        }

        e.setCancelled(true);

        WorldManager wm = plugin.getWorldManager();
        if (wm == null) {
            p.sendMessage("§cWorld system is not initialized.");
            return;
        }

        WorldManager.WorldEntry entry = wm.getWorldByName(worldName);
        if (entry == null) {
            p.sendMessage("§cThis world entry no longer exists.");
            return;
        }

        boolean isAdmin = plugin.hasWorldAdmin(p);

        switch (e.getClick()) {
            case RIGHT, SHIFT_RIGHT -> {
                // Staff can toggle visibility PUBLIC <-> PRIVATE even for default worlds
                if (!isAdmin) {
                    p.sendMessage("§cYou are not allowed to edit worlds.");
                    return;
                }

                WorldManager.Access newAccess = (entry.getAccess() == WorldManager.Access.PUBLIC)
                        ? WorldManager.Access.PRIVATE
                        : WorldManager.Access.PUBLIC;

                wm.setAccess(entry, newAccess);

                p.sendMessage("§7World §e" + entry.getName() + "§7 visibility set to "
                        + (newAccess == WorldManager.Access.PUBLIC ? "§aPUBLIC" : "§cPRIVATE") + "§7.");

                // Refresh GUI to update lore colors
                Bukkit.getScheduler().runTask(plugin, () -> WorldsGui.open(plugin, p));
                return;
            }
            default -> {
                // Left / other clicks fall through to teleport logic
            }
        }

        // Teleport handling
        if (entry.getAccess() == WorldManager.Access.PRIVATE && !isAdmin) {
            p.sendMessage("§cThat world is private.");
            return;
        }

        World world = wm.ensureWorldLoaded(entry);
        if (world == null) {
            p.sendMessage("§cFailed to load world.");
            return;
        }

        // Same motion-sickness-friendly teleport as warps:
        p.addPotionEffect(new PotionEffect(
                PotionEffectType.BLINDNESS,
                25,   // ~1.25s
                1,
                false,
                false,
                false
        ));

        p.playSound(
                p.getLocation(),
                Sound.ENTITY_ENDERMAN_TELEPORT,
                1.0f,
                1.0f
        );

        plugin.getServer().getScheduler().runTaskLater(
                plugin,
                () -> {
                    org.bukkit.Location loc = null;
                    if (entry.isReturnToLastLocation() && plugin.getWorldProfileManager() != null) {
                        loc = plugin.getWorldProfileManager().getLastLocation(p.getUniqueId(), world);
                    }
                    if (loc == null) {
                        loc = world.getSpawnLocation();
                    }
                    p.teleport(loc);
                    p.sendMessage("§aSwitched to world §e" + entry.getName() + "§a.");
                },
                3L // ~0.15s delay for black frame effect
        );
    }
}

