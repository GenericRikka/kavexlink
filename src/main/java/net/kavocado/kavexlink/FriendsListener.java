package net.kavocado.kavexlink;

import org.bukkit.Material;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.HumanEntity;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.inventory.meta.SkullMeta;

import java.util.UUID;

public class FriendsListener implements Listener {

    private final KavexLinkPlugin plugin;

    public FriendsListener(KavexLinkPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler
    public void onInventoryClick(InventoryClickEvent e) {
        if (!e.getView().getTitle().equalsIgnoreCase("Friends")) {
            return;
        }

        e.setCancelled(true); // no taking items

        HumanEntity clicker = e.getWhoClicked();
        if (!(clicker instanceof Player p)) {
            return;
        }

        // Ignore clicks in the player's own inventory
        if (e.getClickedInventory() == null ||
                e.getClickedInventory().equals(p.getInventory())) {
            return;
        }

        ItemStack clicked = e.getCurrentItem();
        if (clicked == null || clicked.getType() != Material.PLAYER_HEAD) {
            return;
        }

        ItemMeta meta = clicked.getItemMeta();
        if (!(meta instanceof SkullMeta skull)) {
            return;
        }

        OfflinePlayer op = skull.getOwningPlayer();
        if (op == null) return;

        UUID friendId = op.getUniqueId();

        // Close the GUI and open DM session
        p.closeInventory();
        plugin.openDmSession(p, friendId);
    }
}

