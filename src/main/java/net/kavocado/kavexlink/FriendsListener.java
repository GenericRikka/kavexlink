package net.kavocado.kavexlink;

import org.bukkit.entity.HumanEntity;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;

public class FriendsListener implements Listener {

    private final KavexLinkPlugin plugin;

    public FriendsListener(KavexLinkPlugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler
    public void onInventoryClick(InventoryClickEvent e) {
        HumanEntity clicker = e.getWhoClicked();
        if (e.getView().getTitle().equalsIgnoreCase("Friends")) {
            e.setCancelled(true); // Prevent grabbing items for now
        }
    }
}

