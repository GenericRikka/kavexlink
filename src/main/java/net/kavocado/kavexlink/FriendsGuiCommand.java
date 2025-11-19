package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.inventory.meta.SkullMeta;

import java.util.Set;
import java.util.UUID;

public class FriendsGuiCommand implements CommandExecutor {

    private final KavexLinkPlugin plugin;

    public FriendsGuiCommand(KavexLinkPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {

        if (!(sender instanceof Player p)) {
            sender.sendMessage("§cOnly players can use this command.");
            return true;
        }

        UUID uuid = p.getUniqueId();
        FriendManager fm = plugin.getFriendManager();
        Set<UUID> friends = fm.getFriends(uuid);

        if (friends.isEmpty()) {
            p.sendMessage("§7You have no friends added yet.");
            return true;
        }

        Inventory inv = Bukkit.createInventory(p, 54, "Friends");

        int index = 0;
        for (UUID f : friends) {
            if (index >= 27) break;

            OfflinePlayer op = Bukkit.getOfflinePlayer(f);
            String name = op.getName() != null ? op.getName() : f.toString();

            int headSlot = index;
            int glassSlot = index + 9;

            // HEAD: simple owning-player skin
            ItemStack head = new ItemStack(Material.PLAYER_HEAD);
            SkullMeta skull = (SkullMeta) head.getItemMeta();
            skull.setOwningPlayer(op);
            skull.setDisplayName("§a" + name);
            head.setItemMeta(skull);
            inv.setItem(headSlot, head);

            // Friend status pane
            Player fp = Bukkit.getPlayer(f);
            boolean online = fp != null && fp.isOnline();
            int unread = fm.getUnreadCount(uuid, f);

            Material mat;
            String text;

            if (unread > 0) {
                mat = Material.ORANGE_STAINED_GLASS_PANE;
                text = "§6" + unread + " unread msgs";
            } else if (online) {
                mat = Material.GREEN_STAINED_GLASS_PANE;
                text = "§aOnline";
            } else {
                mat = Material.RED_STAINED_GLASS_PANE;
                text = "§cOffline";
            }

            ItemStack pane = new ItemStack(mat);
            ItemMeta meta = pane.getItemMeta();
            meta.setDisplayName(text);
            pane.setItemMeta(meta);

            inv.setItem(glassSlot, pane);

            index++;
        }

        p.openInventory(inv);
        return true;
    }
}

