package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.UUID;

public class FriendCommand implements CommandExecutor {

    private final KavexLinkPlugin plugin;

    public FriendCommand(KavexLinkPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage("§cOnly players can use this command.");
            return true;
        }

        Player player = (Player) sender;
        UUID uuid = player.getUniqueId();
        FriendManager fm = plugin.getFriendManager();

        if (args.length != 2) {
            player.sendMessage("§eUsage: /friend accept <player> | /friend deny <player>");
            return true;
        }

        String sub = args[0];
        String targetName = args[1];

        OfflinePlayer target = Bukkit.getOfflinePlayerIfCached(targetName);
        if (target == null) {
            target = Bukkit.getOfflinePlayer(targetName);
        }
        if (target == null || target.getName() == null) {
            player.sendMessage("§cPlayer not found: §e" + targetName);
            return true;
        }

        UUID targetUuid = target.getUniqueId();

        if (sub.equalsIgnoreCase("accept")) {
            boolean ok = fm.acceptRequest(uuid, targetUuid);
            if (!ok) {
                player.sendMessage("§cYou have no pending friend request from §e"
                        + target.getName() + "§c.");
            }
            return true;
        }

        if (sub.equalsIgnoreCase("deny")) {
            boolean ok = fm.denyRequest(uuid, targetUuid);
            if (!ok) {
                player.sendMessage("§cYou have no pending friend request from §e"
                        + target.getName() + "§c.");
            }
            return true;
        }

        player.sendMessage("§eUsage: /friend accept <player> | /friend deny <player>");
        return true;
    }
}

