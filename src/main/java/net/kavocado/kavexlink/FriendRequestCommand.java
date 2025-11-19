package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Set;
import java.util.UUID;

public class FriendRequestCommand implements CommandExecutor {

    private final KavexLinkPlugin plugin;

    public FriendRequestCommand(KavexLinkPlugin plugin) {
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

        if (args.length == 0) {
            player.sendMessage("§eUsage: /friendrequest <player> | /friendrequest view");
            return true;
        }

        if (args.length == 1 && args[0].equalsIgnoreCase("view")) {
            // List incoming requests
            Set<UUID> incoming = fm.getIncomingRequests(uuid);
            if (incoming.isEmpty()) {
                player.sendMessage("§7You have no pending friend requests.");
                return true;
            }

            player.sendMessage("§aPending friend requests:");
            for (UUID from : incoming) {
                OfflinePlayer op = Bukkit.getOfflinePlayer(from);
                String name = (op.getName() != null) ? op.getName() : from.toString();
                player.sendMessage("  §e" + name);
            }
            player.sendMessage("§7Use §e/friend accept <player> §7or §e/friend deny <player>§7.");
            return true;
        }

        if (args.length == 1) {
            // /friendrequest <player>
            String targetName = args[0];
            OfflinePlayer target = Bukkit.getOfflinePlayerIfCached(targetName);
            if (target == null) {
                target = Bukkit.getOfflinePlayer(targetName); // may not have played yet
            }

            if (target == null || (target.getName() == null && !target.hasPlayedBefore())) {
                player.sendMessage("§cPlayer not found: §e" + targetName);
                return true;
            }

            UUID targetUuid = target.getUniqueId();
            if (targetUuid.equals(uuid)) {
                player.sendMessage("§cYou cannot send a friend request to yourself.");
                return true;
            }

            if (fm.areFriends(uuid, targetUuid)) {
                player.sendMessage("§aYou are already friends with §e" + target.getName() + "§a.");
                return true;
            }

            boolean sent = fm.sendFriendRequest(uuid, targetUuid);
            if (!sent) {
                player.sendMessage("§cYou already have a pending request or are already friends.");
                return true;
            }

            player.sendMessage("§aFriend request sent to §e" + target.getName() + "§a.");
            return true;
        }

        player.sendMessage("§eUsage: /friendrequest <player> | /friendrequest view");
        return true;
    }
}

