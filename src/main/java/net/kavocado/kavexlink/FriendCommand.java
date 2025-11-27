package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Set;
import java.util.UUID;

public class FriendCommand implements CommandExecutor {

    private final KavexLinkPlugin plugin;

    public FriendCommand(KavexLinkPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {

        if (!(sender instanceof Player p)) {
            sender.sendMessage("§cOnly players can use this command.");
            return true;
        }

        FriendManager fm = plugin.getFriendManager();
        UUID self = p.getUniqueId();

        if (args.length == 0) {
            p.sendMessage("§7/friend list §f- list your friends");
            p.sendMessage("§7/friend remove <name> §f- remove a friend");
            p.sendMessage("§7/friend unfriend <name> §f- alias for remove");
            p.sendMessage("§7/friend block <name> §f- block a player (no requests, no DMs)");
            p.sendMessage("§7/friend unblock <name> §f- unblock a player");
            p.sendMessage("§7/friend blocked §f- list blocked players");
            p.sendMessage("§7For requests, use §e/friendrequest§7.");
            showFriendList(p, fm, self);
            return true;
        }

        String sub = args[0].toLowerCase();
        switch (sub) {
            case "list":
                showFriendList(p, fm, self);
                return true;

            case "remove":
            case "unfriend":
                if (args.length < 2) {
                    p.sendMessage("§7Usage: §e/friend " + sub + " <player>");
                    return true;
                }
                handleRemove(p, fm, self, args[1]);
                return true;

            case "blocked":
                showBlockedList(p, fm, self);
                return true;

            case "block":
                if (args.length < 2) {
                    p.sendMessage("§7Usage: §e/friend block <player>");
                    return true;
                }
                handleBlock(p, fm, self, args[1]);
                return true;

            case "unblock":
                if (args.length < 2) {
                    p.sendMessage("§7Usage: §e/friend unblock <player>");
                    return true;
                }
                handleUnblock(p, fm, self, args[1]);
                return true;

            default:
                p.sendMessage("§cUnknown subcommand.");
                p.sendMessage("§7Use §e/friend list§7, §e/friend remove <name>§7, §e/friend block <name>§7, etc.");
                return true;
        }
    }

    private void showFriendList(Player p, FriendManager fm, UUID self) {
        Set<UUID> friends = fm.getFriends(self);
        if (friends.isEmpty()) {
            p.sendMessage("§7You have no friends added yet.");
            return;
        }

        p.sendMessage("§7Your friends:");
        for (UUID f : friends) {
            OfflinePlayer op = Bukkit.getOfflinePlayer(f);
            String name = (op.getName() != null ? op.getName() : f.toString());
            boolean online = op.isOnline();
            String status = online ? "§aonline" : "§coffline";
            p.sendMessage("  §e" + name + " §7(" + status + "§7)");
        }
    }

    private void handleRemove(Player p, FriendManager fm, UUID self, String targetName) {
        OfflinePlayer op = Bukkit.getOfflinePlayer(targetName);
        if (op == null || (op.getName() == null && !op.isOnline())) {
            p.sendMessage("§cCould not find player '" + targetName + "'.");
            return;
        }

        UUID targetId = op.getUniqueId();
        if (self.equals(targetId)) {
            p.sendMessage("§cYou cannot unfriend yourself.");
            return;
        }

        if (!fm.areFriends(self, targetId)) {
            p.sendMessage("§cYou are not friends with " +
                    (op.getName() != null ? op.getName() : targetName) + ".");
            return;
        }

        boolean ok = fm.removeFriendship(self, targetId);
        String realName = (op.getName() != null ? op.getName() : targetName);

        if (!ok) {
            p.sendMessage("§cFailed to remove friend. Please try again.");
            return;
        }

        p.sendMessage("§aYou removed §e" + realName + " §afrom your friends list.");

        if (op.isOnline() && op.getPlayer() != null) {
            op.getPlayer().sendMessage("§c" + p.getName() + " removed you from their friends list.");
        } else {
            fm.queueNotification(
                    targetId,
                    "§c" + p.getName() + " removed you from their friends list."
            );
        }
    }

    private void showBlockedList(Player p, FriendManager fm, UUID self) {
        Set<UUID> blocked = fm.getBlocked(self);
        if (blocked.isEmpty()) {
            p.sendMessage("§7You have no blocked players.");
            return;
        }

        p.sendMessage("§7Blocked players:");
        for (UUID u : blocked) {
            OfflinePlayer op = Bukkit.getOfflinePlayer(u);
            String name = (op.getName() != null ? op.getName() : u.toString());
            boolean online = op.isOnline();
            String status = online ? "§aonline" : "§coffline";
            p.sendMessage("  §e" + name + " §7(" + status + "§7)");
        }
    }

    private void handleBlock(Player p, FriendManager fm, UUID self, String targetName) {
        OfflinePlayer op = Bukkit.getOfflinePlayer(targetName);
        if (op == null || (op.getName() == null && !op.isOnline())) {
            p.sendMessage("§cCould not find player '" + targetName + "'.");
            return;
        }

        UUID targetId = op.getUniqueId();
        if (self.equals(targetId)) {
            p.sendMessage("§cYou cannot block yourself.");
            return;
        }

        if (fm.isBlocked(self, targetId)) {
            p.sendMessage("§7You have already blocked §e" +
                    (op.getName() != null ? op.getName() : targetName) + "§7.");
            return;
        }

        boolean ok = fm.block(self, targetId);
        String realName = (op.getName() != null ? op.getName() : targetName);

        if (!ok) {
            p.sendMessage("§cFailed to block player. Please try again.");
            return;
        }

        p.sendMessage("§cYou blocked §e" + realName + "§c.");
        p.sendMessage("§7They can no longer send you friend requests or direct messages.");
    }

    private void handleUnblock(Player p, FriendManager fm, UUID self, String targetName) {
        OfflinePlayer op = Bukkit.getOfflinePlayer(targetName);
        if (op == null || (op.getName() == null && !op.isOnline())) {
            p.sendMessage("§cCould not find player '" + targetName + "'.");
            return;
        }

        UUID targetId = op.getUniqueId();
        if (!fm.isBlocked(self, targetId)) {
            p.sendMessage("§7You have not blocked §e" +
                    (op.getName() != null ? op.getName() : targetName) + "§7.");
            return;
        }

        boolean ok = fm.unblock(self, targetId);
        String realName = (op.getName() != null ? op.getName() : targetName);

        if (!ok) {
            p.sendMessage("§cFailed to unblock player. Please try again.");
            return;
        }

        p.sendMessage("§aYou unblocked §e" + realName + "§a.");
    }
}

