package net.kavocado.kavexlink;

import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitRunnable;

import java.util.Set;
import java.util.UUID;

public class FriendCompassTask extends BukkitRunnable {

    private final KavexLinkPlugin plugin;

    public FriendCompassTask(KavexLinkPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public void run() {

        for (Player player : Bukkit.getOnlinePlayers()) {

            UUID uuid = player.getUniqueId();
            Set<UUID> friends = plugin.getFriendManager().getFriends(uuid);

            // ---- NO FRIENDS → RESET COMPASS ----
            if (friends == null || friends.isEmpty()) {
                player.setCompassTarget(player.getWorld().getSpawnLocation());
                continue;
            }

            Location pLoc = player.getLocation();
            Player nearest = null;
            double nearestSq = Double.MAX_VALUE;

            for (UUID fUuid : friends) {
                Player friend = Bukkit.getPlayer(fUuid);
                if (friend == null || !friend.isOnline()) continue;
                if (!friend.getWorld().equals(player.getWorld())) continue;

                double d2 = pLoc.distanceSquared(friend.getLocation());
                if (d2 < nearestSq) {
                    nearestSq = d2;
                    nearest = friend;
                }
            }

            // ---- HAVE FRIENDS, BUT NONE ONLINE / SAME WORLD ----
            if (nearest == null) {
                player.setCompassTarget(player.getWorld().getSpawnLocation());
                continue;
            }

            // ---- TRACK FRIEND ----
            player.setCompassTarget(nearest.getLocation());
        }
    }
}

