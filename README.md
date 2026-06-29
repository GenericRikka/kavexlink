# KavexLink — Secure Minecraft ↔ Discord Bridge (Paper Plugin)  
### A Lightweight, High-Performance Paper Plugin with Custom Static Water Portals and Live Discord Sync

![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-green.svg)
![Java](https://img.shields.io/badge/Java-25-orange)
![Platform](https://img.shields.io/badge/Paper-1.21%2B%20%2F%2026.2%20Experimental-cyan)
![Status](https://img.shields.io/badge/status-active-success)

KavexLink is the **Minecraft game-server half** of the KavexLink project — an ultra-lightweight, zero-bloat companion plugin designed for **PaperMC** servers. It establishes a real-time, bi-directional, TLS-encrypted connection directly to a backend [Kavex Bot](https://github.com/GenericRikka/kavex-bot) instance.

Unlike traditional chat bridges that use heavy dependencies or unencrypted HTTP REST polling, KavexLink features:
- ⚡ **Asynchronous Native Non-Blocking WebSockets (`java.net.http`)**
- 🌊 **Zero-Glitch Static Water Portals** (No more vanilla portal desyncs or nether math loops)
- 🔨 **Cross-Platform Moderation Sync** (Execute native Discord actions directly from Minecraft chat)
- 📊 **Isolated Multi-World Profiles** (Optional per-world inventories, separate stats, health/hunger resets)
- 🎨 **Dynamic Tab-List Formatting** (Synchronizes Discord roles, colors, and hoisted server prefixes in-game)

---

## ✨ Features

### 🔄 Asynchronous Bi-Directional Mirroring
- **In-Game Chat & Actions:** Broadcasts clean JSON streams directly to your companion Discord webhooks.
- **Server Events:** Automatically formats and forwards player events (*joins, quits, advancements, deaths, world swaps*).
- **In-Game Mention Pings:** Plays an explicit note-block chime (`BLOCK_NOTE_BLOCK_PLING`) whenever an online player is tagged via `@Name` in Discord or in-game chat.

### 🔐 Multi-World Isolation Profiles
- **`separate_inventory`:** Isolates your players' items and armor between custom dimensions or minigame maps.
- **`separate_stats`:** Separately stores health, hunger, saturation, level, and raw experience pools.
- **Stat Resets:** Allows configuring worlds to normalize health or hunger instantly upon entrance frames without breaking global states.

### 🌊 Zero-Glitch Static Water Portals
Replaces the finicky vanilla `NETHER_PORTAL` or `END_PORTAL` mechanisms. Using a custom `BlockFromToEvent` layout, the plugin freezes water physics completely inside portal areas to provide bulletproof 2D warp bounds with zero spilling.
- **Configurable Particle Ambience:** Set specific particle signatures (`PORTAL`, `ENCHANT`, `FLAME`, etc.) and spawn strengths directly per portal bounds.

### 🛡️ Discord-Native In-Game Moderation
Allows linked server staff to manage community accounts globally using a secure cross-platform execution chain:
- `!dckick <player> [reason]` -> Executes a clean kick from the linked Discord server.
- `!dcban <player> [reason]` -> Issues an absolute ban.
- `!dctimeout <player> <minutes> [reason]` -> Native Discord server timeout.

---

## 🏗️ Technical Architecture

KavexLink bypasses complex NMS internals by sticking strictly to modern, high-priority Bukkit event hooks and the lightweight Kyori Adventure API.

```
[ Minecraft Server (KavexLink) ]
│
▼ (High-Priority Event Hooks)
Kyori Adventure / Component Logic
│
▼ (Asynchronous WebSocket Client)
─── wss://bot.example.org/mcws ───► [ Kavex Bot (Asynchronous Python Loop) ]
```

---

## 🛠️ In-Game Commands

| Command | Permission | Description |
| :--- | :--- | :--- |
| `/linkdiscord` | `kavexlink.link` | Generates a short-lived link token for user pairing. |
| `/portal wand` | `kavexlink.worlds.admin` | Gives the structural selection rod (`PLAYER_HEAD` interface). |
| `/portal create <name> <target>` | `kavexlink.worlds.admin` | Binds a 2D water plane selection to a specific world or public warp. |
| `/portals edit <name> particle <type> [str]` | `kavexlink.worlds.admin` | Dynamically alters particle visuals with absolute tab-completion. |
| `/warps <public\|private>` | *None* | Opens a modern `InventoryHolder` chest GUI matrix of active warp nodes. |
| `/worlds` | *None* | Displays visible multi-world destinations based on public access visibility flags. |

---

## 📥 Compilation & Installation

This project targets modern Java execution runtimes (**Java 25+**) and can be compiled natively using Gradle without any external background daemons.

```bash
git clone [https://github.com/GenericRikka/kavexlink.git](https://github.com/GenericRikka/kavexlink.git)
cd kavexlink
```

Ensure your target Paper development artifact is updated inside your build.gradle.kts:

```kotlin
dependencies {
    compileOnly("io.papermc.paper:paper-api:26.2.local-SNAPSHOT")
}
```

Compile the release payload artifact:

```bash
./gradlew clean build --no-daemon
```

Drop the newly compiled artifact sitting at build/libs/KavexLink.jar straight into your Paper data instance plugins/ directory and issue a clean instance reboot.

---

## 📁 Configuration File (config.yml)

The initial boot framework dynamically generates a secure setup matrix inside your data folder structure:

```yaml
# ==============================================================================
# KavexLink Core Configuration
# ==============================================================================

server-name: "Artists MC Realm"
ws-url: "wss://bot.example.org/mcws"

ssl:
  mode: "system"         # system | ca-pem | pinned
  debug: false           # Set true to dump full javax.net handshake debugging logs
  force-tls12: false     # Overrides client system properties for legacy proxy layers

friends:
  dm-history-days: 30    # Lifespan duration for temporary messaging registers
```

---

## 🧩 Related Project: Discord Cog Backend

This game plugin requires the companion asynchronous Python backend application framework to process communication streams:
➡️ [Kavex Bot Engine GitHub][https://github.com/GenericRikka/kavex-bot]

---

## 📜 License

This module is released under the clear BSD 3-Clause License. See the local LICENSE document layout files for details.
