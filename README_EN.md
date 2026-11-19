# Telegram Channel Comment Anti-Spam Bot

[中文](README.md) | **English**

A lightweight, millisecond-latency Telegram anti-spam bot for channel comment sections (Go + pure-Go embedded BoltDB + systemd), engineered for low-memory VPS instances (~7MB static single binary, <10MB resident RAM, sub-second builds without swap thrashing).

> [!NOTE]
> **LLM Disclaimer**
>
> All code in this repository is 100% AI-generated. The maintainer aims to keep the project easy to use, but does not guarantee code quality. Maintainer responses may also be 100% copy-pasted—this is expected, please be aware.

## Key Features

- **Customizable Regex & Anti-Obfuscation Engine (Go RE2)**:
  - **Multi-Condition AND Matching (`all_of`)**: Each rule contains a list of Go RE2 regular expressions that must all match (order-independent), running in guaranteed linear `O(N)` time to prevent ReDoS, with native `\x{XXXX}` Unicode codepoint escapes.
  - **Multi-Target Inspection (`target`)**: Each rule targets `message` (message text & media `caption`, including `edited_message`), `name` (user display name or external channel mask title), `any` (triggers if either message or display name matches—defeating spammers who hide ads in their display name and post filler comments like `1` or `.`), or `combined` (name + message).
  - **Anti-Obfuscation Compact Normalization (`compact: true`)**: Automatically strips zero-width/invisible characters (`\u200b`–`\u200f`, `\ufeff`, braille blank, etc.), removes all whitespace and punctuation separators, and folds fullwidth ASCII, common Traditional-to-Simplified variants, and Kangxi radicals (while preserving emoji/symbol anchors such as `⬅`, `←`, `👈`, `🔞`), defeating space/comma stuffing, variant mixing, and rare CJK Extension A (`U+3400`–`U+4DBF`) homoglyphs.
  - **6 Built-in Default Rules**: Covers `/start ... @*bot` triggers, `@*bot campaign_*` tracking-token spam, leading-arrow bio-bait comments, bio-redirect spam, rare CJK Extension A homoglyphs, and obfuscated illicit ads. Easily extensible in `config.yaml`:
    ```yaml
    rules:
      - name: "start_with_bot_mention"
        target: "message"
        all_of:
          - '(?i)(?:^|[\s"''(\[>])/start(?:\b|@)'
          - '(?i)@[a-z0-9_]{2,}bot\b'

      - name: "rare_homoglyph_spam"
        target: "any"      # Inspect both message text and sender display name / channel mask
        compact: true      # Strip spaces/punctuation and fold Traditional/radical variants
        all_of:
          - '(?:[\x{3400}-\x{4dbf}]\x{5973}|\x{5466}\x{9495})'
    ```
  - **Veteran Member Exemption**: Pre-existing group members and members who joined at least `veteran_days` ago (default `7` days) are exempt from regex false positives; non-member comment-section passersby and newly joined users (<7 days) are strictly enforced.
- **Instant 3-Piece Enforcement & Alert Window**:
  - Deletes the triggering message immediately, executes `banChatMember(revoke_messages=true)` to purge the spammer's history and permanently ban them, or `banChatSenderChat` for external channel masks (automatically exempting the linked main channel itself and anonymous group admins).
  - Extracts all mentioned `@xxxbot` usernames: immediately purges any sleeper bots already in the group and arms a **60-second alert window** to catch follow-up inline bot (`via @bot`) accomplices, unauthorized bot additions, and impersonators.
- **Role-Based Notifications, Collapsible Spoilers & 1-Click Unban**:
  - Supports **many-to-many bindings** (1 group ➔ multiple admins, multiple groups ➔ 1 owner) via static `chat_admins` in `config.yaml` or superadmin DM commands (`/bind`, `/unbind`, `/bindings`). Delegated owners can only view and unban users in their own bound groups.
  - Audit cards wrap suspected spam in Telegram's native collapsible `<blockquote expandable>`, support per-admin **Spoiler masking** (`<tg-spoiler>`) toggled in the private `/panel` menu, and include a `[🔓 一键解封]` (1-click unban) button.

## Quick Start

### 1. Telegram Setup (One-Time)

1. Create a bot via [@BotFather](https://t.me/BotFather) and obtain your `bot_token`.
2. Send `/setprivacy` to `@BotFather` ➔ select your bot ➔ set to **`Disable`** (required to read all group/comment messages).
3. Add the bot to your channel discussion groups as an **Administrator** with:
   - `Delete messages`
   - `Ban users`
4. Send `/start` to your bot in a private chat so it is allowed to send you audit notifications and open the `/panel`.

### 2. Configuration

Edit `config.yaml` in the project root (copied from `config.example.yaml` and ignored by `.gitignore`):

```yaml
bot_token: "YOUR_TELEGRAM_BOT_TOKEN"
admin_ids:
  - YOUR_NUMERIC_TELEGRAM_ID
```

Validate your YAML configuration and regex rules:

```bash
make validate
```

### 3. Install & Run with systemd

```bash
make install-service
```

Common maintenance commands:

```bash
make status   # Check service status and memory usage
make logs     # Follow live logs (journalctl -u anti-spam-bot -f)
make restart  # Rebuild binary and restart service after changes
make test     # Run all unit tests
```

Once running, send `/panel` to your bot in DM to open the control panel (toggle Spoiler masks and manage group bindings).
