# Telegram Channel Comment Anti-Spam Bot

轻量级、毫秒级响应的 Telegram 频道评论区反 Spam 机器人（Go + 纯 Go 嵌入式 BoltDB + systemd），专为小内存 VPS 优化（静态单二进制 ~6MB，常驻内存 <10MB，秒级编译不吃 Swap）。

## 核心特性

- **双模式评论区无缝兼容**：
  - **禁止加入的纯评论区**（配合 auto-kickout）：评论者均非群成员（`left`），触发规则 100% 拦截。
  - **允许加入聊天的评论区**：上线前已在群内的**存量老群友默认豁免**；上线后新入群成员通过 `chat_member` 实时记录入群时间，**满 7 天自动豁免**，未满 7 天触发即封。
- **三件套连坐处置**：
  - 秒删触发消息（覆盖 `message`、`edited_message` 正文与媒体 `caption`，自动剥离零宽混淆字符）。
  - 对普通用户执行 `banChatMember(revoke_messages=true)` 清空历史垃圾消息并永久拉黑；对外部马甲频道执行 `banChatSenderChat`（自动识别并豁免官方绑定的主频道本身与群匿名管理）。
  - 提取消息内所有 `@xxxbot` 名单：当场清剿已潜伏在群内的同名真 Bot，并开启 **60 秒高压警戒窗口**（拦截后续 Inline `via @bot` 同伙号、非法拉入 Bot 及同名伪装号）。
- **审计通知与一键解封**：
  - 每次封禁自动推送卡片至管理员私聊或指定日志群，支持点击 `[🔓 一键解封]` 按钮即时恢复误封用户。

## 快速上手

### 1. Telegram 侧准备（只需一次）

1. 在 [@BotFather](https://t.me/BotFather) 创建机器人获取 `bot_token`。
2. 在 `@BotFather` 发送 `/setprivacy` ➔ 选择该机器人 ➔ 点击 **`Disable`**（关闭隐私模式以读取所有群消息）。
3. 将机器人拉入你的几个频道评论区讨论群，设为**管理员**，勾选以下两项权限：
   - `Delete messages`（删除消息）
   - `Ban users`（封禁用户）
4. 如果用管理员个人私聊接收通知，记得先给你的机器人点一次 **Start**（发一条 `/start`），否则机器人无法主动给你发私聊。

### 2. 修改配置

编辑项目根目录下的 `config.yaml`（已从 `config.example.yaml` 生成，并被 `.gitignore` 忽略防泄密）：

```yaml
bot_token: "填入你的_BOT_TOKEN"
admin_ids:
  - 你的TG数字ID
```

校验配置与正则语法是否正确：

```bash
make validate
```

### 3. 启动 systemd 守护服务

```bash
make install-service
```

常用运维命令：

```bash
make status   # 查看运行状态与内存占用
make logs     # 实时查看日志 (journalctl -u anti-spam-bot -f)
make restart  # 修改代码或配置后重新编译并重启服务
make test     # 运行全部单元测试
```

启动后可私聊机器人发送 `/status` 查看实时运行状态与内存占用。
