# Telegram Channel Comment Anti-Spam Bot

**中文** | [English](README_EN.md)

轻量级、毫秒级响应的 Telegram 频道评论区反 Spam 机器人（Go + 纯 Go 嵌入式 BoltDB + systemd），专为小内存 VPS 优化（静态单二进制 ~6MB，常驻内存 <10MB，秒级编译不吃 Swap）。

> [!NOTE]
> **LLM Disclaimer**
>
> 本项目的全部代码 100% 由 AI 生成，维护者可能会保证项目的易用性，但无法保证代码质量。维护者也有可能使用 100% 复制粘贴的形式回答用户的问题，这是正常现象，还请知悉。

## 核心特性

- **可定制正则与反混淆规则引擎（Go RE2）**：
  - **多条件与匹配（`all_of`）**：每条规则包含一组 Go RE2 正则，顺序无关、全部命中即触发，天然线性时间复杂度 `O(N)` 防正则回溯 DoS，并支持 `\x{XXXX}` Unicode 码点转义。
  - **多目标联合检测（`target`）**：每条规则可指定检测对象——`message`（消息正文与媒体 `caption`，含 `edited_message`）、`name`（用户昵称或马甲频道名）、`any`（正文或昵称任一命中即封，专克「昵称藏广告 + 正文发 `1`/`.`」占位刷屏）、`combined`（昵称 + 正文拼接）。
  - **反混淆紧缩归一化（`compact: true`）**：开启后自动剥离零宽隐形字符（`\u200b`–`\u200f`、`\ufeff`、盲文空白等）、去除全部空格与标点拆字干扰、折叠全角 ASCII、常见繁简异体字及康熙部首（同时保留 `⬅`、`←`、`👈`、`🔞` 等符号锚点），使插标点/空格/繁简混用/生僻扩展区（CJK Ext-A `U+3400`–`U+4DBF`）绕过失效。
  - **内置 6 类默认规则**：覆盖 `/start ... @*bot` 引流、`@*bot campaign_*` 追踪码引流、开头箭头引导看简介、昵称/正文引导进简介、CJK 扩展 A 区生僻同形字与拆字违规引流；可在 `config.yaml` 中自由增删：
    ```yaml
    rules:
      - name: "start_with_bot_mention"
        target: "message"
        all_of:
          - '(?i)(?:^|[\s"''(\[>])/start(?:\b|@)'
          - '(?i)@[a-z0-9_]{2,}bot\b'

      - name: "rare_homoglyph_spam"
        target: "any"      # 同时检查正文与用户昵称/马甲名
        compact: true      # 自动去空格标点拆字 + 繁简/部首折叠
        all_of:
          - '(?:[\x{3400}-\x{4dbf}]\x{5973}|\x{5466}\x{9495})'
    ```
  - **群友豁免机制**：上线前已在群内的存量老成员及入群满 7 天（可配置 `veteran_days`）的群成员不受正则误伤；未加群的评论区路人及入群未满 7 天的新成员直接拦截。
- **三件套连坐处置**：
  - 秒删触发消息，对普通用户执行 `banChatMember(revoke_messages=true)` 清空历史垃圾消息并永久拉黑；对外部马甲频道执行 `banChatSenderChat`（自动识别并豁免官方绑定的主频道本身与群匿名管理）。
  - 提取消息内所有 `@xxxbot` 名单：当场清剿已潜伏在群内的同名真 Bot，并开启 **60 秒高压警戒窗口**（拦截后续 Inline `via @bot` 同伙号、非法拉入 Bot 及同名伪装号）。
- **分权推送、折叠遮罩与一键解封**：
  - 支持 **1 群 ➔ 多管理员 / 多群 ➔ 1 群主** 多对多绑定（支持 `config.yaml` 静态配置或超管私聊 `/bind`、`/unbind`、`/bindings` 动态管理），普通群主仅可查看并解封自己所绑群组。
  - 审计卡片正文默认采用可展开折叠块（`<blockquote expandable>`），并支持每位管理员在私聊 `/panel` 面板中独立切换 **Spoiler 遮罩**，附带 `[🔓 一键解封]` 按钮。

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

启动后可私聊机器人发送 `/panel` 打开控制面板（支持切换 Spoiler 遮罩与管理群组绑定）。
