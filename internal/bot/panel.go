package bot

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// getEffectiveChatAdmins merges static config chat_admins and dynamic BoltDB bindings for chatID.
func (h *Handler) getEffectiveChatAdmins(chatID int64) []int64 {
	seen := make(map[int64]struct{})
	var out []int64

	add := func(ids []int64) {
		for _, id := range ids {
			if id == 0 {
				continue
			}
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				out = append(out, id)
			}
		}
	}

	if h.cfg.ChatAdmins != nil {
		add(h.cfg.ChatAdmins[chatID])
	}
	if dyn, err := h.store.GetChatBindings(chatID); err == nil {
		add(dyn)
	}
	slices.Sort(out)
	return out
}

// getAllEffectiveBindings returns all merged chatID -> []adminID mappings (static + dynamic).
func (h *Handler) getAllEffectiveBindings() map[int64][]int64 {
	merged := make(map[int64]map[int64]struct{})
	addPair := func(chatID, uid int64) {
		if chatID == 0 || uid == 0 {
			return
		}
		if merged[chatID] == nil {
			merged[chatID] = make(map[int64]struct{})
		}
		merged[chatID][uid] = struct{}{}
	}

	for cid, uids := range h.cfg.ChatAdmins {
		for _, uid := range uids {
			addPair(cid, uid)
		}
	}
	if dynAll, err := h.store.ListAllChatBindings(); err == nil {
		for cid, uids := range dynAll {
			for _, uid := range uids {
				addPair(cid, uid)
			}
		}
	}

	out := make(map[int64][]int64, len(merged))
	for cid, set := range merged {
		list := make([]int64, 0, len(set))
		for uid := range set {
			list = append(list, uid)
		}
		slices.Sort(list)
		out[cid] = list
	}
	return out
}

// getAdminManagedChats returns all chat IDs bound to userID (many groups -> 1 owner).
func (h *Handler) getAdminManagedChats(userID int64) []int64 {
	all := h.getAllEffectiveBindings()
	var chats []int64
	for cid, uids := range all {
		if slices.Contains(uids, userID) {
			chats = append(chats, cid)
		}
	}
	slices.Sort(chats)
	return chats
}

// canManageChat reports whether userID is a superadmin or a bound owner/admin of chatID.
func (h *Handler) canManageChat(userID, chatID int64) bool {
	if h.cfg.IsAdmin(userID) {
		return true
	}
	return slices.Contains(h.getEffectiveChatAdmins(chatID), userID)
}

// canAccessPanel reports whether userID is allowed to open the private settings panel.
func (h *Handler) canAccessPanel(userID int64) bool {
	if h.cfg.IsAdmin(userID) {
		return true
	}
	return len(h.getAdminManagedChats(userID)) > 0
}

// resolveAuditRecipients determines which chat/user IDs should receive audit notifications for chatID.
// Supports 1 chat -> N owners/admins and N chats -> 1 owner. Falls back to LogChatID when unbound.
func (h *Handler) resolveAuditRecipients(chatID int64) []int64 {
	admins := h.getEffectiveChatAdmins(chatID)
	if len(admins) == 0 {
		if h.cfg.LogChatID != 0 {
			return []int64{h.cfg.LogChatID}
		}
		return nil
	}

	// If a dedicated log group/channel (negative ID) is configured, carbon-copy it as well.
	if h.cfg.LogChatID < 0 && !slices.Contains(admins, h.cfg.LogChatID) {
		admins = append(admins, h.cfg.LogChatID)
	}
	return admins
}

// isSpoilerEnabled returns the effective spoiler preference for recipientID.
func (h *Handler) isSpoilerEnabled(recipientID int64) bool {
	if enabled, found, err := h.store.GetUserSpoiler(recipientID); err == nil && found {
		return enabled
	}
	return h.cfg.DefaultSpoiler()
}

func (h *Handler) buildPanelView(userID int64, now time.Time) (string, *models.InlineKeyboardMarkup) {
	isSuper := h.cfg.IsAdmin(userID)
	spoilerOn := h.isSpoilerEnabled(userID)

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	uptime := now.Sub(h.startedAt).Round(time.Second)

	spoilerText := "❌"
	toggleBtnText := "🙈 开启遮罩 (Spoiler)"
	if spoilerOn {
		spoilerText = "✅"
		toggleBtnText = "👁 关闭遮罩 (Spoiler)"
	}

	var b strings.Builder
	b.WriteString("⚙️ <b>Anti-Spam Bot 控制面板</b>\n")
	if isSuper {
		fmt.Fprintf(&b, "• <b>身份:</b> 超级管理员 (<code>%d</code>)\n", userID)
		fmt.Fprintf(&b, "• <b>运行时长:</b> <code>%s</code> | <b>内存:</b> <code>%.2f MB</code>\n", uptime, float64(ms.Alloc)/(1024*1024))
		fmt.Fprintf(&b, "• <b>规则数:</b> <code>%d 条</code> | <b>群友豁免:</b> <code>%d 天</code>\n", len(h.cfg.Rules), h.cfg.VeteranDays)
	} else {
		fmt.Fprintf(&b, "• <b>身份:</b> 群主/管理员 (<code>%d</code>)\n", userID)
	}
	fmt.Fprintf(&b, "• <b>推送遮罩 (Spoiler):</b> %s\n", spoilerText)

	if isSuper {
		all := h.getAllEffectiveBindings()
		b.WriteString("\n<b>📋 当前群组绑定关系:</b>\n")
		if len(all) == 0 {
			b.WriteString("<i>暂无单独绑定</i>\n")
		} else {
			cids := make([]int64, 0, len(all))
			for cid := range all {
				cids = append(cids, cid)
			}
			slices.Sort(cids)
			for _, cid := range cids {
				adminStrs := make([]string, 0, len(all[cid]))
				for _, uid := range all[cid] {
					adminStrs = append(adminStrs, fmt.Sprintf("<code>%d</code>", uid))
				}
				fmt.Fprintf(&b, "• 群 <code>%d</code> ➔ %s\n", cid, strings.Join(adminStrs, ", "))
			}
		}
	} else {
		chats := h.getAdminManagedChats(userID)
		b.WriteString("\n<b>📋 我管理的群组:</b>\n")
		for _, cid := range chats {
			fmt.Fprintf(&b, "• <code>%d</code>\n", cid)
		}
	}

	kb := &models.InlineKeyboardMarkup{
		InlineKeyboard: [][]models.InlineKeyboardButton{
			{
				{Text: toggleBtnText, CallbackData: "panel:toggle_spoiler"},
			},
			{
				{Text: "🔄 刷新面板", CallbackData: "panel:refresh"},
			},
		},
	}
	return b.String(), kb
}

func (h *Handler) sendAdminPanel(ctx context.Context, api TelegramAPI, userID, chatID int64, now time.Time) {
	text, kb := h.buildPanelView(userID, now)
	_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
		ChatID:      chatID,
		Text:        text,
		ParseMode:   models.ParseModeHTML,
		ReplyMarkup: kb,
	})
}

func (h *Handler) handleBindCommand(ctx context.Context, api TelegramAPI, msg *models.Message) {
	parts := strings.Fields(msg.Text)
	if len(parts) < 3 {
		_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
			ChatID:    msg.Chat.ID,
			ParseMode: models.ParseModeHTML,
			Text:      "用法: <code>/bind &lt;群ID&gt; &lt;群主/管理员ID&gt; [更多ID...]</code>\n示例: <code>/bind -1002626586289 123456789 987654321</code>",
		})
		return
	}

	chatID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || chatID >= 0 {
		_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
			ChatID: msg.Chat.ID,
			Text:   "❌ 群 ID 格式无效（超级群 ID 通常为 -100 开头的负数）",
		})
		return
	}

	var adminIDs []int64
	for _, raw := range parts[2:] {
		uid, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || uid <= 0 {
			_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
				ChatID: msg.Chat.ID,
				Text:   fmt.Sprintf("❌ 无效的用户 ID: %s", raw),
			})
			return
		}
		adminIDs = append(adminIDs, uid)
	}

	if err := h.store.BindChatAdmins(chatID, adminIDs); err != nil {
		_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
			ChatID: msg.Chat.ID,
			Text:   "❌ 绑定保存失败: " + err.Error(),
		})
		return
	}

	eff := h.getEffectiveChatAdmins(chatID)
	effStrs := make([]string, 0, len(eff))
	for _, id := range eff {
		effStrs = append(effStrs, fmt.Sprintf("<code>%d</code>", id))
	}
	_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
		ChatID:    msg.Chat.ID,
		ParseMode: models.ParseModeHTML,
		Text: fmt.Sprintf(
			"✅ <b>绑定成功</b>\n群 <code>%d</code> 当前绑定的群主/管理员: %s\n\n<i>💡 提示：新绑定的群主/管理员需先私聊本 Bot 点一次 /start 才能收到推送，且可发 /panel 自定义遮罩设置。</i>",
			chatID, strings.Join(effStrs, ", "),
		),
	})
}

func (h *Handler) handleUnbindCommand(ctx context.Context, api TelegramAPI, msg *models.Message) {
	parts := strings.Fields(msg.Text)
	if len(parts) != 3 {
		_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
			ChatID:    msg.Chat.ID,
			ParseMode: models.ParseModeHTML,
			Text:      "用法: <code>/unbind &lt;群ID&gt; &lt;群主/管理员ID&gt;</code>",
		})
		return
	}

	chatID, err1 := strconv.ParseInt(parts[1], 10, 64)
	adminID, err2 := strconv.ParseInt(parts[2], 10, 64)
	if err1 != nil || err2 != nil {
		_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
			ChatID: msg.Chat.ID,
			Text:   "❌ 参数必须是数字 ID",
		})
		return
	}

	removed, err := h.store.UnbindChatAdmin(chatID, adminID)
	if err != nil {
		_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
			ChatID: msg.Chat.ID,
			Text:   "❌ 解绑失败: " + err.Error(),
		})
		return
	}

	inStatic := slices.Contains(h.cfg.ChatAdmins[chatID], adminID)
	var reply string
	switch {
	case removed && inStatic:
		reply = fmt.Sprintf("⚠️ 已移除动态绑定，但 <code>%d</code> 仍在 <code>config.yaml</code> 的 <code>chat_admins</code> 静态配置中，请一并修改配置。", adminID)
	case removed:
		reply = fmt.Sprintf("✅ 已解除群 <code>%d</code> 与管理员 <code>%d</code> 的绑定。", chatID, adminID)
	case inStatic:
		reply = fmt.Sprintf("⚠️ 该绑定位于 <code>config.yaml</code> 的静态配置 <code>chat_admins</code> 中，请直接编辑配置文件移除。")
	default:
		reply = fmt.Sprintf("ℹ️ 群 <code>%d</code> 未绑定管理员 <code>%d</code>。", chatID, adminID)
	}

	_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
		ChatID:    msg.Chat.ID,
		ParseMode: models.ParseModeHTML,
		Text:      reply,
	})
}

func (h *Handler) handleBindingsCommand(ctx context.Context, api TelegramAPI, chatID int64) {
	all := h.getAllEffectiveBindings()
	if len(all) == 0 {
		_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
			ChatID:    chatID,
			ParseMode: models.ParseModeHTML,
			Text:      "📋 当前没有任何群主绑定记录（所有群均默认推送至 <code>log_chat_id</code>）。",
		})
		return
	}

	cids := make([]int64, 0, len(all))
	byAdmin := make(map[int64][]int64)
	for cid, uids := range all {
		cids = append(cids, cid)
		for _, uid := range uids {
			byAdmin[uid] = append(byAdmin[uid], cid)
		}
	}
	slices.Sort(cids)

	var b strings.Builder
	b.WriteString("<b>📋 按群组查看（1 群 ➔ 多管理员）:</b>\n")
	for _, cid := range cids {
		uids := make([]string, 0, len(all[cid]))
		for _, uid := range all[cid] {
			uids = append(uids, fmt.Sprintf("<code>%d</code>", uid))
		}
		fmt.Fprintf(&b, "• <code>%d</code> ➔ %s\n", cid, strings.Join(uids, ", "))
	}

	adminKeys := make([]int64, 0, len(byAdmin))
	for uid := range byAdmin {
		adminKeys = append(adminKeys, uid)
	}
	slices.Sort(adminKeys)

	b.WriteString("\n<b>👤 按管理员查看（1 群主 ➔ 多群组）:</b>\n")
	for _, uid := range adminKeys {
		slices.Sort(byAdmin[uid])
		cStrs := make([]string, 0, len(byAdmin[uid]))
		for _, cid := range byAdmin[uid] {
			cStrs = append(cStrs, fmt.Sprintf("<code>%d</code>", cid))
		}
		fmt.Fprintf(&b, "• <code>%d</code> ➔ %s\n", uid, strings.Join(cStrs, ", "))
	}

	_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
		ChatID:    chatID,
		ParseMode: models.ParseModeHTML,
		Text:      b.String(),
	})
}

// RegisterCommands configures Telegram's native "/" command autocomplete menu.
// Regular bound owners/admins only see /panel in private chats, while superadmins
// additionally see /bind, /unbind, and /bindings in their own private chat.
func (h *Handler) RegisterCommands(ctx context.Context, b *tgbot.Bot) {
	// Default private chat menu for bound group owners/admins
	if _, err := b.SetMyCommands(ctx, &tgbot.SetMyCommandsParams{
		Scope: &models.BotCommandScopeAllPrivateChats{},
		Commands: []models.BotCommand{
			{Command: "panel", Description: "打开控制面板（查询我管理的群组 & 遮罩设置）"},
		},
	}); err != nil {
		slog.Warn("register default private commands failed", "err", err)
	}

	// Superadmin-only private chat menu
	superCommands := []models.BotCommand{
		{Command: "panel", Description: "打开控制面板（状态 & Spoiler 遮罩）"},
		{Command: "bind", Description: "绑定群组与群主/管理员: /bind <群ID> <用户ID...>"},
		{Command: "unbind", Description: "解除绑定: /unbind <群ID> <用户ID>"},
		{Command: "bindings", Description: "查看全部群组绑定关系"},
	}
	for _, adminID := range h.cfg.AdminIDs {
		if _, err := b.SetMyCommands(ctx, &tgbot.SetMyCommandsParams{
			Scope:    &models.BotCommandScopeChat{ChatID: adminID},
			Commands: superCommands,
		}); err != nil {
			slog.Warn("register superadmin commands failed", "admin_id", adminID, "err", err)
		}
	}
}
