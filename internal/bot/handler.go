package bot

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"anti-spam-bot/internal/config"
	"anti-spam-bot/internal/detector"
	"anti-spam-bot/internal/store"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// Handler coordinates Telegram update routing, 7-day veteran checks, and spam enforcement.
type Handler struct {
	cfg       *config.Config
	store     *store.Store
	engine    *detector.Engine
	startedAt time.Time
	nowFunc   func() time.Time

	linkedMu    sync.RWMutex
	linkedChats map[int64]int64 // group chatID -> linked channel ID (0 if none, cached)
}

// NewHandler creates a new Handler instance.
func NewHandler(cfg *config.Config, st *store.Store, eng *detector.Engine) *Handler {
	return &Handler{
		cfg:         cfg,
		store:       st,
		engine:      eng,
		startedAt:   time.Now(),
		nowFunc:     time.Now,
		linkedChats: make(map[int64]int64),
	}
}

// SetNowFunc overrides the clock function (used for deterministic unit tests).
func (h *Handler) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		h.nowFunc = fn
	}
}

// BotDefaultHandler adapts HandleUpdate to github.com/go-telegram/bot's HandlerFunc signature.
func (h *Handler) BotDefaultHandler(ctx context.Context, b *tgbot.Bot, upd *models.Update) {
	h.HandleUpdate(ctx, b, upd)
}

// HandleUpdate processes any incoming Telegram update.
func (h *Handler) HandleUpdate(ctx context.Context, api TelegramAPI, upd *models.Update) {
	if upd == nil {
		return
	}
	now := h.nowFunc()

	if upd.CallbackQuery != nil {
		h.handleCallbackQuery(ctx, api, upd.CallbackQuery, now)
		return
	}
	if upd.ChatMember != nil {
		h.handleChatMember(ctx, api, upd.ChatMember, now)
		return
	}
	if upd.Message != nil {
		h.handleMessage(ctx, api, upd.Message, now)
		return
	}
	if upd.EditedMessage != nil {
		h.handleMessage(ctx, api, upd.EditedMessage, now)
		return
	}
	if upd.GuestMessage != nil {
		h.handleMessage(ctx, api, upd.GuestMessage, now)
		return
	}
}

func (h *Handler) handleMessage(ctx context.Context, api TelegramAPI, msg *models.Message, now time.Time) {
	if msg == nil {
		return
	}

	// Admin status command in private chat only.
	if msg.Chat.Type == models.ChatTypePrivate {
		if msg.From != nil && h.cfg.IsAdmin(msg.From.ID) {
			txt := strings.TrimSpace(msg.Text)
			if strings.HasPrefix(txt, "/status") || strings.HasPrefix(txt, "/start") {
				h.replyAdminStatus(ctx, api, msg.Chat.ID, now)
			}
		}
		return
	}

	// Only enforce in groups and supergroups (channel comment sections are supergroups).
	if msg.Chat.Type != models.ChatTypeGroup && msg.Chat.Type != models.ChatTypeSupergroup {
		return
	}
	if !h.cfg.IsChatAllowed(msg.Chat.ID) {
		return
	}

	// 1. Official channel auto-forward: cache linked channel ID and always exempt.
	if msg.IsAutomaticForward {
		if msg.SenderChat != nil && msg.SenderChat.ID != 0 {
			h.setLinkedChannel(msg.Chat.ID, msg.SenderChat.ID)
		}
		return
	}

	// 2. Hard system & configured admin exemptions.
	if msg.From != nil {
		switch msg.From.ID {
		case telegramServiceUserID, groupAnonymousBotUserID, api.ID():
			return
		}
		if h.cfg.IsAdmin(msg.From.ID) {
			return
		}
	}

	// 3. SenderChat (speaking as a channel or anonymous group admin).
	if msg.SenderChat != nil {
		if msg.SenderChat.ID == msg.Chat.ID {
			// Anonymous group admin speaking on behalf of the group itself.
			return
		}
		linkedID := h.getOrFetchLinkedChannel(ctx, api, msg.Chat.ID)
		if linkedID != 0 && msg.SenderChat.ID == linkedID {
			// The linked main channel itself replying in its own comment section.
			return
		}
	}

	// 4. Direct interception for non-admin external Bots (is_bot=true) speaking in the group/comment section.
	// Legitimate system bots (777000, 1087968824, self) and SenderChat (@Channel_Bot) are already handled above.
	if msg.SenderChat == nil && msg.From != nil && msg.From.IsBot {
		if !h.isGroupAdmin(ctx, api, msg.Chat.ID, msg.From.ID) {
			combinedText := msg.Text
			if msg.Caption != "" {
				if combinedText != "" {
					combinedText += "\n" + msg.Caption
				} else {
					combinedText = msg.Caption
				}
			}
			botReason := fmt.Sprintf("外部非管理员 Bot 发言 (@%s)", msg.From.Username)
			if h.store.IsKnownBadBot(msg.From.Username) {
				botReason = fmt.Sprintf("黑名单恶意 Bot 发言 (@%s)", msg.From.Username)
			}
			if msg.From.Username != "" {
				h.store.AddBadBotsMemory([]string{msg.From.Username})
				_ = h.store.AddBadBots(ctx, msg.Chat.ID, []string{msg.From.Username}, now)
			}
			h.enforceMessage(ctx, api, msg, botReason, combinedText, now)
			return
		}
		return
	}

	// 5. Combine Text + Caption for regex & alert inspection.
	combinedText := msg.Text
	if msg.Caption != "" {
		if combinedText != "" {
			combinedText += "\n" + msg.Caption
		} else {
			combinedText = msg.Caption
		}
	}

	mc := detector.MessageContext{
		ChatID: msg.Chat.ID,
		Text:   combinedText,
	}
	if msg.ViaBot != nil {
		mc.ViaBotUsername = msg.ViaBot.Username
	}
	if msg.SenderChat != nil {
		mc.SenderUsername = msg.SenderChat.Username
		mc.SenderFullName = msg.SenderChat.Title
	} else if msg.From != nil {
		mc.SenderUsername = msg.From.Username
		mc.SenderFullName = formatUserFullName(msg.From)
	}

	alertHit, alertReason := h.engine.CheckAlertAndBadBots(mc, h.store.IsKnownBadBot, now)
	ruleHit, ruleName, extractedBots := h.engine.MatchRules(combinedText)

	if !alertHit && !ruleHit {
		// Fast path: 0 DB queries, 0 Telegram API calls.
		return
	}

	// Immediately arm in-memory bad-bot blacklist & 60s alert window BEFORE any HTTP calls (0ms latency)
	// so concurrent worker goroutines immediately catch any bots replying milliseconds later.
	if ruleHit {
		h.store.AddBadBotsMemory(extractedBots)
		h.engine.TriggerAlert(msg.Chat.ID, extractedBots, now)
	}

	// 6. Fallback exemption: group admins and members who have been in the group >= 7 days.
	// Note: External SenderChat (channel masks) are never group members and never exempt.
	isExternalChannelMask := msg.SenderChat != nil
	if !isExternalChannelMask && msg.From != nil {
		if h.isExemptUser(ctx, api, msg.Chat.ID, msg.From, now) {
			slog.Debug("veteran/admin user exempted from rule match",
				"chat_id", msg.Chat.ID,
				"user_id", msg.From.ID,
				"rule", ruleName,
			)
			return
		}
	}

	// 7. Execute 3-piece enforcement + sleeper bot purge + persist bad bots.
	reason := alertReason
	if ruleHit {
		reason = fmt.Sprintf("命中规则 [%s]", ruleName)
		if len(extractedBots) > 0 {
			if err := h.store.AddBadBots(ctx, msg.Chat.ID, extractedBots, now); err != nil {
				slog.Warn("save bad bots failed", "err", err)
			}
		}
	}
	h.enforceMessage(ctx, api, msg, reason, combinedText, now)

	if ruleHit {
		h.purgeSleeperBots(ctx, api, msg.Chat, extractedBots, now)
	}
}

func (h *Handler) handleChatMember(ctx context.Context, api TelegramAPI, cm *models.ChatMemberUpdated, now time.Time) {
	if cm == nil {
		return
	}
	if cm.Chat.Type != models.ChatTypeGroup && cm.Chat.Type != models.ChatTypeSupergroup {
		return
	}
	chatID := cm.Chat.ID
	if !h.cfg.IsChatAllowed(chatID) {
		return
	}

	target := extractMemberUser(cm.NewChatMember)
	if target == nil {
		target = extractMemberUser(cm.OldChatMember)
	}
	if target == nil || target.ID == api.ID() {
		return
	}

	oldActive := isActiveMember(cm.OldChatMember)
	newActive := isActiveMember(cm.NewChatMember)

	if !oldActive && newActive {
		if err := h.store.RecordMemberJoin(ctx, chatID, target.ID, target.Username, target.IsBot, now); err != nil {
			slog.Warn("record member join failed", "chat_id", chatID, "user_id", target.ID, "err", err)
		}

		// If a non-admin adds a bot during an active alert window (or adds a known bad bot), ban immediately.
		if target.IsBot {
			addedByAdmin := h.cfg.IsAdmin(cm.From.ID) || h.isGroupAdmin(ctx, api, chatID, cm.From.ID)
			if !addedByAdmin && (h.store.IsKnownBadBot(target.Username) || h.engine.IsInAlert(chatID, now)) {
				h.banUserDirect(
					ctx, api, cm.Chat,
					target.ID, formatUserFullName(target), target.Username,
					"警戒窗口内或黑名单非法拉入 Bot",
					now,
				)
				if cm.From.ID != 0 && cm.From.ID != target.ID && !h.isExemptUser(ctx, api, chatID, &cm.From, now) {
					h.banUserDirect(
						ctx, api, cm.Chat,
						cm.From.ID, formatUserFullName(&cm.From), cm.From.Username,
						fmt.Sprintf("非法拉入恶意 Bot (@%s)", target.Username),
						now,
					)
				}
			}
		}
		return
	}

	if oldActive && !newActive {
		if err := h.store.RecordMemberLeave(ctx, chatID, target.ID, now); err != nil {
			slog.Warn("record member leave failed", "chat_id", chatID, "user_id", target.ID, "err", err)
		}
		return
	}

	if newActive && target.Username != "" {
		_ = h.store.UpdateMemberUsername(ctx, chatID, target.ID, target.Username, target.IsBot, now)
	}
}

// isExemptUser checks if user is a configured admin, group admin/owner, pre-existing legacy member,
// or a member who joined the group at least VeteranDuration (7 days) ago.
func (h *Handler) isExemptUser(ctx context.Context, api TelegramAPI, chatID int64, user *models.User, now time.Time) bool {
	if user == nil {
		return false
	}
	if h.cfg.IsAdmin(user.ID) {
		return true
	}

	rec, err := h.store.GetMember(ctx, chatID, user.ID)
	if err != nil {
		slog.Warn("query member record failed", "chat_id", chatID, "user_id", user.ID, "err", err)
	}

	// Fast local cache hit for already-verified legacy veterans or members past the 7-day threshold.
	if rec != nil && rec.InChat {
		if rec.IsLegacy {
			return true
		}
		if !rec.JoinedAt.IsZero() && now.Sub(rec.JoinedAt) >= h.cfg.VeteranDuration() {
			return true
		}
	}

	// Query live Telegram chat member status to check admin rights and current membership.
	cm, err := api.GetChatMember(ctx, &tgbot.GetChatMemberParams{
		ChatID: chatID,
		UserID: user.ID,
	})
	if err != nil || cm == nil {
		slog.Warn("getChatMember failed during exemption check", "chat_id", chatID, "user_id", user.ID, "err", err)
		return false
	}

	if isAdminChatMember(*cm) {
		return true
	}
	if !isActiveMember(*cm) {
		// Not in group (e.g., comment-only group where auto-kickout is active, or non-member commenter).
		return false
	}

	// User IS currently an active member of this group.
	if rec == nil {
		// No join record exists after bot deployment -> pre-existing legacy member! Exempt and cache.
		_ = h.store.MarkLegacyVeteran(ctx, chatID, user.ID, user.Username, now)
		return true
	}
	if rec.IsLegacy {
		return true
	}
	if !rec.InChat {
		// Rejoined while bot missed an event; start fresh timer from now -> not yet 7 days.
		_ = h.store.RecordMemberJoin(ctx, chatID, user.ID, user.Username, user.IsBot, now)
		return false
	}
	return !rec.JoinedAt.IsZero() && now.Sub(rec.JoinedAt) >= h.cfg.VeteranDuration()
}

func (h *Handler) isGroupAdmin(ctx context.Context, api TelegramAPI, chatID, userID int64) bool {
	if userID == 0 {
		return false
	}
	cm, err := api.GetChatMember(ctx, &tgbot.GetChatMemberParams{
		ChatID: chatID,
		UserID: userID,
	})
	if err != nil || cm == nil {
		return false
	}
	return isAdminChatMember(*cm)
}

func (h *Handler) setLinkedChannel(chatID, linkedID int64) {
	h.linkedMu.Lock()
	h.linkedChats[chatID] = linkedID
	h.linkedMu.Unlock()
}

func (h *Handler) getOrFetchLinkedChannel(ctx context.Context, api TelegramAPI, chatID int64) int64 {
	h.linkedMu.RLock()
	linkedID, cached := h.linkedChats[chatID]
	h.linkedMu.RUnlock()
	if cached {
		return linkedID
	}

	info, err := api.GetChat(ctx, &tgbot.GetChatParams{ChatID: chatID})
	if err != nil || info == nil {
		slog.Warn("getChat for linked_chat_id failed", "chat_id", chatID, "err", err)
		return 0
	}
	h.setLinkedChannel(chatID, info.LinkedChatID)
	return info.LinkedChatID
}

func (h *Handler) replyAdminStatus(ctx context.Context, api TelegramAPI, chatID int64, now time.Time) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	uptime := now.Sub(h.startedAt).Round(time.Second)

	msg := fmt.Sprintf(
		"✅ <b>Anti-Spam Bot 运行正常</b>\n"+
			"• <b>运行时长:</b> <code>%s</code>\n"+
			"• <b>内存占用 (Alloc):</b> <code>%.2f MB</code>\n"+
			"• <b>老群友豁免阈值:</b> <code>%d 天</code>\n"+
			"• <b>触发警戒窗口:</b> <code>%d 秒</code>\n"+
			"• <b>加载规则数:</b> <code>%d 条</code>",
		uptime,
		float64(ms.Alloc)/(1024*1024),
		h.cfg.VeteranDays,
		h.cfg.AlertWindowSeconds,
		len(h.cfg.Rules),
	)
	_, _ = api.SendMessage(ctx, &tgbot.SendMessageParams{
		ChatID:    chatID,
		Text:      msg,
		ParseMode: models.ParseModeHTML,
	})
}
