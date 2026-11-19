package bot

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"anti-spam-bot/internal/store"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

// enforceMessage executes the 3-piece enforcement (delete message + ban + revoke history)
// concurrently and dispatches an audit notification with a 1-click unban button.
func (h *Handler) enforceMessage(ctx context.Context, api TelegramAPI, msg *models.Message, reason string, rawContent string, now time.Time) {
	chatID := msg.Chat.ID
	chatTitle := msg.Chat.Title
	if chatTitle == "" {
		chatTitle = fmt.Sprintf("%d", chatID)
	}

	entry := &store.AuditEntry{
		ChatID:    chatID,
		ChatTitle: chatTitle,
		Reason:    reason,
		Snippet:   truncateSnippet(rawContent, 300),
		CreatedAt: now,
	}

	hasSenderChat := msg.SenderChat != nil && msg.SenderChat.ID != chatID
	if !hasSenderChat && msg.From == nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// 1. Delete the triggering spam message immediately in parallel with the ban.
	go func() {
		defer wg.Done()
		if _, err := api.DeleteMessage(ctx, &tgbot.DeleteMessageParams{
			ChatID:    chatID,
			MessageID: msg.ID,
		}); err != nil {
			slog.Warn("delete spam message failed", "chat_id", chatID, "msg_id", msg.ID, "err", err)
		}
	}()

	// 2. Ban either the external SenderChat (channel mask) or the User (with RevokeMessages=true).
	if hasSenderChat {
		entry.SenderChatID = msg.SenderChat.ID
		entry.TargetName = msg.SenderChat.Title
		entry.TargetUsername = msg.SenderChat.Username

		go func() {
			defer wg.Done()
			if _, err := api.BanChatSenderChat(ctx, &tgbot.BanChatSenderChatParams{
				ChatID:       chatID,
				SenderChatID: msg.SenderChat.ID,
			}); err != nil {
				slog.Error("ban sender_chat failed", "chat_id", chatID, "sender_chat_id", msg.SenderChat.ID, "err", err)
			} else {
				slog.Info("banned spam sender_chat",
					"chat_id", chatID,
					"sender_chat_id", msg.SenderChat.ID,
					"title", msg.SenderChat.Title,
					"reason", reason,
				)
			}
		}()
	} else {
		entry.TargetUserID = msg.From.ID
		entry.TargetName = formatUserFullName(msg.From)
		entry.TargetUsername = msg.From.Username

		go func() {
			defer wg.Done()
			if _, err := api.BanChatMember(ctx, &tgbot.BanChatMemberParams{
				ChatID:         chatID,
				UserID:         msg.From.ID,
				RevokeMessages: true,
			}); err != nil {
				slog.Error("ban user failed", "chat_id", chatID, "user_id", msg.From.ID, "err", err)
			} else {
				_ = h.store.RecordMemberLeave(ctx, chatID, msg.From.ID, now)
				slog.Info("banned spam user",
					"chat_id", chatID,
					"user_id", msg.From.ID,
					"username", msg.From.Username,
					"reason", reason,
				)
			}
		}()
	}

	wg.Wait()

	// 3. Persist audit log and notify admin/log channel.
	h.recordAndNotifyAudit(ctx, api, entry)
}

// banUserDirect bans a user/bot by ID (e.g., sleeper bot in group or unauthorized bot inviter) and logs an audit entry.
func (h *Handler) banUserDirect(ctx context.Context, api TelegramAPI, chat models.Chat, targetID int64, targetName, targetUsername, reason string, now time.Time) {
	chatID := chat.ID
	chatTitle := chat.Title
	if chatTitle == "" {
		chatTitle = fmt.Sprintf("%d", chatID)
	}

	if _, err := api.BanChatMember(ctx, &tgbot.BanChatMemberParams{
		ChatID:         chatID,
		UserID:         targetID,
		RevokeMessages: true,
	}); err != nil {
		slog.Error("direct ban user failed", "chat_id", chatID, "user_id", targetID, "reason", reason, "err", err)
		return
	}
	_ = h.store.RecordMemberLeave(ctx, chatID, targetID, now)
	slog.Info("direct banned user/bot", "chat_id", chatID, "user_id", targetID, "username", targetUsername, "reason", reason)

	entry := &store.AuditEntry{
		ChatID:         chatID,
		ChatTitle:      chatTitle,
		TargetUserID:   targetID,
		TargetName:     targetName,
		TargetUsername: targetUsername,
		Reason:         reason,
		CreatedAt:      now,
	}
	h.recordAndNotifyAudit(ctx, api, entry)
}

// purgeSleeperBots checks if any extracted @xxxbot usernames are already present in the group and bans them immediately.
func (h *Handler) purgeSleeperBots(ctx context.Context, api TelegramAPI, chat models.Chat, botUsernames []string, now time.Time) {
	if len(botUsernames) == 0 {
		return
	}
	records, err := h.store.FindMembersByUsernames(ctx, chat.ID, botUsernames)
	if err != nil {
		slog.Warn("query sleeper bots failed", "chat_id", chat.ID, "err", err)
		return
	}
	for _, rec := range records {
		if rec.UserID == api.ID() || h.cfg.IsAdmin(rec.UserID) {
			continue
		}
		h.banUserDirect(
			ctx, api, chat,
			rec.UserID, "@"+rec.Username, rec.Username,
			fmt.Sprintf("清剿被唤醒的群内潜伏 Bot (@%s)", rec.Username),
			now,
		)
	}
}

func (h *Handler) recordAndNotifyAudit(ctx context.Context, api TelegramAPI, entry *store.AuditEntry) {
	auditID, err := h.store.InsertAuditLog(ctx, entry)
	if err != nil {
		slog.Error("insert audit log failed", "err", err)
		return
	}

	recipients := h.resolveAuditRecipients(entry.ChatID)
	if len(recipients) == 0 {
		return
	}

	disablePreview := true
	kb := &models.InlineKeyboardMarkup{
		InlineKeyboard: [][]models.InlineKeyboardButton{
			{
				{
					Text:         "🔓 一键解封",
					CallbackData: fmt.Sprintf("unban:%d", auditID),
				},
			},
		},
	}

	for _, rcptID := range recipients {
		spoiler := h.isSpoilerEnabled(rcptID)
		text := formatAuditHTML(entry, spoiler, "")
		if _, err := api.SendMessage(ctx, &tgbot.SendMessageParams{
			ChatID:             rcptID,
			Text:               text,
			ParseMode:          models.ParseModeHTML,
			LinkPreviewOptions: &models.LinkPreviewOptions{IsDisabled: &disablePreview},
			ReplyMarkup:        kb,
		}); err != nil {
			slog.Warn("send audit notification failed", "recipient_id", rcptID, "audit_id", auditID, "err", err)
		}
	}
}

func wrapSpoiler(escaped string, spoiler bool) string {
	if !spoiler || escaped == "" {
		return escaped
	}
	return "<tg-spoiler>" + escaped + "</tg-spoiler>"
}

func formatAuditHTML(e *store.AuditEntry, spoiler bool, statusLine string) string {
	var b strings.Builder
	b.WriteString("🛡 <b>反 Spam 三件套已执行</b>\n")
	fmt.Fprintf(&b, "<b>群组:</b> %s (<code>%d</code>)\n", escapeHTML(e.ChatTitle), e.ChatID)

	if e.SenderChatID != 0 {
		uname := ""
		if e.TargetUsername != "" {
			uname = " @" + escapeHTML(e.TargetUsername)
		}
		fmt.Fprintf(&b, "<b>频道马甲:</b> %s%s (<code>%d</code>)\n",
			wrapSpoiler(escapeHTML(e.TargetName), spoiler), uname, e.SenderChatID)
	} else {
		uname := ""
		if e.TargetUsername != "" {
			uname = " @" + escapeHTML(e.TargetUsername)
		}
		name := e.TargetName
		if name == "" {
			name = "Unknown"
		}
		fmt.Fprintf(&b, "<b>用户:</b> %s%s (<code>%d</code>)\n",
			wrapSpoiler(escapeHTML(name), spoiler), uname, e.TargetUserID)
	}

	fmt.Fprintf(&b, "<b>原因:</b> %s\n", escapeHTML(e.Reason))
	if e.Snippet != "" {
		fmt.Fprintf(&b, "<b>内容:</b>\n<blockquote expandable>%s</blockquote>\n",
			wrapSpoiler(escapeHTML(e.Snippet), spoiler))
	}
	if statusLine != "" {
		fmt.Fprintf(&b, "\n%s", statusLine)
	}
	return b.String()
}
