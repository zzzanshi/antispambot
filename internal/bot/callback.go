package bot

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

func callbackChatAndMsgID(cb *models.CallbackQuery) (chatID int64, msgID int, ok bool) {
	if cb.Message.Message != nil {
		return cb.Message.Message.Chat.ID, cb.Message.Message.ID, true
	}
	if cb.Message.InaccessibleMessage != nil {
		return cb.Message.InaccessibleMessage.Chat.ID, cb.Message.InaccessibleMessage.MessageID, true
	}
	return 0, 0, false
}

func (h *Handler) handleCallbackQuery(ctx context.Context, api TelegramAPI, cb *models.CallbackQuery, now time.Time) {
	if cb == nil {
		return
	}
	if strings.HasPrefix(cb.Data, "panel:") {
		h.handlePanelCallback(ctx, api, cb, now)
		return
	}
	if strings.HasPrefix(cb.Data, "unban:") {
		h.handleUnbanCallback(ctx, api, cb, now)
		return
	}
}

func (h *Handler) handlePanelCallback(ctx context.Context, api TelegramAPI, cb *models.CallbackQuery, now time.Time) {
	if !h.canAccessPanel(cb.From.ID) {
		_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
			CallbackQueryID: cb.ID,
			Text:            "⛔ 无权访问控制面板",
			ShowAlert:       true,
		})
		return
	}

	var toast string
	switch cb.Data {
	case "panel:toggle_spoiler":
		next := !h.isSpoilerEnabled(cb.From.ID)
		if err := h.store.SetUserSpoiler(cb.From.ID, next); err != nil {
			slog.Error("save spoiler preference failed", "user_id", cb.From.ID, "err", err)
			_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
				CallbackQueryID: cb.ID,
				Text:            "保存设置失败: " + err.Error(),
				ShowAlert:       true,
			})
			return
		}
		if next {
			toast = "🙈 已开启 Spoiler 遮罩"
		} else {
			toast = "👁 已关闭 Spoiler 遮罩（保留折叠）"
		}
	case "panel:refresh":
		toast = "🔄 面板已刷新"
	default:
		return
	}

	if chatID, msgID, ok := callbackChatAndMsgID(cb); ok {
		text, kb := h.buildPanelView(cb.From.ID, now)
		_, _ = api.EditMessageText(ctx, &tgbot.EditMessageTextParams{
			ChatID:      chatID,
			MessageID:   msgID,
			Text:        text,
			ParseMode:   models.ParseModeHTML,
			ReplyMarkup: kb,
		})
	}

	_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
		CallbackQueryID: cb.ID,
		Text:            toast,
	})
}

func (h *Handler) handleUnbanCallback(ctx context.Context, api TelegramAPI, cb *models.CallbackQuery, now time.Time) {
	idStr := strings.TrimPrefix(cb.Data, "unban:")
	auditID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
			CallbackQueryID: cb.ID,
			Text:            "无效的记录 ID",
			ShowAlert:       true,
		})
		return
	}

	entry, err := h.store.GetAuditLog(ctx, auditID)
	if err != nil || entry == nil {
		_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
			CallbackQueryID: cb.ID,
			Text:            "未找到对应的封禁记录",
			ShowAlert:       true,
		})
		return
	}

	// Only superadmins or bound owners/admins of entry.ChatID may unban.
	if !h.canManageChat(cb.From.ID, entry.ChatID) {
		_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
			CallbackQueryID: cb.ID,
			Text:            "⛔ 无权解封该群组的用户",
			ShowAlert:       true,
		})
		return
	}

	spoiler := h.isSpoilerEnabled(cb.From.ID)

	if entry.UnbannedBy != 0 {
		if chatID, msgID, ok := callbackChatAndMsgID(cb); ok {
			disablePreview := true
			statusLine := fmt.Sprintf("✅ <b>此前已由管理员 (<code>%d</code>) 解封</b>", entry.UnbannedBy)
			_, _ = api.EditMessageText(ctx, &tgbot.EditMessageTextParams{
				ChatID:             chatID,
				MessageID:          msgID,
				Text:               formatAuditHTML(entry, spoiler, statusLine),
				ParseMode:          models.ParseModeHTML,
				LinkPreviewOptions: &models.LinkPreviewOptions{IsDisabled: &disablePreview},
			})
		}
		_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
			CallbackQueryID: cb.ID,
			Text:            "该目标此前已解封",
		})
		return
	}

	if entry.SenderChatID != 0 {
		if _, err := api.UnbanChatSenderChat(ctx, &tgbot.UnbanChatSenderChatParams{
			ChatID:       entry.ChatID,
			SenderChatID: entry.SenderChatID,
		}); err != nil {
			slog.Error("unban sender_chat failed", "audit_id", auditID, "err", err)
			_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
				CallbackQueryID: cb.ID,
				Text:            "解封频道马甲失败: " + err.Error(),
				ShowAlert:       true,
			})
			return
		}
	} else if entry.TargetUserID != 0 {
		if _, err := api.UnbanChatMember(ctx, &tgbot.UnbanChatMemberParams{
			ChatID:       entry.ChatID,
			UserID:       entry.TargetUserID,
			OnlyIfBanned: true,
		}); err != nil {
			slog.Error("unban user failed", "audit_id", auditID, "err", err)
			_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
				CallbackQueryID: cb.ID,
				Text:            "解封用户失败: " + err.Error(),
				ShowAlert:       true,
			})
			return
		}
	}

	if err := h.store.MarkAuditUnbanned(ctx, auditID, cb.From.ID, now); err != nil {
		slog.Warn("mark audit unbanned failed", "audit_id", auditID, "err", err)
	}

	adminLabel := formatUserFullName(&cb.From)
	if adminLabel == "" {
		adminLabel = fmt.Sprintf("%d", cb.From.ID)
	}
	statusLine := fmt.Sprintf("✅ <b>已由 %s (<code>%d</code>) 解封</b>", escapeHTML(adminLabel), cb.From.ID)

	if chatID, msgID, ok := callbackChatAndMsgID(cb); ok {
		disablePreview := true
		_, _ = api.EditMessageText(ctx, &tgbot.EditMessageTextParams{
			ChatID:             chatID,
			MessageID:          msgID,
			Text:               formatAuditHTML(entry, spoiler, statusLine),
			ParseMode:          models.ParseModeHTML,
			LinkPreviewOptions: &models.LinkPreviewOptions{IsDisabled: &disablePreview},
		})
	}

	_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
		CallbackQueryID: cb.ID,
		Text:            "✅ 解封成功",
	})
}
