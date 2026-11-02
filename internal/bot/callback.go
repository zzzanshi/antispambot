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

func (h *Handler) handleCallbackQuery(ctx context.Context, api TelegramAPI, cb *models.CallbackQuery, now time.Time) {
	if cb == nil || !strings.HasPrefix(cb.Data, "unban:") {
		return
	}

	if !h.cfg.IsAdmin(cb.From.ID) {
		_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
			CallbackQueryID: cb.ID,
			Text:            "⛔ 无权限执行解封操作（需在 config.yaml 的 admin_ids 中配置）",
			ShowAlert:       true,
		})
		return
	}

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

	if entry.UnbannedBy != 0 {
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

	if cb.Message.Message != nil {
		disablePreview := true
		_, _ = api.EditMessageText(ctx, &tgbot.EditMessageTextParams{
			ChatID:             cb.Message.Message.Chat.ID,
			MessageID:          cb.Message.Message.ID,
			Text:               formatAuditHTML(entry, statusLine),
			ParseMode:          models.ParseModeHTML,
			LinkPreviewOptions: &models.LinkPreviewOptions{IsDisabled: &disablePreview},
		})
	} else if cb.Message.InaccessibleMessage != nil {
		disablePreview := true
		_, _ = api.EditMessageText(ctx, &tgbot.EditMessageTextParams{
			ChatID:             cb.Message.InaccessibleMessage.Chat.ID,
			MessageID:          cb.Message.InaccessibleMessage.MessageID,
			Text:               formatAuditHTML(entry, statusLine),
			ParseMode:          models.ParseModeHTML,
			LinkPreviewOptions: &models.LinkPreviewOptions{IsDisabled: &disablePreview},
		})
	}

	_, _ = api.AnswerCallbackQuery(ctx, &tgbot.AnswerCallbackQueryParams{
		CallbackQueryID: cb.ID,
		Text:            "✅ 解封成功",
	})
}
