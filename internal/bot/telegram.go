package bot

import (
	"context"
	"html"
	"strings"
	"unicode/utf8"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

const (
	telegramServiceUserID    int64 = 777000     // Telegram official channel forward service
	groupAnonymousBotUserID  int64 = 1087968824 // @GroupAnonymousBot
	channelMaskBotUserID     int64 = 136817688  // @Channel_Bot (speaking as a channel)
)

// TelegramAPI abstracts *tgbot.Bot for clean dependency injection and unit testing.
type TelegramAPI interface {
	ID() int64
	DeleteMessage(ctx context.Context, params *tgbot.DeleteMessageParams) (bool, error)
	BanChatMember(ctx context.Context, params *tgbot.BanChatMemberParams) (bool, error)
	UnbanChatMember(ctx context.Context, params *tgbot.UnbanChatMemberParams) (bool, error)
	BanChatSenderChat(ctx context.Context, params *tgbot.BanChatSenderChatParams) (bool, error)
	UnbanChatSenderChat(ctx context.Context, params *tgbot.UnbanChatSenderChatParams) (bool, error)
	GetChat(ctx context.Context, params *tgbot.GetChatParams) (*models.ChatFullInfo, error)
	GetChatMember(ctx context.Context, params *tgbot.GetChatMemberParams) (*models.ChatMember, error)
	SendMessage(ctx context.Context, params *tgbot.SendMessageParams) (*models.Message, error)
	EditMessageText(ctx context.Context, params *tgbot.EditMessageTextParams) (*models.Message, error)
	AnswerCallbackQuery(ctx context.Context, params *tgbot.AnswerCallbackQueryParams) (bool, error)
}

func extractMemberUser(cm models.ChatMember) *models.User {
	switch cm.Type {
	case models.ChatMemberTypeOwner:
		if cm.Owner != nil {
			return cm.Owner.User
		}
	case models.ChatMemberTypeAdministrator:
		if cm.Administrator != nil {
			return &cm.Administrator.User
		}
	case models.ChatMemberTypeMember:
		if cm.Member != nil {
			return cm.Member.User
		}
	case models.ChatMemberTypeRestricted:
		if cm.Restricted != nil {
			return cm.Restricted.User
		}
	case models.ChatMemberTypeLeft:
		if cm.Left != nil {
			return cm.Left.User
		}
	case models.ChatMemberTypeBanned:
		if cm.Banned != nil {
			return cm.Banned.User
		}
	}
	return nil
}

func isActiveMember(cm models.ChatMember) bool {
	switch cm.Type {
	case models.ChatMemberTypeOwner, models.ChatMemberTypeAdministrator, models.ChatMemberTypeMember:
		return true
	case models.ChatMemberTypeRestricted:
		return cm.Restricted != nil && cm.Restricted.IsMember
	default:
		return false
	}
}

func isAdminChatMember(cm models.ChatMember) bool {
	return cm.Type == models.ChatMemberTypeOwner || cm.Type == models.ChatMemberTypeAdministrator
}

func formatUserFullName(u *models.User) string {
	if u == nil {
		return ""
	}
	full := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if full == "" && u.Username != "" {
		return "@" + u.Username
	}
	return full
}

func truncateSnippet(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes]) + "…"
}

func escapeHTML(s string) string {
	return html.EscapeString(s)
}
