package bot

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anti-spam-bot/internal/config"
	"anti-spam-bot/internal/detector"
	"anti-spam-bot/internal/store"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
)

type fakeTelegram struct {
	botID          int64
	linkedChatID   int64
	memberStatuses map[int64]models.ChatMember

	deletedMsgs        []int
	bannedUsers        []int64
	unbannedUsers      []int64
	bannedSenderChats  []int64
	sentMessages       []*tgbot.SendMessageParams
	editedMessages     []*tgbot.EditMessageTextParams
	answeredCallbacks  []*tgbot.AnswerCallbackQueryParams
}

func newFakeTelegram() *fakeTelegram {
	return &fakeTelegram{
		botID:          999000111,
		memberStatuses: make(map[int64]models.ChatMember),
	}
}

func (f *fakeTelegram) ID() int64 { return f.botID }

func (f *fakeTelegram) DeleteMessage(_ context.Context, p *tgbot.DeleteMessageParams) (bool, error) {
	f.deletedMsgs = append(f.deletedMsgs, p.MessageID)
	return true, nil
}

func (f *fakeTelegram) BanChatMember(_ context.Context, p *tgbot.BanChatMemberParams) (bool, error) {
	f.bannedUsers = append(f.bannedUsers, p.UserID)
	return true, nil
}

func (f *fakeTelegram) UnbanChatMember(_ context.Context, p *tgbot.UnbanChatMemberParams) (bool, error) {
	f.unbannedUsers = append(f.unbannedUsers, p.UserID)
	return true, nil
}

func (f *fakeTelegram) BanChatSenderChat(_ context.Context, p *tgbot.BanChatSenderChatParams) (bool, error) {
	f.bannedSenderChats = append(f.bannedSenderChats, p.SenderChatID)
	return true, nil
}

func (f *fakeTelegram) UnbanChatSenderChat(_ context.Context, _ *tgbot.UnbanChatSenderChatParams) (bool, error) {
	return true, nil
}

func (f *fakeTelegram) GetChat(_ context.Context, _ *tgbot.GetChatParams) (*models.ChatFullInfo, error) {
	return &models.ChatFullInfo{LinkedChatID: f.linkedChatID}, nil
}

func (f *fakeTelegram) GetChatMember(_ context.Context, p *tgbot.GetChatMemberParams) (*models.ChatMember, error) {
	if cm, ok := f.memberStatuses[p.UserID]; ok {
		return &cm, nil
	}
	return &models.ChatMember{
		Type: models.ChatMemberTypeLeft,
		Left: &models.ChatMemberLeft{
			Status: models.ChatMemberTypeLeft,
			User:   &models.User{ID: p.UserID},
		},
	}, nil
}

func (f *fakeTelegram) SendMessage(_ context.Context, p *tgbot.SendMessageParams) (*models.Message, error) {
	f.sentMessages = append(f.sentMessages, p)
	return &models.Message{ID: len(f.sentMessages)}, nil
}

func (f *fakeTelegram) EditMessageText(_ context.Context, p *tgbot.EditMessageTextParams) (*models.Message, error) {
	f.editedMessages = append(f.editedMessages, p)
	return &models.Message{ID: p.MessageID}, nil
}

func (f *fakeTelegram) AnswerCallbackQuery(_ context.Context, p *tgbot.AnswerCallbackQueryParams) (bool, error) {
	f.answeredCallbacks = append(f.answeredCallbacks, p)
	return true, nil
}

func setupTestHandler(t *testing.T) (*Handler, *fakeTelegram, *time.Time) {
	t.Helper()
	tBool := true
	cfg := &config.Config{
		BotToken:            "999000111:TEST_TOKEN",
		AdminIDs:            []int64{10001},
		LogChatID:           10001,
		DBPath:              filepath.Join(t.TempDir(), "test.db"),
		VeteranDays:         7,
		AlertWindowSeconds:  60,
		BanAnyInlineInAlert: &tBool,
		BlockKnownBadBots:   &tBool,
		Rules:               config.DefaultRules(),
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open test sqlite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	eng, err := detector.New(cfg)
	if err != nil {
		t.Fatalf("new detector: %v", err)
	}
	h := NewHandler(cfg, st, eng)
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	h.SetNowFunc(func() time.Time { return now })
	return h, newFakeTelegram(), &now
}

func TestCommentOnlyGroup_SpammerSleeperAndAlertWindow(t *testing.T) {
	h, api, now := setupTestHandler(t)
	ctx := context.Background()
	chat := models.Chat{ID: -100555, Type: models.ChatTypeSupergroup, Title: "频道评论区"}

	// Simulate sleeper bot @wbqrmwkzbot having previously joined the group
	h.HandleUpdate(ctx, api, &models.Update{
		ChatMember: &models.ChatMemberUpdated{
			Chat: chat,
			From: models.User{ID: 10001}, // added earlier
			OldChatMember: models.ChatMember{
				Type: models.ChatMemberTypeLeft,
				Left: &models.ChatMemberLeft{User: &models.User{ID: 88802, Username: "wbqrmwkzbot", IsBot: true}},
			},
			NewChatMember: models.ChatMember{
				Type:   models.ChatMemberTypeMember,
				Member: &models.ChatMemberMember{User: &models.User{ID: 88802, Username: "wbqrmwkzbot", IsBot: true}},
			},
		},
	})

	// Non-member commenter (status=left in pure comment group) posts spam
	h.HandleUpdate(ctx, api, &models.Update{
		Message: &models.Message{
			ID:   501,
			Chat: chat,
			From: &models.User{ID: 77701, FirstName: "Spammer", Username: "spam_user1"},
			Text: " /start 818 @bh5lzkymbot\n@wbqrmwkzbot\n@hnfbwfkx7fbot ",
		},
	})

	if len(api.deletedMsgs) != 1 || api.deletedMsgs[0] != 501 {
		t.Fatalf("expected message 501 deleted, got %v", api.deletedMsgs)
	}
	// Both spammer (77701) AND sleeper bot (88802) should be banned!
	if len(api.bannedUsers) != 2 || api.bannedUsers[0] != 77701 || api.bannedUsers[1] != 88802 {
		t.Fatalf("expected [77701, 88802] banned, got %v", api.bannedUsers)
	}
	if len(api.sentMessages) != 2 {
		t.Fatalf("expected 2 audit messages sent, got %d", len(api.sentMessages))
	}

	// 15 seconds later: accomplice sends spam via inline bot during 60s alert window
	*now = now.Add(15 * time.Second)
	h.HandleUpdate(ctx, api, &models.Update{
		Message: &models.Message{
			ID:     502,
			Chat:   chat,
			From:   &models.User{ID: 77702, FirstName: "Accomplice"},
			ViaBot: &models.User{ID: 88801, Username: "bh5lzkymbot", IsBot: true},
			Text:   "点击领取空投福利",
		},
	})
	if len(api.deletedMsgs) != 2 || api.deletedMsgs[1] != 502 {
		t.Fatalf("expected inline bot spam 502 deleted, got %v", api.deletedMsgs)
	}
	if len(api.bannedUsers) != 3 || api.bannedUsers[2] != 77702 {
		t.Fatalf("expected accomplice 77702 banned, got %v", api.bannedUsers)
	}

	// Test 1-click Unban Callback by Admin (10001) on audit_id=1
	h.HandleUpdate(ctx, api, &models.Update{
		CallbackQuery: &models.CallbackQuery{
			ID:   "cb-1",
			From: models.User{ID: 10001, FirstName: "Owner"},
			Data: "unban:1",
			Message: models.MaybeInaccessibleMessage{
				Message: &models.Message{
					ID:   1,
					Chat: models.Chat{ID: 10001, Type: models.ChatTypePrivate},
				},
			},
		},
	})
	if len(api.unbannedUsers) != 1 || api.unbannedUsers[0] != 77701 {
		t.Fatalf("expected user 77701 unbanned via callback, got %v", api.unbannedUsers)
	}
	if len(api.editedMessages) != 1 || !strings.Contains(api.editedMessages[0].Text, "解封") {
		t.Fatalf("expected audit message edited with unban confirmation")
	}
}

func TestVeteran7DayAndLegacyExemption(t *testing.T) {
	h, api, now := setupTestHandler(t)
	ctx := context.Background()
	chat := models.Chat{ID: -100666, Type: models.ChatTypeSupergroup, Title: "开放讨论群"}

	// Case 1: Pre-existing Legacy Member (already in group before bot started -> no join record)
	legacyUser := &models.User{ID: 20001, FirstName: "OldTimer", Username: "oldtimer"}
	api.memberStatuses[20001] = models.ChatMember{
		Type:   models.ChatMemberTypeMember,
		Member: &models.ChatMemberMember{Status: models.ChatMemberTypeMember, User: legacyUser},
	}

	h.HandleUpdate(ctx, api, &models.Update{
		Message: &models.Message{
			ID:   601,
			Chat: chat,
			From: legacyUser,
			Text: "/start 818 @bh5lzkymbot",
		},
	})
	if len(api.bannedUsers) != 0 {
		t.Fatalf("expected legacy member 20001 to be exempt, but banned: %v", api.bannedUsers)
	}

	// Case 2: Newly joined user (< 7 days) SHOULD be banned
	newUser := &models.User{ID: 20002, FirstName: "Newbie"}
	api.memberStatuses[20002] = models.ChatMember{
		Type:   models.ChatMemberTypeMember,
		Member: &models.ChatMemberMember{Status: models.ChatMemberTypeMember, User: newUser},
	}
	h.HandleUpdate(ctx, api, &models.Update{
		ChatMember: &models.ChatMemberUpdated{
			Chat:          chat,
			From:          *newUser,
			OldChatMember: models.ChatMember{Type: models.ChatMemberTypeLeft, Left: &models.ChatMemberLeft{User: newUser}},
			NewChatMember: api.memberStatuses[20002],
		},
	})

	*now = now.Add(3 * 24 * time.Hour) // +3 days (< 7 days)
	h.HandleUpdate(ctx, api, &models.Update{
		Message: &models.Message{
			ID:   602,
			Chat: chat,
			From: newUser,
			Text: "/start 818 @bh5lzkymbot",
		},
	})
	if len(api.bannedUsers) != 1 || api.bannedUsers[0] != 20002 {
		t.Fatalf("expected 3-day newbie 20002 to be banned, got %v", api.bannedUsers)
	}

	// Case 3: Newly joined user who stays >= 7 days SHOULD be exempt
	vetUser := &models.User{ID: 20003, FirstName: "PatientMember"}
	api.memberStatuses[20003] = models.ChatMember{
		Type:   models.ChatMemberTypeMember,
		Member: &models.ChatMemberMember{Status: models.ChatMemberTypeMember, User: vetUser},
	}
	h.HandleUpdate(ctx, api, &models.Update{
		ChatMember: &models.ChatMemberUpdated{
			Chat:          chat,
			From:          *vetUser,
			OldChatMember: models.ChatMember{Type: models.ChatMemberTypeLeft, Left: &models.ChatMemberLeft{User: vetUser}},
			NewChatMember: api.memberStatuses[20003],
		},
	})

	*now = now.Add(7*24*time.Hour + time.Minute) // +7 days 1 minute
	h.HandleUpdate(ctx, api, &models.Update{
		Message: &models.Message{
			ID:   603,
			Chat: chat,
			From: vetUser,
			Text: "/start 818 @someotherbot",
		},
	})
	if len(api.bannedUsers) != 1 {
		t.Fatalf("expected 7-day member 20003 to be exempt, bannedUsers=%v", api.bannedUsers)
	}
}

func TestChannelMaskExemptionVsExternalMaskBan(t *testing.T) {
	h, api, _ := setupTestHandler(t)
	ctx := context.Background()
	api.linkedChatID = -100999888
	chat := models.Chat{ID: -100777, Type: models.ChatTypeSupergroup, Title: "主频道讨论组"}

	// Linked main channel itself posts a message containing /start @myofficialbot -> MUST be exempt
	h.HandleUpdate(ctx, api, &models.Update{
		Message: &models.Message{
			ID:         701,
			Chat:       chat,
			From:       &models.User{ID: channelMaskBotUserID, Username: "Channel_Bot", IsBot: true},
			SenderChat: &models.Chat{ID: -100999888, Type: models.ChatTypeChannel, Title: "我的官方主频道"},
			Text:       "抽奖请点 /start @myofficialbot",
		},
	})
	if len(api.bannedSenderChats) != 0 || len(api.deletedMsgs) != 0 {
		t.Fatalf("expected linked main channel to be exempt!")
	}

	// External scam channel posts spam using channel mask -> MUST delete + BanChatSenderChat
	h.HandleUpdate(ctx, api, &models.Update{
		Message: &models.Message{
			ID:         702,
			Chat:       chat,
			From:       &models.User{ID: channelMaskBotUserID, Username: "Channel_Bot", IsBot: true},
			SenderChat: &models.Chat{ID: -100444333, Type: models.ChatTypeChannel, Title: "博彩引流频道"},
			Text:       "/start 818 @bh5lzkymbot",
		},
	})
	if len(api.deletedMsgs) != 1 || api.deletedMsgs[0] != 702 {
		t.Fatalf("expected external channel spam deleted, got %v", api.deletedMsgs)
	}
	if len(api.bannedSenderChats) != 1 || api.bannedSenderChats[0] != -100444333 {
		t.Fatalf("expected external sender_chat -100444333 banned, got %v", api.bannedSenderChats)
	}
}
