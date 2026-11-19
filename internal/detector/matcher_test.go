package detector

import (
	"reflect"
	"testing"
	"time"

	"anti-spam-bot/internal/config"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	tBool := true
	cfg := &config.Config{
		VeteranDays:         7,
		AlertWindowSeconds:  60,
		BanAnyInlineInAlert: &tBool,
		BlockKnownBadBots:   &tBool,
		Rules:               config.DefaultRules(),
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New engine failed: %v", err)
	}
	return eng
}

func TestMatchRules_UserSampleAndVariants(t *testing.T) {
	eng := newTestEngine(t)

	sample := " /start 818 @bh5lzkymbot\n@wbqrmwkzbot\n@hnfbwfkx7fbot "
	matched, rule, bots := eng.MatchRules(sample)
	if !matched {
		t.Fatalf("expected user sample to match spam rule")
	}
	if rule != "start_with_bot_mention" {
		t.Fatalf("unexpected rule name: %s", rule)
	}
	wantBots := []string{"bh5lzkymbot", "wbqrmwkzbot", "hnfbwfkx7fbot"}
	if !reflect.DeepEqual(bots, wantBots) {
		t.Fatalf("extracted bots = %v, want %v", bots, wantBots)
	}

	variants := []string{
		"/start@bh5lzkymbot",
		"@wbqrmwkzbot /start 999",
		"/st\u200bart 818 @bh5lzk\u200dymbot", // zero-width obfuscation
		"点这里\n/START 1024 @SomeScam_Bot",
	}
	for _, v := range variants {
		ok, _, _ := eng.MatchRules(v)
		if !ok {
			t.Errorf("expected variant %q to match", v)
		}
	}

	benign := []string{
		"这个话题很有意思，大家怎么看？",
		"看看文档 https://example.com/start 里有说明 @ mybot",
		"https://docs.site.org/startup @helperbot",
		"/start 818 @normal_human_user",
		"可以用 @music_dl_bot 下载音乐",
	}
	for _, b := range benign {
		ok, r, _ := eng.MatchRules(b)
		if ok {
			t.Errorf("expected benign message %q NOT to match, but matched rule %s", b, r)
		}
	}
}

func TestAlertWindowAndBadBots(t *testing.T) {
	eng := newTestEngine(t)
	chatID := int64(-100123456)
	t0 := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)

	badSet := map[string]bool{"bh5lzkymbot": true}
	isBad := func(u string) bool { return badSet[u] }

	eng.TriggerAlert(chatID, []string{"bh5lzkymbot", "wbqrmwkzbot"}, t0)
	if !eng.IsInAlert(chatID, t0.Add(30*time.Second)) {
		t.Fatalf("expected chat to be in alert at +30s")
	}

	// Within 60s window: any inline bot is caught
	hit, _ := eng.CheckAlertAndBadBots(MessageContext{
		ChatID:         chatID,
		ViaBotUsername: "random_inline_bot",
		Text:           "buy crypto now",
	}, isBad, t0.Add(30*time.Second))
	if !hit {
		t.Fatalf("expected inline bot during 60s alert window to be caught")
	}

	// After 61s: alert window expires, random inline bot is NOT caught
	if eng.IsInAlert(chatID, t0.Add(61*time.Second)) {
		t.Fatalf("expected alert window to expire after 60s")
	}
	hitAfter, _ := eng.CheckAlertAndBadBots(MessageContext{
		ChatID:         chatID,
		ViaBotUsername: "random_inline_bot",
		Text:           "normal inline query",
	}, isBad, t0.Add(61*time.Second))
	if hitAfter {
		t.Fatalf("expected random inline bot after window expiry NOT to be caught")
	}

	// Known bad bot remains permanently blocked even after 61s
	hitKnownBad, _ := eng.CheckAlertAndBadBots(MessageContext{
		ChatID:         chatID,
		ViaBotUsername: "bh5lzkymbot",
		Text:           "scam ad",
	}, isBad, t0.Add(24*time.Hour))
	if !hitKnownBad {
		t.Fatalf("expected permanently recorded bad bot to still be caught after window expiry")
	}
}

func TestMatchMessage_ObfuscatedSamplesAndDisplayName(t *testing.T) {
	eng := newTestEngine(t)

	// 1. Bot campaign without /start
	hit, rule, bots := eng.MatchMessage(MessageContext{
		Text: "@dsgdsuijsdogsbot campaign_001 g1794578972644d81cae60",
	})
	if !hit || rule != "bot_campaign_spam" {
		t.Fatalf("expected bot_campaign_spam match, got hit=%v rule=%s", hit, rule)
	}
	if !reflect.DeepEqual(bots, []string{"dsgdsuijsdogsbot"}) {
		t.Fatalf("expected extracted bot dsgdsuijsdogsbot, got %v", bots)
	}

	// 2. Obfuscated message samples (comma/space stuffed, Traditional/Simplified mixed, Ext-A rare char, bio bait)
	spamMessages := []string{
		"\u2b05\u9b3c\uff0c\u7236 \u5f3a \uff0c\u4e0a\u521d \uff0c\u4e00\u5973\uff0c \u5152",
		"\U0001f448\U0001f448\u9b3c\u7236\u5f3a\u4e0a\u5341\u5c81\u5973\u513f\u2764",
		"\u5206\u4eab\u521d\u4e00\u5c0f\u4f84\u5973\U0001f51e\u79c1\u5bc6\u89c6\u9891",
		"\u5904\u5973\u819c\u6e05\u6670\u53ef\u89c1",
		"\u8fdb\u7b80\u4ecb\u770b",
		"\u2190 \u597d\u770b",
		"\u5927\u91cf\u6697\u7f51\u34dc\u5973\uff0c\u5c0f\u5b66\u751f\u79c1\u5bc6\u89c6\u9891",
		"\u5927\u91cf\u34dc\u5973\uff0c\u5b78\u751f\u88ab\u4fb5\u72af\u8996\u983b",
		"\u6bcf\u5929\u66f4\u65b0\uff0c\u8fdb\u7b80\u4ecb\u770b",
		"\u5466 \u9495",
	}
	for i, s := range spamMessages {
		ok, r, _ := eng.MatchMessage(MessageContext{Text: s})
		if !ok {
			t.Errorf("spam sample #%d failed to match", i)
		} else if r == "" {
			t.Errorf("spam sample #%d matched with empty rule name", i)
		}
	}

	// 3. Filler comment ("1" / ".") from an account whose Display Name carries obfuscated spam
	for _, filler := range []string{"1", ".", " "} {
		ok, r, _ := eng.MatchMessage(MessageContext{
			SenderFullName: "\u5466 \u9495 \u8fdb\u7b80\u4ecb\u770b",
			Text:           filler,
		})
		if !ok {
			t.Errorf("expected filler %q with spam display name to match, got false (rule=%s)", filler, r)
		}
	}

	// 4. Normal users posting short comments ("1", ".", "好看", "视频不错") must NOT trigger false positives
	benignCases := []MessageContext{
		{SenderFullName: "Alice", Text: "1"},
		{SenderFullName: "Bob", Text: "."},
		{SenderFullName: "\u5f20\u4e09", Text: "\u597d\u770b\uff0c\u8c22\u8c22\u5206\u4eab"},
		{SenderFullName: "\u674e\u56db", Text: "\u8fd9\u4e2a\u89c6\u9891\u526a\u8f91\u5f97\u4e0d\u9519"},
	}
	for _, bc := range benignCases {
		if ok, r, _ := eng.MatchMessage(bc); ok {
			t.Errorf("false positive on benign case %+v (matched rule %s)", bc, r)
		}
	}
}
