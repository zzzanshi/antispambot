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
