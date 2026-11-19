package detector

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"anti-spam-bot/internal/config"
)

var botMentionRegex = regexp.MustCompile(`(?i)@([a-z0-9_]{2,}bot)\b`)

type compiledRule struct {
	name    string
	target  string // "message", "name", "any", "combined"
	compact bool
	allOf   []*regexp.Regexp
}

type alertState struct {
	expiresAt time.Time
	bots      map[string]struct{}
}

// Engine performs fast regex rule matching, bot mention extraction, and 60s alert window tracking.
type Engine struct {
	rules               []compiledRule
	alertDuration       time.Duration
	banAnyInlineInAlert bool
	blockKnownBadBots   bool

	mu     sync.RWMutex
	alerts map[int64]*alertState
}

// New compiles all configured regex rules and initializes the Engine.
func New(cfg *config.Config) (*Engine, error) {
	compiled := make([]compiledRule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		if len(r.AllOf) == 0 {
			return nil, fmt.Errorf("rule %q has empty all_of patterns", r.Name)
		}
		reList := make([]*regexp.Regexp, 0, len(r.AllOf))
		for _, pat := range r.AllOf {
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("compile regex %q in rule %q: %w", pat, r.Name, err)
			}
			reList = append(reList, re)
		}
		target := strings.ToLower(strings.TrimSpace(r.Target))
		if target == "" {
			target = "message"
		}
		switch target {
		case "message", "name", "any", "combined":
		default:
			return nil, fmt.Errorf("rule %q has invalid target %q (expected message, name, any, or combined)", r.Name, r.Target)
		}
		compiled = append(compiled, compiledRule{
			name:    r.Name,
			target:  target,
			compact: r.Compact,
			allOf:   reList,
		})
	}

	banInline := true
	if cfg.BanAnyInlineInAlert != nil {
		banInline = *cfg.BanAnyInlineInAlert
	}
	blockBad := true
	if cfg.BlockKnownBadBots != nil {
		blockBad = *cfg.BlockKnownBadBots
	}

	return &Engine{
		rules:               compiled,
		alertDuration:       cfg.AlertWindowDuration(),
		banAnyInlineInAlert: banInline,
		blockKnownBadBots:   blockBad,
		alerts:              make(map[int64]*alertState),
	}, nil
}

// ExtractBotMentions extracts deduplicated lowercase bot usernames (without leading '@') from text.
func ExtractBotMentions(text string) []string {
	clean := NormalizeText(text)
	matches := botMentionRegex.FindAllStringSubmatch(clean, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		u := strings.ToLower(m[1])
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

func matchAll(allOf []*regexp.Regexp, s string) bool {
	if s == "" {
		return false
	}
	for _, re := range allOf {
		if !re.MatchString(s) {
			return false
		}
	}
	return true
}

// MatchRules evaluates configured spam rules against message text alone.
func (e *Engine) MatchRules(rawText string) (bool, string, []string) {
	return e.MatchMessage(MessageContext{Text: rawText})
}

// MatchMessage evaluates all configured spam rules against message text and sender display name.
// Returns (matched, ruleName, extractedBotUsernames).
func (e *Engine) MatchMessage(mc MessageContext) (bool, string, []string) {
	normMsg := NormalizeText(mc.Text)
	normName := NormalizeText(mc.SenderFullName)
	if normMsg == "" && normName == "" {
		return false, "", nil
	}

	var compactMsg, compactName string
	compactComputed := false
	ensureCompact := func() {
		if !compactComputed {
			compactMsg = CompactAndFold(mc.Text)
			compactName = CompactAndFold(mc.SenderFullName)
			compactComputed = true
		}
	}

	for _, rule := range e.rules {
		msgCandidate := normMsg
		nameCandidate := normName
		if rule.compact {
			ensureCompact()
			msgCandidate = compactMsg
			nameCandidate = compactName
		}

		var hit bool
		switch rule.target {
		case "message":
			hit = matchAll(rule.allOf, msgCandidate)
		case "name":
			hit = matchAll(rule.allOf, nameCandidate)
		case "any":
			hit = matchAll(rule.allOf, msgCandidate) || matchAll(rule.allOf, nameCandidate)
		case "combined":
			combined := nameCandidate
			if msgCandidate != "" {
				if combined != "" {
					combined += "\n" + msgCandidate
				} else {
					combined = msgCandidate
				}
			}
			hit = matchAll(rule.allOf, combined)
		}

		if hit {
			bots := ExtractBotMentions(normMsg + "\n" + normName)
			return true, rule.name, bots
		}
	}
	return false, "", nil
}

// TriggerAlert activates or extends the alert window for chatID and registers target bot usernames.
func (e *Engine) TriggerAlert(chatID int64, botUsernames []string, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	st, ok := e.alerts[chatID]
	if !ok || !now.Before(st.expiresAt) {
		st = &alertState{
			bots: make(map[string]struct{}),
		}
		e.alerts[chatID] = st
	}
	st.expiresAt = now.Add(e.alertDuration)
	for _, u := range botUsernames {
		clean := strings.ToLower(strings.TrimPrefix(u, "@"))
		if clean != "" {
			st.bots[clean] = struct{}{}
		}
	}
}

// IsInAlert reports whether chatID is currently within an active alert window.
func (e *Engine) IsInAlert(chatID int64, now time.Time) bool {
	e.mu.RLock()
	st, ok := e.alerts[chatID]
	if !ok {
		e.mu.RUnlock()
		return false
	}
	active := now.Before(st.expiresAt)
	e.mu.RUnlock()
	return active
}

// MessageContext carries message metadata for alert window & known-bad-bot inspection.
type MessageContext struct {
	ChatID         int64
	SenderUsername string
	SenderFullName string
	ViaBotUsername string
	Text           string
}

// CheckAlertAndBadBots checks whether a message hits known bad bots or active 60s alert window rules.
func (e *Engine) CheckAlertAndBadBots(mc MessageContext, isKnownBadBot func(string) bool, now time.Time) (bool, string) {
	viaBot := strings.ToLower(strings.TrimPrefix(mc.ViaBotUsername, "@"))
	senderUser := strings.ToLower(strings.TrimPrefix(mc.SenderUsername, "@"))
	senderNameLower := strings.ToLower(NormalizeText(mc.SenderFullName))
	mentionedBots := ExtractBotMentions(mc.Text)

	// 1. Check permanent known bad bots list (previously harvested from /start @xxxbot spam)
	if e.blockKnownBadBots && isKnownBadBot != nil {
		if viaBot != "" && isKnownBadBot(viaBot) {
			return true, fmt.Sprintf("调用黑名单恶意 Bot (via @%s)", viaBot)
		}
		if senderUser != "" && isKnownBadBot(senderUser) {
			return true, fmt.Sprintf("黑名单恶意 Bot 发言 (@%s)", senderUser)
		}
		for _, mb := range mentionedBots {
			if isKnownBadBot(mb) {
				return true, fmt.Sprintf("引流黑名单恶意 Bot (@%s)", mb)
			}
		}
	}

	// 2. Check active 60-second alert window for this group
	e.mu.RLock()
	st, hasAlert := e.alerts[mc.ChatID]
	var inAlert bool
	var alertBots map[string]struct{}
	if hasAlert && now.Before(st.expiresAt) {
		inAlert = true
		alertBots = make(map[string]struct{}, len(st.bots))
		for k := range st.bots {
			alertBots[k] = struct{}{}
		}
	}
	e.mu.RUnlock()

	if !inAlert {
		return false, ""
	}

	if viaBot != "" {
		if _, targeted := alertBots[viaBot]; targeted {
			return true, fmt.Sprintf("警戒窗口内目标 Bot 发言 (via @%s)", viaBot)
		}
		if e.banAnyInlineInAlert {
			return true, fmt.Sprintf("警戒窗口内 Inline Bot 发言 (via @%s)", viaBot)
		}
	}

	if senderUser != "" {
		if _, targeted := alertBots[senderUser]; targeted {
			return true, fmt.Sprintf("警戒窗口内目标账号发言 (@%s)", senderUser)
		}
		if strings.HasSuffix(senderUser, "bot") {
			return true, fmt.Sprintf("警戒窗口内疑似 Bot 账号发言 (@%s)", senderUser)
		}
	}

	for botName := range alertBots {
		if botName != "" && strings.Contains(senderNameLower, botName) {
			return true, fmt.Sprintf("警戒窗口内伪装目标 Bot 昵称发言 (%s)", botName)
		}
	}

	for _, mb := range mentionedBots {
		if _, targeted := alertBots[mb]; targeted {
			return true, fmt.Sprintf("警戒窗口内继续刷屏 @%s", mb)
		}
	}

	return false, ""
}
