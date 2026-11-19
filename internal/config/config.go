package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// RuleConfig defines a spam detection rule.
// Target controls what is inspected: "message" (default), "name" (sender display name / channel title),
// "any" (matches if either message or name matches), or "combined" (name + "\n" + message).
// When Compact is true, whitespace/punctuation separators are stripped and Traditional/radical variants
// are folded before matching, defeating comma/space/variant-character obfuscation.
type RuleConfig struct {
	Name    string   `yaml:"name"`
	Target  string   `yaml:"target,omitempty"`
	Compact bool     `yaml:"compact,omitempty"`
	AllOf   []string `yaml:"all_of"`
}

// Config holds the runtime configuration for the anti-spam bot.
type Config struct {
	BotToken             string       `yaml:"bot_token"`
	AdminIDs             []int64      `yaml:"admin_ids"`
	LogChatID            int64        `yaml:"log_chat_id"`
	AllowedChatIDs       []int64      `yaml:"allowed_chat_ids"`
	DBPath               string       `yaml:"db_path"`
	VeteranDays          int          `yaml:"veteran_days"`
	AlertWindowSeconds   int          `yaml:"alert_window_seconds"`
	BanAnyInlineInAlert  *bool        `yaml:"ban_any_inline_in_alert"`
	BlockKnownBadBots    *bool        `yaml:"block_known_bad_bots"`
	Rules                []RuleConfig `yaml:"rules"`
}

// DefaultRules returns the built-in anti-spam rules when none are specified in config.yaml.
func DefaultRules() []RuleConfig {
	return []RuleConfig{
		{
			Name:   "start_with_bot_mention",
			Target: "message",
			AllOf: []string{
				`(?i)(?:^|[\s"'(\[>])/start(?:\b|@)`,
				`(?i)@[a-z0-9_]{2,}bot\b`,
			},
		},
		{
			Name:   "bot_campaign_spam",
			Target: "message",
			AllOf: []string{
				`(?i)@[a-z0-9_]{2,}bot\b`,
				`(?i)(?:\bcampaign[_-]?\d+|\b[a-z]?[0-9a-f]{16,}\b)`,
			},
		},
		{
			Name:    "arrow_bio_bait",
			Target:  "message",
			Compact: true,
			AllOf: []string{
				`^(?:\x{2b05}|\x{2190}|\x{1f448})+(?:\x{597d}\x{770b}|\x{70b9}\x{6211}|\x{770b}\x{7b80}\x{4ecb}|\x{8fdb}\x{7b80}\x{4ecb}|\x{70b9}\x{5934}\x{50cf}|\x{770b}\x{4e3b}\x{9875})`,
			},
		},
		{
			Name:    "bio_redirect_spam",
			Target:  "any",
			Compact: true,
			AllOf: []string{
				`(?:\x{8fdb}\x{7b80}\x{4ecb}\x{770b}|\x{6bcf}\x{5929}\x{66f4}\x{65b0}\x{8fdb}\x{7b80}\x{4ecb})`,
			},
		},
		{
			Name:    "rare_homoglyph_spam",
			Target:  "any",
			Compact: true,
			AllOf: []string{
				`(?:[\x{3400}-\x{4dbf}]\x{5973}|\x{5466}\x{9495}|\x{5e7c}\x{9495}|\x{5466}\x{5973})`,
			},
		},
		{
			Name:    "obfuscated_illegal_ad",
			Target:  "any",
			Compact: true,
			AllOf: []string{
				`(?:\x{9b3c}\x{7236}|\x{5341}\x{5c81}\x{5973}\x{513f}|\x{5c0f}\x{4f84}\x{5973}|\x{5904}\x{5973}\x{819c}|\x{79c1}\x{5bc6}\x{89c6}\x{9891}|\x{88ab}\x{4fb5}\x{72af}\x{89c6}\x{9891}|\x{6697}\x{7f51}.{0,12}\x{89c6}\x{9891}|\x{5c0f}\x{5b66}\x{751f}.{0,8}\x{89c6}\x{9891})`,
			},
		},
	}
}

// Load reads, parses, and validates a YAML configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml %s: %w", path, err)
	}

	if cfg.BotToken == "" || cfg.BotToken == "YOUR_TELEGRAM_BOT_TOKEN" {
		return nil, errors.New("bot_token must be configured in config.yaml")
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "data/antispam.db"
	}
	if cfg.VeteranDays <= 0 {
		cfg.VeteranDays = 7
	}
	if cfg.AlertWindowSeconds <= 0 {
		cfg.AlertWindowSeconds = 60
	}
	if cfg.BanAnyInlineInAlert == nil {
		t := true
		cfg.BanAnyInlineInAlert = &t
	}
	if cfg.BlockKnownBadBots == nil {
		t := true
		cfg.BlockKnownBadBots = &t
	}
	if cfg.LogChatID == 0 && len(cfg.AdminIDs) > 0 {
		cfg.LogChatID = cfg.AdminIDs[0]
	}
	if len(cfg.Rules) == 0 {
		cfg.Rules = DefaultRules()
	}

	return &cfg, nil
}

// VeteranDuration returns the required membership duration to be treated as a veteran user.
func (c *Config) VeteranDuration() time.Duration {
	return time.Duration(c.VeteranDays) * 24 * time.Hour
}

// AlertWindowDuration returns the group alert/lockdown window duration after spam is detected.
func (c *Config) AlertWindowDuration() time.Duration {
	return time.Duration(c.AlertWindowSeconds) * time.Second
}

// IsAdmin checks whether userID is in AdminIDs.
func (c *Config) IsAdmin(userID int64) bool {
	for _, id := range c.AdminIDs {
		if id == userID {
			return true
		}
	}
	return false
}

// IsChatAllowed checks whether chatID is allowed by AllowedChatIDs (empty list allows all chats).
func (c *Config) IsChatAllowed(chatID int64) bool {
	if len(c.AllowedChatIDs) == 0 {
		return true
	}
	for _, id := range c.AllowedChatIDs {
		if id == chatID {
			return true
		}
	}
	return false
}
