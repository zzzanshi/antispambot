package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// RuleConfig defines a spam detection rule.
// All regex patterns in AllOf must match the normalized message text for the rule to trigger.
type RuleConfig struct {
	Name  string   `yaml:"name"`
	AllOf []string `yaml:"all_of"`
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
			Name: "start_with_bot_mention",
			AllOf: []string{
				`(?i)(?:^|[\s"'(\[>])/start(?:\b|@)`,
				`(?i)@[a-z0-9_]{2,}bot\b`,
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
