package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	appbot "anti-spam-bot/internal/bot"
	"anti-spam-bot/internal/config"
	"anti-spam-bot/internal/detector"
	"anti-spam-bot/internal/store"

	tgbot "github.com/go-telegram/bot"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to YAML configuration file")
	validateOnly := flag.Bool("validate", false, "validate config and regex rules, then exit")
	debugLog := flag.Bool("debug", false, "enable debug-level logging")
	flag.Parse()

	logLevel := slog.LevelInfo
	if *debugLog {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("load config failed", "err", err)
		os.Exit(1)
	}

	eng, err := detector.New(cfg)
	if err != nil {
		slog.Error("compile detection rules failed", "err", err)
		os.Exit(1)
	}

	if *validateOnly {
		slog.Info("configuration and regex rules are valid",
			"rules", len(cfg.Rules),
			"veteran_days", cfg.VeteranDays,
			"alert_window_seconds", cfg.AlertWindowSeconds,
		)
		return
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		slog.Error("open bbolt store failed", "db_path", cfg.DBPath, "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := st.Close(); err != nil {
			slog.Warn("close bbolt store error", "err", err)
		}
	}()

	handler := appbot.NewHandler(cfg, st, eng)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	b, err := tgbot.New(
		cfg.BotToken,
		tgbot.WithDefaultHandler(handler.BotDefaultHandler),
		tgbot.WithWorkers(4),
		tgbot.WithAllowedUpdates(tgbot.AllowedUpdates{
			"message",
			"edited_message",
			"chat_member",
			"my_chat_member",
			"callback_query",
		}),
		tgbot.WithErrorsHandler(func(err error) {
			slog.Warn("telegram bot polling error", "err", err)
		}),
	)
	if err != nil {
		slog.Error("init telegram bot failed (check bot_token and network)", "err", err)
		os.Exit(1)
	}

	handler.RegisterCommands(ctx, b)

	slog.Info("anti-spam bot started",
		"bot_id", b.ID(),
		"veteran_days", cfg.VeteranDays,
		"alert_window_seconds", cfg.AlertWindowSeconds,
		"rules_count", len(cfg.Rules),
		"log_chat_id", cfg.LogChatID,
	)

	b.Start(ctx)
	slog.Info("anti-spam bot stopped gracefully")
}
