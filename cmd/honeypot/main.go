package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"darkscope/honeypot/internal/app"
	"darkscope/honeypot/internal/config"
)

func main() {
	configPath := flag.String("config", "configs/config.example.yaml", "path to configuration YAML file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "error", err)
		os.Exit(1)
	}
	slog.Info("config loaded", "path", *configPath)

	ctx, stop := app.SignalContext()
	defer stop()

	if err := app.RunWithSignals(ctx, cfg); err != nil && err != context.Canceled {
		slog.Error("application finished with error", "error", err)
		os.Exit(1)
	}
	fmt.Println("darkscope honeypot stopped gracefully")
}
