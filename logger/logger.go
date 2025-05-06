// logger/logger.go
package logger

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

const (
	logTimeFormat = "20060102_150405"
)

var logLevel = new(slog.LevelVar)

func init() {
	// Initialize the logger with default settings
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(h))
}

// NewLogger creates a new Logger.
func SetOutput(outputPath string) {
	currentTime := time.Now().Format(logTimeFormat)
	fileName := fmt.Sprintf("hanalyzer_warnings_%s.log", currentTime)
	filePath := filepath.Join(outputPath, fileName)

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Error("error opening file", "file", fileName, "error", err.Error())
		os.Exit(1)
	}

	h := slog.NewTextHandler(f, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(h))
}

func SetLevel(level string) {
	switch level {
	case "DEBUG":
		logLevel.Set(slog.LevelDebug)
	case "INFO":
		logLevel.Set(slog.LevelInfo)
	case "WARN":
		logLevel.Set(slog.LevelWarn)
	case "ERROR":
		logLevel.Set(slog.LevelError)
	default:
		slog.Error("invalid log level", "level", level)
		os.Exit(1)
	}
}
