// logger/logger.go
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
)

// LogLevel defines the log levels.
type LogLevel int

var (
	Log *Logger
)

const (
	INFO LogLevel = iota
	DEBUG
	WARN
	ERROR
	logTimeFormat = "20060102_150405"
)

// Logger struct defines the logger.
type Logger struct {
	Writer       io.Writer
	File         *os.File
	FilePath     string
	OutputFolder string
}

// NewLogger creates a new Logger.
func NewLogger(outputPath string) *Logger {
	currentTime := time.Now().Format(logTimeFormat)
	fileName := fmt.Sprintf("saphanalyzer_warnings_%s.log", currentTime)
	filePath := filepath.Join(outputPath, fileName)
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("error opening file: %s", err.Error())
	}
	return &Logger{
		Writer:       os.Stderr,
		File:         file,
		FilePath:     filePath,
		OutputFolder: outputPath,
	}
}

func (l *Logger) CloseFile() {
	if l.File != nil {
		l.File.Close()
		if l.isFileEmpty() {
			os.Remove(l.FilePath)
		}
		l.File = nil
	}
}

// logMessage logs a message with the given log level and color.
func (l *Logger) logMessage(level LogLevel, message string) {
	currentTime := time.Now().Format(logTimeFormat)
	var logPrefix, colorMessage string

	switch level {
	case INFO:
		logPrefix = "[INFO]"
		colorMessage = color.New(color.FgWhite).Sprintf("%s %s %s", logPrefix, currentTime, message)
	case DEBUG:
		logPrefix = "[DEBUG]"
		colorMessage = color.New(color.FgBlue).Sprintf("%s %s %s", logPrefix, currentTime, message)
	case ERROR:
		logPrefix = "[ERR]"
		colorMessage = color.New(color.FgRed).Sprintf("%s %s %s", logPrefix, currentTime, message)
	case WARN:
		logPrefix = "[WARN]"
		colorMessage = color.New(color.FgYellow).Sprintf("%s %s %s", logPrefix, currentTime, message)
		if l.File != nil {
			l.logToFile(logPrefix, currentTime, message)
		}
	}

	fmt.Fprintln(l.Writer, colorMessage)
}

// logMessagef logs a formatted message with the given log level and color.
func (l *Logger) logMessagef(level LogLevel, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	l.logMessage(level, message)
}

// Info logs an info message.
func (l *Logger) Info(message string) {
	l.logMessage(INFO, message)
}

// Infof logs a formatted info message.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.logMessagef(INFO, format, args...)
}

// Debug logs a debug message.
func (l *Logger) Debug(message string) {
	l.logMessage(DEBUG, message)
}

// Debugf logs a formatted debug message.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logMessagef(DEBUG, format, args...)
}

// Warning logs an error message.
func (l *Logger) Warn(message string) {
	l.logMessage(WARN, message)
}

// Warning logs a formatted error message.
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.logMessagef(WARN, format, args...)
}

// Error logs an error message.
func (l *Logger) Error(message string) {
	l.logMessage(ERROR, message)
}

// Errorf logs a formatted error message.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logMessagef(ERROR, format, args...)
}

// logToFile logs a message to a file.
func (l *Logger) logToFile(logPrefix, currentTime, message string) {
	if l.File != nil {
		logMessage := fmt.Sprintf("%s %s %s", logPrefix, currentTime, message)
		fmt.Fprintln(l.File, logMessage)
	}
}

// isFileEmpty checks if the log file is empty.
func (l *Logger) isFileEmpty() bool {
	fileInfo, err := os.Stat(l.FilePath)
	if err != nil {
		return false
	}
	return fileInfo.Size() == 0
}
