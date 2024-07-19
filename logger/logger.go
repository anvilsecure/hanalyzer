// logger/logger.go
package logger

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
)

// LogLevel defines the log levels.
type LogLevel int

var (
	Log *Logger = NewLogger()
)

const (
	INFO LogLevel = iota
	DEBUG
	ERROR
)

// Logger struct defines the logger.
type Logger struct {
	writer io.Writer
}

// NewLogger creates a new Logger.
func NewLogger() *Logger {
	return &Logger{
		writer: os.Stderr,
	}
}

// logMessage logs a message with the given log level and color.
func (l *Logger) logMessage(level LogLevel, message string) {
	currentTime := time.Now().Format("01/02/2006_15:04:05")
	var logPrefix, colorMessage string

	switch level {
	case INFO:
		logPrefix = "[INFO]"
		colorMessage = color.New(color.FgWhite).Sprintf("%s %s %s", logPrefix, currentTime, message)
	case DEBUG:
		logPrefix = "[DEBUG]"
		colorMessage = color.New(color.FgYellow).Sprintf("%s %s %s", logPrefix, currentTime, message)
	case ERROR:
		logPrefix = "[ERR]"
		colorMessage = color.New(color.FgRed).Sprintf("%s %s %s", logPrefix, currentTime, message)
	}

	fmt.Fprintln(l.writer, colorMessage)
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

// Error logs an error message.
func (l *Logger) Error(message string) {
	l.logMessage(ERROR, message)
}

// Errorf logs a formatted error message.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logMessagef(ERROR, format, args...)
}
