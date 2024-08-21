// logger/logger.go
package logger

import (
	"fmt"
	"hana/utils"
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
	Log *Logger = NewLogger()
)

const (
	INFO LogLevel = iota
	DEBUG
	WARN
	ERROR
)

// Logger struct defines the logger.
type Logger struct {
	writer     io.Writer
	file       *os.File
	filePath   string
	OutputPath string
}

// NewLogger creates a new Logger.
func NewLogger() *Logger {
	return &Logger{
		writer: os.Stderr,
	}
}

// Init initializes the logger and sets up the file for WARN messages.
func init() {
	var err error
	Log.OutputPath, err = utils.PrepareOutputFolder()
	if err != nil {
		log.Fatalf("error while preparing output folder: %s\n", err.Error())
	}
	currentTime := time.Now().Format("01022006_150405")
	fileName := fmt.Sprintf("saphanalyzer_warnings_%s.log", currentTime)
	Log.filePath = filepath.Join(Log.OutputPath, fileName)
	file, err := os.OpenFile(Log.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("error opening file: %s", err.Error())
	}
	Log.file = file
}

func (l *Logger) CloseFile() {
	if l.file != nil {
		l.file.Close()
		if l.isFileEmpty() {
			os.Remove(l.filePath)
		}
		l.file = nil
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
		colorMessage = color.New(color.FgBlue).Sprintf("%s %s %s", logPrefix, currentTime, message)
	case ERROR:
		logPrefix = "[ERR]"
		colorMessage = color.New(color.FgRed).Sprintf("%s %s %s", logPrefix, currentTime, message)
	case WARN:
		logPrefix = "[WARN]"
		colorMessage = color.New(color.FgYellow).Sprintf("%s %s %s", logPrefix, currentTime, message)
		if l.file != nil {
			l.logToFile(logPrefix, currentTime, message)
		}
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
	if l.file != nil {
		logMessage := fmt.Sprintf("%s %s %s", logPrefix, currentTime, message)
		fmt.Fprintln(l.file, logMessage)
	}
}

// isFileEmpty checks if the log file is empty.
func (l *Logger) isFileEmpty() bool {
	fileInfo, err := os.Stat(l.filePath)
	if err != nil {
		return false
	}
	return fileInfo.Size() == 0
}
