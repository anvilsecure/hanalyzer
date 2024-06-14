package utils

import (
	"github.com/fatih/color"
)

var (
	White   func(a ...interface{}) string
	Green   func(a ...interface{}) string
	Yellow  func(a ...interface{}) string
	Cyan    func(a ...interface{}) string
	Red     func(a ...interface{}) string
	Info    func(format string, a ...interface{})
	Error   func(format string, a ...interface{})
	Ok      func(format string, a ...interface{})
	Warning func(format string, a ...interface{})
	Title   func(format string, a ...interface{})
)

func init() {
	White = color.New(color.FgWhite).SprintFunc()
	Green = color.New(color.FgGreen).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
	Red = color.New(color.FgRed).SprintFunc()
	Cyan = color.New(color.FgCyan).SprintFunc()
	Info = color.New(color.FgWhite).PrintfFunc()
	Error = color.New(color.FgRed).PrintfFunc()
	Ok = color.New(color.FgGreen).PrintfFunc()
	Warning = color.New(color.FgYellow).PrintfFunc()
	Title = color.New(color.FgCyan).PrintfFunc()
}
