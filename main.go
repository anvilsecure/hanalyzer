package main

import (
	"hana/cmd"
	"hana/logger"
	"hana/presentation"
	"hana/utils"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Log.CloseFile()
		os.Exit(1)
	}()
	cmd.Execute()
	presentation.Render(utils.OutputPath)
	logger.Log.CloseFile()
}
