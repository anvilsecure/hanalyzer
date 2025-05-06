package ssh

import (
	"fmt"
	"log/slog"
	"os"
	"syscall"

	"golang.org/x/term"
)

func askForCredentials() {
	// If the file doesn't exist, ask the user for input
	fmt.Print("Enter username: ")
	var user string
	fmt.Scanln(&user)
	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	password := string(bytePassword)
	sshCreds = SSHCreds{Username: user, Password: password}
}
