package ssh

import (
	"fmt"
	"log"
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
		log.Fatalf(err.Error())
	}
	password := string(bytePassword)
	sshCreds = SSHCreds{Username: user, Password: password}
}
