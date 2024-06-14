package ssh

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"
)

var (
	SSHClient *ssh.Client
	sshCreds  SSHCreds
)

type SSHCreds struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

func readConf() {
	yamlFile := "ssh.conf.yaml"
	yamlData, err := os.ReadFile(yamlFile)
	if err != nil {
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
		sshCreds = SSHCreds{User: user, Password: password}
	} else {
		err = yaml.Unmarshal(yamlData, &sshCreds)
		if err != nil {
			log.Fatalf("Error parsing YAML: %v", err)
		}
	}
}

func init() {
	readConf()
	// Set up the SSH connection
	config := &ssh.ClientConfig{
		User: sshCreds.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshCreds.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	var err error
	SSHClient, err = ssh.Dial("tcp", "hxehost:22", config)
	if err != nil {
		log.Fatalf(err.Error())
	}
	sshCreds.Password = ""
	//defer SSHClient.Close()
}

func ExecCommand(cmd string) (string, error) {
	session, err := SSHClient.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return "", err
	}
	return string(output), nil
}
