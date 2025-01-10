package ssh

import (
	"bytes"
	"hana/config"
	"hana/logger"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	SSHClient *ssh.Client
	sshCreds  SSHCreds
)

type SSHCreds struct {
	Username string `yaml:"user"`
	Password string `yaml:"password"`
}

func Config() {
	var sshConfig *ssh.ClientConfig
	sshCreds = SSHCreds{
		Username: config.Conf.SSH.Username,
		Password: config.Conf.SSH.Password,
	}
	if sshCreds.Username != "" && sshCreds.Password != "" {
		// Set up the SSH connection
		sshConfig = &ssh.ClientConfig{
			User: sshCreds.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(sshCreds.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else {
		askForCredentials()
	}

	var err error
	sshHost := net.JoinHostPort(config.Conf.Host, strconv.Itoa(config.Conf.SSH.Port))
	SSHClient, err = ssh.Dial("tcp", sshHost, sshConfig)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
	sshCreds.Password = ""
	//defer SSHClient.Close()
}

func ExecCommand(cmd string) (string, string, error) {
	session, err := SSHClient.NewSession()
	if err != nil {
		return "", "", nil
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	err = session.Run(cmd)

	if err != nil {
		switch err.Error() {
		case "Process exited with status 2":
			if strings.Contains(stderrBuf.String(), "No such file or directory") {
				return stdoutBuf.String(), stderrBuf.String(), &NoSuchFileOrDirectory
			}
		default:
			return stdoutBuf.String(), stderrBuf.String(), err
		}
	}
	return stdoutBuf.String(), stderrBuf.String(), nil
}
