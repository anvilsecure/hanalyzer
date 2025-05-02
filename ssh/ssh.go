package ssh

import (
	"bytes"
	"hana/logger"
	"net"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	SSHClient   *ssh.Client
	sshCreds    SSHCreds
	AuthMethods []ssh.AuthMethod
)

type SSHCreds struct {
	Username    string     `yaml:"user"`
	Password    string     `yaml:"password"`
	PrivKey     ssh.Signer `yaml:"priv_key"`
	PrivKeyPass string     `yaml:"priv_key_pass"`
}

func Config() {
	var sshConfig *ssh.ClientConfig
	sshCreds.Username = cfg.SSH.Username
	if cfg.SSH.PrivateKey != "" {
		key, err := os.ReadFile(cfg.SSH.PrivateKey)
		if err != nil {
			logger.Log.Errorf("[SSH]Unable to read private key '%s': %s", cfg.SSH.PrivateKey, err.Error())
			os.Exit(1)
		}
		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			logger.Log.Errorf("[SSH]Unable to parse private key '%s': %s", cfg.SSH.PrivateKey, err.Error())
			os.Exit(1)
		}
		sshCreds.PrivKey = signer
		AuthMethods = append(AuthMethods, ssh.PublicKeys(sshCreds.PrivKey))
	} else if cfg.SSH.Password != "" {
		sshCreds.Password = cfg.SSH.Password
		AuthMethods = append(AuthMethods, ssh.Password(sshCreds.Password))
	}
	if sshCreds.Username != "" {
		// Set up the SSH connection
		sshConfig = &ssh.ClientConfig{
			User: sshCreds.Username,
			Auth: AuthMethods,
		}
		if cfg.SSH.IgnoreHostKey {
			sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
		} else {
			knownhostsFile := path.Join(os.Getenv("HOME"), "/.ssh/known_hosts")
			hostkeyCallback, err := knownhosts.New(knownhostsFile)
			if err != nil {
				logger.Log.Errorf("Error while reading '%s' file: %s", knownhostsFile, err.Error())
				os.Exit(1)
			}
			sshConfig.HostKeyCallback = hostkeyCallback
		}
	} else {
		askForCredentials()
	}

	var err error
	sshHost := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.SSH.Port))
	SSHClient, err = ssh.Dial("tcp", sshHost, sshConfig)
	if err != nil {
		logger.Log.Errorf("[ssh]Error during authentication process: %s", err.Error())
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
