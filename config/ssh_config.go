package config

type SSHConfig struct {
	Port               int    `yaml:"port" validate:"required,gte=0,lte=65535"`
	Username           string `yaml:"username" validate:"required"`
	Password           string `yaml:"password" validate:"required"`
	PrivateKey         string `yaml:"private_key"`
	PrivateKeyPassword string `yaml:"private_key_password"`
	IgnoreHostKey      bool   `yaml:"ignore_host_key"`
}

func (s *SSHConfig) IsValid() bool {
	return s.Username != "" && (s.Password != "" || s.PrivateKey != "")
}

func (s *SSHConfig) SetPort(port int) *SSHConfig {
	s.Port = port
	return s
}

func (s *SSHConfig) SetUsername(username string) *SSHConfig {
	s.Username = username
	return s
}

func (s *SSHConfig) SetPassword(password string) *SSHConfig {
	s.Password = password
	return s
}

func (s *SSHConfig) SetPrivateKey(privateKey string) *SSHConfig {
	s.PrivateKey = privateKey
	return s
}

func (s *SSHConfig) SetPrivateKeyPassword(privateKeyPassword string) *SSHConfig {
	s.PrivateKeyPassword = privateKeyPassword
	return s
}

func (s *SSHConfig) SetIgnoreHostKey(ignoreHostKey bool) *SSHConfig {
	s.IgnoreHostKey = ignoreHostKey
	return s
}
