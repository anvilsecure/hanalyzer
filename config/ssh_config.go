package config

type SSHConfig struct {
	Port               int    `yaml:"port"`
	Username           string `yaml:"username"`
	Password           string `yaml:"password"`
	PrivateKey         string `yaml:"private_key"`
	PrivateKeyPassword string `yaml:"private_key_password"`
	IgnoreHostKey      bool   `yaml:"ignore_host_key"`
}

func (s *SSHConfig) IsValid() bool {
	return s.Username != "" && (s.Password != "" || s.PrivateKey != "")
}
