package config

import (
	"log"

	"os"

	"gopkg.in/yaml.v2"
)

var Conf Config

type DBConfig struct {
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type SSHConfig struct {
	Port               int    `yaml:"port"`
	Username           string `yaml:"username"`
	Password           string `yaml:"password"`
	PrivateKey         string `yaml:"private_key"`
	PrivateKeyPassword string `yaml:"private_key_password"`
	IgnoreHostKey      bool   `yaml:"ignore_host_key"`
}

// DatabaseConfig struct to hold database configuration data
type Config struct {
	Host     string    `yaml:"host"`
	SID      string    `yaml:"sid"`
	Database DBConfig  `yaml:"database"`
	SSH      SSHConfig `yaml:"ssh"`
}

// LoadConfig reads and parses conf.yml file
func LoadConfig(configFile string) error {
	// Read config.yml file
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("error reading config file: %v", err)
		return err
	}
	// Parse YAML data into DatabaseConfig struct
	if err := yaml.Unmarshal(data, &Conf); err != nil {
		log.Printf("error parsing config file: %v", err)
		return err
	}
	return nil
}
