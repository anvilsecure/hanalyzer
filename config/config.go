package config

import (
	"log/slog"
	"sync"

	"os"

	"github.com/goccy/go-yaml"
)

var (
	once     sync.Once
	instance Config
)

// DatabaseConfig struct to hold database configuration data
type Config struct {
	Host     string    `yaml:"host" validate:"required"`
	SID      string    `yaml:"sid" validate:"required"`
	Database DBConfig  `yaml:"database"`
	SSH      SSHConfig `yaml:"ssh"`
}

func Get() *Config {
	once.Do(func() {
		// a sane default configuration
		instance = Config{
			Host: "localhost",
			SID:  "HDB",
			Database: DBConfig{
				Port:     39015,
				Username: "SYSTEM",
				Password: "password",
			},
			SSH: SSHConfig{
				Port:               22,
				Username:           "root",
				Password:           "password",
				PrivateKey:         "",
				PrivateKeyPassword: "",
				IgnoreHostKey:      true,
			},
		}
	})

	return &instance
}

// LoadConfig reads and parses conf.yml file
func LoadFromFile(configFile string) *Config {
	// Check if the file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		slog.Error("config file does not exist", "config", configFile)
		return &instance
	}

	// Read config.yml file
	data, err := os.ReadFile(configFile)
	if err != nil {
		slog.Error("error reading config file", "error", err.Error())
		return &instance
	}

	// Parse YAML data into DatabaseConfig struct
	if err := yaml.Unmarshal(data, &instance); err != nil {
		slog.Error("error parsing config file", "error", err.Error())
		return &instance
	}

	return &instance
}
