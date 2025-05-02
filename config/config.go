package config

import (
	"log"
	"sync"

	"os"

	"gopkg.in/yaml.v2"
)

var (
	once     sync.Once
	instance Config
)

// DatabaseConfig struct to hold database configuration data
type Config struct {
	Host     string    `yaml:"host"`
	SID      string    `yaml:"sid"`
	Database DBConfig  `yaml:"database"`
	SSH      SSHConfig `yaml:"ssh"`
}

func InitConfig() *Config {
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
				Port:          22,
				Username:      "root",
				Password:      "password",
				IgnoreHostKey: true,
			},
		}
	})
}

// LoadConfig reads and parses conf.yml file
func LoadFromFile(configFile string) *Config {
	// Check if the file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("config file does not exist: %s", configFile)
		return &instance
	}

	// Read config.yml file
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("error reading config file: %v", err)
		return &instance
	}

	// Parse YAML data into DatabaseConfig struct
	if err := yaml.Unmarshal(data, &instance); err != nil {
		log.Printf("error parsing config file: %v", err)
		return &instance
	}

	return &instance
}
