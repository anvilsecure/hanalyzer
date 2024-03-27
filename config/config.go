package config

import (
	"log"

	"os"

	"gopkg.in/yaml.v2"
)

var DBConfig DatabaseConfig

// DatabaseConfig struct to hold database configuration data
type DatabaseConfig struct {
	Database struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"database"`
}

// LoadConfig reads and parses conf.yml file
func init() {
	// Read config.yml file
	data, err := os.ReadFile("conf.yml")
	if err != nil {
		log.Fatalf("error reading config file: %v", err)
	}
	// Parse YAML data into DatabaseConfig struct
	if err := yaml.Unmarshal(data, &DBConfig); err != nil {
		log.Fatalf("error parsing config file: %v", err)
	}
}
