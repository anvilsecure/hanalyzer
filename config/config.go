package config

import (
	"log"

	"os"

	"gopkg.in/yaml.v2"
)

var Conf Config

type DBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type HostConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type InstanceConfig struct {
	SID string `yaml:"sid"`
}

// DatabaseConfig struct to hold database configuration data
type Config struct {
	Database DBConfig       `yaml:"database"`
	Host     HostConfig     `yaml:"host"`
	Instance InstanceConfig `yaml:"instance"`
}

// LoadConfig reads and parses conf.yml file
func init() {
	// Read config.yml file
	data, err := os.ReadFile("conf.yml")
	if err != nil {
		log.Fatalf("error reading config file: %v", err)
	}
	// Parse YAML data into DatabaseConfig struct
	if err := yaml.Unmarshal(data, &Conf); err != nil {
		log.Fatalf("error parsing config file: %v", err)
	}
}
