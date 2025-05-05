package config

type DBConfig struct {
	Port     int    `yaml:"port" validate:"required,gte=0,lte=65535"`
	Username string `yaml:"username" validate:"required"`
	Password string `yaml:"password" validate:"required"`
}

func (c *DBConfig) SetPort(port int) *DBConfig {
	c.Port = port
	return c
}

func (c *DBConfig) SetUsername(username string) *DBConfig {
	c.Username = username
	return c
}

func (c *DBConfig) SetPassword(password string) *DBConfig {
	c.Password = password
	return c
}
