package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
	"github.com/vaultify/vaultify/pkg/types"
)

// Load loads configuration from environment variables and config files
func Load() (*types.Config, error) {
	// Set defaults
	setDefaults()

	// Configure viper
	viper.SetConfigName("vaultify")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/vaultify")

	// Enable environment variable support
	viper.AutomaticEnv()
	viper.SetEnvPrefix("VAULTIFY")

	// Read config file if it exists
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is OK, we'll use defaults and env vars
	}

	// Unmarshal into config struct
	var config types.Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.grpc_port", 8080)
	viper.SetDefault("server.http_port", 8081)
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.base_url", "http://localhost:8081")

	// Redis defaults
	viper.SetDefault("redis.address", "localhost:6379")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)

	// Audit defaults
	viper.SetDefault("audit.log_file", "./audit.log")
	viper.SetDefault("audit.secret_key", generateDefaultAuditKey())

	// Crypto defaults
	viper.SetDefault("crypto.default_ttl", "24h")
	viper.SetDefault("crypto.max_ttl", "168h") // 7 days
	viper.SetDefault("crypto.default_max_reads", 1)
	viper.SetDefault("crypto.max_max_reads", 1000)
}

func validateConfig(config *types.Config) error {
	// Validate server config
	if config.Server.GRPCPort <= 0 || config.Server.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", config.Server.GRPCPort)
	}
	if config.Server.HTTPPort <= 0 || config.Server.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", config.Server.HTTPPort)
	}

	// Validate Redis config
	if config.Redis.Address == "" {
		return fmt.Errorf("Redis address is required")
	}

	// Validate audit config
	if config.Audit.LogFile == "" {
		return fmt.Errorf("audit log file is required")
	}
	if config.Audit.SecretKey == "" {
		return fmt.Errorf("audit secret key is required")
	}

	// Parse and validate crypto durations
	defaultTTL, err := time.ParseDuration(viper.GetString("crypto.default_ttl"))
	if err != nil {
		return fmt.Errorf("invalid default TTL: %w", err)
	}
	config.Crypto.DefaultTTL = defaultTTL

	maxTTL, err := time.ParseDuration(viper.GetString("crypto.max_ttl"))
	if err != nil {
		return fmt.Errorf("invalid max TTL: %w", err)
	}
	config.Crypto.MaxTTL = maxTTL

	if config.Crypto.DefaultTTL > config.Crypto.MaxTTL {
		return fmt.Errorf("default TTL cannot be greater than max TTL")
	}

	return nil
}

func generateDefaultAuditKey() string {
	// In production, this should be set explicitly via environment variable
	// This is just a fallback for development
	key := os.Getenv("VAULTIFY_AUDIT_SECRET_KEY")
	if key != "" {
		return key
	}
	
	// Generate a simple default key (NOT secure for production)
	return "dev-audit-key-change-in-production"
}