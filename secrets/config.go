package secrets

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/secrets/helper/common"
	"os"
)

// SecretsManagerConfig is the configuration that gets
// written to a single configuration file
type SecretsManagerConfig struct {
	Token     string                 `toml:",omitempty"` // Access token to the instance
	ServerURL string                 `toml:",omitempty"` // The URL of the running server
	Type      SecretsManagerType     `toml:",omitempty"` // The type of SecretsManager
	Name      string                 `toml:",omitempty"` // The name of the current node
	Namespace string                 `toml:",omitempty"` // The namespace of the service
	Extra     map[string]interface{} `toml:",omitempty"` // Any kind of arbitrary data
}

func (c *SecretsManagerConfig) Default() {
	c.Token = "default-token"
	c.Name = "RTFDefaultNode"
	c.Type = HashicorpVault
	c.ServerURL = "http://127.0.0.1:8200"
}

// WriteConfig writes the current configuration to the specified path
func (c *SecretsManagerConfig) WriteConfig(path string) error {
	jsonBytes, _ := json.MarshalIndent(c, "", " ")

	return common.SaveFileSafe(path, jsonBytes, 0660)
}

// ReadConfig reads the SecretsManagerConfig from the specified path
func ReadConfig(path string) (*SecretsManagerConfig, error) {
	configFile, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, readErr
	}

	config := &SecretsManagerConfig{}

	unmarshalErr := json.Unmarshal(configFile, &config)
	if unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return config, nil
}
