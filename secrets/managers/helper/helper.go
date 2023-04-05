package helper

import (
	"errors"
	"github.com/ethereum/go-ethereum/secrets/managers"
	"github.com/ethereum/go-ethereum/secrets/managers/awsssm"
	"github.com/ethereum/go-ethereum/secrets/managers/gcpssm"
	"github.com/ethereum/go-ethereum/secrets/managers/hashicorpvault"
	"github.com/ethereum/go-ethereum/secrets/managers/local"
	"github.com/hashicorp/go-hclog"
)

// SetupLocalSecretsManager is a helper method for boilerplate local secrets manager setup
func SetupLocalSecretsManager(dataDir string) (managers.SecretsManager, error) {
	return local.SecretsManagerFactory(
		nil, // Local secrets manager doesn't require a config
		&managers.SecretsManagerParams{
			Logger: hclog.NewNullLogger(),
			Extra: map[string]interface{}{
				managers.Path: dataDir,
			},
		},
	)
}

// setupHashicorpVault is a helper method for boilerplate hashicorp vault secrets manager setup
func setupHashicorpVault(
	secretsConfig *managers.SecretsManagerConfig,
) (managers.SecretsManager, error) {
	return hashicorpvault.SecretsManagerFactory(
		secretsConfig,
		&managers.SecretsManagerParams{
			Logger: hclog.NewNullLogger(),
		},
	)
}

// setupAWSSSM is a helper method for boilerplate aws ssm secrets manager setup
func setupAWSSSM(
	secretsConfig *managers.SecretsManagerConfig,
) (managers.SecretsManager, error) {
	return awsssm.SecretsManagerFactory(
		secretsConfig,
		&managers.SecretsManagerParams{
			Logger: hclog.NewNullLogger(),
		},
	)
}

// setupGCPSSM is a helper method for boilerplate Google Cloud Computing secrets manager setup
func setupGCPSSM(
	secretsConfig *managers.SecretsManagerConfig,
) (managers.SecretsManager, error) {
	return gcpssm.SecretsManagerFactory(
		secretsConfig,
		&managers.SecretsManagerParams{
			Logger: hclog.NewNullLogger(),
		},
	)
}

// InitCloudSecretsManager returns the cloud secrets manager from the provided config
func InitCloudSecretsManager(secretsConfig *managers.SecretsManagerConfig) (managers.SecretsManager, error) {
	var secretsManager managers.SecretsManager

	switch secretsConfig.Type {
	case managers.HashicorpVault:
		vault, err := setupHashicorpVault(secretsConfig)
		if err != nil {
			return secretsManager, err
		}

		secretsManager = vault
	case managers.AWSSSM:
		AWSSSM, err := setupAWSSSM(secretsConfig)
		if err != nil {
			return secretsManager, err
		}

		secretsManager = AWSSSM
	case managers.GCPSSM:
		GCPSSM, err := setupGCPSSM(secretsConfig)
		if err != nil {
			return secretsManager, err
		}

		secretsManager = GCPSSM
	default:
		return secretsManager, errors.New("unsupported secrets manager")
	}

	return secretsManager, nil
}
