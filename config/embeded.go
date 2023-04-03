package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/core"
)

func mustParseGenesisConfigFromJson(rawJson []byte) *core.Genesis {
	genesis := new(core.Genesis)
	if err := json.Unmarshal(rawJson, genesis); err != nil {
		panic(fmt.Sprintf("invalid genesis file: %v", err))
	}
	return genesis
}

//go:embed embedded/rtf_testnet.json
var testnetRawGenesisConfig []byte

var RTFTestnetGenesisConfig = mustParseGenesisConfigFromJson(testnetRawGenesisConfig)

//go:embed embedded/rtf_mainnet.json
var mainnetRawGenesisConfig []byte

var RTFMainnetGenesisConfig = mustParseGenesisConfigFromJson(mainnetRawGenesisConfig)
