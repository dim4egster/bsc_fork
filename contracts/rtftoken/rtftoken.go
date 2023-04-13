package rtftoken

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

type rtfTokenData struct {
	Bytecode         string `json:"bytecode"`
	DeployedBytecode string `json:"deployedBytecode"`
}

func mustParseRTFTokenConfigFromJson(rawJson []byte) *rtfTokenData {
	rtfToken := new(rtfTokenData)
	if err := json.Unmarshal(rawJson, rtfToken); err != nil {
		panic(fmt.Sprintf("invalid RTFToken file: %v", err))
	}
	return rtfToken
}

//go:embed embeded/RTFToken.json
var rawRTFToken []byte

var RTFToken = mustParseRTFTokenConfigFromJson(rawRTFToken)
