package rules

import _ "embed"

//go:embed web.yaml
var WebYAML []byte

//go:embed auth.yaml
var AuthYAML []byte
