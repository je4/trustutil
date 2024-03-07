package configs

import (
	"embed"
	_ "embed"
)

//go:embed minivault.toml
var ConfigFS embed.FS
