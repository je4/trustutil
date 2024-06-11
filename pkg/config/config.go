package config

import configutil "github.com/je4/utils/v2/pkg/config"

type TLSConfig struct {
	Type          string              `json:"type,omitempty" toml:"type"` // "ENV", "FILE", "SERVICE" OR "SELF"
	Cert          string              `json:"cert,omitempty" toml:"cert"`
	Key           string              `json:"key,omitempty" toml:"key"`
	CA            []string            `json:"ca,omitempty" toml:"ca"`
	Interval      configutil.Duration `json:"interval,omitempty" toml:"interval"`
	UseSystemPool bool                `json:"usesystempool,omitempty" toml:"usesystempool"`
}
