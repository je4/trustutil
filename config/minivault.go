package config

import (
	"emperror.dev/errors"
	"github.com/BurntSushi/toml"
	configutil "github.com/je4/utils/v2/pkg/config"
	"io/fs"
)

type MiniVaultClientConfig struct {
	Name     string              `toml:"name"`
	URIs     []string            `toml:"uris"`
	Validity configutil.Duration `toml:"validity"`
}

type CAConfig struct {
	CA        string               `toml:"ca"`
	CAKey     string               `toml:"cakey"`
	CAKeyPass configutil.EnvString `toml:"cakeypass"`
}

type MiniVaultConfig struct {
	LocalAddr    string                   `toml:"localaddr"`
	ExternalAddr string                   `toml:"externaladdr"`
	TLSCert      string                   `toml:"tlscert"`
	TLSKey       string                   `toml:"tlskey"`
	TLSKeyPass   configutil.EnvString     `toml:"tlskeypass"`
	LogFile      string                   `toml:"logfile"`
	LogLevel     string                   `toml:"loglevel"`
	Vault        CAConfig                 `toml:"vault"`
	ClientCerts  string                   `toml:"clientcerts"`
	Client       []*MiniVaultClientConfig `toml:"client"`
}

func LoadMiniVaultConfig(fSys fs.FS, fp string, conf *MiniVaultConfig) error {
	if _, err := fs.Stat(fSys, fp); err != nil {
		return errors.Errorf("cannot find file [%v] %s", fSys, fp)
	}
	data, err := fs.ReadFile(fSys, fp)
	if err != nil {
		return errors.Wrapf(err, "cannot read file [%v] %s", fSys, fp)
	}
	_, err = toml.Decode(string(data), conf)
	if err != nil {
		return err
	}
	return nil
}
