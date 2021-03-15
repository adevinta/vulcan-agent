/*
Copyright 2019 Adevinta
*/

package docker

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/docker/docker-credential-helpers/client"
)

const (
	conf = ".docker/config.json"
)

// ErrUnsupportedOS is returnned when no the operating system running
// the package is not either linux, macos or windows.
var ErrUnsupportedOS = errors.New("unsupported os")

// Creds stores the credentials for a given
// registry server.
type Creds struct {
	Username string
	Secret   string
}

// Credentials return the credentials for a given repository url.
func Credentials(registry string) (Creds, error) {
	var c Creds
	program, err := shellProgram()
	name := "docker-credential-" + program
	p := client.NewShellProgramFunc(name)
	creds, err := client.Get(p, registry)
	if err != nil {
		return c, err
	}
	c.Secret = creds.Secret
	c.Username = creds.Username
	return c, nil
}

func shellProgram() (string, error) {
	helper, err := fileCfgHelper()
	if err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}

	if errors.Is(err, os.ErrExist) {
		helper, err = osDefaultHelper()
	}

	return helper, err
}

func osDefaultHelper() (string, error) {
	switch os := runtime.GOOS; os {
	case "darwin":
		return "osxkeychain", nil
	case "windows":
		return "wincred", nil
	case "linux":
		return "pass", nil
	default:
		return "", ErrUnsupportedOS
	}

}

func fileCfgHelper() (string, error) {
	// First we try to gather the credentials helper from the default docker
	// config file.
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	p := filepath.Join(u.HomeDir, conf)
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint
	d := json.NewDecoder(f)
	type cfg struct {
		Helper string `json:"credsStore"`
	}
	s := cfg{}
	err = d.Decode(&s)
	if err != nil {
		return "", err
	}
	return s.Helper, nil
}
