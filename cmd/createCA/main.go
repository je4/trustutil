package main

import (
	"fmt"
	"github.com/je4/trustutil/v2/pkg/certutil"
	"log"
	"os"
	"time"
)

func main() {
	pwd := os.Getenv("CA_KEY_PASS")
	if pwd == "" {
		log.Panicf("CA_KEY_PASS not set")
	}

	name := certutil.DefaultName
	name.CommonName = "MiniVault CA"
	ca, caPrivKey, err := certutil.CreateCA(time.Hour*24*365*10, name, certutil.DefaultKeyType)
	if err != nil {
		panic(err)
	}
	encCAPrivKey, err := certutil.EncryptPrivateKey(caPrivKey, []byte(pwd))
	if err != nil {
		log.Panicf("cannot encrypt private key: %v", err)
	}
	os.WriteFile("ca.crt", ca, 0644)
	os.WriteFile("ca.key", encCAPrivKey, 0644)
	for i := range 3 {
		name := certutil.DefaultName
		name.CommonName = fmt.Sprintf("Dummy CA #%d", i)
		ca, key, err := certutil.CreateCA(time.Hour*24*365*10, name, certutil.DefaultKeyType)
		if err != nil {
			panic(err)
		}
		println(string(ca))
		println(string(key))
		println("-----")
	}
}
