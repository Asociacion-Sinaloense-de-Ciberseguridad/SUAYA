package main

import (
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/tls"
)

// md5.Sum ya no se usa.
func config() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
}

func llave() (*mlkem.DecapsulationKey768, [32]byte) {
	k, _ := mlkem.GenerateKey768()
	return k, sha256.Sum256([]byte("x"))
}
