package main

import (
	"fmt"

	"github.com/noobtunnel/noobtunnel/internal/wg"
)

func runKeygen(args []string) error {
	fs := newFlagSet("keygen")
	includePSK := fs.Bool("psk", false, "also print a preshared key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := wg.GenerateKeyPair()
	if err != nil {
		return err
	}
	fmt.Printf("private key: %s\n", keys.Private)
	fmt.Printf("public key:  %s\n", keys.Public)
	if *includePSK {
		psk, err := wg.GeneratePresharedKey()
		if err != nil {
			return err
		}
		fmt.Printf("preshared:   %s\n", psk)
	}
	return nil
}
