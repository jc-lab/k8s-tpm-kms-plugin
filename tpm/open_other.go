//go:build !windows
// +build !windows

package tpm

import "github.com/google/go-tpm/tpm2/transport"

func OpenTPM(devicePath string) (transport.TPMCloser, error) {
	return transport.OpenTPM(devicePath)
}
