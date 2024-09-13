// Copyright 2024 JC-Lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aeskw

import (
	"crypto/aes"
	"encoding/binary"
	"github.com/pkg/errors"
)

// Constants for AES Key Wrap
const (
	AESKeyWrapBlockSize = 8
	IV                  = 0xA6A6A6A6A6A6A6A6
)

// KeyWrap performs AES Key Wrap (RFC 3394) with a 256-bit key.
func KeyWrap(key, plaintext []byte) ([]byte, error) {
	if len(plaintext)%AESKeyWrapBlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the AES block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / AESKeyWrapBlockSize
	ciphertext := make([]byte, (n+1)*AESKeyWrapBlockSize)

	// Initialize A as IV (initial value)
	A := make([]byte, AESKeyWrapBlockSize)
	binary.BigEndian.PutUint64(A, IV)
	copy(ciphertext[:AESKeyWrapBlockSize], A)

	// Copy the plaintext directly into the output buffer (ciphertext)
	copy(ciphertext[AESKeyWrapBlockSize:], plaintext)

	// Key wrapping process
	for t := 0; t < 6*n; t++ {
		// Calculate intermediate value
		blockData := append(A, ciphertext[(t%n+1)*AESKeyWrapBlockSize:(t%n+2)*AESKeyWrapBlockSize]...)
		block.Encrypt(blockData, blockData)

		// Update A and R in ciphertext
		copy(A, blockData[:AESKeyWrapBlockSize])
		binary.BigEndian.PutUint64(A, binary.BigEndian.Uint64(A)^(uint64(t+1)))
		copy(ciphertext[(t%n+1)*AESKeyWrapBlockSize:], blockData[AESKeyWrapBlockSize:])
	}

	// Final A is stored in the first block of ciphertext
	copy(ciphertext[:AESKeyWrapBlockSize], A)

	return ciphertext, nil
}

// KeyUnwrap performs AES Key Unwrap (RFC 3394) with a 256-bit key.
func KeyUnwrap(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%AESKeyWrapBlockSize != 0 || len(ciphertext) < 16 {
		return nil, errors.New("invalid ciphertext length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	n := (len(ciphertext) / AESKeyWrapBlockSize) - 1
	A := make([]byte, AESKeyWrapBlockSize)
	copy(A, ciphertext[:AESKeyWrapBlockSize])

	// Copy the ciphertext into the working buffer
	plaintext := make([]byte, n*AESKeyWrapBlockSize)
	copy(plaintext, ciphertext[AESKeyWrapBlockSize:])

	// Key unwrapping process
	for t := 6*n - 1; t >= 0; t-- {
		// Update A with inverse operation
		binary.BigEndian.PutUint64(A, binary.BigEndian.Uint64(A)^(uint64(t+1)))

		// Calculate intermediate value
		blockData := append(A, plaintext[(t%n)*AESKeyWrapBlockSize:(t%n+1)*AESKeyWrapBlockSize]...)
		block.Decrypt(blockData, blockData)

		copy(A, blockData[:AESKeyWrapBlockSize])
		copy(plaintext[(t%n)*AESKeyWrapBlockSize:], blockData[AESKeyWrapBlockSize:])
	}

	// Check if the IV matches
	if binary.BigEndian.Uint64(A) != IV {
		return nil, errors.New("invalid ciphertext, IV mismatch")
	}

	return plaintext, nil
}
