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
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKeyWrapAndUnwrap(t *testing.T) {
	// Example key and plaintext
	key := []byte("12345678901234567890123456789012") // 32-byte key for AES-256
	plaintext := []byte("Hello, AES Key Wrap!")

	// Pad plaintext to a multiple of 8 bytes
	for len(plaintext)%AESKeyWrapBlockSize != 0 {
		plaintext = append(plaintext, 0)
	}

	// Key Wrap
	wrapped, err := KeyWrap(key, plaintext)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	// Key Unwrap
	unwrapped, err := KeyUnwrap(key, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}

	// Check if the unwrapped plaintext matches the original plaintext
	assert.Equal(t, plaintext, unwrapped, "Unwrapped plaintext does not match the original plaintext.")
}

func TestKeyWrapWithInvalidKeyLength(t *testing.T) {
	// Invalid key length (not 32 bytes)
	key := []byte("shortkey")
	plaintext := []byte("Hello, AES Key Wrap!")

	// Pad plaintext to a multiple of 8 bytes
	for len(plaintext)%AESKeyWrapBlockSize != 0 {
		plaintext = append(plaintext, 0)
	}

	// Attempt to wrap with an invalid key
	_, err := KeyWrap(key, plaintext)
	if err == nil {
		t.Error("Expected error for invalid key length, but got none")
	}
}

func TestKeyUnwrapWithInvalidCiphertext(t *testing.T) {
	// Valid key
	key := []byte("12345678901234567890123456789012") // 32-byte key for AES-256
	// Invalid ciphertext (too short)
	invalidCiphertext := []byte("short")

	// Attempt to unwrap with invalid ciphertext
	_, err := KeyUnwrap(key, invalidCiphertext)
	if err == nil {
		t.Error("Expected error for invalid ciphertext length, but got none")
	}
}

func TestIVMismatch(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32-byte key for AES-256
	plaintext := []byte("Hello, AES Key Wrap!")

	// Pad plaintext to a multiple of 8 bytes
	for len(plaintext)%AESKeyWrapBlockSize != 0 {
		plaintext = append(plaintext, 0)
	}

	// Wrap the key
	wrapped, err := KeyWrap(key, plaintext)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	// Modify the IV in the wrapped ciphertext
	wrapped[0] ^= 0xff

	// Attempt to unwrap with the modified ciphertext
	_, err = KeyUnwrap(key, wrapped)
	if err == nil {
		t.Error("Expected IV mismatch error, but got none")
	}
}

func TestKeyWrapWithKnownValues(t *testing.T) {
	// Given test data
	// https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#kw-aes256
	key, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")       // 128-bit KEK
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF") // Plaintext to wrap
	expectedCiphertext, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	// Perform Key Wrap
	wrapped, err := KeyWrap(key, plaintext)
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	// Check if the wrapped output matches the expected ciphertext
	assert.Equal(t, expectedCiphertext, wrapped, "Wrapped ciphertext does not match expected value.")

	// Perform Key Unwrap
	unwrapped, err := KeyUnwrap(key, wrapped)
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}

	// Check if the unwrapped plaintext matches the original plaintext
	assert.Equal(t, plaintext, unwrapped, "Unwrapped plaintext does not match original value.")
}
