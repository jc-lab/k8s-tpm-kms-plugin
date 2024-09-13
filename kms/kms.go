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

package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"github.com/awnumar/memguard"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jc-lab/k8s-tpm-kms-plugin/internal/aeskw"
	"github.com/jc-lab/k8s-tpm-kms-plugin/tpm"
	"google.golang.org/protobuf/proto"
)

//go:generate protoc --proto_path=. --go_out=. --go_opt=paths=source_relative kms.proto

type Service struct {
	TpmDevice      string
	PCRs           []uint
	SrkPassword    string
	ObjectPassword string
	DataDir        string

	domainKeySize int
	domainKeyTpm  *memguard.Enclave
	domainKeyAdd  *memguard.Enclave

	tpmOpen func() (transport.TPMCloser, error)
}

type EncryptRequest struct {
	Plaintext []byte
}

type EncryptResponse struct {
	Ciphertext []byte
}

type DecryptRequest struct {
	Ciphertext []byte
}

type DecryptResponse struct {
	Plaintext []byte
}

func NewService() (*Service, error) {
	s := &Service{}
	err := s.init()
	return s, err
}

func (s *Service) init() error {
	s.domainKeySize = 32
	s.tpmOpen = func() (transport.TPMCloser, error) {
		return tpm.OpenTPM(s.TpmDevice)
	}
	return nil
}

func (s *Service) SetAdditionalSecret(padditionalSecret *string) {
	if len(*padditionalSecret) > 0 {
		h := sha256.New()
		buf := memguard.NewBuffer(h.Size())
		buf.Melt()
		defer buf.Destroy()

		h.Write([]byte(*padditionalSecret))
		h.Sum(buf.Bytes()[:0])

		s.domainKeyAdd = buf.Seal()
	}
}

func (s *Service) TestTpm() error {
	tpmDev, err := s.tpmOpen()
	if err != nil {
		return err
	}
	tpmDev.Close()
	return nil
}

func (s *Service) Encrypt(ctx context.Context, request *EncryptRequest) (*EncryptResponse, error) {
	var err error
	var wrappedData KmsWrappedData

	dekBuf := memguard.NewBuffer(32)
	defer dekBuf.Destroy()
	dekBuf.Melt()

	wrappedData.EncryptedDek, err = s.generateKeyAndWrap(dekBuf)
	if err != nil {
		return nil, err
	}

	aead, err := createAesGcm(dekBuf.Bytes())
	if err != nil {
		return nil, err
	}

	wrappedData.Nonce = make([]byte, aead.NonceSize())
	_, err = rand.Read(wrappedData.Nonce)
	if err != nil {
		return nil, err
	}

	wrappedData.Ciphertext = aead.Seal(nil, wrappedData.Nonce, request.Plaintext, nil)

	wrappedRaw, err := proto.Marshal(&wrappedData)
	if err != nil {
		return nil, err
	}

	return &EncryptResponse{
		Ciphertext: wrappedRaw,
	}, nil
}

func (s *Service) Decrypt(ctx context.Context, request *DecryptRequest) (*DecryptResponse, error) {
	var wrappedData KmsWrappedData
	if err := proto.Unmarshal(request.Ciphertext, &wrappedData); err != nil {
		return nil, err
	}

	dek, err := s.unwrapKey(wrappedData.EncryptedDek)
	if err != nil {
		return nil, err
	}
	aead, err := createAesGcm(dek)
	memguard.ScrambleBytes(dek)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, wrappedData.Nonce, wrappedData.Ciphertext, nil)
	if err != nil {
		return nil, err
	}

	resp := &DecryptResponse{
		Plaintext: plaintext,
	}
	return resp, nil
}

func (s *Service) generateKeyAndWrap(keyBuf *memguard.LockedBuffer) (encrypted []byte, err error) {
	if _, err = rand.Read(keyBuf.Bytes()); err != nil {
		return nil, err
	}

	return useDomainKey(s, func(domainKey []byte) ([]byte, error) {
		return aeskw.KeyWrap(domainKey, keyBuf.Bytes())
	})
}

func (s *Service) unwrapKey(encryptedKey []byte) (plaintext []byte, err error) {
	return useDomainKey(s, func(domainKey []byte) ([]byte, error) {
		return aeskw.KeyUnwrap(domainKey, encryptedKey)
	})
}

func useDomainKey[R []byte](s *Service, callable func(domainKey []byte) (R, error)) (R, error) {
	domainKey, err := s.domainKeyTpm.Open()
	if err != nil {
		return nil, err
	}
	defer domainKey.Destroy()

	if s.domainKeyAdd != nil {
		domainKey.Melt()
		domainKeyAddBuf, err := s.domainKeyAdd.Open()
		if err != nil {
			return nil, err
		}
		defer domainKeyAddBuf.Destroy()

		xor(domainKey.Bytes(), domainKeyAddBuf.Bytes())
		domainKeyAddBuf.Destroy()
	}

	return callable(domainKey.Bytes())
}

func xor(dest []byte, src []byte) {
	for i := 0; i < len(dest); i++ {
		dest[i] ^= src[i]
	}
}

func createAesGcm(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}
