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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/protobuf/proto"
	"os"
	"unsafe"
)

const (
	nameOfDomainKey = "domain-key"
)

type encryptedExportData32 struct {
	Reserved1 uint8
	Algorithm uint8
	Reserved2 uint8
	KeySize   uint8
	Reserved3 uint32
	Key       [32]byte
}

const sizeOfEncryptedExportData32 = int(unsafe.Sizeof(encryptedExportData32{}))

func (s *Service) Start() error {
	return s.loadDomainKeyTpm()
}

func (s *Service) loadDomainKeyTpm() error {
	domainKeyPlain, err := s.tpmDecryptWithLoad(nameOfDomainKey)
	if err != nil {
		return err
	}
	defer memguard.ScrambleBytes(domainKeyPlain)
	err = s.setDomainKeyFromTpmKey(domainKeyPlain)
	memguard.ScrambleBytes(domainKeyPlain)
	return err
}

func (s *Service) Provision() error {
	domainKeyBuf := memguard.NewBuffer(s.domainKeySize)
	defer domainKeyBuf.Destroy()
	domainKeyBuf.Melt()

	_, err := rand.Read(domainKeyBuf.Bytes())
	if err != nil {
		return err
	}

	err = s.tpmEncryptAndStore(nameOfDomainKey, domainKeyBuf.Bytes())
	if err != nil {
		return err
	}

	return s.setDomainKeyFromTpmKey(domainKeyBuf.Bytes())
}

func (s *Service) Import(inputFile string, password string) error {
	marshalled, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	var exportFile ExportFile
	if err = proto.Unmarshal(marshalled, &exportFile); err != nil {
		return errors.Wrap(err, "unmarshal failed")
	}

	aead, err := createExportCipher(&exportFile, password)
	if err != nil {
		return err
	}

	dstBuf := memguard.NewBuffer(len(exportFile.Ciphertext) - aead.Overhead())
	defer dstBuf.Destroy()
	dstBuf.Melt()

	dstSlice, err := aead.Open(dstBuf.Bytes()[:0], exportFile.Iv, exportFile.Ciphertext, nil)
	if err != nil {
		return err
	}

	if len(dstSlice) < sizeOfEncryptedExportData32 {
		return fmt.Errorf("decrypted data size (%d) < expected size (%d)", len(dstSlice), sizeOfEncryptedExportData32)
	}
	encryptedExportData := (*encryptedExportData32)(unsafe.Pointer(&dstSlice[0]))
	if int(encryptedExportData.KeySize) != len(encryptedExportData.Key[:]) {
		return fmt.Errorf("key size (%d) != expected size (%d)", encryptedExportData.KeySize, len(encryptedExportData.Key[:]))
	}

	domainKey := encryptedExportData.Key[0:encryptedExportData.KeySize]
	if err = s.tpmEncryptAndStore(nameOfDomainKey, domainKey); err != nil {
		return err
	}
	if err = s.setDomainKeyFromTpmKey(domainKey); err != nil {
		return err
	}

	return nil
}

func (s *Service) Export(outputFile string, password string) error {
	if err := s.loadDomainKeyTpm(); err != nil {
		return err
	}

	encBuf := memguard.NewBuffer(sizeOfEncryptedExportData32)
	defer encBuf.Destroy()
	encBuf.Melt()

	encrypted := (*encryptedExportData32)(unsafe.Pointer(&encBuf.Bytes()[0]))
	encrypted.Algorithm = 1
	encrypted.KeySize = 32

	keySize, err := s.getDomainTpmKeyTo(encrypted.Key[:])
	if err != nil {
		return err
	}
	encrypted.KeySize = byte(keySize)

	exportFile := &ExportFile{
		Version:   1,
		Salt:      make([]byte, 16),
		Iteration: 1000,
	}
	if _, err = rand.Read(exportFile.Salt); err != nil {
		return err
	}

	aead, err := createExportCipher(exportFile, password)
	if err != nil {
		return err
	}
	exportFile.Iv = make([]byte, aead.NonceSize())
	if _, err = rand.Read(exportFile.Iv); err != nil {
		return err
	}

	exportFile.Ciphertext = aead.Seal(nil, exportFile.Iv, encBuf.Bytes(), nil)

	marshalled, err := proto.Marshal(exportFile)
	if err != nil {
		return err
	}
	return os.WriteFile(outputFile, marshalled, 0600)
}

func (s *Service) getDomainTpmKeyTo(dst []byte) (int, error) {
	domainKeyBuf, err := s.domainKeyTpm.Open()
	if err != nil {
		return 0, err
	}
	defer domainKeyBuf.Destroy()
	copy(dst, domainKeyBuf.Bytes())
	return domainKeyBuf.Size(), nil
}

func (s *Service) setDomainKeyFromTpmKey(src []byte) error {
	if s.domainKeySize != len(src) {
		return fmt.Errorf("unexpected domain key size (%d) != expected (%d)", len(src), s.domainKeyTpm.Size())
	}
	domainKeyBuf := memguard.NewBuffer(s.domainKeySize)
	defer domainKeyBuf.Destroy()

	domainKeyBuf.Melt()

	dkslice := domainKeyBuf.Bytes()
	copy(dkslice, src)

	s.domainKeyTpm = domainKeyBuf.Seal()

	return nil
}

func createExportCipher(exportFile *ExportFile, password string) (cipher.AEAD, error) {
	encryptKey := pbkdf2.Key([]byte(password), exportFile.Salt, int(exportFile.Iteration), 32, sha256.New)

	c, err := aes.NewCipher(encryptKey)
	memguard.ScrambleBytes(encryptKey)
	if err != nil {
		return nil, errors.Wrap(err, "create cipher failed")
	}

	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, errors.Wrap(err, "create cipher failed")
	}

	return aead, nil
}
