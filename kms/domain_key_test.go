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
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestEncryptedExportData32(t *testing.T) {
	assert.Equal(t, 8+32, sizeOfEncryptedExportData32)
}

func TestProvisionExportImportWithoutPCR(t *testing.T) {
	var svc *Service
	if testNewService(t, &svc) {
		return
	}

	if err := svc.Provision(); err != nil {
		t.Error(err)
		return
	}

	domainKeyAfterProvision := getDomainKey(t, svc)

	tempFile, err := os.CreateTemp("", "tmp-*.pb")
	if err != nil {
		t.Error(err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	if err := svc.Export(tempFile.Name(), "1234"); err != nil {
		t.Error(err)
		return
	}

	if testNewService(t, &svc) {
		return
	}

	if err := svc.Import(tempFile.Name(), "1234"); err != nil {
		t.Error(err)
		return
	}

	domainKeyAfterImport := getDomainKey(t, svc)

	assert.Equal(t, domainKeyAfterProvision, domainKeyAfterImport)
}

func TestProvisionExportImportWithPCR(t *testing.T) {
	var svc *Service
	if testNewService(t, &svc) {
		return
	}

	svc.PCRs = []uint{0, 1, 7}

	if err := svc.Provision(); err != nil {
		t.Error(err)
		return
	}

	domainKeyAfterProvision := getDomainKey(t, svc)

	tempFile, err := os.CreateTemp("", "tmp-*.pb")
	if err != nil {
		t.Error(err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	if err := svc.Export(tempFile.Name(), "1234"); err != nil {
		t.Error(err)
		return
	}

	if testNewService(t, &svc) {
		return
	}

	if err := svc.Import(tempFile.Name(), "1234"); err != nil {
		t.Error(err)
		return
	}

	domainKeyAfterImport := getDomainKey(t, svc)

	assert.Equal(t, domainKeyAfterProvision, domainKeyAfterImport)
}

func testNewService(t *testing.T, psvc **Service) (hasError bool) {
	svc, err := NewService()
	if err != nil {
		t.Error(err)
		return true
	}
	svc.tpmOpen = func() (transport.TPMCloser, error) {
		return GetSimulator()
	}
	svc.DataDir, err = os.MkdirTemp("", "tmp")
	if err != nil {
		t.Error(err)
		return true
	}
	additionSecret := "HELLO WORLD"
	svc.SetAdditionalSecret(&additionSecret)
	*psvc = svc
	return false
}

func getDomainKey(t *testing.T, s *Service) []byte {
	outBuf := make([]byte, s.domainKeyTpm.Size())
	if _, err := s.getDomainTpmKeyTo(outBuf); err != nil {
		t.Error(err)
	}
	return outBuf
}
