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
	"github.com/google/go-tpm/tpm2"
	"github.com/jc-lab/k8s-tpm-kms-plugin/tpm"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"os"
	"path/filepath"
)

func (s *Service) tpmObjectFilePath(name string) string {
	return filepath.Join(s.DataDir, "tpm-object."+name+".pb")
}

func (s *Service) tpmEncryptAndStore(name string, plaintext []byte) error {
	PCRs := s.PCRs

	tpmDev, err := s.tpmOpen()
	if err != nil {
		return errors.Wrap(err, "tpm open failed")
	}
	defer tpmDev.Close()

	createSrkResp, err := tpm.CreatePrimary(tpmDev)
	if err != nil {
		return err
	}
	defer tpm.FlushContext(tpmDev, createSrkResp.ObjectHandle)

	sealResp, err := tpm.Seal(tpmDev, createSrkResp, PCRs, plaintext)
	if err != nil {
		return errors.Wrap(err, "tpm seal failed")
	}

	wrappedData := &TpmWrappedData{
		PrivateArea: tpm2.Marshal(sealResp.OutPrivate),
		PublicArea:  tpm2.Marshal(sealResp.OutPublic),
	}
	for _, pcr := range PCRs {
		wrappedData.Pcrs = append(wrappedData.Pcrs, int32(pcr))
	}
	wrappedRaw, err := proto.Marshal(wrappedData)
	if err != nil {
		return err
	}

	filename := s.tpmObjectFilePath(name)
	return os.WriteFile(filename, wrappedRaw, 0600)
}

func (s *Service) tpmDecryptWithLoad(name string) ([]byte, error) {
	filename := s.tpmObjectFilePath(name)
	wrappedRaw, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var wrappedData TpmWrappedData
	if err := proto.Unmarshal(wrappedRaw, &wrappedData); err != nil {
		return nil, err
	}
	var PCRs []uint
	for _, pcr := range wrappedData.Pcrs {
		PCRs = append(PCRs, uint(pcr))
	}

	tpmDev, err := s.tpmOpen()
	if err != nil {
		return nil, errors.Wrap(err, "tpm open failed")
	}
	defer tpmDev.Close()

	createSrkResp, err := tpm.CreatePrimary(tpmDev)
	if err != nil {
		return nil, err
	}
	defer tpm.FlushContext(tpmDev, createSrkResp.ObjectHandle)

	unsealResp, err := tpm.Unseal(tpmDev, createSrkResp, PCRs, wrappedData.PrivateArea, wrappedData.PublicArea)
	if err != nil {
		return nil, err
	}

	return unsealResp.OutData.Buffer, nil
}
