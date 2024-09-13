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

package tpm

import (
	"crypto/sha256"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jc-lab/k8s-tpm-kms-plugin/internal/testing/swtpm"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestSealAndUnsealWithoutPCR(t *testing.T) {
	simulator, err := swtpm.New()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %+v", err)
		return
	}
	defer simulator.Close()

	openSimulator := func() (transport.TPMCloser, error) {
		device, err := simulator.Open()
		if err != nil {
			return nil, err
		}
		pcrExtend(t, device, 7, []byte("HELLO"))
		return device, nil
	}

	testdata := []byte("secret")

	var PCRs []uint

	var sealed *tpm2.CreateResponse
	t.Run("seal", func(t *testing.T) {
		device, err := openSimulator()
		if err != nil {
			t.Fatalf("could not open device: %v", err)
		}
		defer device.Close()

		createSRKResp, err := CreatePrimary(device)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %+v", err)
		}
		defer func() {
			if err := FlushContext(device, createSRKResp.ObjectHandle); err != nil {
				t.Fatalf("FlushContext(Primary) failed: %+v", err)
			}
		}()

		sealed, err = Seal(device, createSRKResp, PCRs, testdata)
		if err != nil {
			t.Fatalf("Seal failed: %+v", err)
		}
	})

	t.Run("unseal", func(t *testing.T) {
		device, err := openSimulator()
		if err != nil {
			t.Fatalf("could not open device: %v", err)
		}
		defer device.Close()

		createSRKResp, err := CreatePrimary(device)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %+v", err)
		}
		defer func() {
			if err := FlushContext(device, createSRKResp.ObjectHandle); err != nil {
				t.Fatalf("FlushContext(Primary) failed: %+v", err)
			}
		}()

		unsealed, err := Unseal(device, createSRKResp, PCRs, tpm2.Marshal(sealed.OutPrivate), tpm2.Marshal(sealed.OutPublic))
		if err != nil {
			t.Fatalf("Unseal failed: %+v", err)
		}

		assert.Equal(t, testdata, unsealed.OutData.Buffer)
	})
}

func TestSealAndUnsealWithPCR(t *testing.T) {
	simulator, err := swtpm.New()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %+v", err)
		return
	}
	defer simulator.Close()

	openSimulator := func() (transport.TPMCloser, error) {
		device, err := simulator.Open()
		if err != nil {
			return nil, err
		}
		pcrExtend(t, device, 7, []byte("HELLO"))
		return device, nil
	}

	testdata := []byte("secret")

	PCRs := []uint{7}

	var sealed *tpm2.CreateResponse
	t.Run("seal", func(t *testing.T) {
		device, err := openSimulator()
		if err != nil {
			t.Fatalf("could not open device: %v", err)
		}
		defer device.Close()

		createSRKResp, err := CreatePrimary(device)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %+v", err)
		}
		defer func() {
			if err := FlushContext(device, createSRKResp.ObjectHandle); err != nil {
				t.Fatalf("FlushContext(Primary) failed: %+v", err)
			}
		}()

		pcrResp, err := ReadPcr(device, PCRs)
		if err != nil {
			t.Fatalf("ReadPCR failed: %+v", err)
		}
		log.Printf("PCR RESP: %+v", pcrResp)

		sealed, err = Seal(device, createSRKResp, PCRs, testdata)
		if err != nil {
			t.Fatalf("Seal failed: %+v", err)
		}
	})

	t.Run("unseal", func(t *testing.T) {
		device, err := openSimulator()
		if err != nil {
			t.Fatalf("could not open device: %v", err)
		}
		defer device.Close()

		createSRKResp, err := CreatePrimary(device)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %+v", err)
		}
		defer func() {
			if err := FlushContext(device, createSRKResp.ObjectHandle); err != nil {
				t.Fatalf("FlushContext(Primary) failed: %+v", err)
			}
		}()

		pcrResp, err := ReadPcr(device, PCRs)
		if err != nil {
			t.Fatalf("ReadPCR failed: %+v", err)
		}
		log.Printf("PCR RESP: %+v", pcrResp)

		unsealed, err := Unseal(device, createSRKResp, PCRs, tpm2.Marshal(sealed.OutPrivate), tpm2.Marshal(sealed.OutPublic))
		if err != nil {
			t.Fatalf("Unseal failed: %+v", err)
		}

		assert.Equal(t, testdata, unsealed.OutData.Buffer)
	})

	t.Run("unseal_should_failed_with_wrong_pcr", func(t *testing.T) {
		device, err := openSimulator()
		if err != nil {
			t.Fatalf("could not open device: %v", err)
		}
		defer device.Close()

		pcrExtend(t, device, 7, []byte("WRONG"))

		createSRKResp, err := CreatePrimary(device)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %+v", err)
		}
		defer func() {
			if err := FlushContext(device, createSRKResp.ObjectHandle); err != nil {
				t.Fatalf("FlushContext(Primary) failed: %+v", err)
			}
		}()

		pcrResp, err := ReadPcr(device, PCRs)
		if err != nil {
			t.Fatalf("ReadPCR failed: %+v", err)
		}
		log.Printf("PCR RESP: %+v", pcrResp)

		unsealed, err := Unseal(device, createSRKResp, PCRs, tpm2.Marshal(sealed.OutPrivate), tpm2.Marshal(sealed.OutPublic))
		assert.EqualError(t, err, "TPM_RC_POLICY_FAIL (session 1): a policy check failed")
		assert.Nil(t, unsealed)
	})
}

func pcrExtend(t *testing.T, device transport.TPM, pcr int, content []byte) {
	authHandle := tpm2.AuthHandle{
		Handle: tpm2.TPMHandle(pcr),
		Auth:   tpm2.PasswordAuth(nil),
	}

	h := sha256.New()
	h.Write(content)
	digest := h.Sum(nil)
	pcrExtend := tpm2.PCRExtend{
		PCRHandle: authHandle,
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  digest,
				},
			},
		},
	}
	if _, err := pcrExtend.Execute(device); err != nil {
		t.Fatalf("failed to extend pcr for test %v", err)
	}
}
