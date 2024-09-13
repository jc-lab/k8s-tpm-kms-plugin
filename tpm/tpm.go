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
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/pkg/errors"
	"log"
)

func CreatePrimary(device transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	// Create the SRK
	createSRKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	return createSRKCmd.Execute(device)
}

func FlushContext(device transport.TPM, ObjectHandle tpm2.TPMHandle) error {
	flushSRKCmd := tpm2.FlushContext{FlushHandle: ObjectHandle}
	_, err := flushSRKCmd.Execute(device)
	return err
}

func Seal(device transport.TPM, createSrkResp *tpm2.CreatePrimaryResponse, PCRs []uint, data []byte) (*tpm2.CreateResponse, error) {
	var authPolicy tpm2.TPM2BDigest

	if len(PCRs) > 0 {
		policySession, policy, policyClose, err := policyPCRSession(device, PCRs)
		if err != nil {
			return nil, err
		}
		_ = policySession
		policyClose()
		authPolicy = policy.PolicyDigest
	}

	authSession, authClose, err := StartAuthSession(device, createSrkResp, int(tpm2.EncryptInOut))
	if err != nil {
		return nil, err
	}
	defer authClose()

	return tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: createSrkResp.ObjectHandle,
			Name:   createSrkResp.Name,
			Auth:   authSession,
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: data,
				}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:       tpm2.TPMAlgKeyedHash,
			NameAlg:    tpm2.TPMAlgSHA256,
			AuthPolicy: authPolicy,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				NoDA:         true,
				UserWithAuth: len(PCRs) == 0,
			},
		}),
	}.Execute(device)
}

func Unseal(device transport.TPM, createSrkResp *tpm2.CreatePrimaryResponse, PCRs []uint, private []byte, public []byte) (*tpm2.UnsealResponse, error) {
	inPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](private)
	if err != nil {
		return nil, errors.Wrap(err, "private unmarshal failed")
	}
	inPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](public)
	if err != nil {
		return nil, errors.Wrap(err, "public unmarshal failed")
	}

	var policySession tpm2.Session
	if len(PCRs) > 0 {
		session, policy, policyClose, err := policyPCRSession(device, PCRs)
		if err != nil {
			return nil, errors.Wrap(err, "policy pcr policySession failed")
		}
		policySession = session
		_ = policy
		defer policyClose()
	} else {
		policySession = tpm2.PasswordAuth(nil)
	}

	authSession, authClose, err := StartAuthSession(device, createSrkResp, int(tpm2.EncryptOut))
	if err != nil {
		return nil, errors.Wrap(err, "start auth authSession failed")
	}
	defer authClose()

	// Load the sealed blob
	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: createSrkResp.ObjectHandle,
			Name:   createSrkResp.Name,
		},
		InPrivate: *inPrivate,
		InPublic:  *inPublic,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(device, authSession)
	if err != nil {
		return nil, errors.Wrap(err, "load failed")
	}
	defer func() {
		if err := FlushContext(device, loadBlobRsp.ObjectHandle); err != nil {
			log.Printf("flush failed: %+v", errors.WithStack(err))
		}
	}()

	return tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   policySession,
		},
	}.Execute(device, authSession)
}

func StartAuthSession(device transport.TPM, createSrkResp *tpm2.CreatePrimaryResponse, encryptionDir int) (s tpm2.Session, close func() error, err error) {
	primaryPublic, err := createSrkResp.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}

	encOpt := tpm2.AESEncryption(128, tpm2.EncryptInOut)
	if encryptionDir == int(tpm2.EncryptIn) {
		encOpt = tpm2.AESEncryption(128, tpm2.EncryptIn)
	} else if encryptionDir == int(tpm2.EncryptOut) {
		encOpt = tpm2.AESEncryption(128, tpm2.EncryptOut)
	}
	s, close, err = tpm2.HMACSession(
		device,
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Salted(createSrkResp.ObjectHandle, *primaryPublic), // The secret is a salt encrypted to an asymmetric key loaded in the TPM.
		encOpt,
	)
	return
}

func policyPCRSession(device transport.TPM, PCRs []uint) (policySession tpm2.Session, policy *tpm2.PolicyGetDigestResponse, policyClose func() error, err error) {
	policySession, policyClose, err = tpm2.PolicySession(device, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, nil, err
	}

	pcrSelection := tpm2.TPMSPCRSelection{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(PCRs...),
	}
	_, err = tpm2.PolicyPCR{
		PolicySession: policySession.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{pcrSelection},
		},
	}.Execute(device)
	if err != nil {
		policyClose()
		return nil, nil, nil, errors.Wrap(err, "policy pcr failed")
	}

	policy, err = tpm2.PolicyGetDigest{
		PolicySession: policySession.Handle(),
	}.Execute(device)
	if err != nil {
		policyClose()
		return nil, nil, nil, errors.Wrap(err, "unable to get policy digest")
	}

	return policySession, policy, policyClose, nil
}

func ReadPcr(device transport.TPM, PCRs []uint) (*tpm2.PCRReadResponse, error) {
	pcrSelection := tpm2.TPMSPCRSelection{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(PCRs...),
	}
	return tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{pcrSelection},
		},
	}.Execute(device)
}
