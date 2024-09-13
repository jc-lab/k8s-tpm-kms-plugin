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

package v1

import (
	"bytes"
	"context"
	"fmt"
	"github.com/golang/glog"
	"github.com/jc-lab/k8s-tpm-kms-plugin/plugin"
	grpc "google.golang.org/grpc"
	kmsapi "k8s.io/kms/apis/v1beta1"
)

var _ plugin.HealthChecker = (*HealthChecker)(nil)

type HealthChecker struct{}

func NewHealthChecker() *HealthChecker {
	return &HealthChecker{}
}

func (h *HealthChecker) PingRPC(ctx context.Context, conn *grpc.ClientConn) error {
	client := kmsapi.NewKeyManagementServiceClient(conn)

	resp, err := client.Version(ctx, &kmsapi.VersionRequest{})
	if err != nil {
		return fmt.Errorf("failed to retrieve version from gRPC endpoint: %w", err)
	}
	_ = resp

	glog.V(4).Infof("Successfully pinged gRPC")
	return nil
}

func (h *HealthChecker) PingKMS(ctx context.Context, conn *grpc.ClientConn) error {
	client := kmsapi.NewKeyManagementServiceClient(conn)

	testData := []byte("secret")

	encryptResponse, err := client.Encrypt(ctx, &kmsapi.EncryptRequest{
		Version: apiVersion,
		Plain:   testData,
	})
	if err != nil {
		return fmt.Errorf("failed to ping KMS: %w", err)
	}

	decryptResponse, err := client.Decrypt(ctx, &kmsapi.DecryptRequest{
		Version: apiVersion,
		Cipher:  []byte(encryptResponse.Cipher),
	})
	if err != nil {
		return fmt.Errorf("failed to ping KMS: %w", err)
	}

	if !bytes.Equal(testData, decryptResponse.Plain) {
		return fmt.Errorf("failed to decrypt")
	}

	return nil
}
