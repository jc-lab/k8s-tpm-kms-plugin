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
	"context"
	"github.com/golang/glog"
	"google.golang.org/grpc"
	kmsapi "k8s.io/kms/apis/v1beta1"
	"time"

	"github.com/jc-lab/k8s-tpm-kms-plugin/kms"
	"github.com/jc-lab/k8s-tpm-kms-plugin/plugin"
)

const (
	apiVersion     = "v1beta1"
	runtimeName    = "k8s-tpm-kms-plugin"
	runtimeVersion = "0.0.1"
)

var _ plugin.Plugin = (*Plugin)(nil)

// Plugin is the v1 implementation of a plugin.
type Plugin struct {
	keyService *kms.Service
}

// NewPlugin creates a new v1 plugin
func NewPlugin(keyService *kms.Service) *Plugin {
	return &Plugin{
		keyService: keyService,
	}
}

// Register registers the plugin as a service management service.
func (g *Plugin) Register(s *grpc.Server) {
	kmsapi.RegisterKeyManagementServiceServer(s, g)
}

// Version returns the version of Service Plugin.
func (g *Plugin) Version(ctx context.Context, request *kmsapi.VersionRequest) (*kmsapi.VersionResponse, error) {
	return &kmsapi.VersionResponse{
		Version:        apiVersion,
		RuntimeName:    runtimeName,
		RuntimeVersion: runtimeVersion,
	}, nil
}

// Encrypt encrypts payload provided by K8S API Server.
func (g *Plugin) Encrypt(ctx context.Context, request *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
	glog.V(4).Infoln("Processing request for encryption.")
	defer plugin.RecordCryptoOperation("encrypt", time.Now().UTC())

	resp, err := g.keyService.Encrypt(ctx, &kms.EncryptRequest{
		Plaintext: request.Plain,
	})
	if err != nil {
		plugin.TpmFailuresTotal.WithLabelValues("encrypt").Inc()
		return nil, err
	}

	return &kmsapi.EncryptResponse{
		Cipher: resp.Ciphertext,
	}, nil
}

// Decrypt decrypts payload supplied by K8S API Server.
func (g *Plugin) Decrypt(ctx context.Context, request *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
	glog.V(4).Infoln("Processing request for decryption.")
	defer plugin.RecordCryptoOperation("decrypt", time.Now().UTC())

	resp, err := g.keyService.Decrypt(ctx, &kms.DecryptRequest{
		Ciphertext: request.Cipher,
	})
	if err != nil {
		plugin.TpmFailuresTotal.WithLabelValues("decrypt").Inc()
		return nil, err
	}

	return &kmsapi.DecryptResponse{
		Plain: resp.Plaintext,
	}, nil
}
