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

package v2

import (
	"github.com/jc-lab/k8s-tpm-kms-plugin/kms"
	grpc "google.golang.org/grpc"

	"context"
	"time"

	"github.com/golang/glog"
	"github.com/jc-lab/k8s-tpm-kms-plugin/plugin"

	kmsapi "k8s.io/kms/apis/v2"
)

const (
	apiVersion = "v2beta1"
	ok         = "ok"
)

var _ plugin.Plugin = (*Plugin)(nil)

type Plugin struct {
	keyService *kms.Service
}

// New constructs Plugin.
func NewPlugin(keyService *kms.Service) *Plugin {
	p := &Plugin{
		keyService: keyService,
	}

	return p
}

// Register registers the plugin as a service management service.
func (g *Plugin) Register(s *grpc.Server) {
	kmsapi.RegisterKeyManagementServiceServer(s, g)
}

// Status returns the version of KMS API version that plugin supports.
// Response also contains the status of the plugin, which is calculated as availability of the
// encryption key that the plugin is configured with, and the current primary key version.
func (g *Plugin) Status(ctx context.Context, request *kmsapi.StatusRequest) (*kmsapi.StatusResponse, error) {
	defer plugin.RecordCryptoOperation("encrypt", time.Now().UTC())

	statusResp := &kmsapi.StatusResponse{
		Version: apiVersion,
		KeyId:   "default",
		Healthz: ok,
	}
	_, err := g.keyService.Encrypt(ctx, &kms.EncryptRequest{
		Plaintext: []byte("ping"),
	})
	if err != nil {
		plugin.TpmFailuresTotal.WithLabelValues("encrypt").Inc()
		statusResp.Healthz = "error"
	}

	glog.V(4).Infof("Status response: %s", statusResp.Healthz)
	return statusResp, nil
}

// Encrypt encrypts payload provided by K8S API Server.
func (g *Plugin) Encrypt(ctx context.Context, request *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
	glog.V(4).Infof("Processing request for encryption %s", request.Uid)
	defer plugin.RecordCryptoOperation("encrypt", time.Now().UTC())

	resp, err := g.keyService.Encrypt(ctx, &kms.EncryptRequest{
		Plaintext: request.Plaintext,
	})
	if err != nil {
		plugin.TpmFailuresTotal.WithLabelValues("encrypt").Inc()
		return nil, err
	}

	glog.V(4).Infof("Processed request for encryption %s",
		request.Uid)

	return &kmsapi.EncryptResponse{
		Ciphertext: resp.Ciphertext,
		KeyId:      "default",
	}, nil
}

// Decrypt decrypts payload supplied by K8S API Server.
func (g *Plugin) Decrypt(ctx context.Context, request *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
	glog.V(4).Infof("Processing request for decryption %s using %s", request.Uid, request.KeyId)
	defer plugin.RecordCryptoOperation("decrypt", time.Now().UTC())

	resp, err := g.keyService.Decrypt(ctx, &kms.DecryptRequest{
		Ciphertext: request.Ciphertext,
	})
	if err != nil {
		plugin.TpmFailuresTotal.WithLabelValues("decrypt").Inc()
		return nil, err
	}

	return &kmsapi.DecryptResponse{
		Plaintext: resp.Plaintext,
	}, nil
}
