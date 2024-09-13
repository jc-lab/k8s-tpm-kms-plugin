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

package plugin

import (
	"github.com/jc-lab/k8s-tpm-kms-plugin/kms"
	"net/url"
	"time"

	"context"
	"fmt"

	"google.golang.org/grpc/credentials/insecure"
	"net/http"

	"github.com/golang/glog"
	"google.golang.org/grpc"
)

// HealthCheckerManager types that encapsulates healthz functionality of kms-plugin.
// The following health checks are performed:
// 1. Getting version of the plugin - validates gRPC connectivity.
// 2. Asserting that the caller has encrypt and decrypt permissions on the crypto key.
type HealthCheckerManager struct {
	KeyService     *kms.Service
	unixSocketPath string
	callTimeout    time.Duration
	servingURL     *url.URL

	plugin HealthChecker
}

type HealthChecker interface {
	PingRPC(context.Context, *grpc.ClientConn) error
	PingKMS(context.Context, *grpc.ClientConn) error
}

func NewHealthChecker(
	plugin HealthChecker,
	keyService *kms.Service,
	unixSocketPath string,
	callTimeout time.Duration,
	servingURL *url.URL,
) *HealthCheckerManager {
	return &HealthCheckerManager{
		KeyService:     keyService,
		unixSocketPath: unixSocketPath,
		callTimeout:    callTimeout,
		servingURL:     servingURL,
		plugin:         plugin,
	}
}

// Serve creates http server for hosting healthz.
func (m *HealthCheckerManager) Serve() chan error {
	errorCh := make(chan error)
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/%s", m.servingURL.EscapedPath()), m.HandlerFunc)

	go func() {
		defer close(errorCh)
		glog.Infof("Registering healthz listener at %v", m.servingURL)
		select {
		case errorCh <- http.ListenAndServe(m.servingURL.Host, mux):
		default:
		}
	}()

	return errorCh
}

func (m *HealthCheckerManager) HandlerFunc(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), m.callTimeout)
	defer cancel()

	conn, err := dialUnix(m.unixSocketPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer conn.Close()

	if err := m.plugin.PingRPC(ctx, conn); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if err := m.TestTpm(); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if r.FormValue("ping-kms") == "true" {
		if err := m.plugin.PingKMS(ctx, conn); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (h *HealthCheckerManager) TestTpm() error {
	glog.Infof("Testing TPM Open")

	err := h.KeyService.TestTpm()
	if err != nil {
		return fmt.Errorf("failed to test TPM Open %s: %v", h.KeyService.TpmDevice, err)
	}

	glog.Infof("Successfully validated TPM Open")

	return nil
}

func dialUnix(unixSocketPath string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		"unix:"+unixSocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}
