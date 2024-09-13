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

package main

import (
	"flag"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/golang/glog"
	"golang.org/x/term"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jc-lab/k8s-tpm-kms-plugin/cmd/util"
	"github.com/jc-lab/k8s-tpm-kms-plugin/kms"
	"github.com/jc-lab/k8s-tpm-kms-plugin/plugin"
	v1 "github.com/jc-lab/k8s-tpm-kms-plugin/plugin/v1"
	v2 "github.com/jc-lab/k8s-tpm-kms-plugin/plugin/v2"
)

var (
	healthzPort    = flag.Int("healthz-port", 8081, "Port on which to publish healthz")
	healthzPath    = flag.String("healthz-path", "healthz", "Path at which to publish healthz")
	healthzTimeout = flag.Duration("healthz-timeout", 5*time.Second, "timeout in seconds for communicating with the unix socket")

	metricsPort = flag.Int("metrics-port", 8082, "Port on which to publish metrics")
	metricsPath = flag.String("metrics-path", "metrics", "Path at which to publish metrics")

	pathToUnixSocket = flag.String("unix-socket", "/var/run/k8s-tpm-kms-plugin.sock", "Full path to Unix socket that is used for communicating with KubeAPI Server, or Linux socket namespace object - must start with @")
	kmsVersion       = flag.String("kms", "v2", "Kubernetes Service API version. Possible values: v1, v2. Default value is v2.")

	tpmDevice        = flag.String("tpm-device", "/dev/tpmrm0", "TPM_DEVICE Path to tpm device or tpm resource manager.")
	tpmPCRs          = flag.String("tpm-pcrs", "", "TPM_PCRS PCRs to measure.")
	additionalSecret = flag.String("additional-secret", "", "ADDITIONAL_SECRET")

	dataDir = flag.String("data-dir", "/var/lib/k8s-tpm-kms-plugin/", "DATA_DIR Full path to data directory")

	isProvision  = flag.Bool("provision", false, "create Domain Key")
	pathToImport = flag.String("import", "", "Domain Key import path")
	pathToExport = flag.String("export", "", "Domain Key export path")
	password     = flag.String("password", "", "import/export password")
)

func main() {
	var exitErr error

	flag.Parse()
	useEnv(tpmDevice, "TPM_DEVICE")
	useEnv(tpmPCRs, "TPM_PCRS")
	useEnv(dataDir, "DATA_DIR")
	useEnv(additionalSecret, "ADDITIONAL_SECRET")
	mustValidateFlags()

	PCRs := util.ParsePCRs(*tpmPCRs)

	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()

	// Purge the session when we return
	defer memguard.Purge()

	defer func() {
		if exitErr != nil {
			glog.Exit(exitErr)
		}
	}()

	svc, err := kms.NewService()
	if err != nil {
		exitErr = err
		return
	}
	svc.TpmDevice = *tpmDevice
	svc.PCRs = PCRs
	svc.DataDir = *dataDir
	svc.SetAdditionalSecret(additionalSecret)
	*additionalSecret = ""

	if len(*pathToImport) > 0 {
		enterPasswordIfNeeded(password, false)
		exitErr = svc.Import(*pathToImport, *password)
		return
	} else if len(*pathToExport) > 0 {
		enterPasswordIfNeeded(password, true)
		exitErr = svc.Export(*pathToExport, *password)
		return
	} else if *isProvision {
		exitErr = svc.Provision()
		return
	}

	if exitErr = svc.Start(); exitErr != nil {
		return
	}

	metrics := &plugin.Metrics{
		ServingURL: &url.URL{
			Host: fmt.Sprintf("localhost:%d", *metricsPort),
			Path: *metricsPath,
		},
	}

	var p plugin.Plugin
	var healthChecker plugin.HealthChecker
	switch *kmsVersion {
	case "v1":
		p = v1.NewPlugin(svc)
		healthChecker = v1.NewHealthChecker()
		glog.Info("Kubernetes Service API v1beta1")
	case "v2":
		p = v2.NewPlugin(svc)
		healthChecker = v2.NewHealthChecker()
		glog.Info("Kubernetes Service API v2")
	default:
		exitErr = fmt.Errorf("invalid value %q for --kms", *kmsVersion)
		return
	}

	hc := plugin.NewHealthChecker(healthChecker, svc, *pathToUnixSocket, *healthzTimeout, &url.URL{
		Host: fmt.Sprintf("localhost:%d", *healthzPort),
		Path: *healthzPath,
	})

	pluginManager := plugin.NewManager(p, *pathToUnixSocket)

	exitErr = run(pluginManager, hc, metrics)
}

func useEnv(p *string, name string) {
	if *p != "" {
		return
	}
	*p = os.Getenv(name)
}

func enterPasswordIfNeeded(p *string, useConfirm bool) {
	if *p != "" {
		return
	}

	input := enterPasswordString("Enter password: ")
	if useConfirm {
		confirmPassword := enterPasswordString("Confirm: ")
		if confirmPassword != input {
			glog.Exit("confirm password is different")
		}
	}
	*p = input
}

func enterPasswordString(description string) string {
	_, _ = os.Stderr.WriteString(description)
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		glog.Exit(err)
	}
	_, _ = os.Stderr.WriteString("\n")
	return string(input)
}

func run(pluginManager *plugin.PluginManager, h *plugin.HealthCheckerManager, m *plugin.Metrics) error {
	signalsChan := make(chan os.Signal, 1)
	signal.Notify(signalsChan, syscall.SIGINT, syscall.SIGTERM)

	metricsErrCh := m.Serve()
	healthzErrCh := h.Serve()

	gRPCSrv, kmsErrorCh := pluginManager.Start()
	defer func() {
		if gRPCSrv != nil {
			gRPCSrv.GracefulStop()
		}
	}()

	for {
		select {
		case sig := <-signalsChan:
			return fmt.Errorf("captured %v, shutting down kms-plugin", sig)
		case kmsError := <-kmsErrorCh:
			return kmsError
		case metricsErr := <-metricsErrCh:
			// Limiting this to warning only - will run without metrics.
			glog.Warning(metricsErr)
			metricsErrCh = nil
		case healthzErr := <-healthzErrCh:
			// Limiting this to warning only - will run without healthz.
			glog.Warning(healthzErr)
			healthzErrCh = nil
		}
	}
}

func mustValidateFlags() {
	glog.Infof("Checking socket path %q", *pathToUnixSocket)
	socketDir := filepath.Dir(*pathToUnixSocket)
	glog.Infof("Unix Socket directory is %q", socketDir)
	if _, err := os.Stat(socketDir); err != nil {
		glog.Exitf(" Directory %q portion of path-to-unix-socket flag:%q does not seem to exist.", socketDir, *pathToUnixSocket)
	}
	glog.Infof("Communication between KUBE API and Service Plugin containers will be via %q", *pathToUnixSocket)
}
