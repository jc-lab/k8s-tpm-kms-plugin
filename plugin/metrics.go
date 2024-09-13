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
	"fmt"
	"github.com/golang/glog"
	"net/http"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics encapsulates functionality related to serving Prometheus metrics for kms-plugin.
type Metrics struct {
	ServingURL *url.URL
}

var (
	TpmFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "failures_count",
			Help: "Total number of failed TPM operations.",
		},
		[]string{"operation_type"},
	)

	CryptoOperationalLatencies = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "crypto_latencies",
			Help: "Latencies in milliseconds of tpm crypto operations.",
			// When calling KMS latencies may climb into milliseconds.
			Buckets: prometheus.ExponentialBuckets(5, 2, 14),
		},
		[]string{"operation_type"},
	)
)

func init() {
	prometheus.MustRegister(TpmFailuresTotal)
	prometheus.MustRegister(CryptoOperationalLatencies)
}

// Serve creates http server for hosting Prometheus metrics.
func (m *Metrics) Serve() chan error {
	errorChan := make(chan error)
	mux := http.NewServeMux()
	mux.Handle(fmt.Sprintf("/%s", m.ServingURL.EscapedPath()), promhttp.Handler())

	go func() {
		defer close(errorChan)
		glog.Infof("Registering Metrics listener on port %s", m.ServingURL.Port())
		errorChan <- http.ListenAndServe(m.ServingURL.Host, mux)
	}()

	return errorChan
}

func RecordCryptoOperation(operationType string, start time.Time) {
	CryptoOperationalLatencies.WithLabelValues(operationType).Observe(sinceInMilliseconds(start))
}

func sinceInMilliseconds(start time.Time) float64 {
	return float64(time.Since(start) / time.Millisecond)
}
