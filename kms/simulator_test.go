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
	"fmt"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"sync"
)

var simLock sync.Mutex
var simInit bool

type simulatorWrapper struct {
	rwc *simulator.Simulator
	t   transport.TPM
}

func (s *simulatorWrapper) Read(b []byte) (int, error) {
	return s.rwc.Read(b)
}

func (s *simulatorWrapper) Write(b []byte) (int, error) {
	return s.rwc.Write(b)
}

func (s *simulatorWrapper) Send(input []byte) ([]byte, error) {
	return s.t.Send(input)
}

func (s *simulatorWrapper) Close() error {
	if err := tpm2.Shutdown(s.rwc, tpm2.StartupClear); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

func GetSimulator() (transport.TPMCloser, error) {
	simLock.Lock()
	defer simLock.Unlock()

	if !simInit {
		tmp, err := simulator.Get()
		if err != nil {
			return nil, err
		}
		_ = tmp
		simInit = true
	}
	rwc := &simulator.Simulator{}
	s := &simulatorWrapper{
		rwc: rwc,
		t:   transport.FromReadWriter(rwc),
	}
	simInit = true
	return s, nil
}
