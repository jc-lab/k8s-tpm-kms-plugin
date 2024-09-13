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

package swtpm

import (
	"fmt"
	"github.com/google/go-tpm/tpm2/transport"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type Swtpm struct {
	StateDir string
	lock     sync.Mutex
}

func New() (*Swtpm, error) {
	stateDir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	instance := &Swtpm{
		StateDir: stateDir,
	}
	return instance, nil
}

func (s *Swtpm) Close() error {
	return os.RemoveAll(s.StateDir)
}

func (s *Swtpm) Open() (transport.TPMCloser, error) {
	s.lock.Lock()

	randomAddr := fmt.Sprintf("127.1.1.%d", 1+rand.Intn(254))
	cmd := exec.Command("swtpm", "socket", "--tpmstate", "dir="+s.StateDir, "--tpm2", "--server", "type=tcp,port=2321,bindaddr="+randomAddr, "--ctrl", "type=tcp,port=2322,bindaddr="+randomAddr, "--flags", "not-need-init,startup-clear")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		s.lock.Unlock()
		return nil, err
	}
	time.Sleep(time.Millisecond * 500)

	//conn, err := mssim.Open(mssim.Config{
	//	CommandAddress:  randomAddr + ":2321",
	//	PlatformAddress: randomAddr + ":2322",
	//})
	conn, err := net.Dial("tcp", randomAddr+":2321")
	if err != nil {
		cmd.Process.Kill()
		s.lock.Unlock()
		return nil, err
	}
	go func() {
		state, err := cmd.Process.Wait()
		s.lock.Unlock()

		log.Printf("SWTPM Finished: %+v | %+v", state, err)
	}()
	return &tpmWrapper{
		conn: conn,
		t:    transport.FromReadWriter(conn),
		cleanup: func() {
			cmd.Process.Signal(syscall.SIGTERM)
		},
	}, nil
}

type tpmWrapper struct {
	conn    io.ReadWriteCloser
	t       transport.TPM
	cleanup func()
}

func (t *tpmWrapper) Send(input []byte) ([]byte, error) {
	return t.t.Send(input)
}

func (t *tpmWrapper) Close() error {
	defer t.cleanup()
	return t.conn.Close()
}
