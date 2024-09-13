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
	"github.com/golang/glog"
	"github.com/google/go-tpm/tpm2"
	"github.com/jc-lab/k8s-tpm-kms-plugin/cmd/util"
	"github.com/jc-lab/k8s-tpm-kms-plugin/tpm"
	"log"
	"os"
)

var (
	pathToTPM       = flag.String("tpm-device", "/dev/tpmrm0", "Path to tpm device or tpm resource manager.")
	pcrsToMeasure   = flag.String("pcrs", "", "PCRs to measure.")
	pathToPlaintext = flag.String("input", "", "Data to seal.")
	pathToPrivate   = flag.String("output-private", "priv.bin", "Path to the private area.")
	pathToPublic    = flag.String("output-public", "pub.bin", "Path to the public area.")
)

func main() {
	flag.Parse()

	d, err := os.ReadFile(*pathToPlaintext)
	if err != nil {
		glog.Fatal(err)
	}

	PCRs := util.ParsePCRs(*pcrsToMeasure)

	tpmDev, err := tpm.OpenTPM(*pathToTPM)
	if err != nil {
		glog.Fatal(err)
	}
	defer tpmDev.Close()

	createSrkResp, err := tpm.CreatePrimary(tpmDev)
	if err != nil {
		log.Fatalln("createPrimary failed: ", err)
	}
	defer tpm.FlushContext(tpmDev, createSrkResp.ObjectHandle)

	sealResp, err := tpm.Seal(tpmDev, createSrkResp, PCRs, d)
	if err != nil {
		glog.Fatal(err)
	}

	if err := os.WriteFile(*pathToPrivate, tpm2.Marshal(sealResp.OutPrivate), 0644); err != nil {
		glog.Fatal(err)
	}

	if err := os.WriteFile(*pathToPublic, tpm2.Marshal(sealResp.OutPublic), 0600); err != nil {
		glog.Fatal(err)
	}
}
