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
	"github.com/jc-lab/k8s-tpm-kms-plugin/cmd/util"
	"github.com/jc-lab/k8s-tpm-kms-plugin/tpm"
	"log"
	"os"
)

var (
	pathToTPM     = flag.String("tpm-device", "/dev/tpmrm0", "Path to tpm device or tpm resource manager.")
	pcrsToMeasure = flag.String("pcrs", "", "PCR to measure.")
	pathToPrivate = flag.String("input-private", "priv.bin", "Path to the private area.")
	pathToPublic  = flag.String("input-public", "pub.bin", "Path to the public area.")
	pathToOutput  = flag.String("output", "", "Path to output.")
)

func main() {
	flag.Parse()

	privateArea, err := os.ReadFile(*pathToPrivate)
	if err != nil {
		glog.Fatal(err)
	}

	publicArea, err := os.ReadFile(*pathToPublic)
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

	sealResp, err := tpm.Unseal(tpmDev, createSrkResp, PCRs, privateArea, publicArea)
	if err != nil {
		glog.Fatal(err)
	}

	if err := os.WriteFile(*pathToOutput, sealResp.OutData.Buffer, 0644); err != nil {
		glog.Fatal(err)
	}
}
