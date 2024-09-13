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

package util

import (
	"github.com/golang/glog"
	"strconv"
	"strings"
)

func ParsePCRs(s string) []uint {
	var PCRs []uint
	if len(s) > 0 {
		for _, s := range strings.Split(s, ",") {
			pcr, err := strconv.Atoi(s)
			if err != nil {
				glog.Fatalln(err)
			}
			PCRs = append(PCRs, uint(pcr))
		}
	}
	return PCRs
}
