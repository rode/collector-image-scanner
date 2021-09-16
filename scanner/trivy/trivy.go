// Copyright 2021 The Rode Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trivy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/aquasecurity/trivy/pkg/report"
)

//go:generate counterfeiter -generate

//counterfeiter:generate . CommandWrapper
type CommandWrapper interface {
	Version() (*Version, error)
	Scan(imageUri string) (*ScanOutput, error)
}

type trivyCommand struct{}

type Version struct {
	Version string
}

type cmdOutput struct {
	stdOut bytes.Buffer
	stdErr bytes.Buffer
}

type ScanOutput struct {
	Report    *report.Report
	ScanStart time.Time
	ScanEnd   time.Time
}

func NewTrivyCommandWrapper() CommandWrapper {
	return &trivyCommand{}
}

func (t *trivyCommand) Version() (*Version, error) {
	output, err := t.runCmd("--version", "-f", "json")
	if err != nil {
		return nil, fmt.Errorf("error checking Trivy version: %v", err)
	}
	var version Version
	if err = json.Unmarshal(output.stdOut.Bytes(), &version); err != nil {
		return nil, fmt.Errorf("error unmarshalling version information: %v", err)
	}

	return &version, nil
}

func (t *trivyCommand) Scan(imageUri string) (*ScanOutput, error) {
	scanResult := &ScanOutput{}

	scanResult.ScanStart = time.Now()
	output, err := t.runCmd("--quiet", "client", "--format", "json", imageUri)
	scanResult.ScanEnd = time.Now()

	if err != nil {
		return nil, fmt.Errorf("error running image scan: %v", err)
	}

	var scanReport report.Report
	if err = json.Unmarshal(output.stdOut.Bytes(), &scanReport); err != nil {
		return nil, fmt.Errorf("error unmarshalling report: %v", err)
	}
	scanResult.Report = &scanReport

	return scanResult, nil
}

func (t *trivyCommand) runCmd(args ...string) (*cmdOutput, error) {
	output := &cmdOutput{}
	cmd := exec.Command("trivy", args...)
	cmd.Env = append(os.Environ(), "TRIVY_NEW_JSON_SCHEMA=true")
	cmd.Stdout = &output.stdOut
	cmd.Stderr = &output.stdErr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error running command: %w (stderr: %s)", err, output.stdErr.String())
	}

	return output, nil
}
