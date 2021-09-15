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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/google/uuid"
	rode "github.com/rode/rode/proto/v1alpha1"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/package_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type trivyImageScanner struct {
	logger *zap.Logger
	rode   rode.RodeClient
	trivy  *trivyVersion
}

type ImageScanner interface {
	ImageScan(string)
	Init() error
}

type trivyVersion struct {
	Version string
}

func NewImageScanner(logger *zap.Logger, client rode.RodeClient) ImageScanner {
	return &trivyImageScanner{logger: logger, rode: client}
}

func (t *trivyImageScanner) Init() error {
	t.logger.Info("Downloading Trivy Vulnerability DB")
	err := exec.Command("trivy", "image", "--download-db-only").Run()
	if err != nil {
		return err
	}
	t.logger.Info("Done")

	version, err := exec.Command("trivy", "--version", "-f", "json").Output()
	if err != nil {
		return err
	}
	var trivy trivyVersion
	if err := json.Unmarshal(version, &trivy); err != nil {
		return err
	}

	t.trivy = &trivy

	return nil
}

func (t *trivyImageScanner) ImageScan(imageUri string) {
	log := t.logger.Named("ImageScan").With(zap.String("imageUri", imageUri))
	log.Info("Starting scan")

	cmd := exec.Command("trivy", "--quiet", "image", "--format", "json", "--no-progress", imageUri)
	cmd.Env = append(os.Environ(), "TRIVY_NEW_JSON_SCHEMA=true")
	var stdOut bytes.Buffer
	var stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	scanStart := time.Now()
	err := cmd.Run()
	scanEnd := time.Now()

	log.Debug("Scan completed", zap.Duration("scan", scanEnd.Sub(scanStart)))
	if err != nil {
		log.With(zap.String("stderr", stdErr.String())).Error("Error scanning image", zap.Error(err))
		return
	}

	var scanReport report.Report
	err = json.Unmarshal(stdOut.Bytes(), &scanReport)
	if err != nil {
		log.Error("Error unmarshalling scan report", zap.Error(err))
		return
	}

	reportId := uuid.New()
	ctx := context.Background()
	response, err := t.rode.CreateNote(ctx, &rode.CreateNoteRequest{
		Note: &grafeas_go_proto.Note{
			ShortDescription: "Image Scanner Collector Vulnerability Scan",
			LongDescription:  fmt.Sprintf("Image Scanner Collector Vulnerability Scan by Trivy (%s)", t.trivy.Version),
			Kind:             common_go_proto.NoteKind_DISCOVERY,
			RelatedUrl: []*common_go_proto.RelatedUrl{
				{
					Label: "Artifact URL",
					Url:   imageUri,
				},
			},
			Type: &grafeas_go_proto.Note_Discovery{
				Discovery: &discovery_go_proto.Discovery{
					AnalysisKind: common_go_proto.NoteKind_VULNERABILITY,
				},
			},
		},
		NoteId: fmt.Sprintf("image-scanner-collector-scan-%s", reportId.String()),
	})

	if err != nil {
		log.Error("Error creating scan note", zap.Error(err))
		return
	}

	log.Info("noteName", zap.String("noteName", response.Name))
	noteName := response.Name
	discoveryOccurrences := []*grafeas_go_proto.Occurrence{
		{
			Resource: &grafeas_go_proto.Resource{
				Uri: imageUri,
			},
			NoteName:   noteName,
			Kind:       common_go_proto.NoteKind_DISCOVERY,
			CreateTime: timestamppb.New(scanStart),
			Details: &grafeas_go_proto.Occurrence_Discovered{
				Discovered: &discovery_go_proto.Details{
					Discovered: &discovery_go_proto.Discovered{
						ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
						AnalysisStatus:     discovery_go_proto.Discovered_SCANNING,
					}},
			},
		},
		{
			Resource: &grafeas_go_proto.Resource{
				Uri: imageUri,
			},
			NoteName:   noteName,
			Kind:       common_go_proto.NoteKind_DISCOVERY,
			CreateTime: timestamppb.New(scanEnd),
			Details: &grafeas_go_proto.Occurrence_Discovered{
				Discovered: &discovery_go_proto.Details{
					Discovered: &discovery_go_proto.Discovered{
						ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
						AnalysisStatus:     discovery_go_proto.Discovered_FINISHED_SUCCESS,
					}},
			},
		},
	}

	vulns := []*grafeas_go_proto.Occurrence{}

	for _, result := range scanReport.Results {
		for _, vuln := range result.Vulnerabilities {
			relatedUrls := []*common_go_proto.RelatedUrl{}

			for _, url := range vuln.References {
				relatedUrls = append(relatedUrls, &common_go_proto.RelatedUrl{
					Url: url,
				})
			}

			vulns = append(vulns, &grafeas_go_proto.Occurrence{
				Resource: &grafeas_go_proto.Resource{
					Uri: imageUri,
				},
				NoteName:   noteName,
				Kind:       common_go_proto.NoteKind_VULNERABILITY,
				CreateTime: timestamppb.Now(),
				Details: &grafeas_go_proto.Occurrence_Vulnerability{
					Vulnerability: &vulnerability_go_proto.Details{
						Type:              "docker",
						EffectiveSeverity: vulnerability_go_proto.Severity(vulnerability_go_proto.Severity_value[strings.ToUpper(vuln.Severity)]),
						ShortDescription:  vuln.Description,
						RelatedUrls:       relatedUrls,
						PackageIssue: []*vulnerability_go_proto.PackageIssue{
							{
								AffectedLocation: &vulnerability_go_proto.VulnerabilityLocation{
									CpeUri:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.VulnerabilityID),
									Package: vuln.PkgName,
									Version: &package_go_proto.Version{
										Name: vuln.PkgName,
										Kind: package_go_proto.Version_NORMAL,
									},
								},
							},
						},
					},
				},
			})
		}
	}

	_, err = t.rode.BatchCreateOccurrences(ctx, &rode.BatchCreateOccurrencesRequest{
		Occurrences: append(discoveryOccurrences, vulns...),
	})

	if err != nil {
		log.Error("Error creating occurrences in Rode", zap.Error(err))
		return
	}

	log.Info("Successfully created occurrences in Rode")

	// TODO: Clear Trivy cache occasionally
}
