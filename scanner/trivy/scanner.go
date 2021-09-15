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
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/rode/collector-image-scanner/scanner"
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
	logger  *zap.Logger
	rode    rode.RodeClient
	trivy   CommandWrapper
	version string
}

func NewImageScanner(logger *zap.Logger, client rode.RodeClient, trivyWrapper CommandWrapper) scanner.ImageScanner {
	return &trivyImageScanner{
		logger: logger,
		rode:   client,
		trivy:  trivyWrapper,
	}
}

func (t *trivyImageScanner) Init() error {
	t.logger.Info("Discovering Trivy version")
	version, err := t.trivy.Version()
	if err != nil {
		return err
	}
	t.logger.Info("Found Trivy version", zap.String("version", version.Version))
	t.version = version.Version
	return nil
}

func (t *trivyImageScanner) ImageScan(imageUri string) {
	log := t.logger.Named("ImageScan").With(zap.String("imageUri", imageUri))
	log.Info("Starting scan")

	results, err := t.trivy.Scan(imageUri)
	if err != nil {
		log.Error("Error scanning image", zap.Error(err))
		return
	}
	log.Debug("Scan completed", zap.Duration("scan", results.ScanEnd.Sub(results.ScanStart)))

	ctx := context.Background()
	noteName, err := t.createScanNote(ctx, imageUri)
	if err != nil {
		log.Error("Error creating scan note", zap.Error(err))
		return
	}
	log.Info("Created scan note", zap.String("noteName", noteName))
	discoveryOccurrences := t.createDiscoveryOccurrences(noteName, imageUri, results)
	vulnerabilityOccurrences := t.createVulnerabilityOccurrences(noteName, imageUri, results)

	_, err = t.rode.BatchCreateOccurrences(ctx, &rode.BatchCreateOccurrencesRequest{
		Occurrences: append(discoveryOccurrences, vulnerabilityOccurrences...),
	})

	if err != nil {
		log.Error("Error creating occurrences in Rode", zap.Error(err))
		return
	}

	log.Info("Successfully created occurrences in Rode")

	// TODO: Clear Trivy cache occasionally
}

func (t *trivyImageScanner) createScanNote(ctx context.Context, imageUri string) (string, error) {
	reportId := uuid.New()
	response, err := t.rode.CreateNote(ctx, &rode.CreateNoteRequest{
		Note: &grafeas_go_proto.Note{
			ShortDescription: "Image Scanner Collector Vulnerability Scan",
			LongDescription:  fmt.Sprintf("Image Scanner Collector Vulnerability Scan by Trivy (%s)", t.version),
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
		return "", err
	}

	return response.Name, nil
}

func (t *trivyImageScanner) createDiscoveryOccurrences(noteName, imageUri string, results *ScanOutput) []*grafeas_go_proto.Occurrence {
	return []*grafeas_go_proto.Occurrence{
		{
			Resource: &grafeas_go_proto.Resource{
				Uri: imageUri,
			},
			NoteName:   noteName,
			Kind:       common_go_proto.NoteKind_DISCOVERY,
			CreateTime: timestamppb.New(results.ScanStart),
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
			CreateTime: timestamppb.New(results.ScanEnd),
			Details: &grafeas_go_proto.Occurrence_Discovered{
				Discovered: &discovery_go_proto.Details{
					Discovered: &discovery_go_proto.Discovered{
						ContinuousAnalysis: discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED,
						AnalysisStatus:     discovery_go_proto.Discovered_FINISHED_SUCCESS,
					}},
			},
		},
	}
}

func (t *trivyImageScanner) createVulnerabilityOccurrences(noteName, imageUri string, results *ScanOutput) []*grafeas_go_proto.Occurrence {
	vulns := []*grafeas_go_proto.Occurrence{}

	for _, result := range results.Report.Results {
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

	return vulns
}
