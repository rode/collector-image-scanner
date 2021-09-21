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

package trivy_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rode/collector-image-scanner/scanner"
	"github.com/rode/collector-image-scanner/scanner/trivy"
	"github.com/rode/collector-image-scanner/scanner/trivy/trivyfakes"
	"github.com/rode/rode/proto/v1alpha1fakes"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/common_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/discovery_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/grafeas_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/package_go_proto"
	"github.com/rode/rode/protodeps/grafeas/proto/v1beta1/vulnerability_go_proto"
)

var _ = Describe("TrivyScanner", func() {

	var (
		rode         *v1alpha1fakes.FakeRodeClient
		trivyCommand *trivyfakes.FakeCommandWrapper
		scanner      scanner.ImageScanner

		expectedVersion string
		versionError    error
	)

	BeforeEach(func() {
		rode = &v1alpha1fakes.FakeRodeClient{}
		trivyCommand = &trivyfakes.FakeCommandWrapper{}

		expectedVersion = fake.Word()
		versionError = nil

		scanner = trivy.NewImageScanner(logger, rode, trivyCommand)
	})

	JustBeforeEach(func() {
		trivyCommand.VersionReturns(&trivy.Version{Version: expectedVersion}, versionError)
	})

	Context("Init", func() {
		var actualError error

		JustBeforeEach(func() {
			actualError = scanner.Init()
		})

		It("should check the Trivy version", func() {
			Expect(trivyCommand.VersionCallCount()).To(Equal(1))
		})

		It("should not return an error", func() {
			Expect(actualError).NotTo(HaveOccurred())
		})

		When("an error occurs checking the version", func() {
			BeforeEach(func() {
				versionError = errors.New("version error")
			})

			It("should return an error", func() {
				Expect(actualError).To(HaveOccurred())
			})
		})
	})

	Context("ImageScan", func() {
		var (
			imageUri                 string
			expectedOccurrencesCount int

			expectedNoteName string
			expectedNote     *grafeas_go_proto.Note
			createNoteError  error

			scanResults *trivy.ScanOutput
			scanError   error
		)

		BeforeEach(func() {
			expectedNoteName = fake.Word()
			expectedNote = &grafeas_go_proto.Note{
				Name: expectedNoteName,
			}
			createNoteError = nil

			imageUri = fake.Word()
			scanResults = &trivy.ScanOutput{
				Report:     &report.Report{},
				ScanStatus: trivy.ScanningCompleted,
			}
			scanError = nil

			iterations := fake.Number(2, 5)
			for i := 0; i < iterations; i++ {
				vulnerability := types.DetectedVulnerability{
					VulnerabilityID: fake.Word(),
				}
				vulnerability.Description = fake.Word()
				vulnerability.Severity = fake.RandomString([]string{"LOW", "MEDIUM", "HIGH", "CRITICAL"})
				vulnerability.References = []string{fake.URL(), fake.URL()}
				vulnerability.PkgName = fake.Word()

				scanResults.Report.Results = append(scanResults.Report.Results, report.Result{
					Vulnerabilities: []types.DetectedVulnerability{vulnerability},
				})
			}

			expectedOccurrencesCount = 2 + len(scanResults.Report.Results)
		})

		JustBeforeEach(func() {
			rode.CreateNoteReturns(expectedNote, createNoteError)
			trivyCommand.ScanReturns(scanResults, scanError)

			Expect(scanner.Init()).NotTo(HaveOccurred())
			scanner.ImageScan(context.Background(), imageUri)
		})

		It("should create a note for the scan", func() {
			Expect(rode.CreateNoteCallCount()).To(Equal(1))
			_, actualNote, _ := rode.CreateNoteArgsForCall(0)

			Expect(actualNote.NoteId).To(HavePrefix("image-scanner-collector-scan"))
			Expect(actualNote.Note.ShortDescription).To(ContainSubstring("Vulnerability Scan"))
			Expect(actualNote.Note.LongDescription).To(ContainSubstring(fmt.Sprintf("Trivy (%s)", expectedVersion)))
			Expect(actualNote.Note.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
			Expect(actualNote.Note.RelatedUrl).To(HaveLen(1))
			Expect(actualNote.Note.RelatedUrl[0].Url).To(Equal(imageUri))

			actualNoteType := actualNote.Note.Type.(*grafeas_go_proto.Note_Discovery)
			Expect(actualNoteType.Discovery.AnalysisKind).To(Equal(common_go_proto.NoteKind_VULNERABILITY))
		})

		It("should create two discovery occurrences", func() {
			Expect(rode.BatchCreateOccurrencesCallCount()).To(Equal(1))

			_, actualRequest, _ := rode.BatchCreateOccurrencesArgsForCall(0)

			Expect(actualRequest.Occurrences).To(HaveLen(expectedOccurrencesCount))
			for i := 0; i < 2; i++ {
				actualOccurrence := actualRequest.Occurrences[i]

				expectedStatus := discovery_go_proto.Discovered_SCANNING
				if i == 1 {
					expectedStatus = discovery_go_proto.Discovered_FINISHED_SUCCESS
				}

				Expect(actualOccurrence.Resource.Uri).To(Equal(imageUri))
				Expect(actualOccurrence.NoteName).To(Equal(expectedNoteName))
				Expect(actualOccurrence.CreateTime.IsValid()).To(BeTrue())
				Expect(actualOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
				Expect(actualOccurrence.GetDiscovered().Discovered.ContinuousAnalysis).To(Equal(discovery_go_proto.Discovered_CONTINUOUS_ANALYSIS_UNSPECIFIED))
				Expect(actualOccurrence.GetDiscovered().Discovered.AnalysisStatus).To(Equal(expectedStatus))
			}
		})

		It("should create an occurrence for each vulnerability", func() {
			_, actualRequest, _ := rode.BatchCreateOccurrencesArgsForCall(0)

			for i := 2; i < expectedOccurrencesCount; i++ {
				actualOccurrence := actualRequest.Occurrences[i]

				Expect(actualOccurrence.Resource.Uri).To(Equal(imageUri))
				Expect(actualOccurrence.NoteName).To(Equal(expectedNoteName))
				Expect(actualOccurrence.CreateTime.IsValid()).To(BeTrue())
				Expect(actualOccurrence.Kind).To(Equal(common_go_proto.NoteKind_VULNERABILITY))

				expectedResult := scanResults.Report.Results[i-2].Vulnerabilities[0]
				expectedSeverity := vulnerability_go_proto.Severity_value[expectedResult.Severity]

				actualVuln := actualOccurrence.GetVulnerability()
				Expect(actualVuln.Type).To(Equal("docker"))
				Expect(actualVuln.EffectiveSeverity).To(BeEquivalentTo(expectedSeverity))
				Expect(actualVuln.ShortDescription).To(Equal(expectedResult.Description))

				Expect(actualVuln.RelatedUrls).To(HaveLen(len(expectedResult.References)))
				for j := 0; j < len(expectedResult.References); j++ {
					Expect(actualVuln.RelatedUrls[j].Url).To(Equal(expectedResult.References[j]))
				}

				Expect(actualVuln.PackageIssue).To(HaveLen(1))
				Expect(actualVuln.PackageIssue[0].AffectedLocation.Package).To(Equal(expectedResult.PkgName))
				Expect(actualVuln.PackageIssue[0].AffectedLocation.CpeUri).To(ContainSubstring(expectedResult.VulnerabilityID))
				Expect(actualVuln.PackageIssue[0].AffectedLocation.Version.Name).To(Equal(expectedResult.PkgName))
				Expect(actualVuln.PackageIssue[0].AffectedLocation.Version.Kind).To(Equal(package_go_proto.Version_NORMAL))
			}
		})

		When("an error occurs during the scan", func() {
			BeforeEach(func() {
				scanError = errors.New("scan error")
				scanResults.ScanStatus = trivy.ScanningFailed
			})

			It("should create a note and discovery occurrences, but no vulnerability occurrences in Rode", func() {
				Expect(rode.CreateNoteCallCount()).To(Equal(1))
				Expect(rode.BatchCreateOccurrencesCallCount()).To(Equal(1))

				_, actualRequest, _ := rode.BatchCreateOccurrencesArgsForCall(0)

				for i, actualOccurrence := range actualRequest.Occurrences {
					expectedStatus := discovery_go_proto.Discovered_SCANNING
					if i == 1 {
						expectedStatus = discovery_go_proto.Discovered_FINISHED_FAILED
					}

					Expect(actualOccurrence.Kind).To(Equal(common_go_proto.NoteKind_DISCOVERY))
					Expect(actualOccurrence.GetDiscovered().Discovered.AnalysisStatus).To(Equal(expectedStatus))
				}
			})
		})

		When("an error occurs creating the note", func() {
			BeforeEach(func() {
				createNoteError = errors.New("create note error")
			})

			It("should not try to create any occurrences", func() {
				Expect(rode.BatchCreateOccurrencesCallCount()).To(Equal(0))
			})
		})
	})
})
