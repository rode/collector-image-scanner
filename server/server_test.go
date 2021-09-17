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
	"context"
	"encoding/hex"
	"fmt"
	"runtime"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/rode/collector-image-scanner/proto/v1alpha1"
	"github.com/rode/collector-image-scanner/scanner/scannerfakes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ = Describe("Server", func() {

	Context("StartImageScan", func() {
		var (
			ctx      context.Context
			request  *v1alpha1.CreateImageScanRequest
			imageUri string
			server   *collectorImageScannerServer
			scanner  *scannerfakes.FakeImageScanner

			actualEmpty *emptypb.Empty
			actualError error
		)

		BeforeEach(func() {
			ctx = context.Background()
			imageUri = randomImageUri()
			request = &v1alpha1.CreateImageScanRequest{
				ImageUri: imageUri,
			}
			scanner = &scannerfakes.FakeImageScanner{}
			server = NewCollectorImageScannerServer(logger, scanner)
		})

		JustBeforeEach(func() {
			actualEmpty, actualError = server.StartImageScan(ctx, request)
			runtime.Gosched()
		})

		When("the image is valid", func() {
			It("should initiate a scan in the background", func() {
				Expect(scanner.ImageScanCallCount()).To(Equal(1))

				actualCtx, actualUri := scanner.ImageScanArgsForCall(0)
				actualAuthz := metautils.ExtractIncoming(actualCtx).Get("authorization")

				Expect(actualUri).To(Equal(imageUri))
				Expect(actualAuthz).To(BeEmpty())
			})

			It("should not return an error", func() {
				Expect(actualEmpty).To(Equal(&emptypb.Empty{}))
				Expect(actualError).NotTo(HaveOccurred())
			})
		})

		When("the incoming context has an authorization header", func() {
			var expectedAuthorization string

			BeforeEach(func() {
				expectedAuthorization = fake.Word()
				meta := metadata.New(map[string]string{
					"authorization": expectedAuthorization,
				})
				ctx = metautils.NiceMD(meta).ToIncoming(ctx)
			})

			It("should pass the authorization header along", func() {
				Expect(scanner.ImageScanCallCount()).To(Equal(1))

				actualCtx, _ := scanner.ImageScanArgsForCall(0)
				actualAuthz := metautils.ExtractIncoming(actualCtx).Get("authorization")

				Expect(actualAuthz).To(Equal(expectedAuthorization))
			})
		})

		When("the image uri is malformed", func() {
			BeforeEach(func() {
				request.ImageUri = fake.Word()
			})

			It("should not invoke the scanner", func() {
				Expect(scanner.ImageScanCallCount()).To(Equal(0))
			})

			It("should return an error", func() {
				Expect(actualError).To(HaveOccurred())
				status, ok := status.FromError(actualError)
				Expect(ok).To(BeTrue())
				Expect(status.Code()).To(Equal(codes.InvalidArgument))
			})
		})

		DescribeTable("valid image URIs", func(imageUri string) {
			request.ImageUri = imageUri

			_, scanError := server.StartImageScan(ctx, request)
			Expect(scanError).NotTo(HaveOccurred())
		},
			Entry("Docker registry image", "sonarqube@sha256:452e87fe1f932a920bb9546ce0ad148f897565e752fe342058489214b0275c1b"),
			Entry("Docker registry namespaced image", "curlimages/curl@sha256:6e0a786e3e5181df00eaf3a0a1749c18a6bb20b01c9bd192ea72176ce8a1c94b"),
			Entry("Azure Container Registry", "example.azurecr.io/app@sha256:967530243b7964106737d162105dc5ac53bf610c1c8934a7e5022aec7346307e"),
			Entry("Microsoft Container Registry", "mcr.microsoft.com/azure-cli@sha256:2090963629cc9c595bbad24354bb6879112d895bcb2dcd29c604209e30395669"),
			Entry("GitHub Container Registry", "ghcr.io/rode/ui@sha256:a4042b54517a3d36b101fe304435f2ee414bf1dfc0cf0486caa462f4a018ef18"),
			Entry("Hyphenated image name", "ghcr.io/rode/collector-image-scanner@sha256:6ca724440365a72b2cb66f3049cdd1545d395f728c9efe865ebfcc5403cb2ace"),
			Entry("Underscores in image name", "ghcr.io/rode/collector_image_scanner@sha256:6ca724440365a72b2cb66f3049cdd1545d395f728c9efe865ebfcc5403cb2ace"),
		)
	})
})

func randomImageUri() string {
	digestBytes := make([]byte, 32)
	fake.Rand.Read(digestBytes)
	digest := hex.EncodeToString(digestBytes)

	return fmt.Sprintf("%s@sha256:%s", fake.Word(), digest)
}
