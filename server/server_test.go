package server

import (
	"context"
	"fmt"
	"runtime"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rode/collector-image-scanner/proto/v1alpha1"
	"github.com/rode/collector-image-scanner/scanner/scannerfakes"
	"google.golang.org/grpc/codes"
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
			imageUri = fmt.Sprintf("%s@sha256:%s", fake.Word(), fake.LetterN(64))
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
				Expect(scanner.ImageScanArgsForCall(0)).To(Equal(imageUri))
			})

			It("should not return an error", func() {
				Expect(actualEmpty).To(Equal(&emptypb.Empty{}))
				Expect(actualError).NotTo(HaveOccurred())
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
	})
})
