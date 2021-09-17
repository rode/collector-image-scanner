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
	"regexp"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/rode/collector-image-scanner/proto/v1alpha1"
	"github.com/rode/collector-image-scanner/scanner"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

var imageUriPattern = regexp.MustCompile("[[:alnum:]/_.\\-]+@sha256:[[:xdigit:]]{64}")

type collectorImageScannerServer struct {
	logger  *zap.Logger
	scanner scanner.ImageScanner
}

func NewCollectorImageScannerServer(logger *zap.Logger, scanner scanner.ImageScanner) *collectorImageScannerServer {
	return &collectorImageScannerServer{
		logger,
		scanner,
	}
}

func (s *collectorImageScannerServer) StartImageScan(ctx context.Context, request *v1alpha1.CreateImageScanRequest) (*emptypb.Empty, error) {
	if !imageUriPattern.MatchString(request.ImageUri) {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Image URI")
	}
	go s.scanner.ImageScan(extractAuthz(ctx), request.ImageUri)

	return &emptypb.Empty{}, nil
}

func extractAuthz(ctx context.Context) context.Context {
	authzHeader := metautils.ExtractIncoming(ctx).Get("authorization")
	meta := metadata.New(map[string]string{})
	if authzHeader != "" {
		meta.Set("authorization", authzHeader)
	}

	return metautils.NiceMD(meta).ToIncoming(context.Background())
}
