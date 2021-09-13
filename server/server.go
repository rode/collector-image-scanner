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
	"github.com/rode/collector-image-scanner/proto/v1alpha1"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	rodeProjectId             = "projects/rode"
	collectorImageScannerNote = rodeProjectId + "/notes/collector_image_scanner"
)

type collectorImageScannerServer struct {
	logger  *zap.Logger
	scanner ImageScanner
}

func NewCollectorImageScannerServer(logger *zap.Logger, scanner ImageScanner) *collectorImageScannerServer {
	return &collectorImageScannerServer{
		logger,
		scanner,
	}
}

func (s *collectorImageScannerServer) StartImageScan(ctx context.Context, request *v1alpha1.CreateImageScanRequest) (*emptypb.Empty, error) {
	go s.scanner.ImageScan(request.ImageUri)

	return &emptypb.Empty{}, nil
}
