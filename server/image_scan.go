package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/report"
	"go.uber.org/zap"
	"log"
	"os"
	"os/exec"
)
import rode "github.com/rode/rode/proto/v1alpha1"

type trivyImageScanner struct {
	logger *zap.Logger
	rode   rode.RodeClient
}

type ImageScanner interface {
	ImageScan(string)
}

func (t *trivyImageScanner) ImageScan(imageUri string) {
	cmd := exec.Command("trivy", "--quiet", "image", "--format", "json", "--no-progress", imageUri)
	cmd.Env = append(os.Environ(), "TRIVY_NEW_JSON_SCHEMA=true")
	var stdOut bytes.Buffer
	var stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	err := cmd.Run()
	if err != nil {
		log.Println(err)
		log.Println(stdErr.String())
	}

	var scanReport report.Report
	err = json.Unmarshal(stdOut.Bytes(), &scanReport)
	if err != nil {
		log.Println(err)
	}

	fmt.Printf("%v", scanReport)
}

func NewImageScanner(logger *zap.Logger, client rode.RodeClient) ImageScanner {
	return &trivyImageScanner{logger: logger, rode: client}
}
