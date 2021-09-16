# collector-image-scanner

[![test](https://github.com/rode/collector-image-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/rode/collector-image-scanner/actions/workflows/test.yml)

Scans container images and send vulnerability results to [Rode](https://github.com/rode/rode). Currently, [Trivy](https://aquasecurity.github.io/trivy) scans are supported.

## Local Development

1. Start a Trivy server with `trivy server`
1. With Rode running, start the collector with `go run`:
    ```
    go run main.go \
        --rode-insecure-disable-transport-security \
        --rode-host=localhost:50051 \
        --debug
    ```
1. Use the API to request a scan:
   ```
     curl http://localhost:1233/v1alpha1/scan \
        -d '{"imageUri": "curlimages/curl@sha256:6e0a786e3e5181df00eaf3a0a1749c18a6bb20b01c9bd192ea72176ce8a1c94b"}' 
   ```
1. After making changes, run the unit tests with `make test`
1. Use `make license` to add license headers to source code files
