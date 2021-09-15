package scanner

//go:generate counterfeiter -generate

//counterfeiter:generate . ImageScanner
type ImageScanner interface {
	ImageScan(string)
	Init() error
}
