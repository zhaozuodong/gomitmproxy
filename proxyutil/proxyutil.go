package proxyutil

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NewResponse builds new HTTP responses.
// If body is nil, an empty byte.Buffer will be provided to be consistent with
// the guarantees provided by http.Transport and http.Client.
func NewResponse(code int, body io.Reader, req *http.Request) *http.Response {
	if body == nil {
		body = &bytes.Buffer{}
	}

	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(body)
	}

	res := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       rc,
		Request:    req,
	}

	if req != nil {
		res.Close = req.Close
		res.Proto = req.Proto
		res.ProtoMajor = req.ProtoMajor
		res.ProtoMinor = req.ProtoMinor
	}

	return res
}

// Warning adds an error to the Warning header in the format: 199 "gomitmproxy"
// "error message" "date".
func Warning(header http.Header, err error) {
	date := header.Get("Date")
	if date == "" {
		date = time.Now().Format(http.TimeFormat)
	}

	w := fmt.Sprintf(`199 "gomitmproxy" %q %q`, err.Error(), date)
	header.Add("Warning", w)
}

// GetRangeStart returns the byte index of the start of the range, if it has one.
// Returns 0 if the range header is absent, and -1 if the range header is invalid or
// has multi-part ranges.
func GetRangeStart(res *http.Response) int64 {
	if res.StatusCode != http.StatusPartialContent {
		return 0
	}

	if strings.Contains(res.Header.Get("Content-Type"), "multipart/byteranges") {
		return -1
	}

	re := regexp.MustCompile(`bytes (\d+)-\d+/\d+`)
	matchSlice := re.FindStringSubmatch(res.Header.Get("Content-Range"))

	if len(matchSlice) < 2 {
		return -1
	}

	num, err := strconv.ParseInt(matchSlice[1], 10, 64)

	if err != nil {
		return -1
	}
	return num
}
