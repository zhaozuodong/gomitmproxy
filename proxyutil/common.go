package proxyutil

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"github.com/andybalholm/brotli"
	"io"
)

func BodyDecode(enc string, body []byte) ([]byte, error) {
	switch enc {
	case "gzip":
		dreader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		buf := bytes.NewBuffer(make([]byte, 0))
		_, err = io.Copy(buf, dreader)
		if err != nil {
			return nil, err
		}
		err = dreader.Close()
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "br":
		dreader := brotli.NewReader(bytes.NewReader(body))
		buf := bytes.NewBuffer(make([]byte, 0))
		_, err := io.Copy(buf, dreader)
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "deflate":
		dreader := flate.NewReader(bytes.NewReader(body))
		buf := bytes.NewBuffer(make([]byte, 0))
		_, err := io.Copy(buf, dreader)
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return body, nil
	}
}

func BodyEncode(enc string, body []byte) ([]byte, error) {
	switch enc {
	case "gzip":
		var buf bytes.Buffer
		gwriter := gzip.NewWriter(&buf)
		_, err := gwriter.Write(body)
		if err != nil {
			return nil, err
		}
		err = gwriter.Close()
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "br":
		var buf bytes.Buffer
		bwriter := brotli.NewWriter(&buf)
		_, err := bwriter.Write(body)
		if err != nil {
			return nil, err
		}
		err = bwriter.Close()
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "deflate":
		var buf bytes.Buffer
		dwriter, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
		_, err = dwriter.Write(body)
		if err != nil {
			return nil, err
		}
		err = dwriter.Close()
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return body, nil
	}
}
