package middlewares

import "net/http"

type Middleware interface {
	MitmRequest(req *http.Request) error
	MitmResponse(res *http.Response) error
}
