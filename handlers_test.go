package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"

	"github.com/jlewi/hmacproxy/pkg/hmacauth"
	"github.com/jlewi/hydros/pkg/util"
)

// proxiedServer performs the role of the upstream server that requests are proxied to
type proxiedServer struct {
	http.Handler
}

func (ps proxiedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("Success!"))
}

func newServer(opts *HmacProxyOpts) (*httptest.Server, error) {
	// The full command-line program requires that -port be greater than
	// zero, but the test servers will pick ports dynamically. To avoid
	// having useless -port arguments in the test, we'll add a fake
	// argument here.
	opts.Port = 1
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	handler, err := NewHTTPProxyHandler(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create handler")
	}
	return httptest.NewServer(handler), nil
}

func Test_proxy(t *testing.T) {
	type testCase struct {
		name string
		code int
		body string
		path string
	}

	cases := []testCase{
		{
			name: "basic",
			code: http.StatusOK,
			body: "Success!",
			path: "/api/github/webhook",
		},
		{
			name: "notfound",
			code: http.StatusNotFound,
			body: "404 page not found\n",
			path: "/api/github/webhook/extra",
		},
		{
			name: "invalid-sig",
			code: http.StatusUnauthorized,
			body: "unauthorized request\n",
			path: "/api/github/webhook",
		},
	}

	util.SetupLogger("info", true)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			upstream := httptest.NewServer(proxiedServer{})
			opts := &HmacProxyOpts{
				Port:       0,
				Digest:     HmacProxyDigest{Name: "sha256"},
				Secret:     "foobar",
				SignHeader: "Test-Signature",
				Headers:    []string{},
				Mappings: Mappings{Routes: []Route{
					{
						Path:     "/api/github/webhook",
						Upstream: upstream.URL + "/api/github/webhook",
					},
				}},

				SslCert: "",
				SslKey:  "",
			}
			proxy, err := newServer(opts)
			if err != nil {
				t.Fatalf("Failed to create proxy server; error %v", err)
			}

			// Now issue a request
			reqBody := "somepayload"
			buff := bytes.NewBuffer([]byte(reqBody))
			req, err := http.NewRequest(http.MethodPost, proxy.URL+c.path, buff)
			if err != nil {
				t.Fatalf("Error %v", err)
			}

			hmac := hmacauth.NewHmacAuth(opts.Digest.ID, []byte(opts.Secret), opts.SignHeader, opts.Headers, true)

			// Set a valid signature for any test case that doesn't fail with an authorization error.
			if c.code == http.StatusUnauthorized {
				req.Header.Set("Test-Signature", "badsignature")
			} else {
				sig := hmac.RequestSignature(req)
				req.Header.Set("Test-Signature", sig)
			}

			response, err := http.DefaultClient.Do(req)
			defer response.Body.Close()
			if err != nil {
				t.Fatalf("Get failed: %v", err)
			}

			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("Error reading response; %v", err)
			}

			if response.StatusCode != c.code {
				t.Errorf("Unexpected statuscode; got %v, want %v", response.StatusCode, c.code)
			}

			if string(body) != c.body {
				t.Errorf("Unexpected body; Got %v; want %v", string(body), c.body)
			}
		})
	}
}
