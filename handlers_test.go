package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jlewi/hmacproxy/pkg/hmacauth"
	"github.com/jlewi/hydros/pkg/util"
)

func newHandler(opts *HmacProxyOpts) (handler http.Handler, description string) {

	// The full command-line program requires that -port be greater than
	// zero, but the test servers will pick ports dynamically. To avoid
	// having useless -port arguments in the test, we'll add a fake
	// argument here.
	opts.Port = 1
	if err := opts.Validate(); err != nil {
		panic("error parsing options: " + err.Error())
	}
	return NewHTTPProxyHandler(opts)
}

type proxiedServer struct {
	http.Handler
}

func (ps proxiedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("Success!"))
}

func newServer(opts *HmacProxyOpts) (*httptest.Server, string) {
	handler, desc := newHandler(opts)
	return httptest.NewServer(handler), desc
}

func Test_proxy(t *testing.T) {
	type testCase struct {
		name string
		code int
		body string
	}

	cases := []testCase{
		{
			name: "basic",
			code: http.StatusOK,
			body: "Success!",
		},
		{
			name: "invalid-sig",
			code: http.StatusUnauthorized,
			body: "unauthorized request\n",
		},
	}

	util.SetupLogger("info", true)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proxied := httptest.NewServer(proxiedServer{})
			opts := &HmacProxyOpts{
				Port:       0,
				Digest:     HmacProxyDigest{Name: "sha256"},
				Secret:     "foobar",
				SignHeader: "Test-Signature",
				Headers:    []string{},
				Upstream: HmacProxyURL{
					Raw: proxied.URL,
					URL: nil,
				},

				SslCert: "",
				SslKey:  "",
			}
			upstream, _ := newServer(opts)

			reqBody := "somepayload"
			buff := bytes.NewBuffer([]byte(reqBody))
			req, err := http.NewRequest(http.MethodPost, upstream.URL, buff)
			if err != nil {
				t.Fatalf("Error %v", err)
			}

			hmac := hmacauth.NewHmacAuth(opts.Digest.ID, []byte(opts.Secret), opts.SignHeader, opts.Headers, true)
			if c.code == http.StatusOK {
				sig := hmac.RequestSignature(req)
				req.Header.Set("Test-Signature", sig)
			} else {
				req.Header.Set("Test-Signature", "badsignature")
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
