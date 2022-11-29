package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/jlewi/hydros/pkg/util"
	"github.com/pkg/errors"

	"github.com/go-logr/zapr"
	"github.com/jlewi/hmacproxy/pkg/hmacauth"
	"go.uber.org/zap"
)

const (
	healthPath = "/healthz"
)

// Mappings is a list of paths and the upstream to map them to
type Mappings struct {
	Routes []Route `yaml:"routes,omitempty"`
}

type Route struct {
	// Path to math
	Path     string `yaml:"path,omitempty"`
	Upstream string `yaml:"upstream,omitempty"`
}

// NewHTTPProxyHandler returns a http.Handler and its description based on the
// configuration specified in opts.
func NewHTTPProxyHandler(opts *HmacProxyOpts) (*ProxyHandler, error) {
	log := zapr.NewLogger(zap.L())
	bodyOnly := true
	log.Info("Creating hmacauth", "digest", opts.Digest.ID, "header", opts.SignHeader, "headers", opts.Headers, "bodyOnly", bodyOnly)
	auth := hmacauth.NewHmacAuth(opts.Digest.ID,
		[]byte(opts.Secret), opts.SignHeader, opts.Headers, true)

	if len(opts.Mappings.Routes) == 0 {
		return nil, errors.New("At least one route must be specified in mappings")
	}

	h := &ProxyHandler{
		auth:     auth,
		handlers: make(map[string]http.Handler),
	}

	invalidUpstream := make([]string, 0, len(opts.Mappings.Routes))
	for _, r := range opts.Mappings.Routes {
		if r.Path == healthPath {
			return nil, errors.Errorf("Path %v is a reserved path and can't be proxied", r.Path)
		}

		log.Info("Create proxy route", "path", r.Path, "upstream", r.Upstream)

		u, msg := parseUpstream(r.Upstream)

		if msg != "" {
			invalidUpstream = append(invalidUpstream, msg)
			continue
		}
		proxy := newRewritePathProxy(u)
		// Configure the proxy not to check https certificates.
		log.Info("Proxy configured to skip TLS verification")
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		h.handlers[r.Path] = proxy
	}

	if len(invalidUpstream) > 0 {
		return nil, errors.New(strings.Join(invalidUpstream, "; "))
	}
	return h, nil
}

type ProxyHandler struct {
	auth *hmacauth.HmacAuth
	// handler s from a path to the reverse proxy handler for that path
	handlers map[string]http.Handler
}

func (h ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := zapr.NewLogger(zap.L())
	// Add a health check.
	if r.URL.Path == healthPath {
		w.Write([]byte("ok"))
		return
	}
	result, headerSignature, computedSignature := h.auth.AuthenticateRequest(r)

	if result != hmacauth.ResultMatch {
		log.Info("unauthorized request", "url", r.URL, "signature", headerSignature, "computedSignature", computedSignature)
		http.Error(w, "unauthorized request", http.StatusUnauthorized)
		return
	}

	p, ok := h.handlers[r.URL.Path]

	if !ok {
		log.Info("Unhandled path", "path", r.URL.Path)
		http.NotFound(w, r)
		return
	}
	log.V(util.Debug).Info("Proxy request", "path", r.URL.Path)
	p.ServeHTTP(w, r)
}

// parseUpstream checks the raw URL can be parsed and is valid
func parseUpstream(raw string) (*url.URL, string) {
	u, err := url.Parse(raw)

	if err != nil {
		return nil, fmt.Sprintf("Could not parse URL %v", raw)
	}

	problems := make([]string, 0, 5)
	if u.Scheme == "" {
		problems = append(problems, "scheme not specified")
	} else if !(u.Scheme == "http" || u.Scheme == "https") {
		problems = append(problems, "invalid upstream scheme: "+u.Scheme)
	}
	if u.Host == "" {
		problems = append(problems, "host not specified")
	}

	if len(problems) == 0 {
		return u, ""
	} else {
		return nil, fmt.Sprintf("upstream %v is not valid; %v", raw, strings.Join(problems, ", "))
	}
}

// newRewritePathPrxy returns a proxy that forwards to the specified target
func newRewritePathProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = target.Path
		req.URL.RawPath = target.RawPath
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	return &httputil.ReverseProxy{Director: director}
}
