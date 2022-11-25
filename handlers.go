package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"

	"github.com/go-logr/zapr"
	"github.com/jlewi/hmacproxy/pkg/hmacauth"
	"go.uber.org/zap"
)

// NewHTTPProxyHandler returns a http.Handler and its description based on the
// configuration specified in opts.
func NewHTTPProxyHandler(opts *HmacProxyOpts) (handler http.Handler, description string) {
	log := zapr.NewLogger(zap.L())
	bodyOnly := true
	log.Info("Creating hmacauth", "digest", opts.Digest.ID, "header", opts.SignHeader, "headers", opts.Headers, "bodyOnly", bodyOnly)
	auth := hmacauth.NewHmacAuth(opts.Digest.ID,
		[]byte(opts.Secret), opts.SignHeader, opts.Headers, true)

	return authAndProxyHandler(auth, &opts.Upstream)
}

type authHandler struct {
	auth    *hmacauth.HmacAuth
	handler http.Handler
}

func (h authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := zapr.NewLogger(zap.L())
	// Add a health check.
	if r.URL.Path == "/healthz" {
		w.Write([]byte("ok"))
		return
	}
	result, headerSignature, computedSignature := h.auth.AuthenticateRequest(r)

	if result != hmacauth.ResultMatch {
		log.Info("unauthorized request", "url", r.URL, "signature", headerSignature, "computedSignature", computedSignature)
		http.Error(w, "unauthorized request", http.StatusUnauthorized)
	} else {
		h.handler.ServeHTTP(w, r)
	}
}

func authAndProxyHandler(auth *hmacauth.HmacAuth, upstream *HmacProxyURL) (
	handler http.Handler, description string) {
	log := zapr.NewLogger(zap.L())
	description = "proxying authenticated requests to: " + upstream.Raw
	proxy := httputil.NewSingleHostReverseProxy(upstream.URL)
	// Configure the proxy not to check https certificates.
	log.Info("Proxy configured to skip TLS verification")
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	handler = authHandler{auth, proxy}
	return
}
