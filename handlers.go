package main

import (
	"github.com/jlewi/hmacproxy/pkg/hmacauth"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewHTTPProxyHandler returns a http.Handler and its description based on the
// configuration specified in opts.
func NewHTTPProxyHandler(opts *HmacProxyOpts) (
	handler http.Handler, description string) {
	auth := hmacauth.NewHmacAuth(opts.Digest.ID,
		[]byte(opts.Secret), opts.SignHeader, opts.Headers)

	switch opts.Mode {
	case HandlerAuthAndProxy:
		return authAndProxyHandler(auth, &opts.Upstream)
	}
	log.Fatalf("unknown mode: %d\n", opts.Mode)
	return
}

type signingHandler struct {
	auth    hmacauth.HmacAuth
	handler http.Handler
}

func (h signingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.auth.SignRequest(r)
	h.handler.ServeHTTP(w, r)
}

func signAndProxyHandler(auth hmacauth.HmacAuth, upstream *HmacProxyURL) (
	handler http.Handler, description string) {
	description = "proxying signed requests to: " + upstream.Raw
	proxy := httputil.NewSingleHostReverseProxy(upstream.URL)
	handler = signingHandler{auth, proxy}
	return
}

type authHandler struct {
	auth    hmacauth.HmacAuth
	handler http.Handler
}

func (h authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	result, _, _ := h.auth.AuthenticateRequest(r)
	// Add a health check.
	if r.URL.Path == "/healthz" {
		w.Write([]byte("ok"))
		return
	}
	if result != hmacauth.ResultMatch {
		http.Error(w, "unauthorized request", http.StatusUnauthorized)
	} else {
		h.handler.ServeHTTP(w, r)
	}
}

func authAndProxyHandler(auth hmacauth.HmacAuth, upstream *HmacProxyURL) (
	handler http.Handler, description string) {
	description = "proxying authenticated requests to: " + upstream.Raw
	proxy := httputil.NewSingleHostReverseProxy(upstream.URL)
	handler = authHandler{auth, proxy}
	return
}

type authOnlyHandler struct {
	auth hmacauth.HmacAuth
}

func (h authOnlyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origURI := r.Header.Get("X-Original-URI"); origURI != "" {
		if origURL, err := url.ParseRequestURI(origURI); err == nil {
			r.URL = origURL
		}
	}
	result, _, _ := h.auth.AuthenticateRequest(r)

	if result != hmacauth.ResultMatch {
		http.Error(w, "unauthorized request", http.StatusUnauthorized)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
}

func authenticationOnlyHandler(auth hmacauth.HmacAuth) (
	handler http.Handler, description string) {
	description = "responding Accepted/Unauthorized for auth queries"
	handler = authOnlyHandler{auth}
	return
}
