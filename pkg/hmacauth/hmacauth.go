package hmacauth

// TODO(jeremy): This is a more general implementation of hmac then what GitHub requires; in particular
// it supports including headers in the signature. It was inherited from the code I originally forked to create
// the proxy server. We could potentially simplify the code and use
// https://github.com/google/go-github/blob/18cd63d0e2bda56f9018d7f85bf11f81e6ce2dd2/github/messages.go to
// validate the payload. That function is also used by palantir's github apps.

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-logr/zapr"
	"github.com/jlewi/hydros/pkg/util"
	"go.uber.org/zap"
)

const (
	// SigSeparator is the separator character in the signature that separates the algorithm from the signature.
	SigSeparator = "="
)

var supportedAlgorithms = map[string]crypto.Hash{
	"md4":       crypto.MD4,
	"md5":       crypto.MD5,
	"sha1":      crypto.SHA1,
	"sha224":    crypto.SHA224,
	"sha256":    crypto.SHA256,
	"sha384":    crypto.SHA384,
	"sha512":    crypto.SHA512,
	"ripemd160": crypto.RIPEMD160,
}

var algorithmName map[crypto.Hash]string

func init() {
	algorithmName = make(map[crypto.Hash]string)
	for name, algorithm := range supportedAlgorithms {
		algorithmName[algorithm] = name
		// Make sure the algorithm is linked into the binary, per
		// https://golang.org/pkg/crypto/#Hash.Available
		//
		// Note that both sides of the client/server connection must
		// have an algorithm available in order to successfully
		// authenticate using that algorithm
		if algorithm.Available() == false {
			delete(supportedAlgorithms, name)
		}
	}
}

// DigestNameToCryptoHash returns the crypto.Hash value corresponding to the
// algorithm name, or an error if the algorithm is not supported.
func DigestNameToCryptoHash(name string) (result crypto.Hash, err error) {
	var supported bool
	if result, supported = supportedAlgorithms[name]; !supported {
		err = errors.New("hmacauth: hash algorithm not supported: " +
			name)
	}
	return
}

// CryptoHashToDigestName returns the algorithm name corresponding to the
// crypto.Hash ID, or an error if the algorithm is not supported.
func CryptoHashToDigestName(id crypto.Hash) (result string, err error) {
	var supported bool
	if result, supported = algorithmName[id]; !supported {
		err = errors.New("hmacauth: unsupported crypto.Hash #" +
			strconv.Itoa(int(id)))
	}
	return
}

// HmacAuth signs outbound requests and authenticates inbound requests.
type HmacAuth struct {
	hash     crypto.Hash
	key      []byte
	header   string
	headers  []string
	bodyOnly bool
}

// NewHmacAuth returns an HmacAuth object that can be used to sign or
// authenticate HTTP requests based on the supplied parameters.
func NewHmacAuth(hash crypto.Hash, key []byte, header string, headers []string, bodyOnly bool) *HmacAuth {
	if hash.Available() == false {
		var name string
		var supported bool
		if name, supported = algorithmName[hash]; !supported {
			name = "#" + strconv.Itoa(int(hash))
		}
		panic("hmacauth: hash algorithm " + name + " is unavailable")
	}
	canonicalHeaders := make([]string, len(headers))
	for i, h := range headers {
		canonicalHeaders[i] = http.CanonicalHeaderKey(h)
	}
	return &HmacAuth{hash, key, header, canonicalHeaders, bodyOnly}
}

// StringToSign Produces the string that will be prefixed to the request body and
// used to generate the signature.
func (auth *HmacAuth) StringToSign(req *http.Request) string {
	var buffer bytes.Buffer
	_, _ = buffer.WriteString(req.Method)
	_, _ = buffer.WriteString("\n")

	for _, header := range auth.headers {
		values := req.Header[header]
		lastIndex := len(values) - 1
		for i, value := range values {
			_, _ = buffer.WriteString(value)
			if i != lastIndex {
				_, _ = buffer.WriteString(",")
			}
		}
		_, _ = buffer.WriteString("\n")
	}
	_, _ = buffer.WriteString(req.URL.Path)
	if req.URL.RawQuery != "" {
		_, _ = buffer.WriteString("?")
		_, _ = buffer.WriteString(req.URL.RawQuery)
	}
	if req.URL.Fragment != "" {
		_, _ = buffer.WriteString("#")
		_, _ = buffer.WriteString(req.URL.Fragment)
	}
	_, _ = buffer.WriteString("\n")
	return buffer.String()
}

// RequestSignature Generates a signature for the request.
func (auth *HmacAuth) RequestSignature(req *http.Request) string {
	return requestSignature(auth, req, auth.hash)
}

func requestSignature(auth *HmacAuth, req *http.Request,
	hashAlgorithm crypto.Hash) string {
	log := zapr.NewLogger(zap.L()).WithValues("UserAgent", req.UserAgent())
	log.Info("Creating hmac", "algorithm", hashAlgorithm.String())
	h := hmac.New(hashAlgorithm.New, auth.key)

	if !auth.bodyOnly {
		data := []byte(auth.StringToSign(req))
		log.V(util.Debug).Info("Writing header string", "data", string(data))
		_, err := h.Write(data)
		if err != nil {
			log.Error(err, "Problem writing the header string")
		}
	}

	if req.Body != nil {
		reqBody, _ := io.ReadAll(req.Body)
		log.V(util.Debug).Info("Computing body hmac", "length", len(reqBody), "body", string(reqBody))
		req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
		b, err := h.Write(reqBody)
		if err != nil {
			log.Error(err, "Failed to write bytes to hmac")
		}
		log.V(util.Debug).Info("Wrote bytes to hmac", "length", b)
	}

	sig := h.Sum(nil)
	log.V(util.Debug).Info("Computed", "size", h.Size(), "sig", fmt.Sprintf("%x", sig))
	// GitHub encodes the signature as hexadecimal not base64
	return algorithmName[hashAlgorithm] + "=" + fmt.Sprintf("%x", sig)
}

// SignatureFromHeader retrieves the signature included in the request header.
func (auth *HmacAuth) SignatureFromHeader(req *http.Request) string {
	return req.Header.Get(auth.header)
}

// AuthenticationResult is a code used to identify the outcome of
// HmacAuth.AuthenticateRequest().
type AuthenticationResult int

const (
	// ResultNoSignature - the incoming result did not have a signature
	// header.
	ResultNoSignature AuthenticationResult = iota

	// ResultInvalidFormat - the signature header was not parseable.
	ResultInvalidFormat

	// ResultUnsupportedAlgorithm - the signature header specified an
	// unsupported algorithm.
	ResultUnsupportedAlgorithm

	// ResultMatch - the signature from the request header matched the
	// locally-computed signature.
	ResultMatch

	// ResultMismatch - the signature from the request header did not match
	// the locally-computed signature.
	ResultMismatch
)

var validationResultStrings = []string{
	"",
	"ResultNoSignature",
	"ResultInvalidFormat",
	"ResultUnsupportedAlgorithm",
	"ResultMatch",
	"ResultMismatch",
}

func (result AuthenticationResult) String() string {
	return validationResultStrings[result]
}

// AuthenticateRequest authenticates the request, returning the result code, the signature
// from the header, and the locally-computed signature.
func (auth *HmacAuth) AuthenticateRequest(request *http.Request) (
	result AuthenticationResult, headerSignature,
	computedSignature string) {
	log := zapr.NewLogger(zap.L()).WithValues("UserAgent", request.UserAgent())

	headerSignature = auth.SignatureFromHeader(request)
	if headerSignature == "" {
		log.Info("Invalid request; missing signature header", "header", auth.header, "headers", request.Header)
		result = ResultNoSignature
		return
	}

	components := strings.SplitN(headerSignature, SigSeparator, 2)
	if len(components) != 2 {
		log.Info("Invalid request; signature doesn't contain =", "signature", headerSignature)
		result = ResultInvalidFormat
		return
	}

	algorithm, err := DigestNameToCryptoHash(components[0])
	if err != nil {
		log.Info("Invalid request; unsupported algorithm", "algorithm", components[0])
		result = ResultUnsupportedAlgorithm
		return
	}

	computedSignature = requestSignature(auth, request, algorithm)
	if hmac.Equal([]byte(headerSignature), []byte(computedSignature)) {
		result = ResultMatch
	} else {
		result = ResultMismatch
	}
	return
}
