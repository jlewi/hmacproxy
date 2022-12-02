package hmacauth

import (
	"bufio"
	"crypto"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/bmizerany/assert"
)

// These correspond to the headers used in bitly/oauth2_proxy#147.
var HEADERS = []string{
	"Content-Length",
	"Content-Md5",
	"Content-Type",
	"Date",
	"Authorization",
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Access-Token",
	"Cookie",
	"Gap-Auth",
}

func TestSupportedHashAlgorithm(t *testing.T) {
	algorithm, err := DigestNameToCryptoHash("sha1")
	assert.Equal(t, err, nil)
	assert.Equal(t, algorithm, crypto.SHA1)
	assert.Equal(t, algorithm.Available(), true)
}

func TestUnsupportedHashAlgorithm(t *testing.T) {
	algorithm, err := DigestNameToCryptoHash("unsupported")
	assert.NotEqual(t, err, nil)
	assert.Equal(t, err.Error(),
		"hmacauth: hash algorithm not supported: unsupported")
	assert.Equal(t, algorithm, crypto.Hash(0))
	assert.Equal(t, algorithm.Available(), false)
}

func TestResultUnsupportedAlgorithmWillCauseNewHmacAuthToPanic(t *testing.T) {
	defer func() {
		err := recover()
		assert.Equal(t, err,
			"hmacauth: hash algorithm #0 is unavailable")
	}()
	NewHmacAuth(crypto.Hash(0), nil, "", nil, false)
}

func newTestRequest(request ...string) (req *http.Request) {
	reqBuf := bufio.NewReader(
		strings.NewReader(strings.Join(request, "\n")))
	if req, err := http.ReadRequest(reqBuf); err != nil {
		panic(err)
	} else {
		return req
	}
}

func testHmacAuth() *HmacAuth {
	return NewHmacAuth(
		crypto.SHA1, []byte("foobar"), "GAP-Signature", HEADERS, false)
}

func TestRequestSignaturePost(t *testing.T) {
	body := `{ "hello": "world!" }`
	req := newTestRequest(
		"POST /foo/bar HTTP/1.1",
		"Content-Length: "+strconv.Itoa(len(body)),
		"Content-MD5: deadbeef",
		"Content-Type: application/json",
		"Date: 2015-09-28",
		"Authorization: trust me",
		"X-Forwarded-User: mbland",
		"X-Forwarded-Email: mbland@acm.org",
		"X-Forwarded-Access-Token: feedbead",
		"Cookie: foo; bar; baz=quux",
		"Gap-Auth: mbland",
		"",
		body,
	)

	h := testHmacAuth()
	assert.Equal(t, h.StringToSign(req), strings.Join([]string{
		"POST",
		strconv.Itoa(len(body)),
		"deadbeef",
		"application/json",
		"2015-09-28",
		"trust me",
		"mbland",
		"mbland@acm.org",
		"feedbead",
		"foo; bar; baz=quux",
		"mbland",
		"/foo/bar",
	}, "\n")+"\n")
	assert.Equal(t, h.RequestSignature(req),
		"sha1"+SigSeparator+"2b822b543b4c091c305bc3a6b345726563235c72")

	if requestBody, err := io.ReadAll(req.Body); err != nil {
		panic(err)
	} else {
		assert.Equal(t, string(requestBody), body)
	}
}

func newGetRequest() *http.Request {
	return newTestRequest(
		"GET /foo/bar HTTP/1.1",
		"Date: 2015-09-29",
		"Cookie: foo; bar; baz=quux",
		"Gap-Auth: mbland",
		"",
		"",
	)
}

func TestRequestSignatureGetWithFullUrl(t *testing.T) {
	req := newTestRequest(
		"GET http://localhost/foo/bar?baz=quux%2Fxyzzy#plugh HTTP/1.1",
		"Date: 2015-09-29",
		"Cookie: foo; bar; baz=quux",
		"Gap-Auth: mbland",
		"",
		"",
	)

	h := testHmacAuth()
	assert.Equal(t, h.StringToSign(req), strings.Join([]string{
		"GET",
		"",
		"",
		"",
		"2015-09-29",
		"",
		"",
		"",
		"",
		"foo; bar; baz=quux",
		"mbland",
		"/foo/bar?baz=quux%2Fxyzzy#plugh",
	}, "\n")+"\n")
	assert.Equal(t, h.RequestSignature(req),
		"sha1"+SigSeparator+"8a1e4971ef67b25b6bcbadeb478226373da17679")
}

func TestRequestSignatureGetWithMultipleHeadersWithTheSameName(t *testing.T) {
	// Just using "Cookie:" out of convenience.
	req := newTestRequest(
		"GET /foo/bar HTTP/1.1",
		"Date: 2015-09-29",
		"Cookie: foo",
		"Cookie: bar",
		"Cookie: baz=quux",
		"Gap-Auth: mbland",
		"",
		"",
	)

	h := testHmacAuth()
	assert.Equal(t, h.StringToSign(req), strings.Join([]string{
		"GET",
		"",
		"",
		"",
		"2015-09-29",
		"",
		"",
		"",
		"",
		"foo,bar,baz=quux",
		"mbland",
		"/foo/bar",
	}, "\n")+"\n")
	assert.Equal(t, h.RequestSignature(req),
		"sha1"+SigSeparator+"2654647acd57faaab706073f19c4722e8b3ee1a2")
}

func TestAuthenticateRequestResultNoSignature(t *testing.T) {
	h := testHmacAuth()
	req := newGetRequest()
	result, header, computed := h.AuthenticateRequest(req)
	assert.Equal(t, result, ResultNoSignature)
	assert.Equal(t, header, "")
	assert.Equal(t, computed, "")
}

func TestAuthenticateRequestResultInvalidFormat(t *testing.T) {
	h := testHmacAuth()
	req := newGetRequest()
	badValue := "should be algorithm and digest value"
	req.Header.Set("GAP-Signature", badValue)
	result, header, computed := h.AuthenticateRequest(req)
	assert.Equal(t, result, ResultInvalidFormat)
	assert.Equal(t, header, badValue)
	assert.Equal(t, computed, "")
}

func TestAuthenticateRequestResultUnsupportedAlgorithm(t *testing.T) {
	h := testHmacAuth()
	req := newGetRequest()
	validSignature := h.RequestSignature(req)
	components := strings.Split(validSignature, SigSeparator)
	signatureWithResultUnsupportedAlgorithm := "unsupported" + SigSeparator +
		components[1]
	req.Header.Set("GAP-Signature", signatureWithResultUnsupportedAlgorithm)
	result, header, computed := h.AuthenticateRequest(req)
	assert.Equal(t, result, ResultUnsupportedAlgorithm)
	assert.Equal(t, header, signatureWithResultUnsupportedAlgorithm)
	assert.Equal(t, computed, "")
}

func TestAuthenticateRequestResultMatchGithub(t *testing.T) {
	h := NewHmacAuth(
		crypto.SHA256, []byte("This is a test secret."), "X-Hub-Signature-256", []string{}, true)
	body := `{ "hello": "world!" }`
	req := newTestRequest(
		"POST /foo/bar HTTP/1.1",
		"Content-Length: "+strconv.Itoa(len(body)),
		"Content-MD5: deadbeef",
		"Content-Type: application/json",
		"Date: 2015-09-28",
		"Authorization: trust me",
		"X-Forwarded-User: mbland",
		"X-Forwarded-Email: mbland@acm.org",
		"X-Forwarded-Access-Token: feedbead",
		"Cookie: foo; bar; baz=quux",
		"X-Hub-Signature-256: sha256=3717251b8d639afd525320bf7eaf1f9edfa7b4415fde239d2c55c2b08bfc5699",
		"",
		body,
	)
	expected := h.RequestSignature(req)
	result, header, computed := h.AuthenticateRequest(req)
	assert.Equal(t, header, expected)
	assert.Equal(t, result, ResultMatch)
	assert.Equal(t, computed, expected)
}

func TestAuthenticateRequestMismatch(t *testing.T) {
	foobarAuth := testHmacAuth()
	barbazAuth := NewHmacAuth(
		crypto.SHA1, []byte("barbaz"), "GAP-Signature", HEADERS, false)
	req := newGetRequest()
	sig := foobarAuth.RequestSignature(req)
	req.Header.Set("GAP-Signature", sig)
	result, header, computed := barbazAuth.AuthenticateRequest(req)
	assert.Equal(t, result, ResultMismatch)
	assert.Equal(t, header, foobarAuth.RequestSignature(req))
	assert.Equal(t, computed, barbazAuth.RequestSignature(req))
}
