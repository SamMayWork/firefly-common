// Copyright © 2021 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ffresty

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffapi"
	"github.com/hyperledger/firefly-common/pkg/fftls"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

const configDir = "../../test/data/config"

var utConf = config.RootSection("http_unit_tests")

func resetConf() {
	config.RootConfigReset()
	InitConfig(utConf)
}

func TestRequestOK(t *testing.T) {

	customClient := &http.Client{}

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigHeaders, map[string]interface{}{
		"someheader": "headervalue",
	})
	utConf.Set(HTTPConfigAuthUsername, "user")
	utConf.Set(HTTPConfigAuthPassword, "pass")
	utConf.Set(HTTPConfigRetryEnabled, true)
	utConf.Set(HTTPCustomClient, customClient)

	c, err := New(context.Background(), utConf)
	assert.Nil(t, err)
	httpmock.ActivateNonDefault(customClient)
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "http://localhost:12345/test",
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "headervalue", req.Header.Get("someheader"))
			assert.Equal(t, "Basic dXNlcjpwYXNz", req.Header.Get("Authorization"))
			return httpmock.NewStringResponder(200, `{"some": "data"}`)(req)
		})

	resp, err := c.R().Get("/test")
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode())
	assert.Equal(t, `{"some": "data"}`, resp.String())

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestRequestRetry(t *testing.T) {

	ctx := context.Background()

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigRetryEnabled, true)
	utConf.Set(HTTPConfigRetryInitDelay, 1)

	c, err := New(ctx, utConf)
	assert.Nil(t, err)
	httpmock.ActivateNonDefault(c.GetClient())
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "http://localhost:12345/test",
		httpmock.NewStringResponder(500, `{"message": "pop"}`))

	resp, err := c.R().Get("/test")
	assert.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode())
	assert.Equal(t, 6, httpmock.GetTotalCallCount())

	err = WrapRestErr(ctx, resp, err, i18n.MsgConfigFailed)
	assert.Error(t, err)

}

func TestRequestRetryErrorStatusCodeRegex(t *testing.T) {

	ctx := context.Background()

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigRetryEnabled, true)
	utConf.Set(HTTPConfigRetryInitDelay, 1)
	utConf.Set(HTTPConfigRetryErrorStatusCodeRegex, "(?:429|503)")

	c, err := New(ctx, utConf)
	assert.Nil(t, err)
	httpmock.ActivateNonDefault(c.GetClient())
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "http://localhost:12345/test",
		httpmock.NewStringResponder(500, `{"message": "pop"}`))

	httpmock.RegisterResponder("GET", "http://localhost:12345/test2",
		httpmock.NewStringResponder(429, `{"message": "pop"}`))

	httpmock.RegisterResponder("GET", "http://localhost:12345/test3",
		httpmock.NewErrorResponder(errors.New("not http response")))

	resp, err := c.R().Get("/test")
	assert.NoError(t, err)
	assert.Equal(t, 500, resp.StatusCode())
	assert.Equal(t, 1, httpmock.GetTotalCallCount())

	err = WrapRestErr(ctx, resp, err, i18n.MsgConfigFailed)
	assert.Error(t, err)

	resp, err = c.R().Get("/test2")
	assert.NoError(t, err)
	assert.Equal(t, 429, resp.StatusCode())
	assert.Equal(t, 7, httpmock.GetTotalCallCount())

	err = WrapRestErr(ctx, resp, err, i18n.MsgConfigFailed)
	assert.Error(t, err)

	resp, err = c.R().Get("/test3")
	assert.Error(t, err)
	assert.Equal(t, 0, resp.StatusCode())
	assert.Equal(t, 13, httpmock.GetTotalCallCount())

	err = WrapRestErr(ctx, resp, err, i18n.MsgConfigFailed)
	assert.Error(t, err)

}
func TestConfWithProxy(t *testing.T) {

	ctx := context.Background()

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigProxyURL, "http://myproxy.example.com:12345")
	utConf.Set(HTTPConfigRetryEnabled, false)

	c, err := New(ctx, utConf)
	assert.Nil(t, err)
	assert.True(t, c.IsProxySet())
}

func TestLongResponse(t *testing.T) {

	ctx := context.Background()

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigRetryEnabled, false)

	c, err := New(ctx, utConf)
	assert.Nil(t, err)
	httpmock.ActivateNonDefault(c.GetClient())
	defer httpmock.DeactivateAndReset()

	resText := strings.Builder{}
	for i := 0; i < 512; i++ {
		resText.WriteByte(byte('a' + (i % 26)))
	}
	httpmock.RegisterResponder("GET", "http://localhost:12345/test",
		httpmock.NewStringResponder(500, resText.String()))

	resp, err := c.R().Get("/test")
	err = WrapRestErr(ctx, resp, err, i18n.MsgConfigFailed)
	assert.Error(t, err)
}

func TestErrResponse(t *testing.T) {

	ctx := context.Background()

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigRetryEnabled, false)

	c, err := New(ctx, utConf)
	assert.Nil(t, err)
	httpmock.ActivateNonDefault(c.GetClient())
	defer httpmock.DeactivateAndReset()

	resText := strings.Builder{}
	for i := 0; i < 512; i++ {
		resText.WriteByte(byte('a' + (i % 26)))
	}
	httpmock.RegisterResponder("GET", "http://localhost:12345/test",
		httpmock.NewErrorResponder(fmt.Errorf("pop")))

	resp, err := c.R().Get("/test")
	err = WrapRestErr(ctx, resp, err, i18n.MsgConfigFailed)
	assert.Error(t, err)
}

func TestErrResponseBlockRetry(t *testing.T) {

	ctx := context.Background()

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigRetryEnabled, true)
	utConf.Set(HTTPConfigRetryInitDelay, "1ms")
	utConf.Set(HTTPConfigRetryCount, 10000)

	ffrestyConfig, err := GenerateConfig(ctx, utConf)
	assert.NoError(t, err)
	called := make(chan bool, 1)
	ffrestyConfig.OnCheckRetry = func(res *resty.Response, err error) bool {
		assert.NotNil(t, res) // We expect a response object, even though it was an error
		assert.NotNil(t, err)
		called <- true
		return false
	}

	c := NewWithConfig(ctx, *ffrestyConfig)
	httpmock.ActivateNonDefault(c.GetClient())
	defer httpmock.DeactivateAndReset()

	resText := strings.Builder{}
	for i := 0; i < 512; i++ {
		resText.WriteByte(byte('a' + (i % 26)))
	}
	httpmock.RegisterResponder("POST", "http://localhost:12345/test",
		httpmock.NewErrorResponder(fmt.Errorf("pop")))

	resp, err := c.R().SetBody("stuff").Post("/test")
	err = WrapRestErr(ctx, resp, err, i18n.MsgConfigFailed)
	assert.Error(t, err)

	<-called
}

func TestRetryReGenHeaderOnEachRequest(t *testing.T) {

	ctx := context.Background()

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigRetryEnabled, true)
	utConf.Set(HTTPConfigRetryInitDelay, "1ms")
	utConf.Set(HTTPConfigRetryCount, 1)

	ffrestyConfig, err := GenerateConfig(ctx, utConf)
	assert.NoError(t, err)
	reqCount := 0
	ffrestyConfig.OnBeforeRequest = func(req *resty.Request) error {
		reqCount++
		req.Header.Set("utheader", fmt.Sprintf("request_%d", reqCount))
		return nil
	}

	c := NewWithConfig(ctx, *ffrestyConfig)
	httpmock.ActivateNonDefault(c.GetClient())
	defer httpmock.DeactivateAndReset()

	resText := strings.Builder{}
	for i := 0; i < 512; i++ {
		resText.WriteByte(byte('a' + (i % 26)))
	}
	utHeaders := make(chan string, 2)
	httpmock.RegisterResponder("POST", "http://localhost:12345/test", func(req *http.Request) (*http.Response, error) {
		utHeaders <- req.Header.Get("utheader")
		return &http.Response{StatusCode: 500, Body: http.NoBody}, nil
	})

	resp, err := c.R().SetBody("stuff").Post("/test")
	err = WrapRestErr(ctx, resp, err, i18n.MsgConfigFailed)
	assert.Error(t, err)

	assert.Equal(t, "request_1", <-utHeaders)
	assert.Equal(t, "request_2", <-utHeaders)
}

func TestRetryReGenHeaderOnEachRequestFail(t *testing.T) {

	ctx := context.Background()

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigRetryEnabled, true)
	utConf.Set(HTTPConfigRetryInitDelay, "1ms")
	utConf.Set(HTTPConfigRetryCount, 1)

	ffrestyConfig, err := GenerateConfig(ctx, utConf)
	assert.NoError(t, err)
	ffrestyConfig.OnBeforeRequest = func(req *resty.Request) error {
		return fmt.Errorf("pop")
	}

	c := NewWithConfig(ctx, *ffrestyConfig)
	httpmock.ActivateNonDefault(c.GetClient())
	defer httpmock.DeactivateAndReset()

	resp, err := c.R().SetBody("stuff").Post("/test")
	err = WrapRestErr(ctx, resp, err, i18n.MsgConfigFailed)
	assert.Regexp(t, "pop", err)
}

func TestOnAfterResponseNil(t *testing.T) {
	OnAfterResponse(nil, nil)
}

func TestPassthroughHeaders(t *testing.T) {
	passthroughHeaders := http.Header{}
	passthroughHeaders.Set("X-Custom-Header", "custom value")
	ctx := context.WithValue(context.Background(), ffapi.CtxHeadersKey{}, passthroughHeaders)
	ctx = context.WithValue(ctx, ffapi.CtxFFRequestIDKey{}, "customReqID")

	customClient := &http.Client{}

	resetConf()
	utConf.Set(HTTPConfigURL, "http://localhost:12345")
	utConf.Set(HTTPConfigHeaders, map[string]interface{}{
		"someheader": "headervalue",
	})
	utConf.Set(HTTPConfigAuthUsername, "user")
	utConf.Set(HTTPConfigAuthPassword, "pass")
	utConf.Set(HTTPConfigRetryEnabled, true)
	utConf.Set(HTTPCustomClient, customClient)
	utConf.Set(HTTPPassthroughHeadersEnabled, true)

	c, err := New(context.Background(), utConf)
	assert.Nil(t, err)
	httpmock.ActivateNonDefault(customClient)
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "http://localhost:12345/test",
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "customReqID", req.Header.Get(ffapi.FFRequestIDHeader))
			assert.Equal(t, "headervalue", req.Header.Get("someheader"))
			assert.Equal(t, "custom value", req.Header.Get("X-Custom-Header"))
			assert.Equal(t, "Basic dXNlcjpwYXNz", req.Header.Get("Authorization"))
			return httpmock.NewStringResponder(200, `{"some": "data"}`)(req)
		})

	resp, err := c.R().SetContext(ctx).Get("/test")
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode())
	assert.Equal(t, `{"some": "data"}`, resp.String())

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestMissingCAFile(t *testing.T) {
	resetConf()
	utConf.Set(HTTPConfigURL, "https://localhost:12345")
	tlsSection := utConf.SubSection("tls")
	tlsSection.Set(fftls.HTTPConfTLSEnabled, true)
	tlsSection.Set(fftls.HTTPConfTLSCAFile, "non-existent.pem")

	_, err := New(context.Background(), utConf)
	assert.Regexp(t, "FF00153", err)
}

func TestBadCAFile(t *testing.T) {
	resetConf()
	utConf.Set(HTTPConfigURL, "https://localhost:12345")
	tlsSection := utConf.SubSection("tls")
	tlsSection.Set(fftls.HTTPConfTLSEnabled, true)
	tlsSection.Set(fftls.HTTPConfTLSCAFile, configDir+"/firefly.common.yaml")

	_, err := New(context.Background(), utConf)
	assert.Regexp(t, "FF00152", err)
}

func TestBadKeyPair(t *testing.T) {
	resetConf()
	utConf.Set(HTTPConfigURL, "https://localhost:12345")
	tlsSection := utConf.SubSection("tls")
	tlsSection.Set(fftls.HTTPConfTLSEnabled, true)
	tlsSection.Set(fftls.HTTPConfTLSCertFile, configDir+"/firefly.common.yaml")
	tlsSection.Set(fftls.HTTPConfTLSKeyFile, configDir+"/firefly.common.yaml")

	_, err := New(context.Background(), utConf)
	assert.Regexp(t, "FF00206", err)
}

func TestMTLSClientWithServer(t *testing.T) {
	// Create an X509 certificate pair
	privatekey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publickey := &privatekey.PublicKey
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyFile, _ := os.CreateTemp("", "key.pem")
	defer os.Remove(privateKeyFile.Name())
	privateKeyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}
	pem.Encode(privateKeyFile, privateKeyBlock)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	x509Template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Unit Tests"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(100 * time.Second),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, x509Template, x509Template, publickey, privatekey)
	assert.NoError(t, err)
	publicKeyFile, _ := os.CreateTemp("", "cert.pem")
	defer os.Remove(publicKeyFile.Name())
	pem.Encode(publicKeyFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	http.HandleFunc("/hello", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(200)
		json.NewEncoder(res).Encode(map[string]interface{}{"hello": "world"})
	})

	// Create a CA certificate pool and add cert.pem to it
	caCert, err := os.ReadFile(publicKeyFile.Name())
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		TLSConfig: tlsConfig,
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	go func() {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdownContext); err != nil {
				return
			}
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()

	go server.ServeTLS(ln, publicKeyFile.Name(), privateKeyFile.Name())

	// Use ffresty to test the mTLS client as well
	var restyConfig = config.RootSection("resty")
	InitConfig(restyConfig)
	clientTLSSection := restyConfig.SubSection("tls")
	restyConfig.Set(HTTPConfigURL, ln.Addr())
	clientTLSSection.Set(fftls.HTTPConfTLSEnabled, true)
	clientTLSSection.Set(fftls.HTTPConfTLSKeyFile, privateKeyFile.Name())
	clientTLSSection.Set(fftls.HTTPConfTLSCertFile, publicKeyFile.Name())
	clientTLSSection.Set(fftls.HTTPConfTLSCAFile, publicKeyFile.Name())

	c, err := New(context.Background(), restyConfig)
	assert.Nil(t, err)

	httpsAddr := fmt.Sprintf("https://%s/hello", ln.Addr())
	fmt.Println(httpsAddr)
	res, err := c.R().Get(httpsAddr)
	assert.NoError(t, err)

	assert.NoError(t, err)
	if res != nil {
		assert.Equal(t, 200, res.StatusCode())
		var resBody map[string]interface{}
		err = json.Unmarshal(res.Body(), &resBody)
		assert.NoError(t, err)
		assert.Equal(t, "world", resBody["hello"])
	}
	cancelCtx()
}

func TestAdditionOfTrustedCustomCAs(t *testing.T) {
	ctx := context.Background()

	resetConf()

	// Resty tries to load the certificate directly from disk so need to set up a custom
	// file for it to read from and then clean this up from the disk
	tempCAFile, err := os.CreateTemp("", "sample-ca.pem")
	assert.NoError(t, err)
	tempCAFile.WriteString("-----BEGIN CERTIFICATE-----MIIDazCCAlOgAwIBAgIUFDOQYMW6FZa/KZdRuC9BXzDwlfAwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAzMjYxNTQ3MTRaFw0yOTAzMjUxNTQ3MTRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvIwX/dOyka0HOyQrY5a6TqkT/WMUMB3zdDNUob5X1THxigwEOW4Sv+Q19b1HoYLaurlD08UPEZ3OGUVPSx51kpkJgVLZCgHH2tHllUcu9uVIMo57Q0iEUdor8KXQvTTd3kZXSt8qvh02anVwttISZgEQDWhFw5LyLvn3tnN53mVkkdqrVv6ScG9hhpfmsifAEgs0g41KP5Zsdoj8Q/NS4rzw7h8LYUgQKPDLKlPD7nrdoo6CDk5fnm+RcmBKIXG5AQ6DVEa+MrFSCGRC4T9GxbY7nKHnYGRtYzyrnJ3hHszsPhwOx+pTWZEWVSS0ZN24ofuAToMZvTJGWZRBOp44DAgMBAAGjUzBRMB0GA1UdDgQWBBSnRu3t4HSi+FsEz76lFMhUvWebijAfBgNVHSMEGDAWgBSnRu3t4HSi+FsEz76lFMhUvWebijAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAqZ9g6dzI9+bNHpF8oPGsecL2OJSSL43dokkM423izHNIBjv+yZTHPIq5QxEvWHiai+deYEU3h27iWlo9Gd8I40sqb9Ze+N0OFiOkRLk6pDT57SS/9I0ysrBauytmY2iVeCbr1Frq5i+oxY5dPY/x9EYPAua/cFR+NLFyiBnTVw1POhh+cRHv4PeABlBJzG9xXp8xh48zK0YiWP1bDW3ngk+WnB5Lb8Fcny7AdPt+31lT7RmN6wBCcRV4HXwyt3esfXUaC9mLUQRPvFtnX73BhSBRtGM/YzKdfVEjttgAoKGh/CzAZ6uD964VPIH82ItWciM7F/gYSMFjEs6jpd5wB-----END CERTIFICATE-----")

	defer os.Remove(tempCAFile.Name())

	utConf.Set(TrustedCustomCAs, []string{tempCAFile.Name()})

	ffrestyConfig, err := GenerateConfig(ctx, utConf)
	assert.NoError(t, err)

	c := NewWithConfig(ctx, *ffrestyConfig)

	transport, err := c.Transport()
	assert.Nil(t, err)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
}
