package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

const candidateURI = "urn:opcua:peer-certificate-candidate"

type candidateFixture struct {
	key       *rsa.PrivateKey
	cert      []byte
	trusted   []byte
	serverURI string
	mutate    func(*ua.CreateSessionResponse)
}

type candidateCounts struct{ create, activate, opn, session atomic.Int32 }

func candidateCertificate(t *testing.T, key *rsa.PrivateKey, serial int64, before, after time.Time, hostname string) []byte {
	t.Helper()
	uri, err := url.Parse(candidateURI)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "OPC UA certificate candidate"}, NotBefore: before, NotAfter: after, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if ip := net.ParseIP(hostname); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func candidateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func candidateVerifier(trusted []byte, counts *candidateCounts) func([]byte, string) error {
	return func(der []byte, applicationURI string) error {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return ua.StatusBadCertificateInvalid
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return ua.StatusBadCertificateTimeInvalid
		}
		if !bytes.Equal(cert.Raw, trusted) {
			return ua.StatusBadCertificateInvalid
		}
		if err := cert.VerifyHostname("127.0.0.1"); err != nil {
			return ua.StatusBadCertificateHostNameInvalid
		}
		if applicationURI == "" {
			counts.opn.Add(1)
			return nil
		}
		counts.session.Add(1)
		for _, uri := range cert.URIs {
			if uri.String() == applicationURI {
				return nil
			}
		}
		return ua.StatusBadCertificateURIInvalid
	}
}

func startCandidateServer(t *testing.T, f candidateFixture, counts *candidateCounts) (string, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	srv := New(EndPoint("127.0.0.1", port), PrivateKey(f.key), Certificate(f.cert), EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt), EnableAuthMode(ua.UserTokenTypeUserName))
	srv.cfg.applicationURI = f.serverURI
	service := &SessionService{srv: srv}
	srv.RegisterHandler(id.CreateSessionRequest_Encoding_DefaultBinary, func(sc *uasc.SecureChannel, req ua.Request, requestID uint32) (ua.Response, error) {
		counts.create.Add(1)
		response, err := service.CreateSession(sc, req, requestID)
		if err == nil && f.mutate != nil {
			f.mutate(response.(*ua.CreateSessionResponse))
		}
		return response, err
	})
	srv.RegisterHandler(id.ActivateSessionRequest_Encoding_DefaultBinary, func(sc *uasc.SecureChannel, req ua.Request, requestID uint32) (ua.Response, error) {
		counts.activate.Add(1)
		return service.ActivateSession(sc, req, requestID)
	})
	ns := NewMapNamespace(srv, "PeerCertificate")
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	ns.SetValue("A", int32(12345))
	t.Cleanup(func() { cancel(); _ = srv.Close() })
	return fmt.Sprintf("opc.tcp://127.0.0.1:%d", port), fmt.Sprintf("ns=%d;s=A", ns.ID())
}

func newCandidateClient(t *testing.T, endpoint string, f candidateFixture, counts *candidateCounts, hook bool, extra ...opcua.Option) *opcua.Client {
	t.Helper()
	key := candidateKey(t)
	now := time.Now()
	cert := candidateCertificate(t, key, 900, now.Add(-time.Hour), now.Add(time.Hour), "127.0.0.1")
	options := []opcua.Option{opcua.SecurityPolicy("Basic256Sha256"), opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt), opcua.PrivateKey(key), opcua.Certificate(cert), opcua.RemoteCertificate(f.trusted), opcua.AuthUsername("candidate-user", "candidate-password"), opcua.AuthPolicyID("username_Basic256Sha256"), opcua.AutoReconnect(false), opcua.RequestTimeout(time.Second)}
	if hook {
		options = append(options, opcua.VerifyServerCertificate(candidateVerifier(f.trusted, counts)))
	}
	options = append(options, extra...)
	client, err := opcua.NewClient(endpoint, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = client.Close(ctx)
	})
	return client
}

func TestPeerCertificateCandidateRealSecureChannel(t *testing.T) {
	key := candidateKey(t)
	now := time.Now()
	valid := candidateCertificate(t, key, 1, now.Add(-time.Hour), now.Add(time.Hour), "127.0.0.1")
	replacement := candidateCertificate(t, key, 2, now.Add(-time.Hour), now.Add(time.Hour), "127.0.0.1")
	expired := candidateCertificate(t, key, 3, now.Add(-2*time.Hour), now.Add(-time.Hour), "127.0.0.1")
	future := candidateCertificate(t, key, 4, now.Add(time.Hour), now.Add(2*time.Hour), "127.0.0.1")
	wrongHost := candidateCertificate(t, key, 5, now.Add(-time.Hour), now.Add(time.Hour), "wrong.invalid")
	cases := []struct {
		name       string
		f          candidateFixture
		wantCreate int32
		want       ua.StatusCode
	}{
		{"valid", candidateFixture{key: key, cert: valid, trusted: valid, serverURI: candidateURI}, 1, 0},
		{"same_key_new_leaf", candidateFixture{key: key, cert: replacement, trusted: valid, serverURI: candidateURI}, 0, ua.StatusBadCertificateInvalid},
		{"expired_actual_leaf", candidateFixture{key: key, cert: expired, trusted: expired, serverURI: candidateURI}, 0, ua.StatusBadCertificateTimeInvalid},
		{"not_yet_valid_actual_leaf", candidateFixture{key: key, cert: future, trusted: future, serverURI: candidateURI}, 0, ua.StatusBadCertificateTimeInvalid},
		{"wrong_hostname", candidateFixture{key: key, cert: wrongHost, trusted: wrongHost, serverURI: candidateURI}, 0, ua.StatusBadCertificateHostNameInvalid},
		{"wrong_application_uri", candidateFixture{key: key, cert: valid, trusted: valid, serverURI: "urn:wrong"}, 1, ua.StatusBadCertificateURIInvalid},
		{"missing_application_uri", candidateFixture{key: key, cert: valid, trusted: valid, serverURI: ""}, 1, ua.StatusBadCertificateURIInvalid},
		{"missing_matching_endpoint", candidateFixture{key: key, cert: valid, trusted: valid, serverURI: candidateURI, mutate: func(r *ua.CreateSessionResponse) { r.ServerEndpoints = nil }}, 1, ua.StatusBadCertificateURIInvalid},
		{"conflicting_application_uri", candidateFixture{key: key, cert: valid, trusted: valid, serverURI: candidateURI, mutate: func(r *ua.CreateSessionResponse) {
			ep := *r.ServerEndpoints[0]
			app := *ep.Server
			app.ApplicationURI = "urn:conflict"
			ep.Server = &app
			r.ServerEndpoints = append(r.ServerEndpoints, &ep)
		}}, 1, ua.StatusBadCertificateURIInvalid},
		{"session_leaf_differs_from_channel", candidateFixture{key: key, cert: valid, trusted: valid, serverURI: candidateURI, mutate: func(r *ua.CreateSessionResponse) { r.ServerCertificate = replacement }}, 1, ua.StatusBadCertificateInvalid},
		{"invalid_session_signature", candidateFixture{key: key, cert: valid, trusted: valid, serverURI: candidateURI, mutate: func(r *ua.CreateSessionResponse) { r.ServerSignature.Signature = []byte{1} }}, 1, ua.StatusBadSecurityChecksFailed},
		{"nil_session_signature", candidateFixture{key: key, cert: valid, trusted: valid, serverURI: candidateURI, mutate: func(r *ua.CreateSessionResponse) { r.ServerSignature = nil }}, 1, ua.StatusBadSecurityChecksFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			counts := new(candidateCounts)
			endpoint, node := startCandidateServer(t, tc.f, counts)
			client := newCandidateClient(t, endpoint, tc.f, counts, true)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := client.Connect(ctx)
			if tc.want == 0 {
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Read(ctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{{NodeID: ua.MustParseNodeID(node), AttributeID: ua.AttributeIDValue}}})
				if err != nil || len(response.Results) != 1 || response.Results[0].Status != ua.StatusOK || response.Results[0].Value.Value() != int32(12345) {
					t.Fatalf("secure read response=%+v err=%v", response, err)
				}
				if counts.activate.Load() != 1 || counts.opn.Load() != 1 || counts.session.Load() != 1 {
					t.Fatalf("valid callbacks or activation missing: opn=%d session=%d activate=%d", counts.opn.Load(), counts.session.Load(), counts.activate.Load())
				}
			} else {
				if err == nil {
					t.Fatal("rejected identity became connected")
				}
				// The receive loop may report an OPN rejection through its bounded context.
				if tc.wantCreate == 1 && tc.name != "invalid_session_signature" && tc.name != "nil_session_signature" && !errors.Is(err, tc.want) {
					t.Fatalf("error=%v want %v", err, tc.want)
				}
				if counts.activate.Load() != 0 || client.Session() != nil || client.SecureChannel() != nil {
					t.Fatalf("identity rejection retained session/channel or sent credentials: activate=%d", counts.activate.Load())
				}
			}
			if counts.create.Load() != tc.wantCreate {
				t.Fatalf("CreateSession count=%d want=%d", counts.create.Load(), tc.wantCreate)
			}
			t.Logf("create=%d activate=%d acceptedOPN=%d sessionChecks=%d rejected=%v", counts.create.Load(), counts.activate.Load(), counts.opn.Load(), counts.session.Load(), err != nil)
		})
	}
}

func TestPeerCertificateCandidateRenewAndNoHookCompatibility(t *testing.T) {
	key := candidateKey(t)
	now := time.Now()
	valid := candidateCertificate(t, key, 100, now.Add(-time.Hour), now.Add(time.Hour), "127.0.0.1")
	replacement := candidateCertificate(t, key, 101, now.Add(-time.Hour), now.Add(time.Hour), "127.0.0.1")
	t.Run("renew_revalidates_actual_certificate", func(t *testing.T) {
		f := candidateFixture{key: key, cert: valid, trusted: valid, serverURI: candidateURI}
		counts := new(candidateCounts)
		endpoint, _ := startCandidateServer(t, f, counts)
		client := newCandidateClient(t, endpoint, f, counts, true)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := client.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		if err := client.SecureChannel().Renew(ctx); err != nil {
			t.Fatal(err)
		}
		if counts.opn.Load() != 2 {
			t.Fatalf("renew skipped actual certificate: %d", counts.opn.Load())
		}
	})
	t.Run("renew_rejects_no_longer_valid_certificate", func(t *testing.T) {
		f := candidateFixture{key: key, cert: valid, trusted: valid, serverURI: candidateURI}
		counts := new(candidateCounts)
		endpoint, _ := startCandidateServer(t, f, counts)
		var reject atomic.Bool
		var calls atomic.Int32
		verify := candidateVerifier(f.trusted, counts)
		client := newCandidateClient(t, endpoint, f, counts, true, opcua.VerifyServerCertificate(func(der []byte, uri string) error {
			if uri == "" {
				calls.Add(1)
				if reject.Load() {
					return ua.StatusBadCertificateTimeInvalid
				}
			}
			return verify(der, uri)
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := client.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		reject.Store(true)
		if err := client.SecureChannel().Renew(ctx); err == nil {
			t.Fatal("renew accepted rejected certificate")
		}
		if calls.Load() != 2 {
			t.Fatalf("renew validator calls=%d want 2", calls.Load())
		}
		if counts.activate.Load() != 1 {
			t.Fatal("renew repeated session credentials")
		}
	})
	t.Run("no_hook_retains_same_key_compatibility", func(t *testing.T) {
		f := candidateFixture{key: key, cert: replacement, trusted: valid, serverURI: candidateURI}
		counts := new(candidateCounts)
		endpoint, _ := startCandidateServer(t, f, counts)
		client := newCandidateClient(t, endpoint, f, counts, false)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := client.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		if counts.activate.Load() != 1 {
			t.Fatal("unconfigured SDK behavior changed")
		}
	})
}
