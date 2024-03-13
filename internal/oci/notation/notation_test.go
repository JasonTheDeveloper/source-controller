/*
Copyright 2023 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package notation

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	. "github.com/onsi/gomega"
)

func TestOptions(t *testing.T) {
	testCases := []struct {
		name string
		opts []Options
		want *options
	}{
		{
			name: "no options",
			want: &options{},
		},
		{
			name: "signature option",
			opts: []Options{WithRootCertificate([]byte("foo"))},
			want: &options{
				rootCertificate: []byte("foo"),
				rOpt:            nil,
			},
		},
		{
			name: "keychain option",
			opts: []Options{
				WithRemoteOptions(remote.WithAuthFromKeychain(authn.DefaultKeychain)),
				WithKeychain(authn.DefaultKeychain),
			},
			want: &options{
				rootCertificate: nil,
				rOpt:            []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
				keychain:        authn.DefaultKeychain,
			},
		},
		{
			name: "keychain and authenticator option",
			opts: []Options{
				WithRemoteOptions(
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
				),
				WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
				WithKeychain(authn.DefaultKeychain),
			},
			want: &options{
				rootCertificate: nil,
				rOpt: []remote.Option{
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
				},
				auth:     &authn.Basic{Username: "foo", Password: "bar"},
				keychain: authn.DefaultKeychain,
			},
		},
		{
			name: "keychain, authenticator and transport option",
			opts: []Options{
				WithRemoteOptions(
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
					remote.WithTransport(http.DefaultTransport),
				),
				WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
				WithKeychain(authn.DefaultKeychain),
			},
			want: &options{
				rootCertificate: nil,
				rOpt: []remote.Option{
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
					remote.WithTransport(http.DefaultTransport),
				},
				auth:     &authn.Basic{Username: "foo", Password: "bar"},
				keychain: authn.DefaultKeychain,
			},
		},
		{
			name: "truststore, empty document",
			opts: []Options{WithTrustStore(&trustpolicy.Document{})},
			want: &options{
				rootCertificate: nil,
				rOpt:            nil,
				trustPolicy:     &trustpolicy.Document{},
			},
		},
		{
			name: "truststore, dummy document",
			opts: []Options{WithTrustStore(dummyPolicyDocument())},
			want: &options{
				rootCertificate: nil,
				rOpt:            nil,
				trustPolicy:     dummyPolicyDocument(),
			},
		},
		{
			name: "insecure, false",
			opts: []Options{WithInsecureRegistry(false)},
			want: &options{
				rootCertificate: nil,
				rOpt:            nil,
				trustPolicy:     nil,
				insecure:        false,
			},
		},
		{
			name: "insecure, true",
			opts: []Options{WithInsecureRegistry(true)},
			want: &options{
				rootCertificate: nil,
				rOpt:            nil,
				trustPolicy:     nil,
				insecure:        true,
			},
		},
		{
			name: "insecure, default",
			opts: []Options{},
			want: &options{
				rootCertificate: nil,
				rOpt:            nil,
				trustPolicy:     nil,
				insecure:        false,
			},
		},
	}

	// Run the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			o := options{}
			for _, opt := range tc.opts {
				opt(&o)
			}
			if !reflect.DeepEqual(o.rootCertificate, tc.want.rootCertificate) {
				t.Errorf("got %#v, want %#v", &o.rootCertificate, tc.want.rootCertificate)
			}

			if !reflect.DeepEqual(o.trustPolicy, tc.want.trustPolicy) {
				t.Errorf("got %#v, want %#v", &o.trustPolicy, tc.want.trustPolicy)
			}

			if tc.want.rOpt != nil {
				if len(o.rOpt) != len(tc.want.rOpt) {
					t.Errorf("got %d remote options, want %d", len(o.rOpt), len(tc.want.rOpt))
				}
				return
			}

			if tc.want.rOpt == nil {
				if len(o.rOpt) != 0 {
					t.Errorf("got %d remote options, want %d", len(o.rOpt), 0)
				}
			}
		})
	}
}

func TestCleanTrustPolicy(t *testing.T) {
	g := NewWithT(t)

	testCases := []struct {
		name       string
		policy     []trustpolicy.TrustPolicy
		want       *trustpolicy.Document
		logMessage string
	}{
		{
			name: "no trust policy",
			want: nil,
		},
		{
			name: "trust policy verification level set to strict and should not be cleaned",
			policy: []trustpolicy.TrustPolicy{{
				Name:                  "test-statement-name",
				RegistryScopes:        []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
				TrustStores:           []string{"test"},
				TrustedIdentities:     nil,
			}},
			want: &trustpolicy.Document{
				Version: "1.0",
				TrustPolicies: []trustpolicy.TrustPolicy{{
					Name:                  "test-statement-name",
					RegistryScopes:        []string{"*"},
					SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
					TrustStores:           []string{"test"},
					TrustedIdentities:     nil,
				}},
			},
		},
		{
			name: "trust policy with multiple policies and should not be cleaned",
			policy: []trustpolicy.TrustPolicy{
				{
					Name:                  "test-statement-name",
					RegistryScopes:        []string{"*"},
					SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
					TrustStores:           []string{"test"},
					TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
				},
				{
					Name:                  "test-statement-name-2",
					RegistryScopes:        []string{"example.com/podInfo"},
					SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
					TrustStores:           []string{"test"},
					TrustedIdentities:     nil,
				},
			},
			want: &trustpolicy.Document{
				Version: "1.0",
				TrustPolicies: []trustpolicy.TrustPolicy{
					{
						Name:                  "test-statement-name",
						RegistryScopes:        []string{"*"},
						SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
						TrustStores:           []string{"test"},
						TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
					},
					{
						Name:                  "test-statement-name-2",
						RegistryScopes:        []string{"example.com/podInfo"},
						SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
						TrustStores:           []string{"test"},
						TrustedIdentities:     nil,
					},
				},
			},
		},
		{
			name: "trust policy verification level skip should be cleaned",
			policy: []trustpolicy.TrustPolicy{
				{
					Name:                  "test-statement-name",
					RegistryScopes:        []string{"*"},
					SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "skip"},
					TrustStores:           []string{"test"},
					TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
				},
			},
			want: &trustpolicy.Document{
				Version: "1.0",
				TrustPolicies: []trustpolicy.TrustPolicy{
					{
						Name:                  "test-statement-name",
						RegistryScopes:        []string{"*"},
						SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "skip"},
						TrustStores:           []string{},
						TrustedIdentities:     []string{},
					},
				},
			},
			logMessage: "warning: trust policy statement 'test-statement-name' is set to skip signature verification but configured with trust stores and/or trusted identities. Removing trust stores and trusted identities",
		},
		{
			name: "trust policy with multiple policies and mixture of verification levels including ship",
			policy: []trustpolicy.TrustPolicy{
				{
					Name:                  "test-statement-name",
					RegistryScopes:        []string{"*"},
					SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
					TrustStores:           []string{"test"},
					TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
				},
				{
					Name:                  "test-statement-name-2",
					RegistryScopes:        []string{"example.com/podInfo"},
					SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "skip"},
					TrustStores:           []string{"test"},
					TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
				},
			},
			want: &trustpolicy.Document{
				Version: "1.0",
				TrustPolicies: []trustpolicy.TrustPolicy{
					{
						Name:                  "test-statement-name",
						RegistryScopes:        []string{"*"},
						SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
						TrustStores:           []string{"test"},
						TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
					},
					{
						Name:                  "test-statement-name-2",
						RegistryScopes:        []string{"example.com/podInfo"},
						SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "skip"},
						TrustStores:           []string{},
						TrustedIdentities:     []string{},
					},
				},
			},
			logMessage: "warning: trust policy statement 'test-statement-name-2' is set to skip signature verification but configured with trust stores and/or trusted identities. Removing trust stores and trusted identities",
		},
	}

	// Run the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := &testLogger{[]string{}, logr.RuntimeInfo{CallDepth: 1}}
			logger := logr.New(l)

			if tc.want == nil {
				cleanedPolicy := cleanTrustPolicy(nil, logger)
				if !reflect.DeepEqual(cleanedPolicy, tc.want) {
					t.Errorf("got %#v, want %#v", cleanedPolicy, tc.want)
				}
				return
			}

			policy := trustpolicy.Document{
				Version:       "1.0",
				TrustPolicies: tc.policy,
			}

			cleanedPolicy := cleanTrustPolicy(&policy, logger)

			if !reflect.DeepEqual(cleanedPolicy, tc.want) {
				t.Errorf("got %#v, want %#v", cleanedPolicy, tc.want)
			}

			if tc.logMessage != "" {
				g.Expect(len(l.Output)).Should(Equal(1))
				g.Expect(l.Output[0]).Should(Equal(tc.logMessage))
			}
		})
	}
}

func dummyPolicyDocument() (policyDoc *trustpolicy.Document) {
	policyDoc = &trustpolicy.Document{
		Version:       "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{dummyPolicyStatement()},
	}
	return
}

func dummyPolicyStatement() (policyStatement trustpolicy.TrustPolicy) {
	policyStatement = trustpolicy.TrustPolicy{
		Name:                  "test-statement-name",
		RegistryScopes:        []string{"registry.acme-rockets.io/software/net-monitor"},
		SignatureVerification: trustpolicy.SignatureVerification{VerificationLevel: "strict"},
		TrustStores:           []string{"ca:valid-trust-store", "signingAuthority:valid-trust-store"},
		TrustedIdentities:     []string{"x509.subject:CN=Notation Test Root,O=Notary,L=Seattle,ST=WA,C=US"},
	}
	return
}

// mocking LogSink to capture log messages. Source: https://stackoverflow.com/a/71425740
type testLogger struct {
	Output []string
	r      logr.RuntimeInfo
}

func (t *testLogger) doLog(msg string) {
	t.Output = append(t.Output, msg)
}

func (t *testLogger) Init(info logr.RuntimeInfo) {
	t.r = info
}

func (t *testLogger) Enabled(level int) bool {
	return true
}

func (t *testLogger) Info(level int, msg string, keysAndValues ...interface{}) {
	t.doLog(msg)
}

func (t *testLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	t.doLog(msg)
}

func (t *testLogger) WithValues(keysAndValues ...interface{}) logr.LogSink {
	return t
}

func (t *testLogger) WithName(name string) logr.LogSink {
	return t
}
