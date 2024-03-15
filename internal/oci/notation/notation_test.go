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
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/source-controller/internal/oci"
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
		name           string
		policy         []trustpolicy.TrustPolicy
		want           *trustpolicy.Document
		wantLogMessage string
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
			wantLogMessage: "warning: trust policy statement 'test-statement-name' is set to skip signature verification but configured with trust stores and/or trusted identities. Removing trust stores and trusted identities",
		},
		{
			name: "trust policy with multiple policies and mixture of verification levels including skip",
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
			wantLogMessage: "warning: trust policy statement 'test-statement-name-2' is set to skip signature verification but configured with trust stores and/or trusted identities. Removing trust stores and trusted identities",
		},
	}

	// Run the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := &testLogger{[]string{}, logr.RuntimeInfo{CallDepth: 1}}
			logger := logr.New(l)

			if tc.want == nil {
				cleanedPolicy := CleanTrustPolicy(nil, logger)
				if !reflect.DeepEqual(cleanedPolicy, tc.want) {
					t.Errorf("got %#v, want %#v", cleanedPolicy, tc.want)
				}
				return
			}

			policy := trustpolicy.Document{
				Version:       "1.0",
				TrustPolicies: tc.policy,
			}

			cleanedPolicy := CleanTrustPolicy(&policy, logger)

			if !reflect.DeepEqual(cleanedPolicy, tc.want) {
				t.Errorf("got %#v, want %#v", cleanedPolicy, tc.want)
			}

			if tc.wantLogMessage != "" {
				g.Expect(len(l.Output)).Should(Equal(1))
				g.Expect(l.Output[0]).Should(Equal(tc.wantLogMessage))
			}
		})
	}
}

func TestOutcomeChecker(t *testing.T) {
	g := NewWithT(t)

	testCases := []struct {
		name                   string
		outcome                []*notation.VerificationOutcome
		wantErrMessage         string
		wantLogMessage         []string
		wantVerificationResult oci.VerificationResult
	}{
		{
			name:                   "no outcome failed with error message",
			wantVerificationResult: oci.VerificationResultFailed,
			wantErrMessage:         "signature verification failed for all the signatures associated with example.com/podInfo",
		},
		{
			name: "verification result ignored with log message",
			outcome: []*notation.VerificationOutcome{
				{
					VerificationLevel: trustpolicy.LevelAudit,
					VerificationResults: []*notation.ValidationResult{
						{
							Type:   trustpolicy.TypeAuthenticity,
							Action: trustpolicy.ActionLog,
							Error:  fmt.Errorf("123"),
						},
					},
				},
			},
			wantVerificationResult: oci.VerificationResultIgnored,
			wantLogMessage:         []string{"verification check for type 'authenticity' failed for 'example.com/podInfo' with message: '123'"},
		},
		{
			name: "verification result ignored with no log message (skip)",
			outcome: []*notation.VerificationOutcome{
				{
					VerificationLevel:   trustpolicy.LevelSkip,
					VerificationResults: []*notation.ValidationResult{},
				},
			},
			wantVerificationResult: oci.VerificationResultIgnored,
		},
		{
			name: "verification result success with log message",
			outcome: []*notation.VerificationOutcome{
				{
					VerificationLevel: trustpolicy.LevelAudit,
					VerificationResults: []*notation.ValidationResult{
						{
							Type:   trustpolicy.TypeAuthenticTimestamp,
							Action: trustpolicy.ActionLog,
							Error:  fmt.Errorf("456"),
						},
						{
							Type:   trustpolicy.TypeExpiry,
							Action: trustpolicy.ActionLog,
							Error:  fmt.Errorf("789"),
						},
					},
				},
			},
			wantVerificationResult: oci.VerificationResultSuccess,
			wantLogMessage: []string{
				"verification check for type 'authenticTimestamp' failed for 'example.com/podInfo' with message: '456'",
				"verification check for type 'expiry' failed for 'example.com/podInfo' with message: '789'",
			},
		},
		{
			name: "verification result success with no log message",
			outcome: []*notation.VerificationOutcome{
				{
					VerificationLevel:   trustpolicy.LevelAudit,
					VerificationResults: []*notation.ValidationResult{},
				},
			},
			wantVerificationResult: oci.VerificationResultSuccess,
		},
	}

	// Run the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := &testLogger{[]string{}, logr.RuntimeInfo{CallDepth: 1}}
			logger := logr.New(l)

			v := NotationVerifier{
				logger: logger,
			}

			result, err := v.checkOutcome(tc.outcome, "example.com/podInfo")

			if tc.wantErrMessage != "" {
				g.Expect(err).ToNot(BeNil())
				g.Expect(err.Error()).Should(Equal(tc.wantErrMessage))
			} else {
				g.Expect(err).To(BeNil())
			}

			g.Expect(result).Should(Equal(tc.wantVerificationResult))
			g.Expect(len(l.Output)).Should(Equal(len(tc.wantLogMessage)))

			for i, j := range tc.wantLogMessage {
				g.Expect(l.Output[i]).Should(Equal(j))
			}
		})
	}
}

func TestRepoUrlWithDigest(t *testing.T) {
	g := NewWithT(t)

	testCases := []struct {
		name              string
		repoUrl           string
		digest            string
		tag               string
		wantResultUrl     string
		wantErrMessage    string
		passUrlWithoutTag bool
	}{
		{
			name:           "valid repo url with digest",
			repoUrl:        "ghcr.io/stefanprodan/charts/podinfo",
			digest:         "sha256:cdd538a0167e4b51152b71a477e51eb6737553510ce8797dbcc537e1342311bb",
			wantResultUrl:  "ghcr.io/stefanprodan/charts/podinfo@sha256:cdd538a0167e4b51152b71a477e51eb6737553510ce8797dbcc537e1342311bb",
			wantErrMessage: "",
		},
		{
			name:           "valid repo url with tag",
			repoUrl:        "ghcr.io/stefanprodan/charts/podinfo",
			tag:            "6.6.0",
			wantResultUrl:  "ghcr.io/stefanprodan/charts/podinfo@sha256:cdd538a0167e4b51152b71a477e51eb6737553510ce8797dbcc537e1342311bb",
			wantErrMessage: "",
		},
		{
			name:              "valid repo url without tag",
			repoUrl:           "ghcr.io/stefanprodan/charts/podinfo",
			tag:               "6.6.0",
			wantResultUrl:     "ghcr.io/stefanprodan/charts/podinfo@sha256:cdd538a0167e4b51152b71a477e51eb6737553510ce8797dbcc537e1342311bb",
			wantErrMessage:    "url ghcr.io/stefanprodan/charts/podinfo does not contain tag or digest",
			passUrlWithoutTag: true,
		},
	}

	// Run the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := &testLogger{[]string{}, logr.RuntimeInfo{CallDepth: 1}}
			logger := logr.New(l)

			v := NotationVerifier{
				logger: logger,
			}

			var url string
			repo, _ := name.NewRepository(tc.repoUrl)
			var ref name.Reference
			if tc.digest != "" {
				ref = repo.Digest(tc.digest)
				url = fmt.Sprintf("%s@%s", tc.repoUrl, tc.digest)
			} else if tc.tag != "" {
				ref = repo.Tag(tc.tag)
				if !tc.passUrlWithoutTag {
					url = fmt.Sprintf("%s:%s", tc.repoUrl, tc.tag)
				} else {
					url = tc.repoUrl
				}
			} else {
				ref = repo.Tag(name.DefaultTag)
				url = fmt.Sprintf("%s:%s", tc.repoUrl, name.DefaultTag)
			}

			result, err := v.repoUrlWithDigest(url, ref)

			if tc.wantErrMessage != "" {
				g.Expect(err).ToNot(BeNil())
				g.Expect(err.Error()).Should(Equal(tc.wantErrMessage))
			} else {
				g.Expect(err).To(BeNil())
				g.Expect(result).Should(Equal(tc.wantResultUrl))
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
