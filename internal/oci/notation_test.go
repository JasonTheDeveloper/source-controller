package oci

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
)

func TestOptionsForNotary(t *testing.T) {
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
			opts: []Options{WithNotaryPublicCertificate([]byte("foo"))},
			want: &options{
				PublicKey: []byte("foo"),
				ROpt:      nil,
			},
		},
		{
			name: "keychain option",
			opts: []Options{
				WithNotaryRemoteOptions(remote.WithAuthFromKeychain(authn.DefaultKeychain)),
				WithNotaryKeychain(authn.DefaultKeychain),
			},
			want: &options{
				PublicKey: nil,
				ROpt:      []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
				Keychain:  authn.DefaultKeychain,
			},
		},
		{
			name: "keychain and authenticator option",
			opts: []Options{
				WithNotaryRemoteOptions(
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
				),
				WithNotaryAuth(&authn.Basic{Username: "foo", Password: "bar"}),
				WithNotaryKeychain(authn.DefaultKeychain),
			},
			want: &options{
				PublicKey: nil,
				ROpt: []remote.Option{
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
				},
				Auth:     &authn.Basic{Username: "foo", Password: "bar"},
				Keychain: authn.DefaultKeychain,
			},
		},
		{
			name: "keychain, authenticator and transport option",
			opts: []Options{
				WithNotaryRemoteOptions(
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
					remote.WithTransport(http.DefaultTransport),
				),
				WithNotaryAuth(&authn.Basic{Username: "foo", Password: "bar"}),
				WithNotaryKeychain(authn.DefaultKeychain),
			},
			want: &options{
				PublicKey: nil,
				ROpt: []remote.Option{
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
					remote.WithTransport(http.DefaultTransport),
				},
				Auth:     &authn.Basic{Username: "foo", Password: "bar"},
				Keychain: authn.DefaultKeychain,
			},
		},
		{
			name: "truststore, empty document",
			opts: []Options{WithTrustStore(&trustpolicy.Document{})},
			want: &options{
				PublicKey:   nil,
				ROpt:        nil,
				TrustPolicy: &trustpolicy.Document{},
			},
		},
		{
			name: "truststore, dummy document",
			opts: []Options{WithTrustStore(dummyPolicyDocument())},
			want: &options{
				PublicKey:   nil,
				ROpt:        nil,
				TrustPolicy: dummyPolicyDocument(),
			},
		},
		{
			name: "insecure, false",
			opts: []Options{WithInsecureRegistry(false)},
			want: &options{
				PublicKey:   nil,
				ROpt:        nil,
				TrustPolicy: nil,
				Insecure:    false,
			},
		},
		{
			name: "insecure, true",
			opts: []Options{WithInsecureRegistry(true)},
			want: &options{
				PublicKey:   nil,
				ROpt:        nil,
				TrustPolicy: nil,
				Insecure:    true,
			},
		},
		{
			name: "insecure, default",
			opts: []Options{},
			want: &options{
				PublicKey:   nil,
				ROpt:        nil,
				TrustPolicy: nil,
				Insecure:    false,
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
			if !reflect.DeepEqual(o.PublicKey, tc.want.PublicKey) {
				t.Errorf("got %#v, want %#v", &o.PublicKey, tc.want.PublicKey)
			}

			if !reflect.DeepEqual(o.TrustPolicy, tc.want.TrustPolicy) {
				t.Errorf("got %#v, want %#v", &o.TrustPolicy, tc.want.TrustPolicy)
			}

			if tc.want.ROpt != nil {
				if len(o.ROpt) != len(tc.want.ROpt) {
					t.Errorf("got %d remote options, want %d", len(o.ROpt), len(tc.want.ROpt))
				}
				return
			}

			if tc.want.ROpt == nil {
				if len(o.ROpt) != 0 {
					t.Errorf("got %d remote options, want %d", len(o.ROpt), 0)
				}
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
