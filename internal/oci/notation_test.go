package oci

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
)

func TestNotaryOptions(t *testing.T) {
	testCases := []struct {
		name string
		opts []NotationOptions
		want *notationOptions
	}{
		{
			name: "no options",
			want: &notationOptions{},
		},
		{
			name: "signature option",
			opts: []NotationOptions{WithNotaryPublicKey([]byte("foo"))},
			want: &notationOptions{
				PublicKey: []byte("foo"),
				ROpt:      nil,
			},
		},
		{
			name: "keychain option",
			opts: []NotationOptions{WithNotaryRemoteOptions(remote.WithAuthFromKeychain(authn.DefaultKeychain))},
			want: &notationOptions{
				PublicKey: nil,
				ROpt:      []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
			},
		},
		{
			name: "keychain and authenticator option",
			opts: []NotationOptions{WithNotaryRemoteOptions(
				remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
				remote.WithAuthFromKeychain(authn.DefaultKeychain),
			)},
			want: &notationOptions{
				PublicKey: nil,
				ROpt: []remote.Option{
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
				},
			},
		},
		{
			name: "keychain, authenticator and transport option",
			opts: []NotationOptions{WithNotaryRemoteOptions(
				remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
				remote.WithAuthFromKeychain(authn.DefaultKeychain),
				remote.WithTransport(http.DefaultTransport),
			)},
			want: &notationOptions{
				PublicKey: nil,
				ROpt: []remote.Option{
					remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
					remote.WithAuthFromKeychain(authn.DefaultKeychain),
					remote.WithTransport(http.DefaultTransport),
				},
			},
		},
		{
			name: "truststore, empty document",
			opts: []NotationOptions{WithTrustStore(&trustpolicy.Document{})},
			want: &notationOptions{
				PublicKey:  nil,
				ROpt:       nil,
				TrustStore: &trustpolicy.Document{},
			},
		},
		{
			name: "truststore, dummy document",
			opts: []NotationOptions{WithTrustStore(dummyPolicyDocument())},
			want: &notationOptions{
				PublicKey:  nil,
				ROpt:       nil,
				TrustStore: dummyPolicyDocument(),
			},
		},
		{
			name: "insecure, false",
			opts: []NotationOptions{WithInsecureRegistry(false)},
			want: &notationOptions{
				PublicKey:  nil,
				ROpt:       nil,
				TrustStore: nil,
				Insecure:   false,
			},
		},
		{
			name: "insecure, true",
			opts: []NotationOptions{WithInsecureRegistry(true)},
			want: &notationOptions{
				PublicKey:  nil,
				ROpt:       nil,
				TrustStore: nil,
				Insecure:   true,
			},
		},
		{
			name: "insecure, default",
			opts: []NotationOptions{},
			want: &notationOptions{
				PublicKey:  nil,
				ROpt:       nil,
				TrustStore: nil,
				Insecure:   false,
			},
		},
	}

	// Run the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			o := notationOptions{}
			for _, opt := range tc.opts {
				opt(&o)
			}
			if !reflect.DeepEqual(o.PublicKey, tc.want.PublicKey) {
				t.Errorf("got %#v, want %#v", &o.PublicKey, tc.want.PublicKey)
			}

			if !reflect.DeepEqual(o.TrustStore, tc.want.TrustStore) {
				t.Errorf("got %#v, want %#v", &o.TrustStore, tc.want.TrustStore)
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
