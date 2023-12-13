package oci

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	verifier "github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/truststore"

	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	oras "oras.land/oras-go/v2/registry/remote"
	oauth "oras.land/oras-go/v2/registry/remote/auth"
)

// notationOptions is a struct that holds options for notation verifier
type notationOptions struct {
	PublicCertificate []byte
	TrustStore        *trustpolicy.Document
	Keychain          authn.Keychain
	ROpt              []remote.Option
	Insecure          bool
}

// NotationOptions is a function that configures the options applied to a notation verifier
type NotationOptions func(opts *notationOptions)

// WithInsecureRegistry sets notation to verify against insecure registry.
func WithInsecureRegistry(insecure bool) NotationOptions {
	return func(opts *notationOptions) {
		opts.Insecure = insecure
	}
}

// WithTrustStore sets the trust store configuration.
func WithTrustStore(trustStore *trustpolicy.Document) NotationOptions {
	return func(opts *notationOptions) {
		opts.TrustStore = trustStore
	}
}

// WithNotaryPublicCertificate is a function that creates a NotationOptions function option
// to set the public certificate for notary.
// It takes in the certificate data as a byte slice and the name of the certificate.
// The function returns a NotationOptions function option that sets the public certificate
// in the notation options.
func WithNotaryPublicCertificate(data []byte) NotationOptions {
	return func(opts *notationOptions) {
		opts.PublicCertificate = data
	}
}

// WithNotaryRemoteOptions is a functional option for overriding the default
// remote options used by the verifier
func WithNotaryRemoteOptions(opts ...remote.Option) NotationOptions {
	return func(o *notationOptions) {
		o.ROpt = opts
	}
}

// WithNotaryKeychain is a functional option for overriding the default
// remote options used by the verifier
func WithNotaryKeychain(key authn.Keychain) NotationOptions {
	return func(o *notationOptions) {
		o.Keychain = key
	}
}

// NotatryVerifier is a struct which is responsible for executing verification logic
type NotaryVerifier struct {
	auth     authn.Keychain
	verifier *notation.Verifier
	opts     []remote.Option
	insecure bool
}

type trustStore struct {
	cert []byte
}

// GetCertificates implements truststore.X509TrustStore.
func (s trustStore) GetCertificates(ctx context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	raw := s.cert
	block, _ := pem.Decode(raw)
	if block != nil {
		raw = block.Bytes
	}

	certs, err := x509.ParseCertificates(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate '%s': %s", namedStore, err)
	}

	return certs, nil
}

// NewNotaryVerifier initializes a new NotaryVerifier
func NewNotaryVerifier(opts ...NotationOptions) (*NotaryVerifier, error) {
	o := notationOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	store := &trustStore{
		cert: o.PublicCertificate,
	}

	verifier, err := verifier.New(o.TrustStore, store, nil)
	if err != nil {
		return nil, err
	}

	return &NotaryVerifier{
		auth:     o.Keychain,
		verifier: &verifier,
		opts:     o.ROpt,
		insecure: o.Insecure,
	}, nil
}

// Verify verifies the authenticity of the given ref OCI image.
// It returns a boolean indicating if the verification was successful.
// It returns an error if the verification fails, nil otherwise.
func (v *NotaryVerifier) Verify(ctx context.Context, ref name.Reference) (bool, error) {
	url := ref.Name()
	remoteRepo, err := oras.NewRepository(url)
	if err != nil {
		return false, err
	}
	remoteRepo.PlainHTTP = v.insecure

	repo := registry.NewRepository(remoteRepo)

	ss := stringResource{url}

	var credentialProvider func(ctx context.Context, registry string) (oauth.Credential, error)

	if v.auth != nil {
		au, err := v.auth.Resolve(ss)
		if err != nil {
			return false, err
		}

		authConfig, err := au.Authorization()
		if err != nil {
			return false, err
		}

		credentialProvider = func(ctx context.Context, registry string) (oauth.Credential, error) {
			if authConfig.Username != "" || authConfig.Password != "" || authConfig.IdentityToken != "" {
				return oauth.Credential{
					Username:     authConfig.Username,
					Password:     authConfig.Password,
					RefreshToken: authConfig.IdentityToken,
				}, nil
			}
			return oauth.EmptyCredential, nil
		}
	}

	repoClient := &oauth.Client{
		Header: http.Header{
			"User-Agent": {"flux"},
		},
		Cache:      oauth.NewCache(),
		Credential: credentialProvider,
	}

	remoteRepo.Client = repoClient

	i, err := remote.Image(ref, v.opts...)
	if err != nil {
		return false, err
	}

	d, err := i.Digest()
	if err != nil {
		return false, err
	}

	repoUrl := ""

	lastIndex := strings.LastIndex(url, ":")
	firstPart := url[:lastIndex]

	if s := strings.Split(url, ":"); len(s) >= 2 && !strings.Contains(url, "@") {
		repoUrl = fmt.Sprintf("%s@%s", firstPart, d)
	}

	verififyOptions := notation.VerifyOptions{
		ArtifactReference:    repoUrl,
		MaxSignatureAttempts: 50,
	}

	_, signatures, err := notation.Verify(ctx, *v.verifier, repo, verififyOptions)
	if err != nil {
		return false, err
	}

	if len(signatures) == 0 {
		return false, nil
	}

	return true, nil
}

// stringResource represents a resource with a string value.
type stringResource struct {
	registry string
}

// String returns the string representation of the stringResource.
func (r stringResource) String() string {
	return r.registry
}

// RegistryStr returns the registry part of the string resource.
// It splits the registry string by "/" and returns the first element.
func (r stringResource) RegistryStr() string {
	return strings.Split(r.registry, "/")[0]
}
