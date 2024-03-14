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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/registry"
	verifier "github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	oras "oras.land/oras-go/v2/registry/remote"
	oauth "oras.land/oras-go/v2/registry/remote/auth"

	"github.com/fluxcd/source-controller/internal/helm/common"
	"github.com/fluxcd/source-controller/internal/oci"
)

// name of the trustpolicy file defined in the Secret containing
// notation public keys.
const DefaultTrustPolicyKey = "trustpolicy.json"

// options is a struct that holds options for verifier.
type options struct {
	rootCertificate []byte
	rOpt            []remote.Option
	trustPolicy     *trustpolicy.Document
	auth            authn.Authenticator
	keychain        authn.Keychain
	insecure        bool
	logger          logr.Logger
}

// Options is a function that configures the options applied to a Verifier.
type Options func(opts *options)

// WithInsecureRegistry sets notation to verify against insecure registry.
func WithInsecureRegistry(insecure bool) Options {
	return func(opts *options) {
		opts.insecure = insecure
	}
}

// WithTrustStore sets the trust store configuration.
func WithTrustStore(trustStore *trustpolicy.Document) Options {
	return func(opts *options) {
		opts.trustPolicy = trustStore
	}
}

// WithRootCertificate is a functional option for overriding the default
// rootCertificate options used by the verifier to set the root CA certificate for notary.
// It takes in the certificate data as a byte slice.
// The function returns a options function option that sets the public certificate
// in the notation options.
func WithRootCertificate(data []byte) Options {
	return func(opts *options) {
		opts.rootCertificate = data
	}
}

// WithRemoteOptions is a functional option for overriding the default
// remote options used by the verifier
func WithRemoteOptions(opts ...remote.Option) Options {
	return func(o *options) {
		o.rOpt = opts
	}
}

// WithAuth is a functional option for overriding the default
// authenticator options used by the verifier
func WithAuth(auth authn.Authenticator) Options {
	return func(o *options) {
		o.auth = auth
	}
}

// WithKeychain is a functional option for overriding the default
// keychain options used by the verifier
func WithKeychain(key authn.Keychain) Options {
	return func(o *options) {
		o.keychain = key
	}
}

// WithLogger is a function that returns an Options function to set the logger for the options.
// The logger is used for logging purposes within the options.
func WithLogger(logger logr.Logger) Options {
	return func(o *options) {
		o.logger = logger
	}
}

// NotationVerifier is a struct which is responsible for executing verification logic
type NotationVerifier struct {
	auth     authn.Authenticator
	keychain authn.Keychain
	verifier *notation.Verifier
	opts     []remote.Option
	insecure bool
	logger   logr.Logger
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

// NewNotationVerifier initializes a new Verifier
func NewNotationVerifier(opts ...Options) (*NotationVerifier, error) {
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}

	store := &trustStore{
		cert: o.rootCertificate,
	}

	trustpolicy := cleanTrustPolicy(o.trustPolicy, o.logger)
	if trustpolicy == nil {
		return nil, fmt.Errorf("trust policy cannot be empty")
	}

	verifier, err := verifier.New(trustpolicy, store, nil)
	if err != nil {
		return nil, err
	}

	return &NotationVerifier{
		auth:     o.auth,
		keychain: o.keychain,
		verifier: &verifier,
		opts:     o.rOpt,
		insecure: o.insecure,
		logger:   o.logger,
	}, nil
}

// cleanTrustPolicy cleans the given trust policy by removing trust stores and trusted identities
// for trust policy statements that are set to skip signature verification but still have configured trust stores and/or trusted identities.
// It takes a pointer to a trustpolicy.Document and a logger from the logr package as input parameters.
// If the trustPolicy is nil, it returns nil.
// Otherwise, it iterates over the trustPolicy.TrustPolicies and checks if each trust policy statement's
// SignatureVerification.VerificationLevel is set to trustpolicy.LevelSkip.Name.
// If it is, it logs a warning message and removes the trust stores and trusted identities for that trust policy statement.
// Finally, it returns the modified trustPolicy.
func cleanTrustPolicy(trustPolicy *trustpolicy.Document, logger logr.Logger) *trustpolicy.Document {
	if trustPolicy == nil {
		return nil
	}

	for i, j := range trustPolicy.TrustPolicies {
		if j.SignatureVerification.VerificationLevel == trustpolicy.LevelSkip.Name {
			logger.Info(fmt.Sprintf("warning: trust policy statement '%s' is set to skip signature verification but configured with trust stores and/or trusted identities. Removing trust stores and trusted identities", j.Name))
			trustPolicy.TrustPolicies[i].TrustStores = []string{}
			trustPolicy.TrustPolicies[i].TrustedIdentities = []string{}
		}
	}

	return trustPolicy
}

// Verify verifies the authenticity of the given ref OCI image.
// It returns a boolean indicating if the verification was successful.
// It returns an error if the verification fails, nil otherwise.
func (v *NotationVerifier) Verify(ctx context.Context, ref name.Reference) (oci.VerificationResult, error) {
	url := ref.Name()

	remoteRepo, err := v.remoteRepo(url)
	if err != nil {
		return oci.VerificationResultFailed, err
	}

	repo := registry.NewRepository(remoteRepo)

	repoUrl, err := v.repoUrlWithDigest(url, ref)
	if err != nil {
		return oci.VerificationResultFailed, err
	}

	verifyOptions := notation.VerifyOptions{
		ArtifactReference:    repoUrl,
		MaxSignatureAttempts: 3,
	}

	_, outcomes, err := notation.Verify(ctx, *v.verifier, repo, verifyOptions)
	if err != nil {
		return oci.VerificationResultFailed, err
	}

	if len(outcomes) == 0 {
		return oci.VerificationResultFailed, fmt.Errorf("signature verification failed for all the signatures associated with %s", url)
	}

	outcome := outcomes[0]

	if outcome.VerificationLevel == trustpolicy.LevelSkip {
		return oci.VerificationResultIgnored, nil
	}

	for _, i := range outcome.VerificationResults {
		if i.Error != nil {
			if i.Type == trustpolicy.TypeAuthenticity {
				return oci.VerificationResultIgnored, i.Error
			}

			if i.Action == trustpolicy.ActionLog {
				v.logger.Info(fmt.Sprintf("verification check for type %s failed for %s with message %s", i.Type, url, i.Error.Error()))
			}
		}
	}

	return oci.VerificationResultSuccess, nil
}

// remoteRepo is a function that creates a remote repository object for the given repository URL.
// It initializes the repository with the provided URL and sets the PlainHTTP flag based on the value of the 'insecure' field in the Verifier struct.
// It also sets up the credential provider based on the authentication configuration provided in the Verifier struct.
// If authentication is required, it retrieves the authentication credentials and sets up the repository client with the appropriate headers and credentials.
// Finally, it returns the remote repository object and any error encountered during the process.
func (v *NotationVerifier) remoteRepo(repoUrl string) (*oras.Repository, error) {
	remoteRepo, err := oras.NewRepository(repoUrl)
	if err != nil {
		return &oras.Repository{}, err
	}

	remoteRepo.PlainHTTP = v.insecure

	credentialProvider := func(ctx context.Context, registry string) (oauth.Credential, error) {
		return oauth.EmptyCredential, nil
	}

	auth := authn.Anonymous

	if v.auth != nil {
		auth = v.auth
	} else if v.keychain != nil {
		source := common.StringResource{Registry: repoUrl}

		auth, err = v.keychain.Resolve(source)
		if err != nil {
			return &oras.Repository{}, err
		}
	}

	if auth != authn.Anonymous {
		authConfig, err := auth.Authorization()
		if err != nil {
			return &oras.Repository{}, err
		}

		credentialProvider = func(ctx context.Context, registry string) (oauth.Credential, error) {
			if authConfig.Username != "" || authConfig.Password != "" || authConfig.IdentityToken != "" || authConfig.RegistryToken != "" {
				return oauth.Credential{
					Username:     authConfig.Username,
					Password:     authConfig.Password,
					RefreshToken: authConfig.IdentityToken,
					AccessToken:  authConfig.RegistryToken,
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

	return remoteRepo, nil
}

// repoUrlWithDigest takes a repository URL and a reference and returns the repository URL with the digest appended to it.
// If the repository URL does not contain a tag or digest, it returns an error.
func (v *NotationVerifier) repoUrlWithDigest(repoUrl string, ref name.Reference) (string, error) {
	if !strings.Contains(repoUrl, "@") {
		image, err := remote.Image(ref, v.opts...)
		if err != nil {
			return "", err
		}

		digest, err := image.Digest()
		if err != nil {
			return "", err
		}

		lastIndex := strings.LastIndex(repoUrl, ":")
		if lastIndex == -1 {
			return "", fmt.Errorf("url %s does not contain tag or digest", repoUrl)
		}

		firstPart := repoUrl[:lastIndex]

		if s := strings.Split(repoUrl, ":"); len(s) >= 2 {
			repoUrl = fmt.Sprintf("%s@%s", firstPart, digest)
		} else {
			return "", fmt.Errorf("url %s does not contain tag or digest", repoUrl)
		}
	}
	return repoUrl, nil
}
