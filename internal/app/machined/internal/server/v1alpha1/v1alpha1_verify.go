// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/ryanuber/go-glob"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/resources/security"
)

// ImageVerify verifies an image against the configured verification policy.
//
// This endpoint is called by containerd before unpacking an image to ensure
// the image meets the verification requirements configured in the machine config.
//
// If no verification policy is configured, all images are allowed by default.
func (s *Server) ImageVerify(ctx context.Context, req *machine.ImageVerifyRequest) (*machine.ImageVerifyResponse, error) {
	if req.Reference == "" {
		return nil, status.Error(codes.InvalidArgument, "image reference is required")
	} else if req.Digest == "" {
		return nil, status.Error(codes.InvalidArgument, "image digest is required")
	}

	if strings.HasPrefix(req.Reference, "sha256:") {
		return &machine.ImageVerifyResponse{
			Ok:     true,
			Method: "not a named reference",
		}, nil
	}

	cfg, err := s.getVerificationConfig(ctx)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		return &machine.ImageVerifyResponse{
			Ok:     true,
			Method: "image verification not configured",
		}, nil
	}

	verifierSpec, shouldVerify := matchRules(req.Reference, cfg)
	if !shouldVerify {
		return &machine.ImageVerifyResponse{
			Ok:     true,
			Method: "none",
		}, nil
	} else if verifierSpec == nil {
		// this shouldn't happen due to config validation, but just in case
		return nil, status.Error(codes.Internal, "image verification required but no verifier configured")
	}

	digestRef, err := parseReference(req.Reference, req.Digest)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid image reference or digest: %v", err)
	}

	result, err := checkSignatures(ctx, digestRef, verifierSpec)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to verify image signatures: %v", err)
	}

	log.Printf("verification passed=%t | ref=%s reason=%s", result.ok, req.Reference, result.method)

	return &machine.ImageVerifyResponse{
		Ok:     result.ok,
		Method: result.method,
	}, nil
}

type verificationResult struct {
	ok     bool
	method string
}

func matchRules(ref string, spec *security.ImageVerificationConfigSpec) (*security.ImageVerificationVerifierSpec, bool) {
	if strings.Count(ref, "/") < 2 {
		return nil, false
	}

	// TODO: improve this parsing, if users specify specific tags
	// or digests this won't work. Need to clearly define rules
	// for how the image pattern is matched against the reference.
	ref, _, _ = strings.Cut(ref, "@")
	ref, _, _ = strings.Cut(ref, ":")

	for _, rule := range spec.Rules {
		// TODO: maybe allow regex patterns?
		if rule.ImagePattern != "" && !glob.Glob(rule.ImagePattern, ref) {
			continue
		}

		return rule.Verifier, rule.Verify
	}

	return nil, false
}

func checkSignatures(ctx context.Context, digestRef name.Reference, verifier *security.ImageVerificationVerifierSpec) (verificationResult, error) {
	trustedMaterial, err := cosign.TrustedRoot()
	if err != nil {
		return verificationResult{}, fmt.Errorf("failed to get cosign trusted roots: %w", err)
	}

	co := cosign.CheckOpts{
		TrustedMaterial: trustedMaterial,
		Identities: []cosign.Identity{{
			Issuer:        verifier.Issuer,
			Subject:       verifier.Subject,
			SubjectRegExp: verifier.SubjectRegex,
		}},
	}

	var (
		verifyResult verificationResult
		errBundled   error
		errLegacy    error
	)

	verifyResult, errBundled = verifyBundledSignature(ctx, digestRef, co)
	if errBundled == nil {
		return verifyResult, nil
	}

	// fall back to legacy signature verification
	verifyResult, errLegacy = verifyLegacySignature(ctx, digestRef, co)
	if errLegacy == nil {
		return verifyResult, nil
	}

	return verificationResult{}, errors.Join(errBundled, errLegacy)
}

func verifyLegacySignature(ctx context.Context, digestRef name.Reference, co cosign.CheckOpts) (verificationResult, error) {
	co.NewBundleFormat = false

	_, bundleVerified, err := cosign.VerifyImageSignatures(ctx, digestRef, &co)
	if err == nil {
		// determine verification method
		var verificationMethod string

		if co.SigVerifier != nil {
			verificationMethod = "legacy: public key"
		} else {
			verificationMethod = "legacy: certificate subject"
		}

		return verificationResult{ok: bundleVerified, method: verificationMethod}, nil
	}

	return verificationResult{}, err
}

func verifyBundledSignature(ctx context.Context, digestRef name.Reference, co cosign.CheckOpts) (verificationResult, error) {
	co.NewBundleFormat = true

	_, bundleVerified, err := cosign.VerifyImageAttestations(ctx, digestRef, &co)
	if err == nil {
		// determine verification method
		var verificationMethod string

		if co.SigVerifier != nil {
			verificationMethod = "bundled: public key"
		} else {
			verificationMethod = "bundled: certificate subject"
		}

		return verificationResult{ok: bundleVerified, method: verificationMethod}, nil
	}

	return verificationResult{}, err
}

func (s *Server) getVerificationConfig(ctx context.Context) (
	*security.ImageVerificationConfigSpec, error,
) {
	st := s.Controller.Runtime().State().V1Alpha2().Resources()

	verificationConfig, err := safe.StateGetByID[*security.ImageVerificationConfig](
		ctx, st, security.ImageVerificationConfigID)
	if err != nil {
		if state.IsNotFoundError(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get verification config: %w", err)
	}

	return verificationConfig.TypedSpec(), nil
}

func parseReference(reference, digest string) (name.Digest, error) {
	var _none name.Digest

	nameRef, err := name.ParseReference(reference)
	if err != nil {
		return _none, fmt.Errorf("failed to parse image reference: %w", err)
	}

	digestRef, err := name.NewDigest(nameRef.Context().String() + "@" + digest)
	if err != nil {
		return _none, fmt.Errorf("failed to create digest reference: %w", err)
	}

	return digestRef, nil
}
