// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package config

// TrustedRootsConfig defines the interface to access trusted roots configuration.
type TrustedRootsConfig interface {
	ExtraTrustedRootCertificates() []string
}

// WrapTrustedRootsConfig wraps a list of TrustedRootsConfig into a single TrustedRootsConfig aggregating the results.
func WrapTrustedRootsConfig(configs ...TrustedRootsConfig) TrustedRootsConfig {
	return trustedRootConfigWrapper(configs)
}

type trustedRootConfigWrapper []TrustedRootsConfig

func (w trustedRootConfigWrapper) ExtraTrustedRootCertificates() []string {
	return aggregateValues(w, func(c TrustedRootsConfig) []string {
		return c.ExtraTrustedRootCertificates()
	})
}

// ImageVerificationConfig specifies image signature verification policy.
type ImageVerificationConfig interface {
	// Rules returns the list of verification rules.
	Rules() []ImageVerificationRule
}

// ImageVerifier represents a signature verification provider.
type ImageVerifier interface {
	// Issuer returns the OIDC issuer URL.
	Issuer() string
	// Subject returns the expected subject (email, URI, etc).
	Subject() string
	// SubjectRegex returns the regex pattern for subject matching.
	SubjectRegex() string
	// RekorURL returns the Rekor transparency log URL.
	RekorURL() string
}

// ImageVerificationRule represents a rule for image verification.
type ImageVerificationRule interface {
	// ImagePattern returns the image name pattern.
	ImagePattern() string
	// Action returns the action for matching images.
	Verify() bool
	// Verifier returns the verifier to use for this rule (optional).
	Verifier() ImageVerifier
}
