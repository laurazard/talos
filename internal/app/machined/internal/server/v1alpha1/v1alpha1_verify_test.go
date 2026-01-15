package runtime

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/siderolabs/talos/pkg/machinery/resources/security"
)

func TestMatchImageAgainstRules(t *testing.T) {
	testVerifier := &security.ImageVerificationVerifierSpec{}

	tests := []struct {
		name         string
		reference    string
		config       *security.ImageVerificationConfigSpec
		wantVerify   bool
		wantVerifier *security.ImageVerificationVerifierSpec
	}{
		{
			name:         "no rules, default allow",
			reference:    "ghcr.io/siderolabs/talos:v1.0.0",
			config:       &security.ImageVerificationConfigSpec{},
			wantVerify:   false,
			wantVerifier: nil,
		},
		{
			name:      "match registry exact",
			reference: "ghcr.io/siderolabs/talos:v1.0.0",
			config: &security.ImageVerificationConfigSpec{
				Rules: []security.ImageVerificationRuleSpec{
					{
						ImagePattern: "ghcr.io/*",
						Verify:       true,
						Verifier:     testVerifier,
					},
				},
			},
			wantVerify:   true,
			wantVerifier: testVerifier,
		},
		{
			name:      "match image exact",
			reference: "ghcr.io/siderolabs/talos:v1.0.0",
			config: &security.ImageVerificationConfigSpec{
				Rules: []security.ImageVerificationRuleSpec{
					{
						ImagePattern: "ghcr.io/siderolabs/talos*",
						Verify:       true,
						Verifier:     testVerifier,
					},
				},
			},
			wantVerify:   true,
			wantVerifier: testVerifier,
		},
		{
			name:      "match image glob",
			reference: "ghcr.io/siderolabs/talos:v1.0.0",
			config: &security.ImageVerificationConfigSpec{
				Rules: []security.ImageVerificationRuleSpec{
					{
						ImagePattern: "ghcr.io/siderolabs/*",
						Verify:       true,
						Verifier:     testVerifier,
					},
				},
			},
			wantVerify:   true,
			wantVerifier: testVerifier,
		},
		{
			name:      "first rule wins",
			reference: "ghcr.io/siderolabs/talos:v1.0.0",
			config: &security.ImageVerificationConfigSpec{
				Rules: []security.ImageVerificationRuleSpec{
					{
						ImagePattern: "ghcr.io/siderolabs/talos*",
						Verify:       false,
					},
					{
						ImagePattern: "ghcr.io/*",
						Verify:       true,
					},
				},
			},
			wantVerify:   false,
			wantVerifier: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotVerifier, gotVerify := matchRules(tc.reference, tc.config)
			assert.Equal(t, tc.wantVerify, gotVerify)
			assert.Equal(t, tc.wantVerifier, gotVerifier)
		})
	}
}
