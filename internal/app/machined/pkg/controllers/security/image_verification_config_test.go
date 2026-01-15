// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package security_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/siderolabs/talos/internal/app/machined/pkg/controllers/ctest"
	securityctrl "github.com/siderolabs/talos/internal/app/machined/pkg/controllers/security"
	"github.com/siderolabs/talos/pkg/machinery/config/container"
	securitycfg "github.com/siderolabs/talos/pkg/machinery/config/types/security"
	"github.com/siderolabs/talos/pkg/machinery/config/types/v1alpha1"
	"github.com/siderolabs/talos/pkg/machinery/resources/config"
	"github.com/siderolabs/talos/pkg/machinery/resources/security"
)

type ImageVerificationConfigSuite struct {
	ctest.DefaultSuite
}

func (suite *ImageVerificationConfigSuite) TestReconcileNoConfig() {
	ctest.AssertNoResource[*security.ImageVerificationConfig](suite, security.ImageVerificationConfigID)
}

func (suite *ImageVerificationConfigSuite) TestReconcileNoVerificationConfig() {
	// TODO(laurazard): change tests to check that one is always created,
	// regardless of config or not (should have "Enabled: false" when not configured)
	cfg := config.NewMachineConfig(container.NewV1Alpha1(&v1alpha1.Config{
		ConfigVersion: "v1alpha1",
		MachineConfig: &v1alpha1.MachineConfig{
			MachineType: "controlplane",
		},
	}))

	suite.Require().NoError(suite.State().Create(suite.Ctx(), cfg))

	ctest.AssertResource(suite, security.ImageVerificationConfigID, func(r *security.ImageVerificationConfig, asrt *assert.Assertions) {
		asrt.Equal(0, len(r.TypedSpec().Rules))
	})
}

func (suite *ImageVerificationConfigSuite) TestReconcileWithRules() {
	verificationCfg := securitycfg.NewImageVerificationConfigV1Alpha1()
	verificationCfg.ConfigRules = []securitycfg.ImageVerificationRuleV1Alpha1{
		{
			RuleImagePattern: "docker.io/*",
			RuleVerify:       false,
		},
		{
			RuleImagePattern: "ghcr.io/myorg/*",
			RuleVerify:       true,
			RuleVerifier: &securitycfg.ImageVerifierV1Alpha1{
				KeylessIssuer:       "https://token.actions.githubusercontent.com",
				KeylessSubjectRegex: "https://github.com/myorg/.*",
				KeylessRekorURL:     "https://rekor.sigstore.dev",
			},
		},
	}

	cont, err := container.New(
		&v1alpha1.Config{
			ConfigVersion: "v1alpha1",
			MachineConfig: &v1alpha1.MachineConfig{
				MachineType: "controlplane",
			},
		},
		verificationCfg,
	)
	suite.Require().NoError(err)

	cfg := config.NewMachineConfig(cont)
	suite.Require().NoError(suite.State().Create(suite.Ctx(), cfg))

	ctest.AssertResource(suite, security.ImageVerificationConfigID, func(r *security.ImageVerificationConfig, asrt *assert.Assertions) {
		spec := r.TypedSpec()

		asrt.Len(spec.Rules, 2)

		for i, rule := range spec.Rules {
			asrt.Equal(verificationCfg.ConfigRules[i].RuleImagePattern, rule.ImagePattern)
			asrt.Equal(verificationCfg.ConfigRules[i].RuleVerify, rule.Verify)

			expectedVerifier := verificationCfg.ConfigRules[i].RuleVerifier

			if expectedVerifier != nil {
				asrt.Equal(expectedVerifier.KeylessIssuer, rule.Verifier.Issuer)
				asrt.Equal(expectedVerifier.KeylessSubject, rule.Verifier.Subject)
				asrt.Equal(expectedVerifier.KeylessSubjectRegex, rule.Verifier.SubjectRegex)
				asrt.Equal(expectedVerifier.KeylessRekorURL, rule.Verifier.RekorURL)
			} else {
				asrt.Nil(rule.Verifier)
			}
		}
	})
}

func TestImageVerificationConfigSuite(t *testing.T) {
	t.Parallel()

	suite.Run(t, &ImageVerificationConfigSuite{
		DefaultSuite: ctest.DefaultSuite{
			Timeout: 5 * time.Second,
			AfterSetup: func(s *ctest.DefaultSuite) {
				s.Require().NoError(s.Runtime().RegisterController(&securityctrl.ImageVerificationConfigController{}))
			},
		},
	})
}
