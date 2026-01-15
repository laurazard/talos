// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//nolint:revive
package security

import (
	"context"
	"fmt"

	"github.com/cosi-project/runtime/pkg/controller"
	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/siderolabs/gen/optional"
	"go.uber.org/zap"

	"github.com/siderolabs/talos/pkg/machinery/config/config"
	configres "github.com/siderolabs/talos/pkg/machinery/resources/config"
	"github.com/siderolabs/talos/pkg/machinery/resources/security"
)

// ImageVerificationConfigController watches machine config and produces ImageVerificationConfig resource.
type ImageVerificationConfigController struct{}

// Name implements controller.Controller interface.
func (ctrl *ImageVerificationConfigController) Name() string {
	return "security.ImageVerificationConfigController"
}

// Inputs implements controller.Controller interface.
func (ctrl *ImageVerificationConfigController) Inputs() []controller.Input {
	return []controller.Input{
		{
			Namespace: configres.NamespaceName,
			Type:      configres.MachineConfigType,
			ID:        optional.Some(configres.ActiveID),
			Kind:      controller.InputWeak,
		},
	}
}

// Outputs implements controller.Controller interface.
func (ctrl *ImageVerificationConfigController) Outputs() []controller.Output {
	return []controller.Output{
		{
			Type: security.ImageVerificationConfigType,
			Kind: controller.OutputExclusive,
		},
	}
}

// Run implements controller.Controller interface.
func (ctrl *ImageVerificationConfigController) Run(ctx context.Context, r controller.Runtime, logger *zap.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.EventCh():
		}

		newSpec, err := ctrl.loadConfig(ctx, r)
		if err != nil {
			return fmt.Errorf("failed to load image verification config: %w", err)
		}

		existingSpec, err := ctrl.getCurrentSpec(ctx, r)
		if err != nil && !state.IsNotFoundError(err) {
			return fmt.Errorf("failed to get existing image verification config: %w", err)
		}

		if !shouldUpdate(newSpec, existingSpec) {
			logger.Debug("image verification config unchanged, skipping")

			continue
		}

		if err := safe.WriterModify(ctx, r, security.NewImageVerificationConfig(), func(res *security.ImageVerificationConfig) error {
			res.TypedSpec().Rules = newSpec.Rules

			return nil
		}); err != nil {
			return fmt.Errorf("failed to write image verification config: %w", err)
		}
	}
}

func (ctrl *ImageVerificationConfigController) getCurrentSpec(ctx context.Context, r controller.Runtime) (*security.ImageVerificationConfigSpec, error) {
	imgVerificationCfg, err := safe.ReaderGetByID[*security.ImageVerificationConfig](ctx, r, security.ImageVerificationConfigID)
	if err != nil {
		return nil, err
	}

	return imgVerificationCfg.TypedSpec(), nil
}

// loadConfig loads the image verification config from the machine config.
//
// If the machine config does not contain an image verification config,
// an empty config is returned.
func (ctrl *ImageVerificationConfigController) loadConfig(ctx context.Context, r controller.Runtime) (*security.ImageVerificationConfigSpec, error) {
	machineConfig, err := safe.ReaderGetByID[*configres.MachineConfig](ctx, r, configres.ActiveID)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine config: %w", err)
	}

	if machineConfig.Config().ImageVerificationConfig() == nil {
		return &security.ImageVerificationConfigSpec{}, nil
	}

	return convertConfig(machineConfig.Config().ImageVerificationConfig()), nil
}

func convertConfig(cfg config.ImageVerificationConfig) *security.ImageVerificationConfigSpec {
	var (
		cfgRules  = cfg.Rules()
		specRules = make([]security.ImageVerificationRuleSpec, 0, len(cfgRules))
	)

	for _, rule := range cfg.Rules() {
		var verifier *security.ImageVerificationVerifierSpec

		if v := rule.Verifier(); v != nil {
			verifier = &security.ImageVerificationVerifierSpec{
				Issuer:       v.Issuer(),
				Subject:      v.Subject(),
				SubjectRegex: v.SubjectRegex(),
				RekorURL:     v.RekorURL(),
			}
		}

		specRules = append(specRules, security.ImageVerificationRuleSpec{
			ImagePattern: rule.ImagePattern(),
			Verify:       rule.Verify(),
			Verifier:     verifier,
		})
	}

	return &security.ImageVerificationConfigSpec{
		Rules: specRules,
	}
}

func shouldUpdate(newCfg, currentCfg *security.ImageVerificationConfigSpec) bool {
	if newCfg == nil || currentCfg == nil {
		return true
	}

	if len(newCfg.Rules) != len(currentCfg.Rules) {
		return true
	}

	for i := range newCfg.Rules {
		if !rulesEqual(newCfg.Rules[i], currentCfg.Rules[i]) {
			return true
		}
	}

	return false
}

func rulesEqual(a, b security.ImageVerificationRuleSpec) bool {
	return a.ImagePattern == b.ImagePattern &&
		a.Verify == b.Verify &&
		verifiersEqual(a.Verifier, b.Verifier)
}

func verifiersEqual(a, b *security.ImageVerificationVerifierSpec) bool {
	return a.Issuer == b.Issuer &&
		a.Subject == b.Subject &&
		a.SubjectRegex == b.SubjectRegex &&
		a.RekorURL == b.RekorURL
}
