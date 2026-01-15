// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//nolint:revive
package security

import (
	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/resource/meta"
	"github.com/cosi-project/runtime/pkg/resource/protobuf"
	"github.com/cosi-project/runtime/pkg/resource/typed"

	"github.com/siderolabs/talos/pkg/machinery/proto"
)

// ImageVerificationConfigType is type of ImageVerificationConfig resource.
const ImageVerificationConfigType = resource.Type("ImageVerificationConfigs.security.talos.dev")

// ImageVerificationConfig represents ImageVerificationConfig typed resource.
type ImageVerificationConfig = typed.Resource[ImageVerificationConfigSpec, ImageVerificationConfigExtension]

// ImageVerificationConfigID is the ID of the ImageVerificationConfig resource.
const ImageVerificationConfigID = "image-verification"

// ImageVerificationConfigSpec represents the image verification configuration.
//
//gotagsrewrite:gen
type ImageVerificationConfigSpec struct {
	// Rules is the list of verification rules.
	Rules []ImageVerificationRuleSpec `yaml:"rules,omitempty" protobuf:"2"`
}

// ImageVerificationVerifierSpec represents a signature verification provider.
//
//gotagsrewrite:gen
type ImageVerificationVerifierSpec struct {
	// Issuer is the OIDC issuer URL.
	Issuer string `yaml:"issuer" protobuf:"1"`
	// Subject is the expected subject.
	Subject string `yaml:"subject,omitempty" protobuf:"2"`
	// SubjectRegex is a regex pattern for subject matching.
	SubjectRegex string `yaml:"subjectRegex,omitempty" protobuf:"3"`
	// RekorURL is the Rekor transparency log URL.
	RekorURL string `yaml:"rekorURL" protobuf:"4"`
}

// ImageVerificationRuleSpec represents a verification rule.
//
//gotagsrewrite:gen
type ImageVerificationRuleSpec struct {
	// ImagePattern is the image name pattern.
	ImagePattern string `yaml:"imagePattern,omitempty" protobuf:"2"`
	// Action is the action for matching images.
	Verify bool `yaml:"verify" protobuf:"3"`
	// Verifier is the verifier configuration to use.
	Verifier *ImageVerificationVerifierSpec `yaml:"verifier,omitempty" protobuf:"4"`
}

// NewImageVerificationConfig creates new ImageVerificationConfig object.
func NewImageVerificationConfig() *ImageVerificationConfig {
	return typed.NewResource[ImageVerificationConfigSpec, ImageVerificationConfigExtension](
		resource.NewMetadata(NamespaceName, ImageVerificationConfigType, ImageVerificationConfigID, resource.VersionUndefined),
		ImageVerificationConfigSpec{},
	)
}

// ImageVerificationConfigExtension is an auxiliary type for ImageVerificationConfig resource.
type ImageVerificationConfigExtension struct{}

// ResourceDefinition implements meta.ResourceDefinitionProvider interface.
func (ImageVerificationConfigExtension) ResourceDefinition() meta.ResourceDefinitionSpec {
	return meta.ResourceDefinitionSpec{
		Type:             ImageVerificationConfigType,
		Aliases:          []resource.Type{},
		DefaultNamespace: NamespaceName,
		PrintColumns: []meta.PrintColumn{
			{
				Name:     "Enabled",
				JSONPath: "{.enabled}",
			},
		},
	}
}

func init() {
	proto.RegisterDefaultTypes()

	err := protobuf.RegisterDynamic(ImageVerificationConfigType, &ImageVerificationConfig{})
	if err != nil {
		panic(err)
	}
}

const NamespaceName resource.Namespace = "security"
