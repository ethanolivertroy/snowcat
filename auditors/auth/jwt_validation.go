// Copyright 2021-2025 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/praetorian-inc/snowcat/auditors"
	"github.com/praetorian-inc/snowcat/pkg/types"
	securityv1beta "istio.io/api/security/v1beta1"
	clientsecurityv1beta "istio.io/client-go/pkg/apis/security/v1beta1"
)

type jwtValidationAuditor struct{}

func (a *jwtValidationAuditor) Name() string {
	return "Missing JWT Audience Validation"
}

func (a *jwtValidationAuditor) Audit(discovery types.Discovery, resources types.Resources) ([]types.AuditResult, error) {
	log.Infof("running auditor %s", a.Name())

	results := []types.AuditResult{}

	// Check for RequestAuthentication resources without audience validation
	for _, ra := range resources.RequestAuthentications {
		missingAudience := false
		
		for _, rule := range ra.Spec.JwtRules {
			// Check if audience is missing or empty
			if rule.Audiences == nil || len(rule.Audiences) == 0 {
				missingAudience = true
				break
			}
		}

		if missingAudience && len(ra.Spec.JwtRules) > 0 {
			results = append(results, types.AuditResult{
				Name:        a.Name(),
				Description: fmt.Sprintf("RequestAuthentication %s in namespace %s has JWT rules without audience validation, which allows JWT tokens intended for other services to be accepted", ra.Name, ra.Namespace),
				Severity:    types.High,
				Resource:    formatResource(ra),
			})
		}
	}

	return results, nil
}

// Helper function to format the resource for display
func formatResource(ra *clientsecurityv1beta.RequestAuthentication) string {
	return fmt.Sprintf("RequestAuthentication/%s.%s", ra.Name, ra.Namespace)
}

func init() {
	auditors.Register(&jwtValidationAuditor{})
}