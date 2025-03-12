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

package authz

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/praetorian-inc/snowcat/auditors"
	"github.com/praetorian-inc/snowcat/pkg/types"
	securityv1beta "istio.io/api/security/v1beta1"
	clientsecurityv1beta "istio.io/client-go/pkg/apis/security/v1beta1"
)

type overlyPermissiveAuditor struct{}

func (a *overlyPermissiveAuditor) Name() string {
	return "Overly Permissive Authorization Policy"
}

func (a *overlyPermissiveAuditor) Audit(discovery types.Discovery, resources types.Resources) ([]types.AuditResult, error) {
	log.Infof("running auditor %s", a.Name())

	results := []types.AuditResult{}

	// Check all AuthorizationPolicies
	for _, policy := range resources.AuthorizationPolicies {
		// Skip DENY policies, we're only interested in ALLOW policies
		if policy.Spec.Action == securityv1beta.AuthorizationPolicy_DENY {
			continue
		}

		// Check if policy applies to all workloads in namespace (no selector)
		if policy.Spec.Selector == nil || len(policy.Spec.Selector.MatchLabels) == 0 {
			// Check if policy allows all operations with no conditions
			if isOverlyPermissive(policy.Spec) {
				results = append(results, types.AuditResult{
					Name:        a.Name(),
					Description: fmt.Sprintf("AuthorizationPolicy %s in namespace %s is overly permissive and grants unrestricted access to all workloads", policy.Name, policy.Namespace),
					Severity:    types.High,
					Resource:    formatResource(policy),
				})
			}
		}
	}

	return results, nil
}

// isOverlyPermissive checks if a policy allows all traffic without restrictions
func isOverlyPermissive(spec *securityv1beta.AuthorizationPolicy) bool {
	// If policy has no rules, it allows everything
	if len(spec.Rules) == 0 {
		return true
	}

	for _, rule := range spec.Rules {
		// Check if rule has no from/to/when sections which would make it match all traffic
		if (rule.From == nil || len(rule.From) == 0) &&
			(rule.To == nil || len(rule.To) == 0) &&
			(rule.When == nil || len(rule.When) == 0) {
			return true
		}

		// Check for wildcards in FROM section
		for _, from := range rule.From {
			if len(from.Source.Principals) == 1 && from.Source.Principals[0] == "*" {
				// Check if it's the only restriction
				if len(from.Source.RequestPrincipals) == 0 &&
					len(from.Source.Namespaces) == 0 &&
					len(from.Source.IpBlocks) == 0 &&
					len(from.Source.RemoteIpBlocks) == 0 &&
					len(from.Source.NotPrincipals) == 0 &&
					len(from.Source.NotRequestPrincipals) == 0 &&
					len(from.Source.NotNamespaces) == 0 &&
					len(from.Source.NotIpBlocks) == 0 &&
					len(from.Source.NotRemoteIpBlocks) == 0 {
					return true
				}
			}
		}

		// Check for wildcards in TO section
		for _, to := range rule.To {
			if len(to.Operation.Methods) == 1 && to.Operation.Methods[0] == "*" {
				if len(to.Operation.Paths) == 0 &&
					len(to.Operation.Hosts) == 0 &&
					len(to.Operation.Ports) == 0 &&
					len(to.Operation.NotMethods) == 0 &&
					len(to.Operation.NotPaths) == 0 &&
					len(to.Operation.NotHosts) == 0 &&
					len(to.Operation.NotPorts) == 0 {
					return true
				}
			}
		}
	}

	return false
}

// Helper function to format the resource for display
func formatResource(policy *clientsecurityv1beta.AuthorizationPolicy) string {
	return fmt.Sprintf("AuthorizationPolicy/%s.%s", policy.Name, policy.Namespace)
}

func init() {
	auditors.Register(&overlyPermissiveAuditor{})
}