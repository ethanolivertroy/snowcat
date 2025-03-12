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

package gateway

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/praetorian-inc/snowcat/auditors"
	"github.com/praetorian-inc/snowcat/pkg/types"
	networkingv1beta1 "istio.io/api/networking/v1beta1"
	clientnetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
)

type insecureTLSAuditor struct{}

func (a *insecureTLSAuditor) Name() string {
	return "Gateway TLS Configuration Issues"
}

func (a *insecureTLSAuditor) Audit(discovery types.Discovery, resources types.Resources) ([]types.AuditResult, error) {
	log.Infof("running auditor %s", a.Name())

	results := []types.AuditResult{}

	// Check all Gateway resources for TLS issues
	for _, gateway := range resources.Gateways {
		for i, server := range gateway.Spec.Servers {
			// Skip non-HTTPS servers
			if server.Port == nil || server.Port.Protocol != "HTTPS" {
				continue
			}

			// Check if TLS is configured
			if server.Tls == nil {
				results = append(results, types.AuditResult{
					Name:        a.Name(),
					Description: fmt.Sprintf("Gateway %s in namespace %s has an HTTPS server without TLS configuration", gateway.Name, gateway.Namespace),
					Severity:    types.Critical,
					Resource:    formatServerResource(gateway, i),
				})
				continue
			}

			// Check TLS mode
			if server.Tls.Mode == networkingv1beta1.ServerTLSSettings_SIMPLE {
				// Check if certificates are properly configured
				if server.Tls.CredentialName == "" && (server.Tls.ServerCertificate == "" || server.Tls.PrivateKey == "") {
					results = append(results, types.AuditResult{
						Name:        a.Name(),
						Description: fmt.Sprintf("Gateway %s in namespace %s has TLS SIMPLE mode without certificates configured", gateway.Name, gateway.Namespace),
						Severity:    types.High,
						Resource:    formatServerResource(gateway, i),
					})
				}
			}

			// Check for insecure TLS versions
			if server.Tls.MinProtocolVersion == networkingv1beta1.ServerTLSSettings_TLSV1_0 ||
				server.Tls.MinProtocolVersion == networkingv1beta1.ServerTLSSettings_TLSV1_1 {
				results = append(results, types.AuditResult{
					Name:        a.Name(),
					Description: fmt.Sprintf("Gateway %s in namespace %s uses an insecure TLS protocol version (TLSv1.0 or TLSv1.1)", gateway.Name, gateway.Namespace),
					Severity:    types.Medium,
					Resource:    formatServerResource(gateway, i),
				})
			}

			// Check for weak cipher suites if specified
			if len(server.Tls.CipherSuites) > 0 {
				for _, cipher := range server.Tls.CipherSuites {
					if isWeakCipher(cipher) {
						results = append(results, types.AuditResult{
							Name:        a.Name(),
							Description: fmt.Sprintf("Gateway %s in namespace %s uses a weak cipher suite: %s", gateway.Name, gateway.Namespace, cipher),
							Severity:    types.Medium,
							Resource:    formatServerResource(gateway, i),
						})
					}
				}
			}
		}
	}

	return results, nil
}

// Helper function to format the server resource for display
func formatServerResource(gateway *clientnetworkingv1beta1.Gateway, serverIndex int) string {
	return fmt.Sprintf("Gateway/%s.%s/servers[%d]", gateway.Name, gateway.Namespace, serverIndex)
}

// Helper function to check for weak cipher suites
func isWeakCipher(cipher string) bool {
	weakCiphers := map[string]bool{
		"TLS_RSA_WITH_AES_128_CBC_SHA":                true,
		"TLS_RSA_WITH_AES_256_CBC_SHA":                true,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":               true,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":          true,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":          true,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":        true,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":        true,
		"TLS_RSA_WITH_AES_128_CBC_SHA256":             true,
		"TLS_RSA_WITH_AES_256_CBC_SHA256":             true,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":               true,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": false, // Modern cipher (not weak)
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   false, // Modern cipher (not weak)
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       false, // Modern cipher (not weak)
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         false, // Modern cipher (not weak)
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       false, // Modern cipher (not weak)
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         false, // Modern cipher (not weak)
	}

	isWeak, exists := weakCiphers[cipher]
	return exists && isWeak
}

func init() {
	auditors.Register(&insecureTLSAuditor{})
}