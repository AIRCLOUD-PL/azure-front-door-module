package test

import (
	"testing"
	"fmt"
	"strings"

	"github.com/gruntwork-io/terratest/modules/azure"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrontDoorModule(t *testing.T) {
	t.Parallel()

	// Generate unique names for resources
	uniqueId := random.UniqueId()
	resourceGroupName := fmt.Sprintf("rg-fd-test-%s", uniqueId)
	frontDoorName := fmt.Sprintf("fd-test-%s", uniqueId)
	location := "East US"

	// Configure Terraform options
	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resource_group_name": resourceGroupName,
			"location":           location,
			"environment":       "test",
			"frontdoor_profile_name": frontDoorName,
			"sku_name":          "Standard_AzureFrontDoor",
			"endpoints": map[string]interface{}{
				"endpoint1": map[string]interface{}{
					"name":    "endpoint1",
					"enabled": true,
				},
			},
			"origin_groups": map[string]interface{}{
				"origin-group1": map[string]interface{}{
					"name": "origin-group1",
					"health_probe": map[string]interface{}{
						"interval_in_seconds": 100,
						"path":                "/",
						"protocol":            "Https",
						"request_type":        "HEAD",
					},
					"load_balancing": map[string]interface{}{
						"additional_latency_in_milliseconds": 50,
						"sample_size":                        4,
						"successful_samples_required":        3,
					},
				},
			},
			"origins": map[string]interface{}{
				"origin1": map[string]interface{}{
					"name":              "origin1",
					"origin_group_name": "origin-group1",
					"enabled":           true,
					"host_name":         "example.com",
					"http_port":         80,
					"https_port":        443,
				},
			},
			"routes": map[string]interface{}{
				"route1": map[string]interface{}{
					"name":              "route1",
					"endpoint_name":     "endpoint1",
					"origin_group_name": "origin-group1",
					"origin_names":      []string{"origin1"},
					"enabled":           true,
					"patterns_to_match": []string{"/*"},
					"supported_protocols": []string{"Https"},
				},
			},
			"tags": map[string]string{
				"Environment": "test",
				"Module":      "front-door",
			},
		},
	}

	// Clean up resources after test
	defer terraform.Destroy(t, terraformOptions)

	// Deploy resources
	terraform.InitAndApply(t, terraformOptions)

	// Validate Front Door
	validateFrontDoor(t, terraformOptions, frontDoorName, resourceGroupName)

	// Validate outputs
	validateOutputs(t, terraformOptions)
}

func TestFrontDoorWithWAF(t *testing.T) {
	t.Parallel()

	uniqueId := random.UniqueId()
	resourceGroupName := fmt.Sprintf("rg-fd-waf-test-%s", uniqueId)
	frontDoorName := fmt.Sprintf("fd-waf-test-%s", uniqueId)
	location := "East US"

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resource_group_name": resourceGroupName,
			"location":           location,
			"environment":       "test",
			"frontdoor_profile_name": frontDoorName,
			"sku_name":          "Premium_AzureFrontDoor",
			"waf_policies": map[string]interface{}{
				"waf-policy1": map[string]interface{}{
					"name":    "waf-policy1",
					"enabled": true,
					"mode":    "Prevention",
					"managed_rules": []map[string]interface{}{
						{
							"type":    "DefaultRuleSet",
							"version": "1.0",
							"action":  "Block",
						},
					},
				},
			},
			"endpoints": map[string]interface{}{
				"endpoint1": map[string]interface{}{
					"name":    "endpoint1",
					"enabled": true,
				},
			},
			"origin_groups": map[string]interface{}{
				"origin-group1": map[string]interface{}{
					"name": "origin-group1",
				},
			},
			"origins": map[string]interface{}{
				"origin1": map[string]interface{}{
					"name":              "origin1",
					"origin_group_name": "origin-group1",
					"enabled":           true,
					"host_name":         "example.com",
				},
			},
			"routes": map[string]interface{}{
				"route1": map[string]interface{}{
					"name":              "route1",
					"endpoint_name":     "endpoint1",
					"origin_group_name": "origin-group1",
					"origin_names":      []string{"origin1"},
					"enabled":           true,
					"waf_policy_name":   "waf-policy1",
				},
			},
			"tags": map[string]string{
				"Environment": "test",
				"Module":      "front-door-waf",
			},
		},
	}

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	validateFrontDoorWithWAF(t, terraformOptions, frontDoorName, resourceGroupName)
}

func TestFrontDoorWithCustomDomain(t *testing.T) {
	t.Parallel()

	uniqueId := random.UniqueId()
	resourceGroupName := fmt.Sprintf("rg-fd-custom-test-%s", uniqueId)
	frontDoorName := fmt.Sprintf("fd-custom-test-%s", uniqueId)
	location := "East US"

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resource_group_name": resourceGroupName,
			"location":           location,
			"environment":       "test",
			"frontdoor_profile_name": frontDoorName,
			"sku_name":          "Standard_AzureFrontDoor",
			"custom_domains": map[string]interface{}{
				"custom-domain1": map[string]interface{}{
					"name":      "custom-domain1",
					"host_name": "api.example.com",
					"tls": map[string]interface{}{
						"certificate_type":    "ManagedCertificate",
						"minimum_tls_version": "TLS12",
					},
				},
			},
			"endpoints": map[string]interface{}{
				"endpoint1": map[string]interface{}{
					"name":    "endpoint1",
					"enabled": true,
				},
			},
			"origin_groups": map[string]interface{}{
				"origin-group1": map[string]interface{}{
					"name": "origin-group1",
				},
			},
			"origins": map[string]interface{}{
				"origin1": map[string]interface{}{
					"name":              "origin1",
					"origin_group_name": "origin-group1",
					"enabled":           true,
					"host_name":         "backend.example.com",
				},
			},
			"routes": map[string]interface{}{
				"route1": map[string]interface{}{
					"name":                "route1",
					"endpoint_name":       "endpoint1",
					"origin_group_name":   "origin-group1",
					"origin_names":        []string{"origin1"},
					"enabled":             true,
					"custom_domain_names": []string{"custom-domain1"},
				},
			},
			"tags": map[string]string{
				"Environment": "test",
				"Module":      "front-door-custom-domain",
			},
		},
	}

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	validateFrontDoorWithCustomDomain(t, terraformOptions, frontDoorName, resourceGroupName)
}

func TestFrontDoorWithRules(t *testing.T) {
	t.Parallel()

	uniqueId := random.UniqueId()
	resourceGroupName := fmt.Sprintf("rg-fd-rules-test-%s", uniqueId)
	frontDoorName := fmt.Sprintf("fd-rules-test-%s", uniqueId)
	location := "East US"

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"resource_group_name": resourceGroupName,
			"location":           location,
			"environment":       "test",
			"frontdoor_profile_name": frontDoorName,
			"sku_name":          "Premium_AzureFrontDoor",
			"rule_sets": map[string]interface{}{
				"rule-set1": map[string]interface{}{
					"name": "rule-set1",
				},
			},
			"rules": map[string]interface{}{
				"security-rule1": map[string]interface{}{
					"name":          "security-rule1",
					"rule_set_name": "rule-set1",
					"order":         1,
					"actions": map[string]interface{}{
						"request_header_actions": []map[string]interface{}{
							{
								"header_action": "Overwrite",
								"header_name":   "X-Forwarded-Host",
								"value":         "example.com",
							},
						},
						"response_header_actions": []map[string]interface{}{
							{
								"header_action": "Append",
								"header_name":   "X-Security-Header",
								"value":         "enabled",
							},
						},
					},
					"conditions": map[string]interface{}{
						"request_uri": []map[string]interface{}{
							{
								"operator":     "Contains",
								"match_values": []string{"/api/"},
							},
						},
					},
				},
			},
			"endpoints": map[string]interface{}{
				"endpoint1": map[string]interface{}{
					"name":    "endpoint1",
					"enabled": true,
				},
			},
			"origin_groups": map[string]interface{}{
				"origin-group1": map[string]interface{}{
					"name": "origin-group1",
				},
			},
			"origins": map[string]interface{}{
				"origin1": map[string]interface{}{
					"name":              "origin1",
					"origin_group_name": "origin-group1",
					"enabled":           true,
					"host_name":         "example.com",
				},
			},
			"routes": map[string]interface{}{
				"route1": map[string]interface{}{
					"name":            "route1",
					"endpoint_name":   "endpoint1",
					"origin_group_name": "origin-group1",
					"origin_names":    []string{"origin1"},
					"enabled":         true,
					"rule_set_names":  []string{"rule-set1"},
				},
			},
			"tags": map[string]string{
				"Environment": "test",
				"Module":      "front-door-rules",
			},
		},
	}

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	validateFrontDoorWithRules(t, terraformOptions, frontDoorName, resourceGroupName)
}

func validateFrontDoor(t *testing.T, terraformOptions *terraform.Options, frontDoorName, resourceGroupName string) {
	// Get Front Door profile details
	frontDoor := azure.GetFrontDoor(t, frontDoorName, resourceGroupName, "")

	// Validate basic properties
	assert.Equal(t, frontDoorName, frontDoor.Name)
	assert.Equal(t, "Standard_AzureFrontDoor", frontDoor.SKU.Name)
	assert.True(t, frontDoor.EnabledState == "Enabled")
}

func validateFrontDoorWithWAF(t *testing.T, terraformOptions *terraform.Options, frontDoorName, resourceGroupName string) {
	frontDoor := azure.GetFrontDoor(t, frontDoorName, resourceGroupName, "")

	assert.Equal(t, frontDoorName, frontDoor.Name)
	assert.Equal(t, "Premium_AzureFrontDoor", frontDoor.SKU.Name)
	// Note: WAF validation would require additional Azure SDK calls
}

func validateFrontDoorWithCustomDomain(t *testing.T, terraformOptions *terraform.Options, frontDoorName, resourceGroupName string) {
	frontDoor := azure.GetFrontDoor(t, frontDoorName, resourceGroupName, "")

	assert.Equal(t, frontDoorName, frontDoor.Name)
	assert.NotEmpty(t, frontDoor.CustomDomains)
}

func validateFrontDoorWithRules(t *testing.T, terraformOptions *terraform.Options, frontDoorName, resourceGroupName string) {
	frontDoor := azure.GetFrontDoor(t, frontDoorName, resourceGroupName, "")

	assert.Equal(t, frontDoorName, frontDoor.Name)
	assert.NotEmpty(t, frontDoor.Rules)
}

func validateOutputs(t *testing.T, terraformOptions *terraform.Options) {
	// Validate required outputs
	frontDoorId := terraform.Output(t, terraformOptions, "frontdoor_profile_id")
	assert.NotEmpty(t, frontDoorId)
	assert.Contains(t, frontDoorId, "Microsoft.Cdn/profiles")

	frontDoorName := terraform.Output(t, terraformOptions, "frontdoor_profile_name")
	assert.NotEmpty(t, frontDoorName)

	resourceGroupName := terraform.Output(t, terraformOptions, "resource_group_name")
	assert.NotEmpty(t, resourceGroupName)

	location := terraform.Output(t, terraformOptions, "location")
	assert.NotEmpty(t, location)

	endpointIds := terraform.Output(t, terraformOptions, "endpoint_ids")
	assert.NotEmpty(t, endpointIds)

	routeIds := terraform.Output(t, terraformOptions, "route_ids")
	assert.NotEmpty(t, routeIds)
}