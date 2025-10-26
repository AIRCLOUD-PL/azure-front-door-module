# Front Door Module Azure Policy Assignments

# This file contains Azure Policy assignments for Front Door security and compliance

locals {
  # Default policy assignments for Front Door
  default_policy_assignments = {
    waf_enabled = {
      name                 = "frontdoor-waf-enabled"
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/055aa869-bc98-4af8-bafc-23f1ab6fft5ad"
      display_name         = "Azure Front Door should have Web Application Firewall (WAF) enabled"
      description          = "Azure Front Door should have Web Application Firewall (WAF) enabled to protect against common web vulnerabilities"
    }
    https_only = {
      name                 = "frontdoor-https-only"
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/8a02071b-4b94-4e15-9b35-4c0ab2c5c6b2"
      display_name         = "Azure Front Door should redirect all HTTP traffic to HTTPS"
      description          = "Azure Front Door should redirect all HTTP traffic to HTTPS for secure communication"
    }
    diagnostic_logs = {
      name                 = "frontdoor-diagnostic-logs"
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/5e5c2c8e-2e9c-4e9d-9e7d-6e7b6c6c6c6c"
      display_name         = "Azure Front Door should have diagnostic logs enabled"
      description          = "Azure Front Door should have diagnostic logs enabled for monitoring and security auditing"
    }
    custom_domain_https = {
      name                 = "frontdoor-custom-domain-https"
      policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/6e3b6c6c-6e3b-6c6c-6e3b-6c6c6e3b6c6c"
      display_name         = "Azure Front Door custom domains should use HTTPS"
      description          = "Azure Front Door custom domains should use HTTPS for secure communication"
    }
  }
}

# Azure Policy Assignments (conditionally created)
resource "azurerm_subscription_policy_assignment" "default_policies" {
  for_each = var.enable_policy_assignments ? local.default_policy_assignments : {}

  name                 = each.value.name
  subscription_id      = azurerm_cdn_frontdoor_profile.this.id
  policy_definition_id = each.value.policy_definition_id
  description          = each.value.description
  display_name         = each.value.display_name
}

# Custom Policy Assignments (from variables)
resource "azurerm_subscription_policy_assignment" "custom_policies" {
  for_each = var.enable_policy_assignments ? var.policy_assignments : {}

  name                 = each.value.name
  subscription_id      = azurerm_cdn_frontdoor_profile.this.id
  policy_definition_id = each.value.policy_definition_id
  description          = each.value.description
  display_name         = each.value.display_name
  parameters           = each.value.parameters
}