# Front Door Module Outputs

output "frontdoor_profile_id" {
  description = "The ID of the Front Door profile"
  value       = azurerm_cdn_frontdoor_profile.this.id
}

output "frontdoor_profile_name" {
  description = "The name of the Front Door profile"
  value       = azurerm_cdn_frontdoor_profile.this.name
}

output "frontdoor_profile_resource_guid" {
  description = "The resource GUID of the Front Door profile"
  value       = azurerm_cdn_frontdoor_profile.this.resource_guid
}

output "frontdoor_profile_sku_name" {
  description = "The SKU name of the Front Door profile"
  value       = azurerm_cdn_frontdoor_profile.this.sku_name
}

output "resource_group_name" {
  description = "Resource group name"
  value       = var.resource_group_name
}

output "location" {
  description = "Azure region"
  value       = var.location
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "waf_policy_ids" {
  description = "IDs of the WAF policies"
  value       = { for k, v in azurerm_cdn_frontdoor_firewall_policy.this : k => v.id }
}

output "waf_policy_names" {
  description = "Names of the WAF policies"
  value       = { for k, v in azurerm_cdn_frontdoor_firewall_policy.this : k => v.name }
}

output "origin_group_ids" {
  description = "IDs of the origin groups"
  value       = { for k, v in azurerm_cdn_frontdoor_origin_group.this : k => v.id }
}

output "origin_group_names" {
  description = "Names of the origin groups"
  value       = { for k, v in azurerm_cdn_frontdoor_origin_group.this : k => v.name }
}

output "origin_ids" {
  description = "IDs of the origins"
  value       = { for k, v in azurerm_cdn_frontdoor_origin.this : k => v.id }
}

output "origin_names" {
  description = "Names of the origins"
  value       = { for k, v in azurerm_cdn_frontdoor_origin.this : k => v.name }
}

output "endpoint_ids" {
  description = "IDs of the endpoints"
  value       = { for k, v in azurerm_cdn_frontdoor_endpoint.this : k => v.id }
}

output "endpoint_names" {
  description = "Names of the endpoints"
  value       = { for k, v in azurerm_cdn_frontdoor_endpoint.this : k => v.name }
}

output "endpoint_host_names" {
  description = "Host names of the endpoints"
  value       = { for k, v in azurerm_cdn_frontdoor_endpoint.this : k => v.host_name }
}

output "custom_domain_ids" {
  description = "IDs of the custom domains"
  value       = { for k, v in azurerm_cdn_frontdoor_custom_domain.this : k => v.id }
}

output "custom_domain_names" {
  description = "Names of the custom domains"
  value       = { for k, v in azurerm_cdn_frontdoor_custom_domain.this : k => v.name }
}

output "custom_domain_host_names" {
  description = "Host names of the custom domains"
  value       = { for k, v in azurerm_cdn_frontdoor_custom_domain.this : k => v.host_name }
}

output "secret_ids" {
  description = "IDs of the secrets"
  value       = { for k, v in azurerm_cdn_frontdoor_secret.this : k => v.id }
}

output "secret_names" {
  description = "Names of the secrets"
  value       = { for k, v in azurerm_cdn_frontdoor_secret.this : k => v.name }
}

output "route_ids" {
  description = "IDs of the routes"
  value       = { for k, v in azurerm_cdn_frontdoor_route.this : k => v.id }
}

output "route_names" {
  description = "Names of the routes"
  value       = { for k, v in azurerm_cdn_frontdoor_route.this : k => v.name }
}

output "rule_set_ids" {
  description = "IDs of the rule sets"
  value       = { for k, v in azurerm_cdn_frontdoor_rule_set.this : k => v.id }
}

output "rule_set_names" {
  description = "Names of the rule sets"
  value       = { for k, v in azurerm_cdn_frontdoor_rule_set.this : k => v.name }
}

output "rule_ids" {
  description = "IDs of the rules"
  value       = { for k, v in azurerm_cdn_frontdoor_rule.this : k => v.id }
}

output "rule_names" {
  description = "Names of the rules"
  value       = { for k, v in azurerm_cdn_frontdoor_rule.this : k => v.name }
}

output "policy_assignment_ids" {
  description = "IDs of the policy assignments"
  value       = { for k, v in azurerm_subscription_policy_assignment.this : k => v.id }
}

output "policy_assignment_names" {
  description = "Names of the policy assignments"
  value       = { for k, v in azurerm_subscription_policy_assignment.this : k => v.name }
}

output "diagnostic_setting_id" {
  description = "ID of the diagnostic setting"
  value       = var.diagnostic_settings != null ? azurerm_monitor_diagnostic_setting.this["default"].id : null
}

output "diagnostic_setting_name" {
  description = "Name of the diagnostic setting"
  value       = var.diagnostic_settings != null ? azurerm_monitor_diagnostic_setting.this["default"].name : null
}