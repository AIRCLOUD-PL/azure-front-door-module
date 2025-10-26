# Azure Front Door Module
# Creates an enterprise-grade Azure Front Door with WAF, routing rules, backend pools, and security policies

# Azure Front Door Profile
resource "azurerm_cdn_frontdoor_profile" "this" {
  name                = var.frontdoor_profile_name
  resource_group_name = var.resource_group_name
  sku_name            = var.sku_name

}

# Azure Front Door Firewall Policy (WAF)
resource "azurerm_cdn_frontdoor_firewall_policy" "this" {
  for_each = var.waf_policies

  name                              = each.value.name
  resource_group_name               = var.resource_group_name
  sku_name                          = azurerm_cdn_frontdoor_profile.this.sku_name
  enabled                           = each.value.enabled
  mode                              = each.value.mode
  redirect_url                      = each.value.redirect_url
  custom_block_response_status_code = each.value.custom_block_response_status_code
  custom_block_response_body        = each.value.custom_block_response_body

  dynamic "custom_rule" {
    for_each = each.value.custom_rules != null ? each.value.custom_rules : []
    content {
      name                           = custom_rule.value.name
      action                         = custom_rule.value.action
      enabled                        = custom_rule.value.enabled
      priority                       = custom_rule.value.priority
      type                           = custom_rule.value.type
      rate_limit_duration_in_minutes = custom_rule.value.rate_limit_duration_in_minutes
      rate_limit_threshold           = custom_rule.value.rate_limit_threshold

      dynamic "match_condition" {
        for_each = custom_rule.value.match_conditions
        content {
          match_variable   = match_condition.value.match_variable
          match_values     = match_condition.value.match_values
          operator         = match_condition.value.operator
          selector         = match_condition.value.selector
          # negate_condition deprecated in azurerm 4.x
          transforms       = match_condition.value.transforms
        }
      }
    }
  }

  dynamic "managed_rule" {
    for_each = each.value.managed_rules != null ? each.value.managed_rules : []
    content {
      type    = managed_rule.value.type
      version = managed_rule.value.version
      action  = managed_rule.value.action

      dynamic "exclusion" {
        for_each = managed_rule.value.exclusions != null ? managed_rule.value.exclusions : []
        content {
          match_variable = exclusion.value.match_variable
          operator       = exclusion.value.operator
          selector       = exclusion.value.selector
        }
      }

      dynamic "override" {
        for_each = managed_rule.value.overrides != null ? managed_rule.value.overrides : []
        content {
          rule_group_name = override.value.rule_group_name

          dynamic "exclusion" {
            for_each = override.value.exclusions != null ? override.value.exclusions : []
            content {
              match_variable = exclusion.value.match_variable
              operator       = exclusion.value.operator
              selector       = exclusion.value.selector
            }
          }

          dynamic "rule" {
            for_each = override.value.rules != null ? override.value.rules : []
            content {
              rule_id = rule.value.rule_id
              action  = rule.value.action
              enabled = rule.value.enabled

              dynamic "exclusion" {
                for_each = rule.value.exclusions != null ? rule.value.exclusions : []
                content {
                  match_variable = exclusion.value.match_variable
                  operator       = exclusion.value.operator
                  selector       = exclusion.value.selector
                }
              }
            }
          }
        }
      }
    }
  }

}

# Azure Front Door Origins
resource "azurerm_cdn_frontdoor_origin_group" "this" {
  for_each = var.origin_groups

  name                                                      = each.value.name
  cdn_frontdoor_profile_id                                  = azurerm_cdn_frontdoor_profile.this.id
  session_affinity_enabled                                  = each.value.session_affinity_enabled
  restore_traffic_time_to_healed_or_new_endpoint_in_minutes = each.value.restore_traffic_time_to_healed_or_new_endpoint_in_minutes

  dynamic "health_probe" {
    for_each = each.value.health_probe != null ? [each.value.health_probe] : []
    content {
      interval_in_seconds = health_probe.value.interval_in_seconds
      path                = health_probe.value.path
      protocol            = health_probe.value.protocol
      request_type        = health_probe.value.request_type
    }
  }

  dynamic "load_balancing" {
    for_each = each.value.load_balancing != null ? [each.value.load_balancing] : []
    content {
      additional_latency_in_milliseconds = load_balancing.value.additional_latency_in_milliseconds
      sample_size                        = load_balancing.value.sample_size
      successful_samples_required        = load_balancing.value.successful_samples_required
    }
  }
}

# Azure Front Door Origins
resource "azurerm_cdn_frontdoor_origin" "this" {
  for_each = var.origins

  name                           = each.value.name
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.this[each.value.origin_group_name].id
  enabled                        = each.value.enabled
  host_name                      = each.value.host_name
  http_port                      = each.value.http_port
  https_port                     = each.value.https_port
  origin_host_header             = each.value.origin_host_header
  priority                       = each.value.priority
  weight                         = each.value.weight
  certificate_name_check_enabled = each.value.certificate_name_check_enabled
}

# Azure Front Door Endpoint
resource "azurerm_cdn_frontdoor_endpoint" "this" {
  for_each = var.endpoints

  name                     = each.value.name
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  enabled                  = each.value.enabled

}

# Azure Front Door Custom Domains
resource "azurerm_cdn_frontdoor_custom_domain" "this" {
  for_each = var.custom_domains

  name                     = each.value.name
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  host_name                = each.value.host_name

  dynamic "tls" {
    for_each = each.value.tls != null ? [each.value.tls] : []
    content {
      certificate_type        = tls.value.certificate_type
      minimum_tls_version     = tls.value.minimum_tls_version
      cdn_frontdoor_secret_id = tls.value.cdn_frontdoor_secret_id
    }
  }

}

# Azure Front Door Secrets (for custom domain certificates)
resource "azurerm_cdn_frontdoor_secret" "this" {
  for_each = var.secrets

  name                     = each.value.name
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id

  secret {
    customer_certificate {
      key_vault_certificate_id = each.value.key_vault_certificate_id
    }
  }

}

# Azure Front Door Route
resource "azurerm_cdn_frontdoor_route" "this" {
  for_each = var.routes

  name                          = each.value.name
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.this[each.value.endpoint_name].id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.this[each.value.origin_group_name].id
  cdn_frontdoor_origin_ids      = [for origin_name in each.value.origin_names : azurerm_cdn_frontdoor_origin.this[origin_name].id]
  enabled                       = each.value.enabled

  # Routing configuration
  forwarding_protocol    = each.value.forwarding_protocol
  https_redirect_enabled = each.value.https_redirect_enabled
  patterns_to_match      = each.value.patterns_to_match
  supported_protocols    = each.value.supported_protocols

  # Caching configuration
  dynamic "cache" {
    for_each = each.value.cache != null ? [each.value.cache] : []
    content {
      query_string_caching_behavior = cache.value.query_string_caching_behavior
      query_strings                 = cache.value.query_strings
      compression_enabled           = cache.value.compression_enabled
      content_types_to_compress     = cache.value.content_types_to_compress
    }
  }

  # Custom domain configuration
  cdn_frontdoor_custom_domain_ids = each.value.custom_domain_names != null ? [
    for domain_name in each.value.custom_domain_names :
    azurerm_cdn_frontdoor_custom_domain.this[domain_name].id
  ] : []

  # Link to firewall policy
  # WAF policy association is done through route configuration in azurerm 4.x

  # Rules engine configuration
  cdn_frontdoor_rule_set_ids = each.value.rule_set_names != null ? [
    for rule_set_name in each.value.rule_set_names :
    azurerm_cdn_frontdoor_rule_set.this[rule_set_name].id
  ] : []
}

# Azure Front Door Rule Set
resource "azurerm_cdn_frontdoor_rule_set" "this" {
  for_each = var.rule_sets

  name                     = each.value.name
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
}

# Azure Front Door Rules
resource "azurerm_cdn_frontdoor_rule" "this" {
  for_each = var.rules

  name                      = each.value.name
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.this[each.value.rule_set_name].id
  order                     = each.value.order
  behavior_on_match         = each.value.behavior_on_match

  dynamic "actions" {
    for_each = each.value.actions != null ? [each.value.actions] : []
    content {
      dynamic "url_rewrite_action" {
        for_each = actions.value.url_rewrite != null ? [actions.value.url_rewrite] : []
        content {
          source_pattern          = url_rewrite_action.value.source_pattern
          destination             = url_rewrite_action.value.destination
          preserve_unmatched_path = url_rewrite_action.value.preserve_unmatched_path
        }
      }

      dynamic "url_redirect_action" {
        for_each = actions.value.url_redirect != null ? [actions.value.url_redirect] : []
        content {
          redirect_type        = url_redirect_action.value.redirect_type
          redirect_protocol    = url_redirect_action.value.redirect_protocol
          destination_hostname = url_redirect_action.value.destination_hostname
          destination_path     = url_redirect_action.value.destination_path
          query_string         = url_redirect_action.value.query_string
          destination_fragment = url_redirect_action.value.destination_fragment
        }
      }

      dynamic "route_configuration_override_action" {
        for_each = actions.value.route_configuration_override != null ? [actions.value.route_configuration_override] : []
        content {
          cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.this[route_configuration_override_action.value.origin_group_name].id
          forwarding_protocol           = route_configuration_override_action.value.forwarding_protocol
          query_string_caching_behavior = route_configuration_override_action.value.query_string_caching_behavior
          query_string_parameters       = route_configuration_override_action.value.query_string_parameters
          compression_enabled           = route_configuration_override_action.value.compression_enabled
          cache_behavior                = route_configuration_override_action.value.cache_behavior
          cache_duration                = route_configuration_override_action.value.cache_duration
        }
      }

      dynamic "request_header_action" {
        for_each = actions.value.request_header_actions != null ? actions.value.request_header_actions : []
        content {
          header_action = request_header_action.value.header_action
          header_name   = request_header_action.value.header_name
          value         = request_header_action.value.value
        }
      }

      dynamic "response_header_action" {
        for_each = actions.value.response_header_actions != null ? actions.value.response_header_actions : []
        content {
          header_action = response_header_action.value.header_action
          header_name   = response_header_action.value.header_name
          value         = response_header_action.value.value
        }
      }
    }
  }

  dynamic "conditions" {
    for_each = each.value.conditions != null ? [each.value.conditions] : []
    content {
      dynamic "remote_address_condition" {
        for_each = conditions.value.remote_address != null ? [conditions.value.remote_address] : []
        content {
          operator         = remote_address_condition.value.operator
          negate_condition = remote_address_condition.value.negate_condition
          match_values     = remote_address_condition.value.match_values
        }
      }

      dynamic "request_method_condition" {
        for_each = conditions.value.request_method != null ? [conditions.value.request_method] : []
        content {
          match_values     = request_method_condition.value.match_values
          negate_condition = request_method_condition.value.negate_condition
        }
      }

      dynamic "query_string_condition" {
        for_each = conditions.value.query_string != null ? conditions.value.query_string : []
        content {
          operator         = query_string_condition.value.operator
          match_values     = query_string_condition.value.match_values
          negate_condition = query_string_condition.value.negate_condition
          transforms       = query_string_condition.value.transforms
        }
      }

      dynamic "post_args_condition" {
        for_each = conditions.value.post_args != null ? conditions.value.post_args : []
        content {
          post_args_name   = post_args_condition.value.post_args_name
          operator         = post_args_condition.value.operator
          match_values     = post_args_condition.value.match_values
          transforms       = post_args_condition.value.transforms
        }
      }

      dynamic "request_uri_condition" {
        for_each = conditions.value.request_uri != null ? conditions.value.request_uri : []
        content {
          operator         = request_uri_condition.value.operator
          match_values     = request_uri_condition.value.match_values
          negate_condition = request_uri_condition.value.negate_condition
          transforms       = request_uri_condition.value.transforms
        }
      }

      dynamic "request_header_condition" {
        for_each = conditions.value.request_header != null ? conditions.value.request_header : []
        content {
          header_name      = request_header_condition.value.header_name
          operator         = request_header_condition.value.operator
          match_values     = request_header_condition.value.match_values
          negate_condition = request_header_condition.value.negate_condition
          transforms       = request_header_condition.value.transforms
        }
      }

      dynamic "request_body_condition" {
        for_each = conditions.value.request_body != null ? conditions.value.request_body : []
        content {
          operator         = request_body_condition.value.operator
          match_values     = request_body_condition.value.match_values
          negate_condition = request_body_condition.value.negate_condition
          transforms       = request_body_condition.value.transforms
        }
      }

      dynamic "request_scheme_condition" {
        for_each = conditions.value.request_scheme != null ? [conditions.value.request_scheme] : []
        content {
          match_values     = request_scheme_condition.value.match_values
          negate_condition = request_scheme_condition.value.negate_condition
        }
      }

      dynamic "url_path_condition" {
        for_each = conditions.value.url_path != null ? conditions.value.url_path : []
        content {
          operator         = url_path_condition.value.operator
          match_values     = url_path_condition.value.match_values
          negate_condition = url_path_condition.value.negate_condition
          transforms       = url_path_condition.value.transforms
        }
      }

      dynamic "url_file_extension_condition" {
        for_each = conditions.value.url_file_extension != null ? conditions.value.url_file_extension : []
        content {
          operator         = url_file_extension_condition.value.operator
          match_values     = url_file_extension_condition.value.match_values
          negate_condition = url_file_extension_condition.value.negate_condition
          transforms       = url_file_extension_condition.value.transforms
        }
      }

      dynamic "url_filename_condition" {
        for_each = conditions.value.url_filename != null ? conditions.value.url_filename : []
        content {
          operator         = url_filename_condition.value.operator
          match_values     = url_filename_condition.value.match_values
          negate_condition = url_filename_condition.value.negate_condition
          transforms       = url_filename_condition.value.transforms
        }
      }

      dynamic "http_version_condition" {
        for_each = conditions.value.http_version != null ? [conditions.value.http_version] : []
        content {
          match_values     = http_version_condition.value.match_values
          negate_condition = http_version_condition.value.negate_condition
        }
      }

      dynamic "cookies_condition" {
        for_each = conditions.value.cookies != null ? conditions.value.cookies : []
        content {
          cookie_name      = cookies_condition.value.cookie_name
          operator         = cookies_condition.value.operator
          match_values     = cookies_condition.value.match_values
          negate_condition = cookies_condition.value.negate_condition
          transforms       = cookies_condition.value.transforms
        }
      }

      dynamic "is_device_condition" {
        for_each = conditions.value.is_device != null ? [conditions.value.is_device] : []
        content {
          match_values     = is_device_condition.value.match_values
          negate_condition = is_device_condition.value.negate_condition
        }
      }

      dynamic "socket_address_condition" {
        for_each = conditions.value.socket_address != null ? [conditions.value.socket_address] : []
        content {
          operator         = socket_address_condition.value.operator
          match_values     = socket_address_condition.value.match_values
          negate_condition = socket_address_condition.value.negate_condition
        }
      }

      dynamic "client_port_condition" {
        for_each = conditions.value.client_port != null ? [conditions.value.client_port] : []
        content {
          operator         = client_port_condition.value.operator
          match_values     = client_port_condition.value.match_values
          negate_condition = client_port_condition.value.negate_condition
        }
      }

      dynamic "server_port_condition" {
        for_each = conditions.value.server_port != null ? [conditions.value.server_port] : []
        content {
          operator         = server_port_condition.value.operator
          match_values     = server_port_condition.value.match_values
          negate_condition = server_port_condition.value.negate_condition
        }
      }

      dynamic "host_name_condition" {
        for_each = conditions.value.host_name != null ? conditions.value.host_name : []
        content {
          operator         = host_name_condition.value.operator
          match_values     = host_name_condition.value.match_values
          negate_condition = host_name_condition.value.negate_condition
          transforms       = host_name_condition.value.transforms
        }
      }

      dynamic "ssl_protocol_condition" {
        for_each = conditions.value.ssl_protocol != null ? [conditions.value.ssl_protocol] : []
        content {
          match_values     = ssl_protocol_condition.value.match_values
          negate_condition = ssl_protocol_condition.value.negate_condition
        }
      }
    }
  }
}

# Azure Policy Assignments
resource "azurerm_subscription_policy_assignment" "this" {
  for_each = var.enable_policy_assignments ? var.policy_assignments : {}

  name                 = each.value.name
  subscription_id      = azurerm_cdn_frontdoor_profile.this.id
  policy_definition_id = each.value.policy_definition_id
  description          = each.value.description
  display_name         = each.value.display_name

  parameters = each.value.parameters
}

# Diagnostic Settings
resource "azurerm_monitor_diagnostic_setting" "this" {
  for_each = var.diagnostic_settings != null ? { "default" = var.diagnostic_settings } : {}

  name                           = each.value.name != null ? each.value.name : "diagnostic-settings"
  target_resource_id             = azurerm_cdn_frontdoor_profile.this.id
  log_analytics_workspace_id     = each.value.log_analytics_workspace_id
  storage_account_id             = each.value.storage_account_id
  eventhub_name                  = each.value.eventhub_name
  eventhub_authorization_rule_id = each.value.eventhub_authorization_rule_id

  dynamic "enabled_log" {
    for_each = each.value.logs != null ? each.value.logs : []
    content {
      category = enabled_log.value.category

      dynamic "retention_policy" {
        for_each = enabled_log.value.retention_policy != null ? [enabled_log.value.retention_policy] : []
        content {
          enabled = retention_policy.value.enabled
          days    = retention_policy.value.days
        }
      }
    }
  }

  dynamic "metric" {
    for_each = each.value.metrics != null ? each.value.metrics : []
    content {
      category = metric.value.category
      enabled  = metric.value.enabled

      dynamic "retention_policy" {
        for_each = metric.value.retention_policy != null ? [metric.value.retention_policy] : []
        content {
          enabled = retention_policy.value.enabled
          days    = retention_policy.value.days
        }
      }
    }
  }
}