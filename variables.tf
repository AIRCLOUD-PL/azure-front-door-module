# Front Door Module Variables

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, test, prod)"
  type        = string
}

variable "frontdoor_profile_name" {
  description = "Name of the Front Door profile"
  type        = string
}

variable "sku_name" {
  description = "SKU name for the Front Door profile"
  type        = string
  default     = "Standard_AzureFrontDoor"
  validation {
    condition = contains([
      "Standard_AzureFrontDoor",
      "Premium_AzureFrontDoor"
    ], var.sku_name)
    error_message = "SKU name must be either 'Standard_AzureFrontDoor' or 'Premium_AzureFrontDoor'."
  }
}

# WAF Policy Variables
variable "waf_policies" {
  description = "WAF policies configuration"
  type = map(object({
    name                              = string
    enabled                           = optional(bool, true)
    mode                              = optional(string, "Prevention")
    redirect_url                      = optional(string)
    custom_block_response_status_code = optional(number)
    custom_block_response_body        = optional(string)
    custom_rules = optional(list(object({
      name                           = string
      action                         = string
      enabled                        = optional(bool, true)
      priority                       = number
      type                           = string
      rate_limit_duration_in_minutes = optional(number)
      rate_limit_threshold           = optional(number)
      match_conditions = list(object({
        match_variable   = string
        match_values     = list(string)
        operator         = string
        selector         = optional(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      }))
    })), [])
    managed_rules = optional(list(object({
      type    = string
      version = string
      action  = optional(string, "Block")
      exclusions = optional(list(object({
        match_variable = string
        operator       = string
        selector       = string
      })), [])
      overrides = optional(list(object({
        rule_group_name = string
        exclusions = optional(list(object({
          match_variable = string
          operator       = string
          selector       = string
        })), [])
        rules = optional(list(object({
          rule_id = string
          action  = string
          enabled = optional(bool, true)
          exclusions = optional(list(object({
            match_variable = string
            operator       = string
            selector       = string
          })), [])
        })), [])
      })), [])
    })), [])
  }))
  default = {}
}

# Origin Group Variables
variable "origin_groups" {
  description = "Origin groups configuration"
  type = map(object({
    name                                                      = string
    session_affinity_enabled                                  = optional(bool, false)
    restore_traffic_time_to_healed_or_new_endpoint_in_minutes = optional(number, 10)
    health_probe = optional(object({
      interval_in_seconds = optional(number, 100)
      path                = optional(string, "/")
      protocol            = optional(string, "Https")
      request_type        = optional(string, "HEAD")
    }))
    load_balancing = optional(object({
      additional_latency_in_milliseconds = optional(number, 50)
      sample_size                        = optional(number, 4)
      successful_samples_required        = optional(number, 3)
    }))
  }))
  default = {}
}

# Origin Variables
variable "origins" {
  description = "Origins configuration"
  type = map(object({
    name                           = string
    origin_group_name              = string
    enabled                        = optional(bool, true)
    host_name                      = string
    http_port                      = optional(number, 80)
    https_port                     = optional(number, 443)
    origin_host_header             = optional(string)
    priority                       = optional(number, 1)
    weight                         = optional(number, 1000)
    certificate_name_check_enabled = optional(bool, true)
  }))
  default = {}
}

# Endpoint Variables
variable "endpoints" {
  description = "Endpoints configuration"
  type = map(object({
    name    = string
    enabled = optional(bool, true)
  }))
  default = {}
}

# Custom Domain Variables
variable "custom_domains" {
  description = "Custom domains configuration"
  type = map(object({
    name      = string
    host_name = string
    tls = optional(object({
      certificate_type        = optional(string, "ManagedCertificate")
      minimum_tls_version     = optional(string, "TLS12")
      cdn_frontdoor_secret_id = optional(string)
    }))
  }))
  default = {}
}

# Secret Variables
variable "secrets" {
  description = "Secrets configuration for custom domain certificates"
  type = map(object({
    name                     = string
    key_vault_certificate_id = string
  }))
  default = {}
}

# Route Variables
variable "routes" {
  description = "Routes configuration"
  type = map(object({
    name                   = string
    endpoint_name          = string
    origin_group_name      = string
    origin_names           = list(string)
    enabled                = optional(bool, true)
    forwarding_protocol    = optional(string, "HttpsOnly")
    https_redirect_enabled = optional(bool, true)
    patterns_to_match      = optional(list(string), ["/*"])
    supported_protocols    = optional(list(string), ["Https"])
    cache = optional(object({
      query_string_caching_behavior = optional(string, "IgnoreQueryString")
      query_strings                 = optional(list(string), [])
      compression_enabled           = optional(bool, true)
      content_types_to_compress     = optional(list(string), ["text/plain", "text/html", "text/css", "text/xml", "application/json", "application/javascript", "application/xml", "application/xml+rss", "image/svg+xml"])
    }))
    custom_domain_names = optional(list(string), [])
    waf_policy_name     = optional(string)
    rule_set_names      = optional(list(string), [])
  }))
  default = {}
}

# Rule Set Variables
variable "rule_sets" {
  description = "Rule sets configuration"
  type = map(object({
    name = string
  }))
  default = {}
}

# Rule Variables
variable "rules" {
  description = "Rules configuration"
  type = map(object({
    name              = string
    rule_set_name     = string
    order             = number
    behavior_on_match = optional(string, "Continue")
    actions = optional(object({
      url_rewrite = optional(object({
        source_pattern          = string
        destination             = string
        preserve_unmatched_path = optional(bool, false)
      }))
      url_redirect = optional(object({
        redirect_type        = string
        redirect_protocol    = optional(string)
        destination_hostname = optional(string)
        destination_path     = optional(string)
        query_string         = optional(string)
        destination_fragment = optional(string)
      }))
      route_configuration_override = optional(object({
        origin_group_name             = string
        forwarding_protocol           = optional(string)
        query_string_caching_behavior = optional(string)
        query_string_parameters       = optional(list(string))
        compression_enabled           = optional(bool)
        cache_behavior                = optional(string)
        cache_duration                = optional(string)
      }))
      request_header_actions = optional(list(object({
        header_action = string
        header_name   = string
        value         = optional(string)
      })), [])
      response_header_actions = optional(list(object({
        header_action = string
        header_name   = string
        value         = optional(string)
      })), [])
    }))
    conditions = optional(object({
      remote_address = optional(object({
        operator         = optional(string, "Any")
        negate_condition = optional(bool, false)
        match_values     = optional(list(string), [])
      }))
      request_method = optional(object({
        match_values     = list(string)
        negate_condition = optional(bool, false)
      }))
      query_string = optional(list(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      })), [])
      post_args = optional(list(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
        selector         = string
      })), [])
      request_uri = optional(list(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      })), [])
      request_header = optional(list(object({
        header_name      = string
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      })), [])
      request_body = optional(list(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      })), [])
      request_scheme = optional(object({
        match_values     = list(string)
        negate_condition = optional(bool, false)
      }))
      url_path = optional(list(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      })), [])
      url_file_extension = optional(list(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      })), [])
      url_filename = optional(list(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      })), [])
      http_version = optional(object({
        match_values     = list(string)
        negate_condition = optional(bool, false)
      }))
      cookies = optional(list(object({
        cookie_name      = string
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      })), [])
      is_device = optional(object({
        match_values     = list(string)
        negate_condition = optional(bool, false)
      }))
      socket_address = optional(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
      }))
      client_port = optional(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
      }))
      server_port = optional(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
      }))
      host_name = optional(list(object({
        operator         = string
        match_values     = list(string)
        negate_condition = optional(bool, false)
        transforms       = optional(list(string), [])
      })), [])
      ssl_protocol = optional(object({
        match_values     = list(string)
        negate_condition = optional(bool, false)
      }))
    }))
  }))
  default = {}
}

# Azure Policy Variables
variable "enable_policy_assignments" {
  description = "Enable Azure Policy assignments"
  type        = bool
  default     = false
}

variable "policy_assignments" {
  description = "Azure Policy assignments"
  type = map(object({
    name                 = string
    policy_definition_id = string
    display_name         = string
    description          = optional(string)
    parameters           = optional(string)
  }))
  default = {}
}

# Diagnostic Settings Variables
variable "diagnostic_settings" {
  description = "Diagnostic settings configuration"
  type = object({
    name                           = optional(string)
    log_analytics_workspace_id     = optional(string)
    storage_account_id             = optional(string)
    eventhub_name                  = optional(string)
    eventhub_authorization_rule_id = optional(string)
    logs = optional(list(object({
      category = string
      retention_policy = optional(object({
        enabled = bool
        days    = number
      }))
    })), [])
    metrics = optional(list(object({
      category = string
      enabled  = bool
      retention_policy = optional(object({
        enabled = bool
        days    = number
      }))
    })), [])
  })
  default = null
}

# Tags
variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}